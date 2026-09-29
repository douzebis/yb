// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! The error catalog and the renderer (spec 0025 §2–§3).
//!
//! The catalog maps (operation, status word) to what / why / fix texts.  It
//! never depends on the firmware version.

use super::{CardError, CardOp, PcscCode, YbError};
use std::error::Error as StdError;

const ISSUES_URL: &str = "https://github.com/douzebis/yb/issues";

/// Which operations a catalog entry applies to.
#[derive(Clone, Copy)]
enum OpPat {
    Any,
    Is(fn(&CardOp) -> bool),
}

impl OpPat {
    fn matches(self, op: &CardOp) -> bool {
        match self {
            Self::Any => true,
            Self::Is(pred) => pred(op),
        }
    }
}

/// One catalog entry.  `sw & mask == sw_value` selects the status words.
/// Texts may use `{tries}` (low nibble of a `63Cx`), `{cred}` (PIN or
/// PUK), `{algo}` (the management key algorithm yb used) and `{slot}`.
struct Entry {
    op: OpPat,
    sw_value: u16,
    mask: u16,
    what: &'static str,
    why: &'static str,
    fix: &'static str,
}

const EXACT: u16 = 0xFFFF;

/// The catalog, most specific entries first (spec 0025 §2).
static CATALOG: &[Entry] = &[
    Entry {
        op: OpPat::Is(|op| *op == CardOp::VerifyPin),
        sw_value: 0x63C0,
        mask: 0xFFF0,
        what: "wrong PIN",
        why: "{tries}",
        fix: "",
    },
    Entry {
        op: OpPat::Is(|op| *op == CardOp::VerifyPin),
        sw_value: 0x6983,
        mask: EXACT,
        what: "the PIN is blocked",
        why: "too many wrong attempts",
        fix: "unblock it with the PUK (`ykman piv access unblock-pin`); if the PUK is \
              blocked too, only a PIV reset helps, and it erases everything",
    },
    Entry {
        op: OpPat::Is(|op| *op == CardOp::ChangePin),
        sw_value: 0x63C0,
        mask: 0xFFF0,
        what: "wrong current PIN",
        why: "{tries}",
        fix: "",
    },
    Entry {
        op: OpPat::Is(|op| *op == CardOp::ChangePuk),
        sw_value: 0x63C0,
        mask: 0xFFF0,
        what: "wrong current PUK",
        why: "{tries}",
        fix: "",
    },
    Entry {
        op: OpPat::Is(|op| matches!(op, CardOp::ChangePin | CardOp::ChangePuk)),
        sw_value: 0x6983,
        mask: EXACT,
        what: "the {cred} is blocked",
        why: "too many wrong attempts",
        fix: "",
    },
    Entry {
        op: OpPat::Is(|op| matches!(op, CardOp::ChangePin | CardOp::ChangePuk)),
        sw_value: 0x6985,
        mask: EXACT,
        what: "the new {cred} does not meet this YubiKey's complexity requirement",
        why: "the YubiKey enforces a PIN complexity policy",
        fix: "choose a less predictable value (no repeated or sequential digits, \
              not a common PIN)",
    },
    Entry {
        op: OpPat::Is(|op| *op == CardOp::MgmtAuth),
        sw_value: 0x6A80,
        mask: EXACT,
        what: "cannot authenticate with the management key",
        why: "the YubiKey rejected the {algo} algorithm yb used",
        fix: "`yb fsck` shows the card's management key algorithm",
    },
    Entry {
        op: OpPat::Is(|op| *op == CardOp::MgmtAuth),
        sw_value: 0x6982,
        mask: EXACT,
        what: "wrong management key",
        why: "the key from YB_MANAGEMENT_KEY or from PRINTED is not the YubiKey's \
              management key",
        fix: "check YB_MANAGEMENT_KEY; `yb fsck` shows whether the YubiKey keeps its \
              management key",
    },
    Entry {
        op: OpPat::Is(|op| *op == CardOp::ReadObject(crate::auxiliaries::OBJ_PRINTED)),
        sw_value: 0x6A82,
        mask: EXACT,
        what: "the management key is not stored on the YubiKey",
        why: "the YubiKey does not keep its management key, or was set up by another tool",
        fix: "set YB_MANAGEMENT_KEY, or have yb keep a new one on the YubiKey with \
              `yb rotate-management-key`",
    },
    Entry {
        op: OpPat::Is(|op| matches!(op, CardOp::ReadCertificate(_))),
        sw_value: 0x6A82,
        mask: EXACT,
        what: "no key in slot {slot}",
        why: "this YubiKey has not been set up for yb",
        fix: "`yb format --generate`",
    },
    Entry {
        op: OpPat::Is(|op| matches!(op, CardOp::WriteObject(_))),
        sw_value: 0x6A84,
        mask: EXACT,
        what: "the YubiKey's storage is full",
        why: "the PIV area's ~51 KB are used up",
        fix: "`yb fsck --nvm`, then remove blobs",
    },
    Entry {
        op: OpPat::Is(|op| matches!(op, CardOp::WriteObject(_))),
        sw_value: 0x6982,
        mask: EXACT,
        what: "the YubiKey refused the write",
        why: "management key authentication did not happen or was lost",
        fix: "this is likely a yb bug: please report it",
    },
    Entry {
        op: OpPat::Is(|op| {
            matches!(
                op,
                CardOp::GenerateKey(_) | CardOp::Sign(_) | CardOp::Ecdh(_)
            )
        }),
        sw_value: 0x6982,
        mask: EXACT,
        what: "the YubiKey requires the PIN or a touch for this key",
        why: "the PIN was not verified, or the key requires a touch",
        fix: "run the command again, and touch the YubiKey if it blinks",
    },
    Entry {
        op: OpPat::Is(|op| matches!(op, CardOp::Sign(_) | CardOp::Ecdh(_))),
        sw_value: 0x6A80,
        mask: EXACT,
        what: "the key in slot {slot} cannot do this operation",
        why: "it is not an EC P-256 key",
        fix: "`yb format --generate` (erases the store)",
    },
    Entry {
        op: OpPat::Any,
        sw_value: 0x6D00,
        mask: EXACT,
        what: "this YubiKey does not support this operation",
        why: "its firmware is too old for it",
        fix: "",
    },
    Entry {
        op: OpPat::Is(|op| *op == CardOp::SelectPiv),
        sw_value: 0x6A82,
        mask: EXACT,
        what: "the PIV application is not available",
        why: "PIV is disabled on this YubiKey, or the device is not a YubiKey",
        fix: "`ykman config usb --enable PIV`",
    },
];

/// The user-facing explanation of an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    pub what: String,
    pub why: Option<String>,
    pub fix: Option<String>,
    /// Details line content (card errors only).
    pub details: Option<String>,
}

/// What the renderer needs besides the error itself.  Only the fallback
/// for unexpected errors uses it (spec 0025 §2).
#[derive(Debug, Clone, Default)]
pub struct RenderEnv {
    pub firmware: Option<String>,
    pub yb_version: Option<String>,
}

/// Explanation of a PC/SC failure, e.g. for `list-readers` hints.
pub fn explain_pcsc(code: &PcscCode) -> Option<Explanation> {
    let (what, fix) = match code {
        PcscCode::NoService => (
            "the smart card service is not running",
            "start pcscd (`systemctl start pcscd.socket`); on NixOS, set \
             `services.pcscd.enable = true`",
        ),
        PcscCode::NoReaders => (
            "no YubiKey found",
            "check that it is plugged in and that its CCID interface is enabled \
             (`ykman config usb`); in a VM, check the USB passthrough (`lsusb` shows `1050:…`)",
        ),
        PcscCode::SharingViolation => (
            "another program is using the YubiKey",
            "usually gpg's scdaemon: `gpgconf --kill scdaemon`",
        ),
        PcscCode::RemovedCard | PcscCode::ResetCard => (
            "the YubiKey was removed or reset during the operation",
            "reconnect it; after a write command, run `yb fsck` to check the store",
        ),
        PcscCode::Other(_) => return None,
    };
    Some(Explanation {
        what: what.to_owned(),
        why: None,
        fix: Some(fix.to_owned()),
        details: None,
    })
}

fn substitute(template: &str, op: &CardOp, sw: u16, err: &CardError) -> String {
    let cred = if *op == CardOp::ChangePuk {
        "PUK"
    } else {
        "PIN"
    };
    let tries = (sw & 0x0F) as u8;
    let tries_text = match tries {
        0 => format!("no attempts left: the {cred} is now blocked"),
        1 => format!("1 attempt left; one more failure blocks the {cred}"),
        n => format!("{n} attempts left before the {cred} is blocked"),
    };
    let algo = match err {
        CardError::Status { ctx, .. } => ctx.algo.map(|a| a.to_string()),
        _ => None,
    }
    .unwrap_or_else(|| "management key".to_owned());
    let slot = match op {
        CardOp::ReadCertificate(s) | CardOp::Sign(s) | CardOp::Ecdh(s) | CardOp::GenerateKey(s) => {
            format!("0x{s:02x}")
        }
        _ => "the store slot".to_owned(),
    };
    template
        .replace("{tries}", &tries_text)
        .replace("{cred}", cred)
        .replace("{algo}", &algo)
        .replace("{slot}", &slot)
}

fn non_empty(s: String) -> Option<String> {
    (!s.is_empty()).then_some(s)
}

/// Explain a card error, or `None` if the catalog does not know it.
fn explain_card(err: &CardError) -> Option<Explanation> {
    let details = Some(err.details());
    let (op, sw) = match err {
        CardError::Status { op, sw, .. } => (*op, *sw),
        // yb itself found the management key wrong (response mismatch):
        // same explanation as the card saying so.
        CardError::Protocol {
            op: CardOp::MgmtAuth,
            ..
        } => (CardOp::MgmtAuth, 0x6982),
        CardError::Protocol { .. } => return None,
        CardError::Pcsc { code, .. } => {
            return explain_pcsc(code).map(|e| Explanation { details, ..e });
        }
    };
    let entry = CATALOG
        .iter()
        .find(|e| e.op.matches(&op) && sw & e.mask == e.sw_value)?;
    Some(Explanation {
        what: substitute(entry.what, &op, sw, err),
        why: non_empty(substitute(entry.why, &op, sw, err)),
        fix: non_empty(substitute(entry.fix, &op, sw, err)),
        details,
    })
}

/// The fallback for card errors the catalog does not know: all the
/// context available, never identifying data (spec 0025 §2).
fn unexpected(err: &CardError, env: &RenderEnv) -> Explanation {
    let op = match err {
        CardError::Status { op, .. } | CardError::Protocol { op, .. } => op.describe(),
        CardError::Pcsc { .. } => "the operation".to_owned(),
    };
    let mut details = err.details();
    if let CardError::Status { ctx, .. } = err {
        if let Some(algo) = ctx.algo {
            details.push_str(&format!("; management key algorithm {algo}"));
        }
    }
    if let Some(ref fw) = env.firmware {
        details.push_str(&format!("; firmware {fw}"));
    }
    if let Some(ref v) = env.yb_version {
        details.push_str(&format!("; yb {v}"));
    }
    Explanation {
        what: format!("the YubiKey rejected {op}"),
        why: Some(format!(
            "this is unexpected — please report it at {ISSUES_URL} with the details below"
        )),
        fix: None,
        details: Some(details),
    }
}

fn sentence(s: &str) -> String {
    let mut chars = s.chars();
    let mut out: String = match chars.next() {
        Some(c) => c.to_uppercase().chain(chars).collect(),
        None => String::new(),
    };
    if !out.ends_with(['.', '!', '?']) {
        out.push('.');
    }
    out
}

fn with_period(s: &str) -> String {
    if s.ends_with(['.', '!', '?']) {
        s.to_owned()
    } else {
        format!("{s}.")
    }
}

/// Render an error chain for the user (spec 0025 §3).
///
/// If the chain contains a [`CardError`] or [`YbError`], its explanation is
/// shown: as the headline when it stands alone, or as `Cause:` / `Try:`
/// under the outer context messages.  Other errors render as `{e:#}`.
pub fn render(err: &anyhow::Error, env: &RenderEnv) -> String {
    let chain: Vec<&(dyn StdError + 'static)> = err.chain().collect();
    let typed = chain.iter().enumerate().find_map(|(i, e)| {
        if let Some(c) = e.downcast_ref::<CardError>() {
            Some((i, explain_card(c).unwrap_or_else(|| unexpected(c, env))))
        } else {
            e.downcast_ref::<YbError>().map(|y| {
                (
                    i,
                    Explanation {
                        what: y.what.clone(),
                        why: y.why.clone(),
                        fix: y.fix.clone(),
                        details: None,
                    },
                )
            })
        }
    });
    let Some((index, exp)) = typed else {
        return format!("Error: {err:#}");
    };

    let mut lines = Vec::new();
    if index == 0 {
        lines.push(format!("Error: {}", with_period(&exp.what)));
        if let Some(ref why) = exp.why {
            lines.push(format!("  {}", sentence(why)));
        }
    } else {
        let outer: Vec<String> = chain[..index].iter().map(|e| e.to_string()).collect();
        lines.push(format!("Error: {}", outer.join(": ")));
        let cause = match exp.why {
            Some(ref why) => format!("{} ({why})", exp.what),
            None => exp.what.clone(),
        };
        lines.push(format!("  Cause: {}", with_period(&cause)));
    }
    if let Some(ref fix) = exp.fix {
        lines.push(format!("  Try: {}", with_period(fix)));
    }
    if let Some(ref details) = exp.details {
        lines.push(format!("  (details: {details})"));
    }
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::{ErrCtx, PcscOp};
    use super::*;
    use crate::piv::MgmtAlgo;
    use anyhow::Context as _;

    fn env() -> RenderEnv {
        RenderEnv {
            firmware: Some("5.4.3".to_owned()),
            yb_version: Some("0.4.2".to_owned()),
        }
    }

    fn status(op: CardOp, sw: u16) -> anyhow::Error {
        let [a, b] = sw.to_be_bytes();
        anyhow::Error::new(CardError::status(op, a, b))
    }

    /// First line and details line of a standalone card error.
    fn first_and_details(e: anyhow::Error) -> (String, String) {
        let text = render(&e, &env());
        let first = text.lines().next().unwrap().to_owned();
        let details = text.lines().last().unwrap().to_owned();
        (first, details)
    }

    #[test]
    fn every_catalog_entry_renders() {
        let cases: &[(CardOp, u16, &str)] = &[
            (CardOp::VerifyPin, 0x63C2, "Error: wrong PIN."),
            (CardOp::VerifyPin, 0x6983, "Error: the PIN is blocked."),
            (
                CardOp::MgmtAuth,
                0x6A80,
                "Error: cannot authenticate with the management key.",
            ),
            (CardOp::MgmtAuth, 0x6982, "Error: wrong management key."),
            (
                CardOp::ReadObject(crate::auxiliaries::OBJ_PRINTED),
                0x6A82,
                "Error: the management key is not stored on the YubiKey.",
            ),
            (
                CardOp::ReadCertificate(0x82),
                0x6A82,
                "Error: no key in slot 0x82.",
            ),
            (
                CardOp::WriteObject(0x5F0003),
                0x6A84,
                "Error: the YubiKey's storage is full.",
            ),
            (
                CardOp::WriteObject(0x5F0003),
                0x6982,
                "Error: the YubiKey refused the write.",
            ),
            (
                CardOp::Sign(0x82),
                0x6982,
                "Error: the YubiKey requires the PIN or a touch for this key.",
            ),
            (
                CardOp::Ecdh(0x82),
                0x6A80,
                "Error: the key in slot 0x82 cannot do this operation.",
            ),
            (
                CardOp::GenerateKey(0x82),
                0x6D00,
                "Error: this YubiKey does not support this operation.",
            ),
            (
                CardOp::SelectPiv,
                0x6A82,
                "Error: the PIV application is not available.",
            ),
        ];
        for &(op, sw, expected) in cases {
            let (first, details) = first_and_details(status(op, sw));
            assert_eq!(first, expected, "{op:?} {sw:04X}");
            assert_eq!(
                details,
                format!("  (details: {} → SW {sw:04X})", op.describe()),
                "{op:?} {sw:04X}"
            );
        }
    }

    #[test]
    fn wrong_pin_counts_down() {
        let text = render(&status(CardOp::VerifyPin, 0x63C1), &env());
        assert!(
            text.contains("1 attempt left; one more failure blocks the PIN"),
            "{text}"
        );
        let text = render(&status(CardOp::VerifyPin, 0x63C2), &env());
        assert!(text.contains("2 attempts left"), "{text}");
    }

    #[test]
    fn response_mismatch_is_a_wrong_management_key() {
        let e = anyhow::Error::new(CardError::protocol(
            CardOp::MgmtAuth,
            "card response mismatch",
        ));
        let text = render(&e, &env());
        assert!(text.starts_with("Error: wrong management key."), "{text}");
        assert!(text.ends_with("(details: management key authentication → card response mismatch)"));
    }

    #[test]
    fn pcsc_errors_are_explained() {
        for (code, what) in [
            (PcscCode::NoService, "the smart card service is not running"),
            (PcscCode::NoReaders, "no YubiKey found"),
            (
                PcscCode::SharingViolation,
                "another program is using the YubiKey",
            ),
            (
                PcscCode::RemovedCard,
                "the YubiKey was removed or reset during the operation",
            ),
        ] {
            let e = anyhow::Error::new(CardError::Pcsc {
                op: PcscOp::Connect,
                code: code.clone(),
            });
            let text = render(&e, &env());
            assert!(text.starts_with(&format!("Error: {what}.")), "{text}");
            assert!(text.contains("  Try: "), "{text}");
            assert!(text.contains(&format!("(details: connecting to the YubiKey → {code})")));
        }
    }

    #[test]
    fn unexpected_errors_carry_all_context() {
        let e = anyhow::Error::new(
            CardError::status(CardOp::WriteObject(0x5F0001), 0x6F, 0x00).with_ctx(ErrCtx {
                algo: Some(MgmtAlgo::Aes192),
            }),
        );
        assert_eq!(
            render(&e, &env()),
            "Error: the YubiKey rejected write object 0x5F0001.\n  \
             This is unexpected — please report it at https://github.com/douzebis/yb/issues \
             with the details below.\n  \
             (details: write object 0x5F0001 → SW 6F00; management key algorithm AES-192; \
             firmware 5.4.3; yb 0.4.2)"
        );
    }

    /// Spec 0025 §3, first example.
    #[test]
    fn snapshot_standalone_card_error() {
        let e = anyhow::Error::new(CardError::status(CardOp::MgmtAuth, 0x6A, 0x80).with_ctx(
            ErrCtx {
                algo: Some(MgmtAlgo::Tdes),
            },
        ));
        assert_eq!(
            render(&e, &env()),
            "Error: cannot authenticate with the management key.\n  \
             The YubiKey rejected the 3DES algorithm yb used.\n  \
             Try: `yb fsck` shows the card's management key algorithm.\n  \
             (details: management key authentication → SW 6A80)"
        );
    }

    /// Spec 0025 §3, second example: a card error under context.
    #[test]
    fn snapshot_card_error_under_context() {
        let e = Err::<(), _>(CardError::status(CardOp::WriteObject(0x5F0003), 0x6A, 0x84))
            .context("yb format stopped while erasing the store (completed: nothing)")
            .unwrap_err();
        assert_eq!(
            render(&e, &env()),
            "Error: yb format stopped while erasing the store (completed: nothing)\n  \
             Cause: the YubiKey's storage is full (the PIV area's ~51 KB are used up).\n  \
             Try: `yb fsck --nvm`, then remove blobs.\n  \
             (details: write object 0x5F0003 → SW 6A84)"
        );
    }

    #[test]
    fn yb_errors_render_without_details() {
        let e = anyhow::Error::new(
            YbError::new("the management key is not in PRINTED and is not the factory default")
                .fix("set YB_MANAGEMENT_KEY"),
        );
        assert_eq!(
            render(&e, &env()),
            "Error: the management key is not in PRINTED and is not the factory default.\n  \
             Try: set YB_MANAGEMENT_KEY."
        );
    }

    #[test]
    fn untyped_errors_render_as_before() {
        let e = anyhow::anyhow!("plain failure").context("outer");
        assert_eq!(render(&e, &env()), "Error: outer: plain failure");
    }
}
