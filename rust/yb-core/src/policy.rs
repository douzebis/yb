// SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Default-credential policy (spec 0024): what each command does when some
//! credentials are still at their factory values.
//!
//! yb refuses only when it is about to put a secret behind a credential
//! that does not protect it.  A default PIN or PUK exposes every secret (the
//! PUK can set a new PIN); a default management key allows tampering but
//! reveals nothing.

use crate::auxiliaries::DefaultCredentials;
use crate::errors::YbError;
use anyhow::Result;

/// The operation about to act, for [`default_policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretOp {
    Fetch,
    Store,
    Remove,
    Fsck,
    Format { protect: bool },
    SelfTest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Silent,
    Warn,
    Refuse,
}

impl SecretOp {
    /// The spec 0024 §2 table: (action on a default PIN or PUK, action on a
    /// default management key).
    fn actions(self) -> (Action, Action) {
        use Action::{Refuse, Silent, Warn};
        match self {
            Self::Fetch => (Warn, Silent),
            Self::Store => (Refuse, Warn),
            Self::Remove | Self::Fsck | Self::Format { protect: false } => (Warn, Warn),
            // --protect stores the new management key behind the PIN, and
            // replaces the factory management key.
            Self::Format { protect: true } => (Refuse, Silent),
            // Unchanged from before spec 0024.
            Self::SelfTest => (Refuse, Refuse),
        }
    }
}

/// Apply the policy for `op`: `Err` for a refusal, otherwise the warnings
/// to show (at most one line).  `allow_defaults` turns refusals into
/// warnings.
pub fn default_policy(
    op: SecretOp,
    defaults: &DefaultCredentials,
    allow_defaults: bool,
) -> Result<Vec<String>> {
    let (on_pin_puk, on_mgmt) = op.actions();
    let pin_puk: Vec<&str> = [(defaults.pin, "PIN"), (defaults.puk, "PUK")]
        .into_iter()
        .filter_map(|(is_default, label)| is_default.then_some(label))
        .collect();
    let mgmt: Vec<&str> = defaults
        .management_key
        .then_some("management key")
        .into_iter()
        .collect();

    let (mut refused, mut warned) = (Vec::new(), Vec::new());
    for (labels, action) in [(pin_puk, on_pin_puk), (mgmt, on_mgmt)] {
        match action {
            Action::Refuse if !allow_defaults => refused.extend(labels),
            Action::Refuse | Action::Warn => warned.extend(labels),
            Action::Silent => {}
        }
    }

    if !refused.is_empty() {
        let what = join(&refused);
        if op == SecretOp::SelfTest {
            return Err(
                YbError::new(format!("YubiKey has default credentials: {what}"))
                    .why("this is insecure")
                    .fix("use --allow-defaults to override")
                    .into(),
            );
        }
        return Err(
            YbError::new(format!("this YubiKey still has the factory-default {what}"))
                .why("anything stored on it could be read by whoever holds the key")
                .fix(
                    "change the PIN and PUK with `ykman piv access change-pin` and \
                     `ykman piv access change-puk` (the store is kept); for testing \
                     only, --allow-defaults overrides",
                )
                .into(),
        );
    }
    Ok(if warned.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "Warning: this YubiKey uses the factory-default {}.",
            join(&warned)
        )]
    })
}

/// "PIN", "PIN and PUK", "PIN, PUK and management key".
fn join(labels: &[&str]) -> String {
    match labels {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [init @ .., last] => format!("{} and {last}", init.join(", ")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const NONE: DefaultCredentials = DefaultCredentials {
        pin: false,
        puk: false,
        management_key: false,
    };
    const PIN: DefaultCredentials = DefaultCredentials { pin: true, ..NONE };
    const PUK: DefaultCredentials = DefaultCredentials { puk: true, ..NONE };
    const MGMT: DefaultCredentials = DefaultCredentials {
        management_key: true,
        ..NONE
    };

    const ALL_OPS: [SecretOp; 7] = [
        SecretOp::Fetch,
        SecretOp::Store,
        SecretOp::Remove,
        SecretOp::Fsck,
        SecretOp::Format { protect: false },
        SecretOp::Format { protect: true },
        SecretOp::SelfTest,
    ];

    /// "refuse", "warn" or "silent" for `op` with `defaults`.
    fn outcome(op: SecretOp, defaults: DefaultCredentials, allow: bool) -> &'static str {
        match default_policy(op, &defaults, allow) {
            Err(_) => "refuse",
            Ok(w) if w.is_empty() => "silent",
            Ok(_) => "warn",
        }
    }

    #[test]
    fn table_default_pin_or_puk() {
        for creds in [PIN, PUK] {
            let got: Vec<_> = ALL_OPS
                .iter()
                .map(|&op| outcome(op, creds, false))
                .collect();
            assert_eq!(
                got,
                ["warn", "refuse", "warn", "warn", "warn", "refuse", "refuse"],
                "{creds:?}"
            );
        }
    }

    #[test]
    fn table_default_management_key() {
        let got: Vec<_> = ALL_OPS.iter().map(|&op| outcome(op, MGMT, false)).collect();
        assert_eq!(
            got,
            ["silent", "warn", "warn", "warn", "warn", "silent", "refuse"]
        );
    }

    #[test]
    fn nothing_default_is_silent() {
        for op in ALL_OPS {
            assert_eq!(outcome(op, NONE, false), "silent", "{op:?}");
        }
    }

    #[test]
    fn allow_defaults_turns_refusals_into_warnings() {
        for op in ALL_OPS {
            for creds in [PIN, PUK, MGMT] {
                assert_ne!(outcome(op, creds, true), "refuse", "{op:?} {creds:?}");
            }
        }
    }

    #[test]
    fn messages_name_the_credentials() {
        let all = DefaultCredentials {
            pin: true,
            puk: true,
            management_key: true,
        };
        let w = default_policy(SecretOp::Remove, &all, false).unwrap();
        assert_eq!(
            w,
            ["Warning: this YubiKey uses the factory-default PIN, PUK and management key."]
        );
        let e = default_policy(SecretOp::Store, &all, false).unwrap_err();
        assert!(e
            .to_string()
            .starts_with("this YubiKey still has the factory-default PIN and PUK ("));
    }
}
