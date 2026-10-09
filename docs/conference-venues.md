<!--
SPDX-FileCopyrightText: Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# yb — Conference Venue Analysis

*Researched June 2026.*

---

## What yb offers a conference audience

`yb` is a Rust CLI tool for hardware-backed encrypted blob storage on a
YubiKey PIV application.  Technical talking points:

- **Hybrid encryption** — ECDH (on-card) + HKDF-SHA256 + AES-256-GCM; private
  key never leaves the device; GENERAL AUTHENTICATE APDU only.
- **Zero `unsafe` Rust** — no subprocesses; all PIV operations are native PC/SC
  APDUs; full RustCrypto stack (`p256`, `aes-gcm`, `hkdf`, `subtle`).
- **Credential-free integrity auditing** — ECDSA signatures appended at write
  time; `fsck` verifies using only the public key from the X.509 cert in the
  PIV slot — no PIN, no management key.
- **Custom binary format** (`yblob`) — self-describing chunks; exact-size
  dynamic objects; transparent brotli/xz compression; registered in the
  `file` magic database (bug #666, merged June 2025) as a format-stability
  signal.
- **Testable hardware code** — `VirtualPiv` backend with real P-256 crypto;
  `YB_FIXTURE` YAML escape hatch for subprocess tests; tier-2 NixOS VM tests
  with `vsmartcard-vpcd` + `piv-authenticator`.
- **Packaging** — accepted into nixpkgs (PR #514826) after substantive
  reviewer scrutiny and colleague endorsement; `cargo install --locked`;
  macOS and Linux; shell completions for bash/zsh/fish.

---

## Venue analysis

### Tier A — Strong fit

#### EuroRust 2026

- **Dates:** October 14–17, 2026 — Barcelona & online
- **CFP deadline:** Not yet announced (likely opens summer 2026)
- **Format:** ~30-minute talks; workshops available
- **Review process:** Programme committee review; no published proceedings
- **Fit:** Best single venue. The entire audience writes Rust.  Three distinct
  angles all land here:
  1. *Zero-`unsafe` hardware cryptography in Rust* — the PC/SC + p256 +
     aes-gcm + subtle stack; why each crate was chosen; what `zeroize` and
     `subtle::ConstantTimeEq` protect against.
  2. *Designing a Rust library that is also a good CLI* — the `yb-core` /
     `yb` crate split; `PivBackend` trait; `VirtualPiv` for tests without
     hardware.
  3. *Testing Rust that talks to hardware* — the `VirtualPiv` / `YB_FIXTURE`
     / vsmartcard tier-1/tier-2 architecture is genuinely unusual and
     publishable on its own merits.
- **Action:** Monitor `eurorust.eu` for CFP opening; prepare abstract
  leading with the hardware-testability angle (most distinctive).

---

#### FOSDEM 2027 — Rust devroom or Security devroom

- **Dates:** February 2027 — Brussels (free admission)
- **CFP deadline:** ~November 2026
- **Format:** 25-minute talks; high acceptance bar for technical depth
- **Review process:** Devroom committee review; no published proceedings
- **Fit:** Excellent for a 25-minute deep technical talk.  The Rust devroom
  is one of the most attended at FOSDEM; the Security devroom is a natural
  fit for the PIV + ECDSA + hardware-key angle.  A dual submission (Rust
  devroom primary, Security devroom backup) is allowed.  The Nix/NixOS
  devroom is a third option given the nixpkgs submission.
- **Action:** Prepare a submission for the Rust devroom first.  The
  hardware-testability angle is the strongest differentiator.

---

#### Black Hat Europe 2026 — Arsenal

- **Dates:** December 7–10, 2026 — ExCeL London
- **CFP deadline:** **June 19, 2026** (open now — closes in ~13 days)
- **Format:** Interactive demo booth (~1h50m); attendees walk up; no talk
- **Review process:** Arsenal committee review; no proceedings
- **Fit:** Arsenal is specifically for open-source security and research
  tools.  MIT license ✓, GitHub repo ✓, format spec documentation ✓.
  The security framing is natural: hardware-backed AEAD, credential-free
  tamper detection, default-credential guard.  Interactive format suits
  a CLI tool well — attendees try it against their own YubiKey.
- **Action:** Submit before June 19.  Does not conflict with any other
  active submission.

---

#### RustConf 2027

- **Dates:** ~September 2027 (CFP for 2026 closed Feb 16)
- **Format:** ~30-minute talks
- **Review process:** Programme committee; no published proceedings
- **Fit:** Same audience as EuroRust; overlapping angles.  File for 2027
  if EuroRust 2026 is accepted (different events, no conflict).

---

### Tier B — Good fit, watch for CFP

#### KubeCon + CloudNativeCon 2027

- **Fit:** "Hardware-backed secrets in the developer workflow" — storing
  kubeconfig credentials, signing keys, or CI secrets on a YubiKey and
  retrieving them with a single static binary.  The nixpkgs submission
  and the reproducible Nix build add ecosystem credibility.  Better as a
  lightning talk or a project pavilion appearance than a full session.

#### Open Source Summit Europe / NA 2027

- **Fit:** General open-source practitioner audience.  The "no dependencies
  beyond PC/SC, single static binary, MIT license, nixpkgs" packaging story
  works.  Less technical depth than the Rust conferences.

#### DEF CON / Black Hat USA 2027 — Arsenal

- **Fit:** Same framing as Black Hat Europe but US-based.  CFP closed for
  2026 (May 1); file for 2027.

---

## Talk angles by venue

| Angle | Best venues |
|---|---|
| Zero-`unsafe` hardware crypto in Rust | EuroRust, RustConf, FOSDEM Rust devroom |
| Testing hardware-dependent Rust (`VirtualPiv`, `YB_FIXTURE`) | EuroRust, RustConf, FOSDEM Rust devroom |
| Hardware-backed AEAD + credential-free tamper detection | Black Hat Arsenal, FOSDEM Security devroom |
| Secrets on a YubiKey for the developer workflow | KubeCon, Open Source Summit |
| MIT/Rust/Nix/nixpkgs packaging story | FOSDEM Nix devroom, Open Source Summit |

---

## For a technical promotion candidacy — venue recommendation

The goal is a **review committee** and ideally **published proceedings** that
can be cited in a promotion dossier.

Among the venues above, none publish proceedings in the academic sense.
The Rust/security conference circuit is practitioner-oriented.  However,
two venues produce durable, citable, indexed artefacts:

### Primary recommendation — USENIX ;login: / USENIX WOOT

**USENIX WOOT (Workshop on Offensive Technologies)**

- **Dates:** co-located with USENIX Security; next edition ~August 2027
- **CFP deadline:** ~April 2027
- **Format:** 5–10 page paper + presentation; peer-reviewed; published in
  open-access proceedings indexed by DBLP and Google Scholar
- **Fit:** The credential-free tamper-detection design, the ECDSA-trailer
  format, and the hardware-backed AEAD scheme are all publication-worthy
  security engineering contributions.  The comparison between the legacy
  Python implementation (AES-CBC, no authentication, secrets in subprocess
  args) and the hardened Rust rewrite is a concrete case study.
  WOOT accepts tool papers — "here is a tool, here is its security model,
  here is the threat analysis" is an established paper genre at this venue.
- **Why it helps a promotion dossier:** peer-reviewed, open-access, DBLP-
  indexed; USENIX is the leading systems-security venue; a WOOT paper
  carries genuine weight in a technical promotion at an engineering-oriented
  company.

**USENIX ;login:**  (magazine, not conference)

- Open to practitioner articles (2–6 pages, editorial review, not peer-
  reviewed); lower bar than WOOT but still citable and widely read.
  A shorter companion piece to a WOOT submission, or a standalone article,
  is worth considering.

---

### Secondary recommendation — IEEE S&P (Oakland) poster / SRC

**IEEE Symposium on Security and Privacy — Student Research Competition /
Poster track**

- **CFP deadline:** ~December 2026 for the May 2027 edition
- **Format:** 2-page extended abstract + poster; reviewed; published in
  supplementary proceedings
- **Fit:** If the speaker has an academic affiliation (S3NS / Thales counts
  as industry research), a poster at Oakland is citable and highly visible
  in the security community.

---

### Tertiary recommendation — Usenix ATC or EuroSys short paper

If the focus shifts from security to *systems* (the YubiKey NVM budget
management, dynamic object sizing, the testable-hardware-abstraction design),
a short paper at **USENIX ATC** or **EuroSys** (tools/experience track) would
be well-placed.  These are highly competitive but carry strong weight in a
systems-engineering promotion.

---

### Summary table — review committee + proceedings

| Venue | Peer review | Published proceedings | DBLP / Scholar indexed | Difficulty |
|---|---|---|---|---|
| USENIX WOOT | Yes (double-blind) | Yes (open access) | Yes | Moderate |
| USENIX ;login: | Editorial | Yes (magazine) | Partial | Low |
| IEEE S&P poster | Yes | Yes (supplementary) | Partial | Moderate |
| USENIX ATC / EuroSys (short paper) | Yes (double-blind) | Yes | Yes | High |
| EuroRust / FOSDEM / Black Hat Arsenal | Programme committee | No | No | Low–Moderate |

**Recommended path for a promotion dossier:**

1. Submit to **Black Hat Europe 2026 Arsenal** (deadline June 19) for
   immediate public visibility and an open-source security credential.
2. Prepare a **USENIX WOOT 2027** paper (4–8 pages) over the summer/autumn
   2026, centred on the security engineering story: threat model, CBC → GCM
   migration, ECDSA integrity scheme, credential-free audit.  The security
   review (`docs/sec-review.md`) and the spec trail (`docs/specs/`) provide
   the raw material for a structured paper.
3. Submit to **EuroRust 2026** or **FOSDEM 2027 Rust devroom** for the
   engineering/community visibility track — complements the WOOT paper
   without duplicating it.

---

## Immediate actions

| Action | Deadline |
|---|---|
| Submit to Black Hat Europe 2026 Arsenal | **June 19, 2026** |
| Monitor `eurorust.eu` for CFP opening | Summer 2026 |
| Monitor FOSDEM 2027 Rust/Security devroom CFP | ~November 2026 |
| Draft USENIX WOOT 2027 abstract | Autumn 2026 |

---

## Yubico community outreach

A Yubico invitation or community appearance is a different kind of signal
from a peer-reviewed paper, but a real one: it says the people who make the
hardware think the work is worth showing their users.  That third-party
endorsement from the primary vendor is hard to manufacture — you cannot submit
to it, you have to earn it — and a promotion committee will read it that way.

The nixpkgs publication is the strongest credential to lead with in any
outreach: it is evidence that the tool survived substantive external review
and that colleagues attested to its utility.  The `file` magic registration
is a secondary supporting point (format stability, documentation discipline)
but is not itself a quality signal — anyone who follows the process correctly
can add an entry.

### Recommended approach and sequence

**1. Works With YubiKey listing (do first)**

Yubico maintains a public "Works With YubiKey" directory of third-party
integrations.  `yb` qualifies: it uses the PIV application, is open-source,
and has a published format spec.  Getting listed creates a permanent, citable
reference on Yubico's own site.  It is the lowest-friction step and should
be done before any other outreach.

**2. GitHub issue or discussion in a Yubico repo**

Yubico maintains several open-source repos (`yubikey-manager`,
`yubico-piv-tool`, `python-piv`).  A well-written technical note — framed
as "here is a tool that uses PIV retired-key-certificate slots in an
undocumented way; here is the format spec; wanted to flag it to the
maintainers" — is a low-pressure, credible introduction.  The yblob format
spec is thorough enough to make this a serious technical communication rather
than a promotional pitch.  A documentation PR to `yubikey-manager` (the
retired certificate slots `0x5F_0000`–`0x5F_0013` are not covered in depth
there) would be even stronger: it puts the work in front of Yubico engineers
in the context where they are most receptive.

**3. Developer Relations email**

After the nixpkgs PR is merged and the repo has some public traction, reach
out to the Yubico developer relations team (`developers.yubico.com`).  Keep
it short: what the tool does, link to the GitHub repo, link to the nixpkgs
package, one sentence on the colleague endorsement.  Offer three concrete
asks in decreasing order of effort — developer blog post, community webinar,
mention in the developer newsletter — so they can say yes to any one of them.

**4. Community forum writeup**

A technical post framed as "what I learned building a PIV blob store in
Rust" — covering the NVM budget, ECDH on-card, the ECDSA integrity scheme,
the testable-hardware-abstraction design — is likely to be organically
surfaced to Yubico staff and is the piece most likely to generate an
inbound invitation rather than an outbound ask.

### Value for a promotion dossier

A Yubico community appearance does not carry the same weight as a
peer-reviewed paper, but it adds a complementary dimension: practitioner
credibility from the primary vendor.  The combination of a WOOT paper
(academic peer review) + a Yubico community appearance (industry endorsement
from the hardware vendor) + nixpkgs acceptance (distribution-quality
engineering, colleague attestation) covers three distinct axes that a
promotion committee will recognise independently.

---

## References

- Repository: `github.com/douzebis/yb`
- Format specification: `docs/YBLOB_FORMAT.md`
- Security review: `docs/sec-review.md`
- Integrity signature spec: `docs/specs/0017-blob-integrity-signature.md`
- Security hardening spec: `docs/specs/0006-security-hardening.md`
- nixpkgs PR: #514826
