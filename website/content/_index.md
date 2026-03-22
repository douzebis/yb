+++
title = "yb docs"
+++

# yb — Secure Blob Storage in Your YubiKey

Documentation for the `yb` command-line tool.

## User documentation

- [README](readme) — Overview, installation, and usage guide
- [Man pages](man-pages) — Reference manual for all `yb` commands

## Design documentation

- [Design](design) — Architecture, crate structure, and implementation details
- [YBLOB format](yblob-format) — Binary wire format for the PIV object store
- [Test harness](test-harness) — Test taxonomy: tier-1 unit tests and tier-2 NixOS VM tests
- [Security review](sec-review) — Security analysis and hardening findings

## Specs

| Spec | Title | Status |
|------|-------|--------|
| [0001](specs/0001-rust-port) | Rust port of the yb CLI | implemented |
| [0002](specs/0002-crate-structure) | Crate structure: library + CLI split | draft |
| [0003](specs/0003-implementation-plan) | Implementation plan for spec 0002 evolutions | draft |
| [0004](specs/0004-tier2-hardware-piv-tests) | Tier-2 Integration Tests for HardwarePiv | ready |
| [0005](specs/0005-nix-integration-test-build) | Nix Build for Integration Tests (Tier-2) | implemented |
| [0006](specs/0006-security-hardening) | Security Hardening (Rust) | ready |
| [0007](specs/0007-cli-improvements) | CLI Improvements | draft |
| [0008](specs/0008-cli-tests) | CLI integration tests | implemented |
| [0009](specs/0009-cli-subprocess-tests) | CLI subprocess tests | implemented |
| [0010](specs/0010-dynamic-object-sizing) | Dynamic PIV Object Sizing | implemented |
| [0011](specs/0011-refactor-and-test-coverage) | Refactoring Opportunities and Test Coverage Gaps | implemented |
| [0012](specs/0012-transparent-compression) | Transparent Compression | implemented |
| [0013](specs/0013-interactive-device-selection) | Interactive Device Selection with LED Feedback | implemented |
| [0014](specs/0014-operation-generator) | ToyFilesystem and OperationGenerator Test Primitives | implemented |
| [0015](specs/0015-self-test-command) | `yb self-test` Command | implemented |
| [0016](specs/0016-pre-allocated-tiered-store) | Pre-Allocated Tiered Store | suspended |
