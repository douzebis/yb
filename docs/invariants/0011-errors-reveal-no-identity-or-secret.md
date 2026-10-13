<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0011 — Errors Reveal No Identity or Secret

**Sources:** spec 0025

## Invariant

Error messages never contain the YubiKey's serial number or reader
name, the PIN, or a management key.

## Why

Errors are pasted into bug reports and chats.

## Where the code keeps it

- `errors::render` and the error catalog.

## Limits

- The firmware version appears in the report for unexpected errors.

## Regression tests

- `rust/yb/tests/cli_tests.rs`: `wrong_pin_then_blocked`, `wrong_explicit_management_key`, `storage_full_on_first_write`, `storage_full_midway_notes_partial_update`, `missing_certificate_explained`
