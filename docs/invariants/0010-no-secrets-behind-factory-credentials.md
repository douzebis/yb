<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0010 — No Secrets Behind Factory Credentials

**Sources:** spec 0024

## Invariant

`yb store` refuses to write while the PIN or the PUK is the factory
value, unless `--allow-defaults` is given; reads only warn.

## Why

Factory credentials are public: anything stored behind them is readable
by whoever holds the YubiKey.

## Where the code keeps it

- `default_policy` (the spec 0024 table), applied by
  `Context::enforce_default_policy` before any write.

## Post-quantum stores (spec 0028)

The PIV PIN and PUK protect nothing there, so the rule above does not
apply; instead, `yb format` and `yb management-key set` refuse the
factory management key (D7), and FIDO2 has no factory PIN: a
post-quantum store cannot be used without one.

## Regression tests

- `rust/yb-piv-harness/src/bin/yb_cli_tests.rs`: `pq_format_refusals`, `pq_management_key_set`
- `rust/yb/tests/cli_tests.rs`: `default_pin_or_puk_refuses_store_but_not_reads`, `format_protect_refusal_writes_nothing`
- `rust/yb-core/src/policy.rs`: `table_default_pin_or_puk`
