<!--
SPDX-FileCopyrightText: 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)

SPDX-License-Identifier: MIT
-->

# 0021 — A Snapshot Never Plans a Write

**Sources:** spec 0049

## Invariant

A write in a snapshot session (libyubiblob's `YUBIBLOB_OPEN_SNAPSHOT`)
plans from a whole read made under its own card lock, never from the
snapshot.  With `IF_UNCHANGED`, it fails with `YUBIBLOB_ERR_CHANGED`,
writing nothing, when the blob in that read differs from the blob in the
snapshot (rewritten, removed, or created since).

## Why

A snapshot may be stale: another program may have written since.  A
write planned from it could put its copy into objects another blob now
holds, free objects another program reused, or give its copy an age that
does not make it the newer one (spec 0049, "Set aside").

## Where the code keeps it

- `store_blob_with_checked` and `remove_blobs_checked`: the whole read
  under the lock (`reload_for_write`) replaces the store passed in, then
  `before_write` runs on it; `unchanged_since` compares the blob's head
  (bytes and age).
- libyubiblob's `Session`: a write starts from a copy of the snapshot
  and keeps what the write read (`after_write`).

## Limits

- `IF_UNCHANGED` compares the blob as it is: a blob created then removed
  since the snapshot (absent both times) passes; nothing written by
  others is lost then.
- Questions answered from the snapshot are as of its last refresh or
  write, by design.

## Regression tests

- `rust/yb-core/tests/concurrency_tests.rs`: `snapshot_sessions_are_serializable`, `a_write_from_a_snapshot_avoids_objects_taken_since`, `a_blob_replaced_since_the_snapshot`, `a_blob_removed_or_created_since_the_snapshot`, `a_store_formatted_again_since_the_snapshot`, `a_store_filled_since_the_snapshot`
- `rust/yubiblob/tests/api.rs`: `snapshot_session`, `if_unchanged_needs_a_snapshot_session`
