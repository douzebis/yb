// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! NVM fragmentation experiment for YubiKey PIV data objects.
//!
//! Each test is independent and can be run individually.  Tests perform a full
//! PIV reset at the start so results are reproducible.
//!
//! # Warning
//!
//! **DESTRUCTIVE**: performs a full PIV application reset multiple times.
//! All PIV keys, certificates and objects are wiped.
//! Use only on a dedicated test YubiKey.
//!
//! # Usage
//!
//! ```
//! # Run one or more named tests:
//! YB_MANAGEMENT_KEY=... cargo run --bin nvm_frag_test -- [READER_SUBSTRING] TEST...
//!
//! # List available tests:
//! cargo run --bin nvm_frag_test -- --help
//! ```
//!
//! # Tests
//!
//! - **capacity** — NVM capacity probe: fill with MAX_OBJECT_SIZE objects,
//!   binary-search the remaining headroom, report total bytes.
//! - **max-obj-size** — Empirically find the largest payload accepted by PUT DATA
//!   (verifies the 3,063-byte figure).
//! - **headroom** — Write 20 slots at MAX_OBJECT_SIZE; binary-search remaining
//!   headroom; report unused capacity.
//! - **frag-random** — Random-size stress (100 writes × 20 slots) then fill MAX;
//!   measures raw fragmentation loss.
//! - **frag-shrink1** — Same stress, then shrink all 20 slots to 1 byte, then
//!   fill MAX; tests whether 1-byte occupants block recovery.
//! - **frag-delete** — Same stress, then delete all 20 slots (0-byte PUT DATA),
//!   then fill MAX; tests whether freeing merges dead regions.
//! - **frag-grow** — Write 20 slots at MAX_OBJECT_SIZE, shrink to 256 bytes,
//!   then try to write one more MAX_OBJECT_SIZE slot; tests
//!   whether shrinking frees enough NVM for a new large object.

use anyhow::{bail, Context, Result};
use std::ffi::CString;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum PIV object payload size (the APDU limit).
const MAX_OBJECT_SIZE: usize = 3_052;

/// Object IDs: 0x5F0000 through 0x5F00FF (256 slots available on YubiKey 5).
const OBJECT_ID_BASE: u32 = 0x5F_0000;
const MAX_SLOTS: usize = 256; // full PIV addressable range 0x5F0000..0x5F00FF

/// Default management key (3DES, factory default).
const DEFAULT_MGMT_KEY: &str = "010203040506070801020304050607080102030405060708";

// ---------------------------------------------------------------------------
// APDU helpers
// ---------------------------------------------------------------------------

fn connect(reader: &str) -> Result<pcsc::Card> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).context("establishing PC/SC context")?;
    let reader_cstr = CString::new(reader).context("CString::new")?;
    let card = ctx
        .connect(&reader_cstr, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
        .context("connecting to reader")?;
    Ok(card)
}

fn transmit(card: &pcsc::Card, apdu: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
    let resp = card.transmit(apdu, &mut buf).context("APDU transmit")?;
    Ok(resp.to_vec())
}

fn select_piv(card: &pcsc::Card) -> Result<()> {
    let apdu = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08];
    let resp = transmit(card, &apdu)?;
    check_sw(&resp, "SELECT PIV")?;
    Ok(())
}

fn check_sw(resp: &[u8], label: &str) -> Result<()> {
    let n = resp.len();
    if n < 2 {
        bail!("{label}: response too short");
    }
    let sw1 = resp[n - 2];
    let sw2 = resp[n - 1];
    if sw1 == 0x90 && sw2 == 0x00 {
        Ok(())
    } else {
        bail!("{label}: SW={sw1:02x}{sw2:02x}")
    }
}

#[allow(dead_code)]
fn sw(resp: &[u8]) -> (u8, u8) {
    let n = resp.len();
    if n < 2 {
        (0, 0)
    } else {
        (resp[n - 2], resp[n - 1])
    }
}

/// PIV RESET — wipe the entire PIV application on the YubiKey.
///
/// Delegates to `ykman piv reset --force`.  The raw RESET APDU (00 FB 00 00)
/// requires both PIN and PUK to be blocked first, which involves multiple
/// steps that ykman handles reliably.
fn piv_reset(reader: &str) -> Result<()> {
    // ykman selects the device by serial when multiple are present; for a
    // single-device setup the plain form works fine.
    let status = std::process::Command::new("ykman")
        .args(["piv", "reset", "--force"])
        .status()
        .context("running ykman piv reset")?;
    if !status.success() {
        bail!("ykman piv reset failed (exit {})", status);
    }
    // Brief pause: after reset the firmware reinitialises PIV; reconnecting
    // immediately can yield stale state on some firmware versions.
    std::thread::sleep(std::time::Duration::from_millis(200));
    let _ = reader; // reserved for future multi-device support
    Ok(())
}

/// Authenticate the management key (3DES, default key).
fn auth_mgmt_key(card: &pcsc::Card, key_hex: &str) -> Result<()> {
    let key_bytes = hex::decode(key_hex).context("decoding management key")?;
    let p1: u8 = match key_bytes.len() {
        24 => 0x03, // 3DES
        16 => 0x08, // AES-128
        32 => 0x0C, // AES-256
        n => bail!("unsupported management key length: {n} bytes"),
    };
    let block_size: usize = if p1 == 0x03 { 8 } else { 16 };

    // Step 1: request witness
    let step1 = [0x00, 0x87, p1, 0x9B, 0x04, 0x7C, 0x02, 0x80, 0x00];
    let resp1 = transmit(card, &step1)?;
    check_sw(&resp1, "MGMT AUTH step1")?;

    // Parse 7C <len> 80 <len> <witness_enc>
    let data1 = &resp1[..resp1.len() - 2];
    let witness_enc = parse_inner_tlv(data1, 0x7C, 0x80)?;

    // Decrypt witness
    let witness_dec = ecb_decrypt(&key_bytes, &witness_enc, block_size)?;

    // Generate our challenge
    let challenge: Vec<u8> = (0..block_size).map(|_| rand::random::<u8>()).collect();

    // Build step2 data: 7C [ 80 <witness_dec>  81 <challenge> ]
    let mut inner = Vec::new();
    inner.push(0x80);
    inner.push(witness_dec.len() as u8);
    inner.extend_from_slice(&witness_dec);
    inner.push(0x81);
    inner.push(challenge.len() as u8);
    inner.extend_from_slice(&challenge);

    let mut outer = vec![0x7C, inner.len() as u8];
    outer.extend_from_slice(&inner);

    let mut step2 = vec![0x00, 0x87, p1, 0x9B, outer.len() as u8];
    step2.extend_from_slice(&outer);
    let resp2 = transmit(card, &step2)?;
    check_sw(&resp2, "MGMT AUTH step2")?;

    // Verify card encrypted our challenge
    let data2 = &resp2[..resp2.len() - 2];
    let challenge_resp = parse_inner_tlv(data2, 0x7C, 0x82)?;
    let challenge_enc = ecb_encrypt(&key_bytes, &challenge, block_size)?;
    if challenge_enc != challenge_resp {
        bail!("management key authentication failed");
    }
    Ok(())
}

fn ecb_decrypt(key: &[u8], data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    ecb_op(key, data, block_size, false)
}

fn ecb_encrypt(key: &[u8], data: &[u8], block_size: usize) -> Result<Vec<u8>> {
    ecb_op(key, data, block_size, true)
}

fn ecb_op(key: &[u8], data: &[u8], _block_size: usize, encrypt: bool) -> Result<Vec<u8>> {
    use cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit};
    use des::TdesEde3;

    if key.len() == 24 {
        // 3DES ECB, one block at a time (8-byte blocks)
        let mut out = data.to_vec();
        for chunk in out.chunks_mut(8) {
            let block = cipher::generic_array::GenericArray::from_mut_slice(chunk);
            if encrypt {
                TdesEde3::new(cipher::generic_array::GenericArray::from_slice(key))
                    .encrypt_block_mut(block);
            } else {
                TdesEde3::new(cipher::generic_array::GenericArray::from_slice(key))
                    .decrypt_block_mut(block);
            }
        }
        return Ok(out);
    }

    bail!(
        "unsupported key length for ECB: {} bytes (only 3DES/24 supported)",
        key.len()
    )
}

fn parse_inner_tlv(data: &[u8], outer_tag: u8, inner_tag: u8) -> Result<Vec<u8>> {
    // Find outer tag
    let outer = find_tlv(data, outer_tag)?;
    // Find inner tag
    find_tlv(&outer, inner_tag)
}

fn find_tlv(data: &[u8], tag: u8) -> Result<Vec<u8>> {
    let mut i = 0;
    while i < data.len() {
        let t = data[i];
        i += 1;
        if i >= data.len() {
            break;
        }
        let len = data[i] as usize;
        i += 1;
        if i + len > data.len() {
            bail!("TLV truncated at tag 0x{t:02x}");
        }
        let value = data[i..i + len].to_vec();
        i += len;
        if t == tag {
            return Ok(value);
        }
    }
    bail!("TLV tag 0x{tag:02x} not found");
}

/// PUT DATA for object `id` with `payload`.  Returns true on success, false on 6A84 (NVM full).
fn put_data(card: &mut pcsc::Card, id: u32, payload: &[u8]) -> Result<bool> {
    let idb = id.to_be_bytes();

    // Wrap payload in TLV 53
    let content = encode_tlv(0x53, payload);

    // Build data field: 5C 03 XX XX XX <content>
    let mut data_field = vec![0x5C, 0x03, idb[1], idb[2], idb[3]];
    data_field.extend_from_slice(&content);

    // Send via chained APDUs
    let tx = card
        .transaction()
        .context("SCardBeginTransaction for PUT DATA")?;
    let mut remaining = data_field.as_slice();
    loop {
        let chunk = remaining.len().min(0xFF);
        let is_last = chunk == remaining.len();
        let cla: u8 = if is_last { 0x00 } else { 0x10 };
        let mut apdu = vec![cla, 0xDB, 0x3F, 0xFF, chunk as u8];
        apdu.extend_from_slice(&remaining[..chunk]);
        remaining = &remaining[chunk..];

        let resp = transmit_tx(&tx, &apdu)?;
        let n = resp.len();
        if n < 2 {
            bail!("PUT DATA: response too short");
        }
        let sw1 = resp[n - 2];
        let sw2 = resp[n - 1];
        if is_last {
            drop(tx);
            if sw1 == 0x90 && sw2 == 0x00 {
                return Ok(true);
            }
            if sw1 == 0x6A && sw2 == 0x84 {
                return Ok(false); // NVM full
            }
            if sw1 == 0x67 && sw2 == 0x00 {
                return Ok(false); // wrong length — payload too large for applet
            }
            bail!("PUT DATA failed: SW={sw1:02x}{sw2:02x}");
        } else if sw1 == 0x67 && sw2 == 0x00 {
            drop(tx);
            return Ok(false); // wrong length — payload too large for applet
        } else if sw1 != 0x90 || sw2 != 0x00 {
            bail!("PUT DATA (chained) failed: SW={sw1:02x}{sw2:02x}");
        }
    }
}

/// GET DATA for object `id`.
/// Returns `Some(payload_len)` on success (9000), `None` if not found (6A82).
fn get_data(card: &pcsc::Card, id: u32) -> Result<Option<usize>> {
    let idb = id.to_be_bytes();
    // Data field: 5C 03 XX XX XX
    let apdu = [
        0x00, 0xCB, 0x3F, 0xFF, 0x05, 0x5C, 0x03, idb[1], idb[2], idb[3],
    ];
    let mut data: Vec<u8> = Vec::new();
    let mut resp = transmit(card, &apdu)?;

    loop {
        let n = resp.len();
        if n < 2 {
            bail!("GET DATA: response too short");
        }
        let sw1 = resp[n - 2];
        let sw2 = resp[n - 1];

        if sw1 == 0x6A && sw2 == 0x82 {
            return Ok(None); // object not found — slot is empty
        }

        // Accumulate data bytes (everything before the SW).
        data.extend_from_slice(&resp[..n - 2]);

        if sw1 == 0x90 && sw2 == 0x00 {
            break; // done
        }
        if sw1 == 0x61 {
            // More data available — issue GET RESPONSE.
            let get_resp = [0x00, 0xC0, 0x00, 0x00, sw2];
            resp = transmit(card, &get_resp)?;
        } else {
            bail!("GET DATA failed: SW={sw1:02x}{sw2:02x}");
        }
    }

    // data is the TLV-wrapped payload: 53 <len> <payload>.
    if data.is_empty() || data[0] != 0x53 {
        bail!(
            "GET DATA: unexpected response TLV tag 0x{:02x}",
            data.first().unwrap_or(&0)
        );
    }
    let payload_len = if data.len() < 2 {
        0
    } else if data[1] < 0x80 {
        data[1] as usize
    } else if data[1] == 0x81 {
        if data.len() < 3 {
            bail!("GET DATA: truncated length");
        }
        data[2] as usize
    } else if data[1] == 0x82 {
        if data.len() < 4 {
            bail!("GET DATA: truncated length");
        }
        ((data[2] as usize) << 8) | data[3] as usize
    } else {
        bail!("GET DATA: unsupported length encoding 0x{:02x}", data[1]);
    };
    Ok(Some(payload_len))
}

fn transmit_tx(tx: &pcsc::Transaction<'_>, apdu: &[u8]) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; pcsc::MAX_BUFFER_SIZE_EXTENDED];
    let resp = tx.transmit(apdu, &mut buf).context("APDU transmit (tx)")?;
    Ok(resp.to_vec())
}

fn encode_tlv(tag: u8, data: &[u8]) -> Vec<u8> {
    let len = data.len();
    let mut out = Vec::new();
    out.push(tag);
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push((len & 0xFF) as u8);
    }
    out.extend_from_slice(data);
    out
}

// ---------------------------------------------------------------------------
// Experiment helpers
// ---------------------------------------------------------------------------

struct Piv {
    reader: String,
    mgmt_key: String,
}

impl Piv {
    fn connect(&self) -> Result<pcsc::Card> {
        let card = connect(&self.reader)?;
        select_piv(&card)?;
        Ok(card)
    }

    fn reset(&self) -> Result<()> {
        eprint!("  PIV reset... ");
        piv_reset(&self.reader)?;
        eprintln!("done.");
        Ok(())
    }

    fn auth(&self, card: &mut pcsc::Card) -> Result<()> {
        auth_mgmt_key(card, &self.mgmt_key)
    }

    /// Return the current payload size of slot `idx`, or 0 if empty/not found.
    fn size(&self, card: &pcsc::Card, idx: usize) -> Result<usize> {
        let id = OBJECT_ID_BASE + idx as u32;
        Ok(get_data(card, id)?.unwrap_or(0))
    }

    /// Write `payload` to object `idx` (0-based), authenticated.
    /// Updates `slot_sizes[idx]`: set to payload length on success, 0 on failure
    /// (a failed PUT DATA clears the slot on the YubiKey).
    fn write(
        &self,
        card: &mut pcsc::Card,
        idx: usize,
        payload: &[u8],
        slot_sizes: &mut [usize; 256],
    ) -> Result<bool> {
        let id = OBJECT_ID_BASE + idx as u32;
        let ok = put_data(card, id, payload)?;
        slot_sizes[idx] = if ok { payload.len() } else { 0 };
        Ok(ok)
    }
}

/// Upper bound for slot size probing — above the empirically measured max (3063)
/// to ensure we never miss a larger-than-expected allocation.
const PROBE_MAX: usize = 4095;

/// Measure total free NVM by filling all currently-empty slots to their maximum
/// capacity via dichotomy, summing the results, then freeing them all.
///
/// Idempotent: only touches slots that GET DATA reports as empty; restores them
/// to empty afterwards.  Returns total free bytes found.
fn measure_free_nvm(piv: &Piv, card: &mut pcsc::Card) -> Result<usize> {
    // Identify empty slots via GET DATA.
    let mut empty_slots = Vec::new();
    for i in 0..MAX_SLOTS {
        if piv.size(card, i)? == 0 {
            empty_slots.push(i);
        }
    }
    eprintln!(
        "  measure_free_nvm: {} empty slots found out of {MAX_SLOTS}.",
        empty_slots.len()
    );

    // Fill each empty slot to its maximum via dichotomy.
    // Stop early if the first probe already yields 0 (NVM full).
    let mut ss = [0usize; 256];
    let mut total = 0usize;
    for &slot in &empty_slots {
        let size = dichotomy_fill(piv, card, slot, &mut ss)?;
        eprintln!("    slot {slot:3}: {size} bytes");
        if size == 0 {
            eprintln!("    NVM full — stopping early.");
            break;
        }
        total += size;
    }

    // Free all probe slots — restore to empty.
    for &slot in &empty_slots {
        piv.auth(card)?;
        piv.write(card, slot, &[], &mut ss)?;
    }

    eprintln!("  measure_free_nvm: total free = {total} bytes.");
    Ok(total)
}

/// Fill slot `idx` to the maximum size that fits using dichotomy.
/// Slot must be empty on entry.  Returns the size written (slot holds that
/// many bytes on return).
fn dichotomy_fill(
    piv: &Piv,
    card: &mut pcsc::Card,
    idx: usize,
    slot_sizes: &mut [usize; 256],
) -> Result<usize> {
    let mut lo = 1usize;
    let mut hi = PROBE_MAX;
    let mut committed = 0usize; // current size held by the slot

    while lo <= hi {
        let mid = (lo + hi) / 2;
        piv.auth(card)?;
        if piv.write(card, idx, &vec![0xEEu8; mid], slot_sizes)? {
            committed = mid;
            lo = mid + 1;
        } else {
            // Failed write cleared the slot — re-commit last known good size.
            if committed > 0 {
                piv.auth(card)?;
                piv.write(card, idx, &vec![0xEEu8; committed], slot_sizes)?;
            }
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }
    Ok(committed)
}

// ---------------------------------------------------------------------------
// Experiments
// ---------------------------------------------------------------------------

/// Measure the true NVM capacity after a fresh PIV reset.
///
/// Step 1: fill slots 0, 1, … with MAX_OBJECT_SIZE objects until 6A84.
///         Let N = number that fit, USED = N × MAX_OBJECT_SIZE.
/// Step 2: binary-search for the largest object that fits in slot N
///         (the remaining NVM headroom).  Call it DELTA.
/// Step 3: try slot N+1 with 1 byte → must fail with 6A84 (NVM truly full).
///
/// Reports: total NVM available = USED + DELTA, overhead = 51200 − total.
fn experiment_capacity(piv: &Piv) -> Result<usize> {
    const GROSS_NVM: usize = 51_200;

    eprintln!("\n=== EXPERIMENT 1: NVM CAPACITY PROBE ===");
    eprintln!("Fill with {MAX_OBJECT_SIZE}-byte objects, then binary-search for the delta.");

    piv.reset()?;
    let mut card = piv.connect()?;
    let large = vec![0xAAu8; MAX_OBJECT_SIZE];

    // Step 1: fill with MAX_OBJECT_SIZE until 6A84.
    eprint!("  Step 1 — fill with {MAX_OBJECT_SIZE}-byte objects: ");
    piv.auth(&mut card)?;
    let mut ss = [0usize; 256];
    let mut n = 0usize;
    for i in 0..MAX_SLOTS {
        match piv.write(&mut card, i, &large, &mut ss)? {
            true => n += 1,
            false => break,
        }
    }
    let used = n * MAX_OBJECT_SIZE;
    eprintln!("{n} objects, {used} bytes.");

    // Step 2: binary-search for the largest object that fits in slot n.
    eprint!("  Step 2 — binary-search remaining headroom (slot {n}): ");
    piv.auth(&mut card)?;
    let mut lo = 1usize;
    let mut hi = MAX_OBJECT_SIZE;
    let mut delta = 0usize;
    while lo <= hi {
        let mid = (lo + hi) / 2;
        let probe = vec![0xBBu8; mid];
        if piv.write(&mut card, n, &probe, &mut ss)? {
            delta = mid;
            lo = mid + 1;
            piv.auth(&mut card)?;
            piv.write(&mut card, n, &[0x00], &mut ss)?;
            piv.auth(&mut card)?;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }
    eprintln!("delta = {delta} bytes.");

    // Step 3: confirm slot n+1 rejects even 1 byte after writing delta into slot n.
    eprint!(
        "  Step 3 — write delta bytes to slot {n}, then 1 byte to slot {}: ",
        n + 1
    );
    piv.auth(&mut card)?;
    let delta_payload = vec![0xCCu8; delta];
    piv.write(&mut card, n, &delta_payload, &mut ss)?;
    piv.auth(&mut card)?;
    let one_more = piv.write(&mut card, n + 1, &[0xFFu8], &mut ss)?;
    if one_more {
        eprintln!("WARNING: extra byte succeeded — delta calculation may be off.");
    } else {
        eprintln!("correctly rejected (6A84).");
    }

    let total_nvm = used + delta;
    let overhead = GROSS_NVM.saturating_sub(total_nvm);
    eprintln!();
    eprintln!("  Total NVM available for data objects : {total_nvm} bytes");
    eprintln!("  PIV applet overhead (51200 − {total_nvm}) : {overhead} bytes");
    eprintln!("  Breakdown: {n} × {MAX_OBJECT_SIZE} + {delta} = {total_nvm}");

    Ok(total_nvm)
}

/// Run one deterministic stress pass across `STRESS_SLOTS` slots for `STRESS_ROUNDS` rounds.
///
/// Uses a fixed seed so results are reproducible across runs.
/// Returns without touching any other slots.
fn run_stress(piv: &Piv, card: &mut pcsc::Card, slot_sizes: &mut [usize; 256]) -> Result<()> {
    use rand::{rngs::SmallRng, Rng, SeedableRng};

    const STRESS_SLOTS: usize = 20;
    const STRESS_ROUNDS: usize = 100;
    const AUTH_INTERVAL: usize = 10;
    const SEED: u64 = 0xDEAD_BEEF_1234_5678;

    let mut rng = SmallRng::seed_from_u64(SEED);

    eprintln!(
        "  Stress phase ({STRESS_ROUNDS} writes across {STRESS_SLOTS} slots, seed={SEED:#x}):"
    );
    piv.auth(card)?;
    for round in 0..STRESS_ROUNDS {
        if round % AUTH_INTERVAL == 0 && round > 0 {
            piv.auth(card)?;
        }
        let slot = rng.gen::<usize>() % STRESS_SLOTS;
        let size = 1 + rng.gen::<usize>() % MAX_OBJECT_SIZE;
        let payload = vec![(round & 0xFF) as u8; size];
        let ok = piv.write(card, slot, &payload, slot_sizes)?;
        if (round + 1) % 20 == 0 {
            let mark = if ok { "ok" } else { "oom" };
            eprintln!(
                "    round {:3}: slot={slot:2} size={size:4} [{mark}]",
                round + 1
            );
        }
    }
    Ok(())
}

/// Fill slots `start..MAX_SLOTS` with `size`-byte objects until 6A84.
/// Returns (slot_count, total_bytes).
fn fill_sequential(
    piv: &Piv,
    card: &mut pcsc::Card,
    start: usize,
    size: usize,
    slot_sizes: &mut [usize; 256],
) -> Result<(usize, usize)> {
    let payload = vec![0xDDu8; size];
    let mut count = 0usize;
    for i in start..MAX_SLOTS {
        piv.auth(card)?;
        match piv.write(card, i, &payload, slot_sizes)? {
            true => count += 1,
            false => break,
        }
    }
    Ok((count, count * size))
}

/// Run one fragmentation sub-test (frag-random, frag-shrink1, or frag-delete).
///
/// All three share the same structure:
///   1. Fresh PIV reset.
///   2. Random-size stress (100 writes × 20 slots).
///   3. Optional post-stress treatment of the 20 stressed slots.
///   4. Sequential fill with MAX_OBJECT_SIZE from slot 0.
///   5. Report bytes written vs baseline.
fn experiment_fragmentation(piv: &Piv, baseline_nvm: usize, test: &str) -> Result<()> {
    const STRESS_SLOTS: usize = 20;

    let label = match test {
        "frag-random" => "stress → fill MAX (no post-treatment)",
        "frag-shrink1" => "stress → shrink to 1 byte → fill MAX",
        "frag-delete" => "stress → delete (0-byte PUT DATA) → fill MAX",
        _ => unreachable!(),
    };

    eprintln!("\n=== TEST: {test} ===");
    eprintln!("  {label}");
    eprintln!("  Baseline NVM: {baseline_nvm} bytes");

    piv.reset()?;
    let mut card = piv.connect()?;
    let mut ss = [0usize; 256];
    run_stress(piv, &mut card, &mut ss)?;

    // Post-stress treatment.
    match test {
        "frag-shrink1" => {
            eprintln!("  Shrinking {STRESS_SLOTS} stressed slots to 1 byte:");
            let mut ok_count = 0usize;
            let mut fail_count = 0usize;
            for i in 0..STRESS_SLOTS {
                piv.auth(&mut card)?;
                if piv.write(&mut card, i, &[0x00], &mut ss)? {
                    ok_count += 1;
                } else {
                    fail_count += 1;
                }
            }
            eprintln!("    {ok_count} shrunk, {fail_count} failed (6A84 — unexpected).");
        }
        "frag-delete" => {
            eprintln!("  Deleting {STRESS_SLOTS} stressed slots (0-byte PUT DATA):");
            let mut ok_count = 0usize;
            let mut fail_count = 0usize;
            for i in 0..STRESS_SLOTS {
                piv.auth(&mut card)?;
                if piv.write(&mut card, i, &[], &mut ss)? {
                    ok_count += 1;
                } else {
                    fail_count += 1;
                }
            }
            eprintln!("    {ok_count} deleted, {fail_count} failed (6A84 — unexpected).");
        }
        _ => {}
    }

    eprintln!("  Fill with {MAX_OBJECT_SIZE}-byte objects (slots 0..):");
    let (count, bytes) = fill_sequential(piv, &mut card, 0, MAX_OBJECT_SIZE, &mut ss)?;
    // Account for slots that the fill could not overwrite (still hold their
    // stressed sizes).  ss[i] reflects the current committed size of each slot.
    let residual: usize = ss.iter().sum::<usize>().saturating_sub(bytes);
    let total = bytes + residual;
    let diff = total as isize - baseline_nvm as isize;
    eprintln!("    {count} objects × {MAX_OBJECT_SIZE} = {bytes} bytes (fill).");
    eprintln!("    Residual in un-filled slots: {residual} bytes.");
    eprintln!("    Total committed: {total} bytes.");
    eprintln!("    Difference vs baseline: {diff:+} bytes");

    eprintln!();
    match diff.cmp(&0) {
        std::cmp::Ordering::Equal => {
            eprintln!("  Result: NO FRAGMENTATION — full capacity preserved.");
        }
        std::cmp::Ordering::Less => {
            eprintln!(
                "  Result: {diff} bytes unaccounted for vs baseline (true fragmentation loss)."
            );
        }
        std::cmp::Ordering::Greater => {
            eprintln!("  Result: Unexpected gain — measurement artifact, investigate.");
        }
    }

    Ok(())
}

/// Empirically find the largest PUT DATA payload size accepted by the YubiKey.
///
/// Binary-searches the range 1..=8192 on a freshly-reset device.
/// Reports the maximum accepted size and whether it matches MAX_OBJECT_SIZE.
fn test_max_obj_size(piv: &Piv) -> Result<usize> {
    eprintln!("\n=== TEST: max-obj-size ===");
    eprintln!("Binary-search for the largest accepted PUT DATA payload (slot 0).");

    piv.reset()?;
    let mut card = piv.connect()?;
    let mut ss = [0usize; 256];

    let mut lo = 1usize;
    let mut hi = 8192usize;
    let mut max_ok = 0usize;

    while lo <= hi {
        let mid = (lo + hi) / 2;
        let payload = vec![0xAAu8; mid];
        piv.auth(&mut card)?;
        // Clean up any previous write so NVM is not consumed.
        piv.write(&mut card, 0, &[], &mut ss)?;
        piv.auth(&mut card)?;
        let ok = piv.write(&mut card, 0, &payload, &mut ss)?;
        if ok {
            max_ok = mid;
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
        eprintln!("  probe {mid:5}: {}", if ok { "ok" } else { "rejected" });
    }

    eprintln!();
    eprintln!("  Maximum accepted payload size : {max_ok} bytes");
    if max_ok == MAX_OBJECT_SIZE {
        eprintln!("  Matches MAX_OBJECT_SIZE ({MAX_OBJECT_SIZE}) — assumption confirmed.");
    } else {
        eprintln!("  DIFFERS from MAX_OBJECT_SIZE ({MAX_OBJECT_SIZE}) — update the constant!");
    }
    Ok(max_ok)
}

/// Write 20 slots at MAX_OBJECT_SIZE, then binary-search remaining headroom.
///
/// Reports how much NVM is "unused" (cannot hold another MAX_OBJECT_SIZE object)
/// after filling 20 slots.
fn test_headroom(piv: &Piv) -> Result<()> {
    const FILL_SLOTS: usize = 20;

    eprintln!("\n=== TEST: headroom ===");
    eprintln!(
        "Write {FILL_SLOTS} slots at {MAX_OBJECT_SIZE} bytes, binary-search remaining headroom."
    );

    piv.reset()?;
    let mut card = piv.connect()?;
    let mut ss = [0usize; 256];
    let large = vec![0xAAu8; MAX_OBJECT_SIZE];

    eprint!("  Writing {FILL_SLOTS} slots at {MAX_OBJECT_SIZE} bytes: ");
    piv.auth(&mut card)?;
    let mut written = 0usize;
    for i in 0..FILL_SLOTS {
        piv.auth(&mut card)?;
        match piv.write(&mut card, i, &large, &mut ss)? {
            true => written += 1,
            false => {
                eprintln!("OOM at slot {i} — only {written} slots fit.");
                break;
            }
        }
    }
    let used = written * MAX_OBJECT_SIZE;
    eprintln!("{written} written, {used} bytes used.");

    // Binary-search remaining headroom in slot `written`.
    eprint!("  Binary-search remaining headroom (slot {written}): ");
    piv.auth(&mut card)?;
    let mut lo = 0usize;
    let mut hi = MAX_OBJECT_SIZE;
    let mut delta = 0usize;
    while lo <= hi {
        let mid = (lo + hi) / 2;
        if mid == 0 {
            break;
        }
        let probe = vec![0xBBu8; mid];
        piv.auth(&mut card)?;
        piv.write(&mut card, written, &[], &mut ss)?; // free slot before probe
        piv.auth(&mut card)?;
        if piv.write(&mut card, written, &probe, &mut ss)? {
            delta = mid;
            lo = mid + 1;
        } else {
            if mid == 0 {
                break;
            }
            hi = mid - 1;
        }
    }
    eprintln!("{delta} bytes.");

    eprintln!();
    eprintln!("  Slots written     : {written} × {MAX_OBJECT_SIZE} = {used} bytes");
    eprintln!("  Remaining headroom: {delta} bytes");
    eprintln!("  Total accounted   : {} bytes", used + delta);
    eprintln!("  \"Wasted\" (not usable for another {MAX_OBJECT_SIZE}-byte object): {delta} bytes");
    Ok(())
}

/// Write 20 slots at MAX_OBJECT_SIZE, shrink all to 256 bytes, then attempt
/// one more MAX_OBJECT_SIZE write.
///
/// Tests whether shrinking existing slots frees enough NVM for a new large object.
fn test_frag_grow(piv: &Piv) -> Result<()> {
    const FILL_SLOTS: usize = 20;
    const SHRINK_SIZE: usize = 256;

    eprintln!("\n=== TEST: frag-grow ===");
    eprintln!(
        "Write {FILL_SLOTS} slots at {MAX_OBJECT_SIZE} bytes, shrink to {SHRINK_SIZE}, \
         then write one more at {MAX_OBJECT_SIZE}."
    );

    piv.reset()?;
    let mut card = piv.connect()?;
    let mut ss = [0usize; 256];
    let large = vec![0xAAu8; MAX_OBJECT_SIZE];

    eprint!("  Writing {FILL_SLOTS} slots at {MAX_OBJECT_SIZE} bytes: ");
    piv.auth(&mut card)?;
    let mut written = 0usize;
    for i in 0..FILL_SLOTS {
        piv.auth(&mut card)?;
        match piv.write(&mut card, i, &large, &mut ss)? {
            true => written += 1,
            false => {
                eprintln!("OOM at slot {i} — only {written} slots fit.");
                break;
            }
        }
    }
    eprintln!("{written} written ({} bytes).", written * MAX_OBJECT_SIZE);

    eprint!("  Shrinking {written} slots to {SHRINK_SIZE} bytes: ");
    let small = vec![0xBBu8; SHRINK_SIZE];
    let mut shrunk = 0usize;
    for i in 0..written {
        piv.auth(&mut card)?;
        if piv.write(&mut card, i, &small, &mut ss)? {
            shrunk += 1;
        }
    }
    eprintln!("{shrunk} shrunk.");

    eprint!("  Attempting one more {MAX_OBJECT_SIZE}-byte write (slot {written}): ");
    piv.auth(&mut card)?;
    let ok = piv.write(&mut card, written, &large, &mut ss)?;
    eprintln!("{}", if ok { "SUCCESS" } else { "FAILED (6A84)" });

    eprintln!();
    if ok {
        let freed = written * (MAX_OBJECT_SIZE - SHRINK_SIZE);
        eprintln!("  Shrinking freed ~{freed} bytes → new {MAX_OBJECT_SIZE}-byte object fit.");
        eprintln!("  --> YubiKey NVM allocator reclaims freed tails in-place.");
    } else {
        eprintln!("  Shrinking did NOT free enough NVM for a new {MAX_OBJECT_SIZE}-byte object.");
        eprintln!("  --> Freed tails are fragmented (each < {MAX_OBJECT_SIZE} bytes).");
    }
    Ok(())
}

/// Map the free-chunk landscape of the NVM heap after a stress pass.
///
/// Uses slots starting at `probe_start` as probes.  For each slot, binary-searches
/// the largest allocation that fits (consuming that free chunk), keeps it, then
/// moves to the next slot.  Stops when nothing fits at all (NVM full).
/// Returns the list of chunk sizes found.
fn map_free_chunks(
    piv: &Piv,
    card: &mut pcsc::Card,
    probe_start: usize,
    slot_sizes: &mut [usize; 256],
) -> Result<Vec<usize>> {
    let mut chunks = Vec::new();
    let mut slot = probe_start;
    loop {
        // Check if any NVM is available by trying 1 byte.
        piv.auth(card)?;
        if !piv.write(card, slot, &[0xEEu8], slot_sizes)? {
            break; // NVM completely full.
        }
        // Slot now holds 1 byte — grow it to max via dichotomy.
        // dichotomy_fill expects an empty slot, so free it first.
        piv.auth(card)?;
        piv.write(card, slot, &[], slot_sizes)?;

        let size = dichotomy_fill(piv, card, slot, slot_sizes)?;
        if size == 0 {
            break;
        }
        eprintln!("    slot {:3}: free chunk = {size} bytes", slot);
        chunks.push(size);
        slot += 1;
    }
    Ok(chunks)
}

/// Map the NVM free-chunk distribution before and after freeing one stressed slot.
///
/// Pass 1 (after stress):
///   - Use slots 20, 21, … to greedily consume free chunks via binary-search.
///   - Each slot gets the largest allocation that fits; stops when NVM is full.
///   - This reveals the size and count of free regions in the heap.
///
/// Pass 2 (after freeing slot 0):
///   - Free the probe slots from pass 1.
///   - Free slot 0 (one of the 20 stressed slots).
///   - Repeat the greedy mapping from slot 20.
///   - Compare: if freeing slot 0 merged with an adjacent free chunk, one of the
///     chunks in pass 2 will be larger than the largest in pass 1.
fn test_frag_map(piv: &Piv) -> Result<()> {
    const PROBE_START: usize = 20;

    eprintln!("\n=== TEST: frag-map ===");
    eprintln!("  Map free-chunk landscape after stress, then after freeing one stressed slot.");

    piv.reset()?;
    let mut card = piv.connect()?;
    let mut ss = [0usize; 256];
    run_stress(piv, &mut card, &mut ss)?;

    // Pass 1: map free chunks.
    eprintln!("\n  Pass 1 — mapping free chunks after stress (slots {PROBE_START}+):");
    let chunks1 = map_free_chunks(piv, &mut card, PROBE_START, &mut ss)?;
    let total1: usize = chunks1.iter().sum();
    eprintln!(
        "  Pass 1 total: {} free chunks, {} bytes",
        chunks1.len(),
        total1
    );

    // Free the probe slots.
    eprintln!(
        "\n  Freeing probe slots ({PROBE_START}..{}):",
        PROBE_START + chunks1.len()
    );
    for i in PROBE_START..PROBE_START + chunks1.len() {
        piv.auth(&mut card)?;
        piv.write(&mut card, i, &[], &mut ss)?;
    }

    // Free slot 0 (one stressed slot).
    eprintln!("  Freeing stressed slot 0.");
    piv.auth(&mut card)?;
    piv.write(&mut card, 0, &[], &mut ss)?;

    // Pass 2: re-map free chunks.
    eprintln!("\n  Pass 2 — mapping free chunks after freeing slot 0 (slots {PROBE_START}+):");
    let chunks2 = map_free_chunks(piv, &mut card, PROBE_START, &mut ss)?;
    let total2: usize = chunks2.iter().sum();
    eprintln!(
        "  Pass 2 total: {} free chunks, {} bytes",
        chunks2.len(),
        total2
    );

    // Summary.
    eprintln!();
    eprintln!("  Pass 1 chunks: {:?}", chunks1);
    eprintln!("  Pass 2 chunks: {:?}", chunks2);
    eprintln!();
    let max1 = chunks1.iter().copied().max().unwrap_or(0);
    let max2 = chunks2.iter().copied().max().unwrap_or(0);
    if max2 > max1 {
        eprintln!(
            "  Largest chunk grew: {max1} → {max2} bytes \
             → freeing slot 0 merged with an adjacent free region."
        );
    } else {
        eprintln!(
            "  Largest chunk unchanged: {max1} → {max2} bytes \
             → freed slot 0 is isolated (no merge with neighbors)."
        );
    }
    if total2 > total1 {
        eprintln!(
            "  Total free bytes grew: {total1} → {total2} (+{}).",
            total2 - total1
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const ALL_TESTS: &[&str] = &[
    "capacity",
    "max-obj-size",
    "headroom",
    "free-nvm",
    "shrink0",
    "frag-random",
    "frag-shrink1",
    "frag-delete",
    "frag-grow",
    "frag-map",
];

fn print_help() {
    eprintln!("Usage: nvm_frag_test [READER_SUBSTRING] TEST [TEST ...]");
    eprintln!();
    eprintln!("Available tests:");
    eprintln!("  capacity      NVM capacity probe (fill + binary-search headroom)");
    eprintln!("  max-obj-size  Empirically find the largest accepted PUT DATA payload");
    eprintln!("  headroom      Write 20 × MAX slots, report unused capacity");
    eprintln!("  frag-random   Random-size stress → fill MAX (measures fragmentation loss)");
    eprintln!("  frag-shrink1  Random stress → shrink to 1 byte → fill MAX");
    eprintln!("  frag-delete   Random stress → delete (0-byte) → fill MAX");
    eprintln!("  free-nvm      Measure total free NVM (fills empty slots, then restores them)");
    eprintln!("  shrink0       Write 1 byte to slot 0 (no reset; for manual NVM manipulation)");
    eprintln!("  frag-grow     Write 20 × MAX, shrink to 256, try one more MAX write");
    eprintln!("  frag-map      Map free-chunk sizes after stress; then free one slot and remap");
    eprintln!();
    eprintln!("Environment:");
    eprintln!("  YB_MANAGEMENT_KEY   hex 3DES key (default: factory key)");
    eprintln!();
    eprintln!("Example:");
    eprintln!("  nvm_frag_test capacity frag-random");
}

fn find_reader(substring: Option<&str>) -> Result<String> {
    let ctx = pcsc::Context::establish(pcsc::Scope::User).context("establishing PC/SC context")?;
    let mut buf = vec![0u8; 65536];
    let readers: Vec<String> = ctx
        .list_readers(&mut buf)
        .context("listing readers")?
        .map(|r| r.to_string_lossy().into_owned())
        .collect();

    if readers.is_empty() {
        bail!("no PC/SC readers found");
    }

    match substring {
        Some(sub) => {
            let found = readers.iter().find(|r| r.contains(sub)).cloned();
            found.ok_or_else(|| {
                anyhow::anyhow!("no reader matching {:?}; available: {:?}", sub, readers)
            })
        }
        None => Ok(readers[0].clone()),
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // --help / -h
    if args.iter().any(|a| a == "--help" || a == "-h") {
        print_help();
        return Ok(());
    }

    // First non-flag arg that matches a known test name → start of test list.
    // Anything before it that doesn't match is treated as reader substring.
    let mut reader_sub: Option<&str> = None;
    let mut test_names: Vec<&str> = Vec::new();

    for arg in &args[1..] {
        if ALL_TESTS.contains(&arg.as_str()) {
            test_names.push(arg.as_str());
        } else if test_names.is_empty() {
            // Before any test name → reader substring.
            reader_sub = Some(arg.as_str());
        } else {
            bail!(
                "unknown test {:?}; run with --help to see available tests",
                arg
            );
        }
    }

    if test_names.is_empty() {
        eprintln!("No tests specified.  Run with --help to see available tests.");
        return Ok(());
    }

    let mgmt_key =
        std::env::var("YB_MANAGEMENT_KEY").unwrap_or_else(|_| DEFAULT_MGMT_KEY.to_owned());

    let reader = find_reader(reader_sub)?;
    eprintln!("Using reader: {reader}");
    eprintln!("Management key: {mgmt_key}");
    eprintln!("Tests to run: {}", test_names.join(", "));
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
    eprintln!("║  NVM FRAGMENTATION EXPERIMENT — DESTRUCTIVE                          ║");
    eprintln!("║  All PIV keys, certificates and objects will be wiped.               ║");
    eprintln!("║  Use only on a dedicated test YubiKey!                               ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
    eprintln!();
    eprint!("Press Enter to proceed, or Ctrl-C to abort: ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;

    let piv = Piv { reader, mgmt_key };

    // capacity is used as baseline_nvm by frag-* tests; compute it once if needed.
    let mut baseline_nvm: Option<usize> = None;
    let needs_baseline = test_names
        .iter()
        .any(|t| matches!(*t, "frag-random" | "frag-shrink1" | "frag-delete"));

    if needs_baseline || test_names.contains(&"capacity") {
        let nvm = experiment_capacity(&piv)?;
        baseline_nvm = Some(nvm);
    }

    for test in &test_names {
        match *test {
            "capacity" => { /* already ran above */ }
            "max-obj-size" => {
                test_max_obj_size(&piv)?;
            }
            "headroom" => {
                test_headroom(&piv)?;
            }
            "free-nvm" => {
                eprintln!("\n=== TEST: free-nvm ===");
                eprintln!("  Measures free NVM on the current device state (no reset).");
                let mut card = piv.connect()?;
                let free = measure_free_nvm(&piv, &mut card)?;
                eprintln!("  Total free NVM: {free} bytes");
            }
            "shrink0" => {
                eprintln!("\n=== shrink0: write 1 byte to slot 0 ===");
                let mut card = piv.connect()?;
                let mut ss = [0usize; 256];
                piv.auth(&mut card)?;
                let ok = piv.write(&mut card, 0, &[0xEEu8; 1], &mut ss)?;
                eprintln!(
                    "  slot 0 → 1 byte: {}",
                    if ok { "ok" } else { "FAILED (NVM full?)" }
                );
            }
            "frag-random" | "frag-shrink1" | "frag-delete" => {
                experiment_fragmentation(&piv, baseline_nvm.unwrap(), test)?;
            }
            "frag-grow" => {
                test_frag_grow(&piv)?;
            }
            "frag-map" => {
                test_frag_map(&piv)?;
            }
            _ => unreachable!(),
        }
    }

    Ok(())
}
