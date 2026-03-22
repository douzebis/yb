// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! NVM fragmentation experiment for YubiKey PIV data objects.
//!
//! Investigates whether repeated PUT DATA calls at varying object sizes
//! cause permanent NVM consumption (fragmentation) on the YubiKey 5.
//!
//! # Experiment design
//!
//! Three phases, each starting from a fresh PIV reset:
//!
//! 1. **Baseline** — write MAX_OBJECT_SIZE objects to IDs 0x5F0000, 0x5F0001, …
//!    until `SW=6A84` (NVM full).  Records the maximum number of objects that
//!    fit and the total NVM consumed.
//!
//! 2. **Fixed-size cycling** — write N objects at MAX_OBJECT_SIZE, overwrite all
//!    with MAX_OBJECT_SIZE again (simulating updates), repeat for R rounds.
//!    After each round fill until `6A84` to see if capacity is preserved.
//!
//! 3. **Variable-size cycling** — write N objects at MAX_OBJECT_SIZE, overwrite
//!    all with a 9-byte sentinel, overwrite all with MAX_OBJECT_SIZE again.
//!    Repeat for R rounds.  Fill until `6A84` after each round.  If
//!    fragmentation occurs, capacity drops each round.
//!
//! # Warning
//!
//! **DESTRUCTIVE**: performs a full PIV application reset (`yb piv reset`
//! equivalent) multiple times.  All PIV keys, certificates and objects are
//! wiped.  Use only on a dedicated test YubiKey.
//!
//! # Usage
//!
//! ```
//! YB_PIN=123456 YB_MANAGEMENT_KEY=010203040506070801020304050607080102030405060708 \
//!     cargo run --bin nvm-frag-test -- [READER_SUBSTRING]
//! ```
//!
//! If no reader substring is given, uses the first connected reader.

use anyhow::{bail, Context, Result};
use std::ffi::CString;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum PIV object payload size (the APDU limit).
const MAX_OBJECT_SIZE: usize = 3_052;

/// Object IDs: 0x5F0000 through 0x5F00FF (256 slots available on YubiKey 5).
const OBJECT_ID_BASE: u32 = 0x5F_0000;
const MAX_SLOTS: usize = 128; // yb uses 0x5F0000..0x5F007F; expand to 128 here

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
            bail!("PUT DATA failed: SW={sw1:02x}{sw2:02x}");
        } else if sw1 != 0x90 || sw2 != 0x00 {
            bail!("PUT DATA (chained) failed: SW={sw1:02x}{sw2:02x}");
        }
    }
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

    /// Write `payload` to object `idx` (0-based), authenticated.
    fn write(&self, card: &mut pcsc::Card, idx: usize, payload: &[u8]) -> Result<bool> {
        let id = OBJECT_ID_BASE + idx as u32;
        put_data(card, id, payload)
    }
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
    let mut n = 0usize;
    for i in 0..MAX_SLOTS {
        match piv.write(&mut card, i, &large)? {
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
        if piv.write(&mut card, n, &probe)? {
            delta = mid;
            lo = mid + 1;
            // Erase the successful write before trying a larger one.
            // Write 1-byte to release the slot (a 1-byte object is always smaller).
            piv.auth(&mut card)?;
            piv.write(&mut card, n, &[0x00])?;
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
    piv.write(&mut card, n, &delta_payload)?;
    piv.auth(&mut card)?;
    let one_more = piv.write(&mut card, n + 1, &[0xFFu8])?;
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

/// Stress-test NVM fragmentation with random-size random-slot writes.
///
/// Uses STRESS_SLOTS object slots.  Runs STRESS_ROUNDS rounds of random writes
/// (random slot in 0..STRESS_SLOTS, random size in 1..=MAX_OBJECT_SIZE, ignoring
/// failures).  Re-authenticates every AUTH_INTERVAL writes to keep the session
/// alive.  After all rounds, overwrites every slot with MAX_OBJECT_SIZE starting
/// from slot 0, counting bytes until 6A84.  Reports total vs baseline.
fn experiment_fragmentation(piv: &Piv, baseline_nvm: usize) -> Result<()> {
    const STRESS_SLOTS: usize = 20;
    const STRESS_ROUNDS: usize = 100;
    const AUTH_INTERVAL: usize = 10;

    eprintln!("\n=== EXPERIMENT 2: RANDOM-SIZE FRAGMENTATION STRESS ===");
    eprintln!(
        "{STRESS_ROUNDS} random writes across {STRESS_SLOTS} slots (any size 1..={MAX_OBJECT_SIZE}), \
         then fill sequentially with {MAX_OBJECT_SIZE}-byte objects."
    );

    piv.reset()?;
    let mut card = piv.connect()?;

    // Random writes — ignore 6A84, keep going.
    eprintln!("  Stress phase ({STRESS_ROUNDS} writes):");
    piv.auth(&mut card)?;
    for round in 0..STRESS_ROUNDS {
        if round % AUTH_INTERVAL == 0 && round > 0 {
            piv.auth(&mut card)?;
        }
        let slot = (rand::random::<usize>()) % STRESS_SLOTS;
        let size = 1 + (rand::random::<usize>()) % MAX_OBJECT_SIZE;
        let payload = vec![(round & 0xFF) as u8; size];
        let ok = piv.write(&mut card, slot, &payload)?;
        if (round + 1) % 20 == 0 {
            let mark = if ok { "ok" } else { "oom" };
            eprintln!(
                "    round {:3}: slot={slot:2} size={size:4} [{mark}]",
                round + 1
            );
        }
    }

    // Final fill: overwrite every slot 0..MAX_SLOTS with MAX_OBJECT_SIZE sequentially.
    eprintln!("  Final fill with {MAX_OBJECT_SIZE}-byte objects:");
    piv.auth(&mut card)?;
    let large = vec![0xDDu8; MAX_OBJECT_SIZE];
    let mut total_bytes = 0usize;
    let mut slot_count = 0usize;
    for i in 0..MAX_SLOTS {
        piv.auth(&mut card)?;
        match piv.write(&mut card, i, &large)? {
            true => {
                total_bytes += MAX_OBJECT_SIZE;
                slot_count += 1;
            }
            false => break,
        }
    }
    eprintln!("    {slot_count} objects × {MAX_OBJECT_SIZE} = {total_bytes} bytes.");

    let diff = total_bytes as isize - baseline_nvm as isize;
    eprintln!();
    eprintln!("  Baseline NVM  : {baseline_nvm} bytes");
    eprintln!("  Post-stress   : {total_bytes} bytes");
    eprintln!("  Difference    : {diff:+} bytes");
    match diff.cmp(&0) {
        std::cmp::Ordering::Equal => {
            eprintln!("  --> NO FRAGMENTATION: full capacity preserved after random-size stress.");
            eprintln!("      Dynamic object sizing (spec 0010) is safe.");
        }
        std::cmp::Ordering::Less => {
            eprintln!("  --> FRAGMENTATION DETECTED: {diff} bytes permanently lost.");
            eprintln!("      Variable-size writes consume NVM that cannot be reclaimed.");
        }
        std::cmp::Ordering::Greater => {
            eprintln!("  --> Unexpected gain — measurement artifact, investigate.");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

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
    let reader_sub = args.get(1).map(|s| s.as_str());

    let mgmt_key =
        std::env::var("YB_MANAGEMENT_KEY").unwrap_or_else(|_| DEFAULT_MGMT_KEY.to_owned());

    let reader = find_reader(reader_sub)?;
    eprintln!("Using reader: {reader}");
    eprintln!("Management key: {mgmt_key}");
    eprintln!();
    eprintln!("╔══════════════════════════════════════════════════════════════════════╗");
    eprintln!("║  NVM FRAGMENTATION EXPERIMENT — DESTRUCTIVE                         ║");
    eprintln!("║  All PIV keys, certificates and objects will be wiped.              ║");
    eprintln!("║  Use only on a dedicated test YubiKey!                              ║");
    eprintln!("╚══════════════════════════════════════════════════════════════════════╝");
    eprintln!();
    eprint!("Press Enter to proceed, or Ctrl-C to abort: ");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;

    let piv = Piv { reader, mgmt_key };

    let baseline_nvm = experiment_capacity(&piv)?;
    experiment_fragmentation(&piv, baseline_nvm)?;

    Ok(())
}
