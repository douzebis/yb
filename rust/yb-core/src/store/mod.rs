// SPDX-FileCopyrightText: 2025 - 2026 Frederic Ruget <fred@atlant.is> <fred@s3ns.io> (GitHub: @douzebis)
// SPDX-FileCopyrightText: 2025 - 2026 Thales Cloud Sécurisé
//
// SPDX-License-Identifier: MIT

//! Binary store: serialization / deserialization of PIV objects.

pub mod constants;

use anyhow::{bail, Context, Result};
use constants::*;
use std::collections::{HashMap, HashSet};

use crate::orchestrator::BLOB_SIZE_C_BIT;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::piv::PivBackend;

// ---------------------------------------------------------------------------
// Object
// ---------------------------------------------------------------------------

/// One PIV data object.  May be empty (age == 0) or occupied (age > 0).
#[derive(Debug, Clone)]
pub struct Object {
    /// Index within the store (0 = object at OBJECT_ID_ZERO).
    pub(crate) index: u8,
    /// Object size in bytes (same for all objects in a store).
    pub(crate) object_size: usize,

    // -- fields present in every object --
    pub(crate) yblob_magic: u32,
    pub(crate) object_count: u8,
    pub(crate) store_key_slot: u8,
    /// Age counter (0 = empty).
    pub(crate) age: u32,

    // -- fields present when age != 0 --
    pub(crate) chunk_pos: u8,
    pub(crate) next_chunk: u8,

    // -- fields present only in head chunks (chunk_pos == 0) --
    /// Modification time as a Unix timestamp (seconds since epoch).
    pub blob_mtime: u32,
    /// Byte length of the (possibly encrypted) payload stored across all chunks.
    pub blob_size: u32,
    /// PIV slot used for encryption (0 = unencrypted).
    pub blob_key_slot: u8,
    /// Byte length of the plaintext before encryption.
    pub blob_plain_size: u32,
    /// Whether the stored payload is compressed (C-bit = bit 23 of blob_plain_size).
    pub is_compressed: bool,
    pub blob_name: String,

    /// Raw chunk payload bytes (excluding all header fields).
    pub(crate) payload: Vec<u8>,

    /// Whether this object needs to be written back to the YubiKey.
    pub(crate) dirty: bool,
}

impl Object {
    /// Deserialize a PIV object from raw bytes.
    pub fn from_bytes(index: u8, data: &[u8]) -> Result<Self> {
        let object_size = data.len();
        if !(OBJECT_MIN_SIZE..=OBJECT_MAX_SIZE).contains(&object_size) {
            bail!(
                "object {index}: invalid size {object_size} \
                 (expected {OBJECT_MIN_SIZE}..={OBJECT_MAX_SIZE})"
            );
        }

        let magic = read_u32_le(data, MAGIC_O)?;
        if magic != YBLOB_MAGIC {
            bail!("object {index}: bad magic 0x{magic:08x} (expected 0x{YBLOB_MAGIC:08x})");
        }

        let object_count = data[OBJECT_COUNT_O];
        let store_key_slot = data[STORE_KEY_SLOT_O];
        let age = read_u24_le(data, OBJECT_AGE_O)?;

        if age == 0 {
            // Empty slot — remaining fields are zero / don't-care.
            return Ok(Self {
                index,
                object_size,
                yblob_magic: magic,
                object_count,
                store_key_slot,
                age: 0,
                chunk_pos: 0,
                next_chunk: 0,
                blob_mtime: 0,
                blob_size: 0,
                blob_key_slot: 0,
                blob_plain_size: 0,
                is_compressed: false,
                blob_name: String::new(),
                payload: Vec::new(),
                dirty: false,
            });
        }

        let chunk_pos = data[CHUNK_POS_O];
        let next_chunk = data[NEXT_CHUNK_O];

        let (
            blob_mtime,
            blob_size,
            blob_key_slot,
            blob_plain_size,
            is_compressed,
            blob_name,
            payload_start,
        ) = if chunk_pos == 0 {
            let mtime = read_u32_le(data, BLOB_MTIME_O)?;
            let bsize = read_u24_le(data, BLOB_SIZE_O)?;
            let bkslot = data[BLOB_KEY_SLOT_O];
            let raw_plain = read_u24_le(data, BLOB_PLAIN_SIZE_O)?;
            let compressed = raw_plain & BLOB_SIZE_C_BIT as u32 != 0;
            let plain = raw_plain & !(BLOB_SIZE_C_BIT as u32);
            let nlen = data[BLOB_NAME_LEN_O] as usize;
            if BLOB_NAME_O + nlen > object_size {
                bail!("object {index}: name length {nlen} overflows object");
            }
            let name = std::str::from_utf8(&data[BLOB_NAME_O..BLOB_NAME_O + nlen])
                .with_context(|| format!("object {index}: blob name is not valid UTF-8"))?
                .to_owned();
            (
                mtime,
                bsize,
                bkslot,
                plain,
                compressed,
                name,
                BLOB_NAME_O + nlen,
            )
        } else {
            (0, 0, 0, 0, false, String::new(), CONTINUATION_PAYLOAD_O)
        };

        // Read all remaining bytes as payload — both head and continuation.
        // Consumers that want only the blob data (fetch_blob) truncate to
        // blob_size themselves.  fsck uses the full bytes to locate the yb2
        // signature trailer via collect_blob_chain.
        let raw_payload = &data[payload_start..];
        let payload = raw_payload.to_vec();

        Ok(Self {
            index,
            object_size,
            yblob_magic: magic,
            object_count,
            store_key_slot,
            age,
            chunk_pos,
            next_chunk,
            blob_mtime,
            blob_size,
            blob_key_slot,
            blob_plain_size,
            is_compressed,
            blob_name,
            payload,
            dirty: false,
        })
    }

    /// Serialize this object to the minimum number of bytes required.
    ///
    /// - Empty slot (age == 0): 9-byte sentinel (common header only).
    /// - Head chunk: `0x17 + name_len + payload_len` bytes.
    /// - Continuation chunk: `0x0B + payload_len` bytes.
    ///
    /// The result is always in the range `OBJECT_MIN_SIZE`..=`OBJECT_MAX_SIZE`.
    pub fn to_bytes(&self) -> Vec<u8> {
        if self.age == 0 {
            // Empty-slot sentinel: 9-byte common header only.
            let mut buf = vec![0u8; OBJECT_MIN_SIZE];
            write_u32_le(&mut buf, MAGIC_O, self.yblob_magic);
            buf[OBJECT_COUNT_O] = self.object_count;
            buf[STORE_KEY_SLOT_O] = self.store_key_slot;
            // OBJECT_AGE stays 0.
            return buf;
        }

        if self.chunk_pos == 0 {
            // Head chunk: headers + name + payload.
            let name_bytes = self.blob_name.as_bytes();
            let total = (BLOB_NAME_O + name_bytes.len() + self.payload.len())
                .clamp(OBJECT_MIN_SIZE, OBJECT_MAX_SIZE);
            let mut buf = vec![0u8; total];
            write_u32_le(&mut buf, MAGIC_O, self.yblob_magic);
            buf[OBJECT_COUNT_O] = self.object_count;
            buf[STORE_KEY_SLOT_O] = self.store_key_slot;
            write_u24_le(&mut buf, OBJECT_AGE_O, self.age);
            buf[CHUNK_POS_O] = self.chunk_pos;
            buf[NEXT_CHUNK_O] = self.next_chunk;
            write_u32_le(&mut buf, BLOB_MTIME_O, self.blob_mtime);
            write_u24_le(&mut buf, BLOB_SIZE_O, self.blob_size);
            buf[BLOB_KEY_SLOT_O] = self.blob_key_slot;
            write_u24_le(
                &mut buf,
                BLOB_PLAIN_SIZE_O,
                self.blob_plain_size | self.c_bit(),
            );
            buf[BLOB_NAME_LEN_O] = name_bytes.len() as u8;
            buf[BLOB_NAME_O..BLOB_NAME_O + name_bytes.len()].copy_from_slice(name_bytes);
            let payload_start = BLOB_NAME_O + name_bytes.len();
            let payload_end = (payload_start + self.payload.len()).min(total);
            buf[payload_start..payload_end]
                .copy_from_slice(&self.payload[..payload_end - payload_start]);
            buf
        } else {
            // Continuation chunk: headers + payload.
            let total = (CONTINUATION_PAYLOAD_O + self.payload.len())
                .clamp(OBJECT_MIN_SIZE, OBJECT_MAX_SIZE);
            let mut buf = vec![0u8; total];
            write_u32_le(&mut buf, MAGIC_O, self.yblob_magic);
            buf[OBJECT_COUNT_O] = self.object_count;
            buf[STORE_KEY_SLOT_O] = self.store_key_slot;
            write_u24_le(&mut buf, OBJECT_AGE_O, self.age);
            buf[CHUNK_POS_O] = self.chunk_pos;
            buf[NEXT_CHUNK_O] = self.next_chunk;
            let payload_end = (CONTINUATION_PAYLOAD_O + self.payload.len()).min(total);
            buf[CONTINUATION_PAYLOAD_O..payload_end]
                .copy_from_slice(&self.payload[..payload_end - CONTINUATION_PAYLOAD_O]);
            buf
        }
    }

    /// Mark this object as empty (age = 0) and dirty.
    ///
    /// Uses an explicit full struct literal so that adding a new field causes a
    /// compile error here, forcing the author to decide whether it should be
    /// preserved or zeroed on reset.
    pub fn reset(&mut self) {
        let index = self.index;
        let object_count = self.object_count;
        let store_key_slot = self.store_key_slot;
        *self = Self {
            index,
            object_size: OBJECT_MIN_SIZE, // write compact 9-byte sentinel
            yblob_magic: crate::store::constants::YBLOB_MAGIC,
            object_count,
            store_key_slot,
            age: 0,
            chunk_pos: 0,
            next_chunk: 0,
            blob_mtime: 0,
            blob_size: 0,
            blob_key_slot: 0,
            blob_plain_size: 0,
            is_compressed: false,
            blob_name: String::new(),
            payload: Vec::new(),
            dirty: true,
        };
    }

    /// Maximum payload capacity in a head chunk given a name of `name_len` bytes.
    ///
    /// Uses `OBJECT_MAX_SIZE` (the hard limit) regardless of the `object_size`
    /// argument, which is ignored and retained only for call-site compatibility.
    pub fn head_payload_capacity(_object_size: usize, name_len: usize) -> usize {
        OBJECT_MAX_SIZE.saturating_sub(BLOB_NAME_O + name_len)
    }

    /// Maximum payload capacity in a continuation chunk.
    ///
    /// Uses `OBJECT_MAX_SIZE` (the hard limit).  The `object_size` argument is
    /// ignored and retained only for call-site compatibility.
    pub fn continuation_payload_capacity(_object_size: usize) -> usize {
        OBJECT_MAX_SIZE.saturating_sub(CONTINUATION_PAYLOAD_O)
    }

    /// Returns `BLOB_SIZE_C_BIT` when the blob is compressed, 0 otherwise.
    /// Used when serializing `blob_plain_size` to the wire format.
    fn c_bit(&self) -> u32 {
        BLOB_SIZE_C_BIT as u32 * self.is_compressed as u32
    }

    pub fn is_empty(&self) -> bool {
        self.age == 0
    }

    pub fn is_head(&self) -> bool {
        self.age != 0 && self.chunk_pos == 0
    }

    pub fn is_encrypted(&self) -> bool {
        self.blob_key_slot != 0
    }

    // -- Accessors for internal fields --

    /// Set the raw chunk payload.  Intended for test helpers that need to
    /// construct synthetic objects via [`Store::make_object`].
    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = payload;
    }

    pub fn index(&self) -> u8 {
        self.index
    }

    pub fn age(&self) -> u32 {
        self.age
    }

    pub fn chunk_pos(&self) -> u8 {
        self.chunk_pos
    }

    pub fn next_chunk(&self) -> u8 {
        self.next_chunk
    }

    /// Raw chunk payload bytes (read-only).
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    /// Length of the raw chunk payload bytes.
    pub fn payload_len(&self) -> usize {
        self.payload.len()
    }

    pub fn object_size(&self) -> usize {
        self.object_size
    }
}

// ---------------------------------------------------------------------------
// ObjectParams
// ---------------------------------------------------------------------------

/// Named parameters for [`Store::make_object`].
pub struct ObjectParams {
    pub index: u8,
    pub age: u32,
    pub chunk_pos: u8,
    pub next_chunk: u8,
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// The full set of PIV objects that make up one yb store.
pub struct Store {
    pub reader: String,
    pub object_size: usize,
    pub object_count: u8,
    pub store_key_slot: u8,
    pub objects: Vec<Object>,
    /// Highest age seen across all objects; new objects get age = store_age + 1.
    pub store_age: u32,
}

impl Store {
    /// Read all objects from the device and construct a Store.
    pub fn from_device(reader: &str, piv: &dyn PivBackend) -> Result<Self> {
        let first_id = OBJECT_ID_ZERO;
        let raw = piv
            .read_object(reader, first_id)
            .with_context(|| format!("reading object 0x{first_id:06x}"))?;

        let first =
            Object::from_bytes(0, &raw).with_context(|| "parsing object 0 (store header)")?;

        let object_count = first.object_count;
        let object_size = raw.len();
        let store_key_slot = first.store_key_slot;

        let mut objects = vec![first];
        for i in 1..object_count {
            let id = OBJECT_ID_ZERO + i as u32;
            let raw = piv
                .read_object(reader, id)
                .with_context(|| format!("reading object 0x{id:06x}"))?;
            let obj = Object::from_bytes(i, &raw).with_context(|| format!("parsing object {i}"))?;
            objects.push(obj);
        }

        let store_age = objects.iter().map(|o| o.age).max().unwrap_or(0);

        Ok(Self {
            reader: reader.to_owned(),
            object_size,
            object_count,
            store_key_slot,
            objects,
            store_age,
        })
    }

    /// Write a fresh empty store to the device (yb format).
    ///
    /// Each slot is initialised with a compact 9-byte empty-slot sentinel
    /// (spec 0010).  No `object_size` parameter — size is determined
    /// dynamically at write time.
    pub fn format(
        reader: &str,
        piv: &dyn PivBackend,
        object_count: u8,
        store_key_slot: u8,
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> Result<Self> {
        // Build a temporary store (no objects yet) so we can use make_object.
        let mut store = Self {
            reader: reader.to_owned(),
            object_size: OBJECT_MIN_SIZE,
            object_count,
            store_key_slot,
            objects: Vec::with_capacity(object_count as usize),
            store_age: 0,
        };
        for i in 0..object_count {
            // age == 0 produces a 9-byte empty-slot sentinel.
            store.objects.push(store.make_object(ObjectParams {
                index: i,
                age: 0,
                chunk_pos: 0,
                next_chunk: 0,
            }));
        }
        store.sync(piv, management_key, pin)?;
        Ok(store)
    }

    /// Remove corrupt / orphaned / duplicate objects.
    pub fn sanitize(&mut self) {
        // Remove heads with invalid ages (age should be > 0 for occupied).
        // Remove older duplicate-named blobs.
        // Remove chunks whose head cannot be reached.

        // Collect heads: name -> (index, age)
        let mut seen: HashMap<String, (u8, u32)> = HashMap::new();
        let mut to_reset: Vec<u8> = Vec::new();

        for obj in self.objects.iter().filter(|o| o.is_head()) {
            if let Some(&(prev_idx, prev_age)) = seen.get(&obj.blob_name) {
                // Keep the newer one, reset the older.
                if obj.age > prev_age {
                    to_reset.push(prev_idx);
                    seen.insert(obj.blob_name.clone(), (obj.index, obj.age));
                } else {
                    to_reset.push(obj.index);
                }
            } else {
                seen.insert(obj.blob_name.clone(), (obj.index, obj.age));
            }
        }

        // Collect all reachable chunk indices.
        let mut reachable: HashSet<u8> = HashSet::new();
        for (head_idx, _) in seen.values() {
            let mut idx = *head_idx;
            loop {
                reachable.insert(idx);
                let next = self.objects[idx as usize].next_chunk;
                if next == idx {
                    break;
                }
                idx = next;
            }
        }

        // Mark unreachable non-empty objects for reset.
        for obj in self.objects.iter().filter(|o| !o.is_empty()) {
            if !reachable.contains(&obj.index) {
                to_reset.push(obj.index);
            }
        }

        for idx in to_reset {
            self.objects[idx as usize].reset();
        }
    }

    /// Write all dirty objects back to the device.
    pub fn sync(
        &mut self,
        piv: &dyn PivBackend,
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> Result<()> {
        use indicatif::{ProgressBar, ProgressStyle};

        let dirty: Vec<u8> = self
            .objects
            .iter()
            .filter(|o| o.dirty)
            .map(|o| o.index)
            .collect();

        let pb = ProgressBar::new(dirty.len() as u64);
        pb.set_style(
            ProgressStyle::with_template("Writing objects: [{bar:30}] {pos}/{len}")
                .unwrap()
                .progress_chars("=>-"),
        );

        for idx in &dirty {
            let obj = &mut self.objects[*idx as usize];
            let id = OBJECT_ID_ZERO + obj.index as u32;
            let data = obj.to_bytes();
            piv.write_object(&self.reader, id, &data, management_key, pin)
                .with_context(|| format!("writing object 0x{id:06x}"))?;
            obj.dirty = false;
            pb.inc(1);
        }
        pb.finish_and_clear();
        Ok(())
    }

    /// Allocate the next free object index, or None if the store is full.
    pub fn alloc_free(&self) -> Option<u8> {
        self.objects.iter().find(|o| o.is_empty()).map(|o| o.index)
    }

    /// Number of free (empty) slots.
    pub fn free_count(&self) -> usize {
        self.objects.iter().filter(|o| o.is_empty()).count()
    }

    /// Find the head object for a blob by name.
    pub fn find_head(&self, name: &str) -> Option<&Object> {
        self.objects
            .iter()
            .find(|o| o.is_head() && o.blob_name == name)
    }

    /// Follow the chunk chain from a head, collecting all chunk indices in order.
    ///
    /// Includes a cycle guard: if a `next_chunk` pointer revisits an already-
    /// seen index (corrupt store), the walk stops early so the function always
    /// terminates.
    pub fn chunk_chain(&self, head_index: u8) -> Vec<u8> {
        let mut chain = vec![head_index];
        let mut seen: HashSet<u8> = HashSet::from([head_index]);
        let mut idx = head_index;
        loop {
            let next = self.objects[idx as usize].next_chunk;
            if next == idx {
                break;
            }
            if seen.contains(&next) {
                // Corrupt store: cycle detected — stop walking.
                break;
            }
            seen.insert(next);
            chain.push(next);
            idx = next;
        }
        chain
    }

    /// Current Unix timestamp (seconds), for use as blob_mtime.
    pub fn now_unix() -> u32 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as u32)
            .unwrap_or(0)
    }

    /// Bump the store age and return the new value for a new chunk.
    pub fn next_age(&mut self) -> u32 {
        self.store_age += 1;
        self.store_age
    }

    /// Construct a new occupied `Object` for this store, filling all common
    /// header fields from the store's own metadata.  Blob-specific fields
    /// (`blob_mtime`, `blob_size`, `blob_key_slot`, `blob_plain_size`,
    /// `is_compressed`, `blob_name`, `payload`) are left at their zero values
    /// for the caller to set.
    pub fn make_object(&self, p: ObjectParams) -> Object {
        Object {
            index: p.index,
            object_size: self.object_size,
            yblob_magic: crate::store::constants::YBLOB_MAGIC,
            object_count: self.object_count,
            store_key_slot: self.store_key_slot,
            age: p.age,
            chunk_pos: p.chunk_pos,
            next_chunk: p.next_chunk,
            blob_mtime: 0,
            blob_size: 0,
            blob_key_slot: 0,
            blob_plain_size: 0,
            is_compressed: false,
            blob_name: String::new(),
            payload: Vec::new(),
            dirty: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------

pub(crate) fn read_u32_le(buf: &[u8], offset: usize) -> Result<u32> {
    let end = offset + 4;
    if end > buf.len() {
        bail!(
            "read_u32_le: offset {offset}+4 out of bounds (buf len {})",
            buf.len()
        );
    }
    Ok(u32::from_le_bytes(buf[offset..end].try_into().unwrap()))
}

pub(crate) fn read_u24_le(buf: &[u8], offset: usize) -> Result<u32> {
    let end = offset + 3;
    if end > buf.len() {
        bail!(
            "read_u24_le: offset {offset}+3 out of bounds (buf len {})",
            buf.len()
        );
    }
    let b = &buf[offset..end];
    Ok(b[0] as u32 | ((b[1] as u32) << 8) | ((b[2] as u32) << 16))
}

pub(crate) fn write_u32_le(buf: &mut [u8], offset: usize, v: u32) {
    buf[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
}

pub(crate) fn write_u24_le(buf: &mut [u8], offset: usize, v: u32) {
    buf[offset] = (v & 0xff) as u8;
    buf[offset + 1] = ((v >> 8) & 0xff) as u8;
    buf[offset + 2] = ((v >> 16) & 0xff) as u8;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
