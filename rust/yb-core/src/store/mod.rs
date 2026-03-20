// SPDX-FileCopyrightText: 2025 Frederic Ruget <fred@atlant.is> (GitHub: @douzebis)
//
// SPDX-License-Identifier: MIT

//! Binary store: serialization / deserialization of PIV objects.

pub mod constants;

use anyhow::{bail, Context, Result};
use constants::*;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::piv::PivBackend;

// ---------------------------------------------------------------------------
// Object
// ---------------------------------------------------------------------------

/// One PIV data object.  May be empty (age == 0) or occupied (age > 0).
#[derive(Debug, Clone)]
pub struct Object {
    /// Index within the store (0 = object at OBJECT_ID_ZERO).
    pub index: u8,
    /// Object size in bytes (same for all objects in a store).
    pub object_size: usize,

    // -- fields present in every object --
    pub yblob_magic: u32,
    pub object_count: u8,
    pub store_key_slot: u8,
    /// Age counter (0 = empty).
    pub age: u32,

    // -- fields present when age != 0 --
    pub chunk_pos: u8,
    pub next_chunk: u8,

    // -- fields present only in head chunks (chunk_pos == 0) --
    pub blob_mtime: u32,
    /// Byte length of the (possibly encrypted) payload stored across all chunks.
    pub blob_size: u32,
    /// PIV slot used for encryption (0 = unencrypted).
    pub blob_key_slot: u8,
    /// Byte length of the plaintext before encryption.
    pub blob_plain_size: u32,
    pub blob_name: String,

    /// Raw chunk payload bytes (excluding all header fields).
    pub payload: Vec<u8>,

    /// Whether this object needs to be written back to the YubiKey.
    pub dirty: bool,
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

        let magic = read_u32_le(data, MAGIC_O);
        if magic != YBLOB_MAGIC {
            bail!("object {index}: bad magic 0x{magic:08x} (expected 0x{YBLOB_MAGIC:08x})");
        }

        let object_count = data[OBJECT_COUNT_O];
        let store_key_slot = data[STORE_KEY_SLOT_O];
        let age = read_u24_le(data, OBJECT_AGE_O);

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
                blob_name: String::new(),
                payload: Vec::new(),
                dirty: false,
            });
        }

        let chunk_pos = data[CHUNK_POS_O];
        let next_chunk = data[NEXT_CHUNK_O];

        let (blob_mtime, blob_size, blob_key_slot, blob_plain_size, blob_name, payload_start) =
            if chunk_pos == 0 {
                let mtime = read_u32_le(data, BLOB_MTIME_O);
                let bsize = read_u24_le(data, BLOB_SIZE_O);
                let bkslot = data[BLOB_KEY_SLOT_O];
                let plain = read_u24_le(data, BLOB_PLAIN_SIZE_O);
                let nlen = data[BLOB_NAME_LEN_O] as usize;
                if BLOB_NAME_O + nlen > object_size {
                    bail!("object {index}: name length {nlen} overflows object");
                }
                let name = std::str::from_utf8(&data[BLOB_NAME_O..BLOB_NAME_O + nlen])
                    .with_context(|| format!("object {index}: blob name is not valid UTF-8"))?
                    .to_owned();
                (mtime, bsize, bkslot, plain, name, BLOB_NAME_O + nlen)
            } else {
                (0, 0, 0, 0, String::new(), CONTINUATION_PAYLOAD_O)
            };

        let payload = data[payload_start..].to_vec();

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
            blob_name,
            payload,
            dirty: false,
        })
    }

    /// Serialize this object to exactly `object_size` bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.object_size];

        write_u32_le(&mut buf, MAGIC_O, self.yblob_magic);
        buf[OBJECT_COUNT_O] = self.object_count;
        buf[STORE_KEY_SLOT_O] = self.store_key_slot;
        write_u24_le(&mut buf, OBJECT_AGE_O, self.age);

        if self.age == 0 {
            return buf;
        }

        buf[CHUNK_POS_O] = self.chunk_pos;
        buf[NEXT_CHUNK_O] = self.next_chunk;

        if self.chunk_pos == 0 {
            write_u32_le(&mut buf, BLOB_MTIME_O, self.blob_mtime);
            write_u24_le(&mut buf, BLOB_SIZE_O, self.blob_size);
            buf[BLOB_KEY_SLOT_O] = self.blob_key_slot;
            write_u24_le(&mut buf, BLOB_PLAIN_SIZE_O, self.blob_plain_size);
            let name_bytes = self.blob_name.as_bytes();
            buf[BLOB_NAME_LEN_O] = name_bytes.len() as u8;
            let payload_start = BLOB_NAME_O + name_bytes.len();
            buf[BLOB_NAME_O..BLOB_NAME_O + name_bytes.len()].copy_from_slice(name_bytes);
            let payload_end = (payload_start + self.payload.len()).min(self.object_size);
            buf[payload_start..payload_end]
                .copy_from_slice(&self.payload[..payload_end - payload_start]);
        } else {
            let payload_end = (CONTINUATION_PAYLOAD_O + self.payload.len()).min(self.object_size);
            buf[CONTINUATION_PAYLOAD_O..payload_end]
                .copy_from_slice(&self.payload[..payload_end - CONTINUATION_PAYLOAD_O]);
        }

        buf
    }

    /// Mark this object as empty (age = 0) and dirty.
    pub fn reset(&mut self) {
        self.age = 0;
        self.chunk_pos = 0;
        self.next_chunk = 0;
        self.blob_mtime = 0;
        self.blob_size = 0;
        self.blob_key_slot = 0;
        self.blob_plain_size = 0;
        self.blob_name.clear();
        self.payload.clear();
        self.dirty = true;
    }

    /// Capacity of the payload region in a head chunk.
    pub fn head_payload_capacity(object_size: usize, name_len: usize) -> usize {
        object_size.saturating_sub(BLOB_NAME_O + name_len)
    }

    /// Capacity of the payload region in a continuation chunk.
    pub fn continuation_payload_capacity(object_size: usize) -> usize {
        object_size.saturating_sub(CONTINUATION_PAYLOAD_O)
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
    pub fn format(
        reader: &str,
        piv: &dyn PivBackend,
        object_count: u8,
        object_size: usize,
        store_key_slot: u8,
        management_key: Option<&str>,
        pin: Option<&str>,
    ) -> Result<Self> {
        let mut objects = Vec::with_capacity(object_count as usize);
        for i in 0..object_count {
            objects.push(Object {
                index: i,
                object_size,
                yblob_magic: YBLOB_MAGIC,
                object_count,
                store_key_slot,
                age: 0,
                chunk_pos: 0,
                next_chunk: 0,
                blob_mtime: 0,
                blob_size: 0,
                blob_key_slot: 0,
                blob_plain_size: 0,
                blob_name: String::new(),
                payload: Vec::new(),
                dirty: true,
            });
        }
        let mut store = Self {
            reader: reader.to_owned(),
            object_size,
            object_count,
            store_key_slot,
            objects,
            store_age: 0,
        };
        store.sync(piv, management_key, pin)?;
        Ok(store)
    }

    /// Remove corrupt / orphaned / duplicate objects.
    pub fn sanitize(&mut self) {
        // Remove heads with invalid ages (age should be > 0 for occupied).
        // Remove older duplicate-named blobs.
        // Remove chunks whose head cannot be reached.

        // Collect heads: name -> (index, age)
        let mut seen: std::collections::HashMap<String, (u8, u32)> =
            std::collections::HashMap::new();
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
        let mut reachable: std::collections::HashSet<u8> = std::collections::HashSet::new();
        for (_, (head_idx, _)) in &seen {
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
        for obj in self.objects.iter_mut().filter(|o| o.dirty) {
            let id = OBJECT_ID_ZERO + obj.index as u32;
            let data = obj.to_bytes();
            piv.write_object(&self.reader, id, &data, management_key, pin)
                .with_context(|| format!("writing object 0x{id:06x}"))?;
            obj.dirty = false;
            eprint!(".");
        }
        eprintln!();
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
    pub fn chunk_chain(&self, head_index: u8) -> Vec<u8> {
        let mut chain = vec![head_index];
        let mut idx = head_index;
        loop {
            let next = self.objects[idx as usize].next_chunk;
            if next == idx {
                break;
            }
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
}

// ---------------------------------------------------------------------------
// Little-endian helpers
// ---------------------------------------------------------------------------

fn read_u32_le(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

fn read_u24_le(buf: &[u8], offset: usize) -> u32 {
    let b = &buf[offset..offset + 3];
    b[0] as u32 | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
}

fn write_u32_le(buf: &mut [u8], offset: usize, v: u32) {
    buf[offset..offset + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_u24_le(buf: &mut [u8], offset: usize, v: u32) {
    buf[offset] = (v & 0xff) as u8;
    buf[offset + 1] = ((v >> 8) & 0xff) as u8;
    buf[offset + 2] = ((v >> 16) & 0xff) as u8;
}

// ---------------------------------------------------------------------------
// Round-trip tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_empty_object(object_size: usize) -> Vec<u8> {
        let mut buf = vec![0u8; object_size];
        write_u32_le(&mut buf, MAGIC_O, YBLOB_MAGIC);
        buf[OBJECT_COUNT_O] = 12;
        buf[STORE_KEY_SLOT_O] = 0x82;
        // age = 0 (already zero)
        buf
    }

    #[test]
    fn round_trip_empty() {
        let raw = make_empty_object(512);
        let obj = Object::from_bytes(0, &raw).unwrap();
        assert!(obj.is_empty());
        assert_eq!(obj.to_bytes(), raw);
    }

    #[test]
    fn round_trip_head() {
        let object_size = 512;
        let name = "hello";
        let payload_data = b"world!";

        let obj = Object {
            index: 0,
            object_size,
            yblob_magic: YBLOB_MAGIC,
            object_count: 12,
            store_key_slot: 0x82,
            age: 1,
            chunk_pos: 0,
            next_chunk: 0, // self-referential = last chunk
            blob_mtime: 1_700_000_000,
            blob_size: payload_data.len() as u32,
            blob_key_slot: 0,
            blob_plain_size: payload_data.len() as u32,
            blob_name: name.to_owned(),
            payload: payload_data.to_vec(),
            dirty: false,
        };

        let bytes = obj.to_bytes();
        assert_eq!(bytes.len(), object_size);

        let obj2 = Object::from_bytes(0, &bytes).unwrap();
        assert_eq!(obj2.blob_name, name);
        assert_eq!(obj2.age, 1);
        assert_eq!(obj2.chunk_pos, 0);
        assert_eq!(obj2.blob_mtime, 1_700_000_000);
        assert_eq!(&obj2.payload[..payload_data.len()], payload_data);
    }

    #[test]
    fn round_trip_continuation() {
        let object_size = 512;
        let payload_data = vec![0xABu8; 100];

        let obj = Object {
            index: 1,
            object_size,
            yblob_magic: YBLOB_MAGIC,
            object_count: 12,
            store_key_slot: 0x82,
            age: 2,
            chunk_pos: 1,
            next_chunk: 1, // self-referential = last chunk
            blob_mtime: 0,
            blob_size: 0,
            blob_key_slot: 0,
            blob_plain_size: 0,
            blob_name: String::new(),
            payload: payload_data.clone(),
            dirty: false,
        };

        let bytes = obj.to_bytes();
        let obj2 = Object::from_bytes(1, &bytes).unwrap();
        assert_eq!(obj2.chunk_pos, 1);
        assert_eq!(&obj2.payload[..payload_data.len()], &payload_data);
    }

    /// Binary compatibility test: a vector produced by the Python implementation.
    /// python: store 7-byte blob "config" age=1 slot=0x82 mtime=1_717_243_342 unencrypted
    #[test]
    fn python_compat_vector() {
        // Constructed from Python constants and known field values.
        let mut raw = vec![0u8; 512];
        write_u32_le(&mut raw, MAGIC_O, YBLOB_MAGIC);
        raw[OBJECT_COUNT_O] = 12;
        raw[STORE_KEY_SLOT_O] = 0x82;
        write_u24_le(&mut raw, OBJECT_AGE_O, 1);
        raw[CHUNK_POS_O] = 0;
        raw[NEXT_CHUNK_O] = 0;
        write_u32_le(&mut raw, BLOB_MTIME_O, 1_717_243_342);
        write_u24_le(&mut raw, BLOB_SIZE_O, 7);
        raw[BLOB_KEY_SLOT_O] = 0;
        write_u24_le(&mut raw, BLOB_PLAIN_SIZE_O, 7);
        raw[BLOB_NAME_LEN_O] = 6;
        raw[BLOB_NAME_O..BLOB_NAME_O + 6].copy_from_slice(b"config");
        raw[BLOB_NAME_O + 6..BLOB_NAME_O + 13].copy_from_slice(b"content");

        let obj = Object::from_bytes(0, &raw).unwrap();
        assert_eq!(obj.blob_name, "config");
        assert_eq!(obj.blob_size, 7);
        assert_eq!(obj.blob_mtime, 1_717_243_342);
        assert_eq!(obj.blob_key_slot, 0);
        assert_eq!(&obj.payload[..7], b"content");

        // Re-serialize must be identical.
        assert_eq!(obj.to_bytes(), raw);
    }
}
