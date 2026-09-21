//! Registry ids keyed by name, in RocksDB.
//!
//! `id` holds every registry's lowercased name. `name` and `rev` are the seeks: the name, or
//! its reverse, then the id, so a prefix of either is a contiguous range.
//!
//! No write needs to be atomic with another: state is the source of truth and
//! [`crate::exex::reconcile`] re-reads whatever a crash left short.

use std::{path::Path, sync::Arc};

use alloy_primitives::{Address, B256};
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamily, ColumnFamilyDescriptor, DB, DBCompressionType,
    Direction, IteratorMode, Options, WriteBatch,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Bump when a key or value changes shape; an index stamped otherwise is rebuilt.
const LAYOUT: &str = "anchoring-name-index/1";

const CF_META: &str = "meta";
const CF_ID: &str = "id";
const CF_NAME: &str = "name";
const CF_REV: &str = "rev";
const CFS: [&str; 4] = [CF_META, CF_ID, CF_NAME, CF_REV];

const KEY_LAYOUT: &[u8] = b"layout";
const KEY_SOURCE: &[u8] = b"source";
const KEY_TIP: &[u8] = b"tip";

/// Between a name and its id, so a name that starts another is not a prefix of its keys.
const SEPARATOR: u8 = 0;

/// How a name is compared. Every mode is case-insensitive.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Mode {
    #[default]
    Exact,
    Prefix,
    Suffix,
    Contains,
}

impl Mode {
    /// The bare word, or the name or number the module's `RegistryNameMatchMode` took.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            "0"
            | "1"
            | "EXACT"
            | "REGISTRY_NAME_MATCH_MODE_UNSPECIFIED"
            | "REGISTRY_NAME_MATCH_MODE_EXACT" => Some(Self::Exact),
            "2" | "PREFIX" | "REGISTRY_NAME_MATCH_MODE_PREFIX" => Some(Self::Prefix),
            "3" | "SUFFIX" | "REGISTRY_NAME_MATCH_MODE_SUFFIX" => Some(Self::Suffix),
            "4" | "CONTAINS" | "REGISTRY_NAME_MATCH_MODE_CONTAINS" => Some(Self::Contains),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Prefix => "prefix",
            Self::Suffix => "suffix",
            Self::Contains => "contains",
        }
    }
}

impl Serialize for Mode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Mode {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::parse(&value)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown match mode {value}")))
    }
}

/// The block the index was last brought level with. Reported, not relied on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tip {
    pub block_num: u64,
    pub hash: B256,
}

impl Tip {
    pub const fn new(block_num: u64, hash: B256) -> Self {
        Self { block_num, hash }
    }
}

/// The writing half, owned by the ExEx alone.
#[derive(Debug)]
pub struct Store {
    db: Arc<DB>,
}

/// The read half, shared by RPC handlers; RocksDB serializes nothing behind a writer.
#[derive(Clone, Debug)]
pub struct Reader {
    db: Arc<DB>,
}

impl Store {
    /// Open the index at `path`, rebuilding one written by another layout: it holds
    /// nothing state cannot hand back, and refusing it would refuse to start the node.
    pub fn open(path: impl AsRef<Path>) -> eyre::Result<Self> {
        let path = path.as_ref();
        let store = Self::open_at(path)?;
        match store.db.get_cf(store.cf(CF_META), KEY_LAYOUT)?.as_deref() {
            Some(held) if held == LAYOUT.as_bytes() => Ok(store),
            None if store.last_id()? == 0 => store.stamp(),
            _ => {
                warn!(target: "tempo::anchoring_index", "the anchoring name index was written by another layout; rebuilding it");
                drop(store);
                DB::destroy(&Options::default(), path)?;
                Self::open_at(path)?.stamp()
            }
        }
    }

    fn stamp(self) -> eyre::Result<Self> {
        self.db
            .put_cf(self.cf(CF_META), KEY_LAYOUT, LAYOUT.as_bytes())?;
        Ok(self)
    }

    fn open_at(path: &Path) -> eyre::Result<Self> {
        // RocksDB's defaults are sized for a node's own storage; this writes a few keys a
        // block, and a burst at the backfill.
        let cache = Cache::new_lru_cache(8 * 1024 * 1024);
        let mut table = BlockBasedOptions::default();
        table.set_block_cache(&cache);
        let tuned = || {
            let mut opts = Options::default();
            opts.set_compression_type(DBCompressionType::Lz4);
            opts.set_write_buffer_size(4 * 1024 * 1024);
            opts.set_max_write_buffer_number(2);
            opts.set_block_based_table_factory(&table);
            opts
        };

        let mut opts = tuned();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = CFS.map(|name| ColumnFamilyDescriptor::new(name, tuned()));
        Ok(Self {
            db: Arc::new(DB::open_cf_descriptors(&opts, path, cfs)?),
        })
    }

    pub fn reader(&self) -> Reader {
        Reader {
            db: self.db.clone(),
        }
    }

    /// Record which chain and contract this index holds, or refuse another's: every chain
    /// numbers registries from 1, so a foreign index looks level.
    pub fn bind(&self, chain_id: u64, contract: Address) -> eyre::Result<()> {
        let source = format!("chain {chain_id} contract {contract}");
        match self.db.get_cf(self.cf(CF_META), KEY_SOURCE)? {
            Some(held) if held == source.as_bytes() => Ok(()),
            Some(held) => eyre::bail!(
                "the index is from {}, not {source}: delete it to rebuild",
                String::from_utf8_lossy(&held)
            ),
            None => Ok(self
                .db
                .put_cf(self.cf(CF_META), KEY_SOURCE, source.as_bytes())?),
        }
    }

    /// Index `rows` as `(id, name)`.
    pub fn insert(&mut self, rows: &[(u64, String)]) -> eyre::Result<()> {
        let mut batch = WriteBatch::default();
        for (id, name) in rows {
            let lower = name.to_lowercase();
            batch.put_cf(self.cf(CF_ID), id.to_be_bytes(), lower.as_bytes());
            for (family, key) in keys(&lower, *id) {
                batch.put_cf(self.cf(family), key, b"");
            }
        }
        Ok(self.db.write(batch)?)
    }

    /// Drop every registry past `last`, and answer with how many that was.
    pub fn truncate_above(&mut self, last: u64) -> eyre::Result<u64> {
        let mut batch = WriteBatch::default();
        let mut dropped = 0;
        let from = last.saturating_add(1).to_be_bytes();
        for row in self.db.iterator_cf(
            self.cf(CF_ID),
            IteratorMode::From(&from, Direction::Forward),
        ) {
            let (key, name) = row?;
            let id = id_of(&key)?;
            batch.delete_cf(self.cf(CF_ID), &key);
            for (family, key) in keys(&String::from_utf8_lossy(&name), id) {
                batch.delete_cf(self.cf(family), key);
            }
            dropped += 1;
        }
        self.db.write(batch)?;
        Ok(dropped)
    }

    pub fn record_tip(&mut self, tip: Tip) -> eyre::Result<()> {
        let mut value = [0u8; 40];
        value[..8].copy_from_slice(&tip.block_num.to_be_bytes());
        value[8..].copy_from_slice(tip.hash.as_slice());
        Ok(self.db.put_cf(self.cf(CF_META), KEY_TIP, value)?)
    }

    pub fn last_id(&self) -> eyre::Result<u64> {
        self.reader().last_id()
    }

    fn cf(&self, name: &str) -> &ColumnFamily {
        cf(&self.db, name)
    }
}

impl Reader {
    /// The highest id indexed, or 0. Ids have no holes, so this is all the index lacks.
    pub fn last_id(&self) -> eyre::Result<u64> {
        match self
            .db
            .iterator_cf(cf(&self.db, CF_ID), IteratorMode::End)
            .next()
        {
            Some(row) => id_of(&row?.0),
            None => Ok(0),
        }
    }

    pub fn tip(&self) -> eyre::Result<Option<Tip>> {
        let Some(value) = self.db.get_cf(cf(&self.db, CF_META), KEY_TIP)? else {
            return Ok(None);
        };
        if value.len() != 40 {
            eyre::bail!("tip: expected 40 bytes, found {}", value.len());
        }
        Ok(Some(Tip::new(
            u64::from_be_bytes(value[..8].try_into().expect("8 bytes")),
            B256::from_slice(&value[8..]),
        )))
    }

    /// The ids matching `name` under `mode`, in id order, `limit` of them from `offset`.
    ///
    /// Exact, prefix and suffix seek a key range; `contains` cannot, and reads the names.
    pub fn search(
        &self,
        mode: Mode,
        name: &str,
        offset: u64,
        limit: u64,
    ) -> eyre::Result<Vec<u64>> {
        let lower = name.to_lowercase();
        let (family, seek) = match mode {
            Mode::Exact => (CF_NAME, name_prefix(&lower)),
            Mode::Prefix => (CF_NAME, lower.as_bytes().to_vec()),
            Mode::Suffix => (CF_REV, reversed(&lower).into_bytes()),
            Mode::Contains => return self.scan(&lower, offset, limit),
        };

        let mut ids = Vec::new();
        for row in self.db.iterator_cf(
            cf(&self.db, family),
            IteratorMode::From(&seek, Direction::Forward),
        ) {
            let (key, _) = row?;
            if !key.starts_with(&seek) {
                break;
            }
            ids.push(id_of(&key)?);
        }
        ids.sort_unstable();
        Ok(page(ids, offset, limit))
    }

    /// Every name in id order, stopping once the page is full.
    fn scan(&self, lower: &str, offset: u64, limit: u64) -> eyre::Result<Vec<u64>> {
        let mut ids = Vec::new();
        let mut skipped = 0;
        for row in self
            .db
            .iterator_cf(cf(&self.db, CF_ID), IteratorMode::Start)
        {
            if ids.len() as u64 >= limit {
                break;
            }
            let (key, name) = row?;
            if !String::from_utf8_lossy(&name).contains(lower) {
                continue;
            }
            match skipped < offset {
                true => skipped += 1,
                false => ids.push(id_of(&key)?),
            }
        }
        Ok(ids)
    }
}

fn cf<'a>(db: &'a DB, name: &str) -> &'a ColumnFamily {
    db.cf_handle(name).expect("cf created at open")
}

/// Every key a registry is written under, by family.
fn keys(lower: &str, id: u64) -> Vec<(&'static str, Vec<u8>)> {
    vec![
        (CF_NAME, name_key(lower, id)),
        (CF_REV, name_key(&reversed(lower), id)),
    ]
}

/// `name . 0`: the prefix of every key for that exact name.
fn name_prefix(lower: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(lower.len() + 1);
    key.extend_from_slice(lower.as_bytes());
    key.push(SEPARATOR);
    key
}

/// `name . 0 . id`.
fn name_key(lower: &str, id: u64) -> Vec<u8> {
    let mut key = name_prefix(lower);
    key.extend_from_slice(&id.to_be_bytes());
    key
}

/// Reversed by character, so a multi-byte name still matches by suffix.
fn reversed(lower: &str) -> String {
    lower.chars().rev().collect()
}

fn id_of(key: &[u8]) -> eyre::Result<u64> {
    let tail = key
        .len()
        .checked_sub(8)
        .ok_or_else(|| eyre::eyre!("index key: shorter than the id it ends with"))?;
    Ok(u64::from_be_bytes(key[tail..].try_into().expect("8 bytes")))
}

fn page(ids: Vec<u64>, offset: u64, limit: u64) -> Vec<u64> {
    ids.into_iter()
        .skip(usize::try_from(offset).unwrap_or(usize::MAX))
        .take(usize::try_from(limit).unwrap_or(usize::MAX))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(names: &[&str]) -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path().join("index")).unwrap();
        let rows: Vec<(u64, String)> = names
            .iter()
            .enumerate()
            .map(|(i, name)| (i as u64 + 1, (*name).to_string()))
            .collect();
        store.insert(&rows).unwrap();
        (dir, store)
    }

    const NAMES: [&str; 5] = [
        "Fund Alpha",
        "Alpha Fund",
        "alpha",
        "Beta Fund",
        "Gamma Alpha Fund",
    ];

    fn found(reader: &Reader, mode: Mode, name: &str) -> Vec<u64> {
        reader.search(mode, name, 0, 50).unwrap()
    }

    /// Including a name that is a prefix of another, which every mode gets wrong differently.
    #[test]
    fn every_mode_matches_case_insensitively_and_in_id_order() {
        let (_dir, store) = store(&NAMES);
        let reader = store.reader();

        assert_eq!(found(&reader, Mode::Exact, "ALPHA"), vec![3]);
        assert_eq!(found(&reader, Mode::Prefix, "alpha"), vec![2, 3]);
        assert_eq!(found(&reader, Mode::Suffix, "FUND"), vec![2, 4, 5]);
        assert_eq!(found(&reader, Mode::Contains, "alpha"), vec![1, 2, 3, 5]);
        assert!(found(&reader, Mode::Exact, "fund").is_empty());
    }

    #[test]
    fn offset_and_limit_cut_the_same_page_in_every_mode() {
        let (_dir, store) = store(&NAMES);
        let reader = store.reader();

        assert_eq!(
            reader.search(Mode::Contains, "alpha", 1, 2).unwrap(),
            vec![2, 3]
        );
        assert_eq!(reader.search(Mode::Prefix, "alpha", 1, 5).unwrap(), vec![3]);
        assert_eq!(
            reader.search(Mode::Suffix, "fund", 0, 2).unwrap(),
            vec![2, 4]
        );
        assert!(
            reader
                .search(Mode::Contains, "alpha", 99, 5)
                .unwrap()
                .is_empty()
        );
        // A zero limit is an empty page, not an unbounded read.
        assert!(
            reader
                .search(Mode::Contains, "alpha", 0, 0)
                .unwrap()
                .is_empty()
        );
        assert!(
            reader
                .search(Mode::Prefix, "alpha", 0, 0)
                .unwrap()
                .is_empty()
        );
    }

    /// The seek families too, or their keys still name an id that is gone.
    #[test]
    fn truncating_drops_a_registry_from_every_family() {
        let (_dir, mut store) = store(&NAMES);
        assert_eq!(store.last_id().unwrap(), 5);

        assert_eq!(store.truncate_above(2).unwrap(), 3);
        let reader = store.reader();
        assert_eq!(reader.last_id().unwrap(), 2);
        assert_eq!(found(&reader, Mode::Contains, "alpha"), vec![1, 2]);
        assert_eq!(found(&reader, Mode::Prefix, "alpha"), vec![2]);
        assert!(found(&reader, Mode::Suffix, "gamma alpha fund").is_empty());
    }

    /// A reorg can put a different registry under the same id.
    #[test]
    fn a_replaced_registry_keeps_none_of_its_old_keys() {
        let (_dir, mut store) = store(&NAMES);
        store.truncate_above(4).unwrap();
        store.insert(&[(5, "Delta Fund".to_string())]).unwrap();

        let reader = store.reader();
        assert!(found(&reader, Mode::Exact, "gamma alpha fund").is_empty());
        assert_eq!(found(&reader, Mode::Exact, "delta fund"), vec![5]);
        assert_eq!(found(&reader, Mode::Contains, "alpha"), vec![1, 2, 3]);
    }

    #[test]
    fn an_index_from_another_layout_is_rebuilt() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index");
        {
            let mut store = Store::open(&path).unwrap();
            store.insert(&[(1, "Fund Alpha".to_string())]).unwrap();
            store
                .db
                .put_cf(store.cf(CF_META), KEY_LAYOUT, b"anchoring-name-index/0")
                .unwrap();
        }

        let store = Store::open(&path).unwrap();
        assert_eq!(store.last_id().unwrap(), 0, "the old rows are gone");
        let stamp = store.db.get_cf(store.cf(CF_META), KEY_LAYOUT).unwrap();
        assert_eq!(stamp.as_deref(), Some(LAYOUT.as_bytes()));
    }

    #[test]
    fn an_index_from_another_chain_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let contract = Address::repeat_byte(0x0a);
        let store = Store::open(dir.path().join("index")).unwrap();
        store.bind(1, contract).unwrap();
        store.bind(1, contract).unwrap();

        assert!(store.bind(2, contract).is_err());
        assert!(store.bind(1, Address::repeat_byte(0x0b)).is_err());
    }

    #[test]
    fn an_index_reopens_with_its_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index");
        {
            let mut store = Store::open(&path).unwrap();
            store.insert(&[(1, "Fund Alpha".to_string())]).unwrap();
            store
                .record_tip(Tip::new(7, B256::repeat_byte(0x11)))
                .unwrap();
        }
        let store = Store::open(&path).unwrap();
        let reader = store.reader();
        assert_eq!(reader.last_id().unwrap(), 1);
        assert_eq!(
            reader.tip().unwrap(),
            Some(Tip::new(7, B256::repeat_byte(0x11)))
        );
        assert_eq!(found(&reader, Mode::Prefix, "fund"), vec![1]);
    }

    #[test]
    fn a_mode_parses_from_its_word_its_proto_name_or_its_number() {
        assert_eq!(Mode::parse("contains"), Some(Mode::Contains));
        assert_eq!(
            Mode::parse("REGISTRY_NAME_MATCH_MODE_PREFIX"),
            Some(Mode::Prefix)
        );
        assert_eq!(Mode::parse(" 3 "), Some(Mode::Suffix));
        assert_eq!(Mode::parse("0"), Some(Mode::Exact));
        assert_eq!(Mode::parse("substring"), None);
    }
}
