//! Registries read straight out of the contract's storage. `layout/anchoring.json` in the
//! contracts repo pins the slots, and the dump writer and explorer read them the same way.

use alloy_primitives::{Address, B256, U256, keccak256};
use reth_storage_api::StateProvider;
use serde::{Deserialize, Serialize};

/// `_registryCount`, packed at byte 20 of slot 3.
const COUNT_SLOT: u64 = 3;
const COUNT_SHIFT: usize = 20 * 8;

/// `_registries`, a `mapping(uint64 => Registry)`.
const REGISTRIES_SLOT: u64 = 4;

/// `Registry`'s members after `id`, which sits at the base slot.
const NAME: u64 = 1;
const DESCRIPTION: u64 = 2;
const CREATOR: u64 = 3;
const CREATED_AT: u64 = 4;
const METADATA: u64 = 5;

/// Longer is a misread length word, not a field.
const MAX_STRING: usize = 1 << 20;

/// `IAnchoring.Registry`, field for field.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Registry {
    pub id: u64,
    pub name: String,
    pub description: String,
    pub creator: String,
    pub created_at: String,
    pub metadata: String,
}

/// One storage word, however state is reached; tests use a map of slots.
pub trait Words {
    fn word(&self, slot: U256) -> eyre::Result<U256>;
}

/// The contract's storage in a state the node holds.
pub struct Storage<'a> {
    state: &'a dyn StateProvider,
    contract: Address,
}

impl<'a> Storage<'a> {
    pub fn new(state: &'a dyn StateProvider, contract: Address) -> Self {
        Self { state, contract }
    }
}

impl Words for Storage<'_> {
    fn word(&self, slot: U256) -> eyre::Result<U256> {
        Ok(self
            .state
            .storage(self.contract, B256::from(slot.to_be_bytes::<32>()))?
            .unwrap_or_default())
    }
}

/// How many registries the contract holds; ids run from 1 to this without holes.
pub fn registry_count(words: &impl Words) -> eyre::Result<u64> {
    let word = words.word(U256::from(COUNT_SLOT))?;
    Ok(((word >> COUNT_SHIFT) & U256::from(u64::MAX)).to::<u64>())
}

/// The name of registry `id`, all the index is built from.
pub fn registry_name(words: &impl Words, id: u64) -> eyre::Result<String> {
    string(words, base(id) + U256::from(NAME))
}

/// Registry `id` in full.
pub fn registry(words: &impl Words, id: u64) -> eyre::Result<Registry> {
    let base = base(id);
    Ok(Registry {
        id,
        name: string(words, base + U256::from(NAME))?,
        description: string(words, base + U256::from(DESCRIPTION))?,
        creator: string(words, base + U256::from(CREATOR))?,
        created_at: string(words, base + U256::from(CREATED_AT))?,
        metadata: string(words, base + U256::from(METADATA))?,
    })
}

/// `keccak256(key . slot)`, the key padded to a word.
fn base(id: u64) -> U256 {
    let mut input = [0u8; 64];
    input[24..32].copy_from_slice(&id.to_be_bytes());
    input[32..].copy_from_slice(&U256::from(REGISTRIES_SLOT).to_be_bytes::<32>());
    U256::from_be_bytes(keccak256(input).0)
}

/// A Solidity `string`: in the word under 32 bytes, else at `keccak256(slot)` with the word
/// holding twice its length; the low bit says which.
fn string(words: &impl Words, slot: U256) -> eyre::Result<String> {
    let word = words.word(slot)?;
    let bytes = word.to_be_bytes::<32>();
    if bytes[31] & 1 == 0 {
        let len = (bytes[31] >> 1) as usize;
        return Ok(String::from_utf8_lossy(&bytes[..len]).into_owned());
    }

    let len = word >> 1usize;
    if len > U256::from(MAX_STRING) {
        eyre::bail!("string at slot {slot} claims {len} bytes");
    }
    let len = len.to::<usize>();

    let mut out = Vec::with_capacity(len);
    let mut at = U256::from_be_bytes(keccak256(slot.to_be_bytes::<32>()).0);
    while out.len() < len {
        out.extend_from_slice(&words.word(at)?.to_be_bytes::<32>());
        at += U256::from(1);
    }
    out.truncate(len);
    Ok(String::from_utf8_lossy(&out).into_owned())
}

#[cfg(test)]
pub(crate) mod fixture {
    use std::collections::HashMap;

    use super::*;

    /// Storage as the contract writes it.
    #[derive(Default)]
    pub(crate) struct Slots(pub(crate) HashMap<U256, U256>);

    impl Words for Slots {
        fn word(&self, slot: U256) -> eyre::Result<U256> {
            Ok(self.0.get(&slot).copied().unwrap_or_default())
        }
    }

    impl Slots {
        pub(crate) fn count(&mut self, count: u64) -> &mut Self {
            self.0
                .insert(U256::from(COUNT_SLOT), U256::from(count) << COUNT_SHIFT);
            self
        }

        /// `value` at `slot`, short or long as Solidity would store it.
        pub(crate) fn string(&mut self, slot: U256, value: &str) -> &mut Self {
            let bytes = value.as_bytes();
            if bytes.len() < 32 {
                let mut word = [0u8; 32];
                word[..bytes.len()].copy_from_slice(bytes);
                word[31] = (bytes.len() as u8) << 1;
                self.0.insert(slot, U256::from_be_bytes(word));
                return self;
            }
            self.0.insert(slot, U256::from(bytes.len() * 2 + 1));
            let base = U256::from_be_bytes(keccak256(slot.to_be_bytes::<32>()).0);
            for (i, chunk) in bytes.chunks(32).enumerate() {
                let mut word = [0u8; 32];
                word[..chunk.len()].copy_from_slice(chunk);
                self.0
                    .insert(base + U256::from(i), U256::from_be_bytes(word));
            }
            self
        }

        pub(crate) fn registry(&mut self, id: u64, name: &str, metadata: &str) -> &mut Self {
            let base = base(id);
            self.0.insert(base, U256::from(id));
            self.string(base + U256::from(NAME), name);
            self.string(base + U256::from(METADATA), metadata)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{fixture::Slots, *};

    /// The count shares its slot with an address.
    #[test]
    fn count_is_read_out_of_the_word_it_is_packed_into() {
        // `_formerAdmin` occupies the low 20 bytes of the same slot.
        let admin = U256::from_be_slice(&[0x11; 20]);
        let mut slots = Slots::default();
        slots.0.insert(
            U256::from(COUNT_SLOT),
            (U256::from(2_182u64) << COUNT_SHIFT) | admin,
        );
        assert_eq!(registry_count(&slots).unwrap(), 2_182);
    }

    /// A chain with no registries has no slot written.
    #[test]
    fn an_unwritten_count_is_zero() {
        assert_eq!(registry_count(&Slots::default()).unwrap(), 0);
    }

    /// Both string encodings.
    #[test]
    fn a_registry_reads_back_short_and_long_strings() {
        let long = "m".repeat(100);
        let mut slots = Slots::default();
        slots.registry(7, "Fund Alpha", &long);

        let registry = registry(&slots, 7).unwrap();
        assert_eq!(registry.id, 7);
        assert_eq!(registry.name, "Fund Alpha");
        assert_eq!(registry.metadata, long);
        // Fields the fixture never wrote are empty, not an error.
        assert_eq!(registry.creator, "");

        assert_eq!(registry_name(&slots, 7).unwrap(), "Fund Alpha");
    }

    /// The boundary the low bit decides.
    #[test]
    fn a_name_of_exactly_thirty_two_bytes_reads_back() {
        let name = "n".repeat(32);
        let mut slots = Slots::default();
        slots.registry(1, &name, "");
        assert_eq!(registry_name(&slots, 1).unwrap(), name);
    }

    /// Refused rather than allocated for.
    #[test]
    fn an_absurd_length_is_refused() {
        let mut slots = Slots::default();
        slots
            .0
            .insert(base(1) + U256::from(NAME), U256::from(u64::MAX));
        assert!(registry_name(&slots, 1).is_err());
    }
}
