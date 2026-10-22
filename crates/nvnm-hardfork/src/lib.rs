//! NVNM's hardfork lane: `N1`, `N2`, … scheduled by the genesis' `n1Time`, … apart from Tempo's
//! `T*` forks. `cargo x add-hardfork --lane nvnm --hardfork N1` adds the next fork.

#![cfg_attr(not(feature = "std"), no_std)]

use alloy_hardforks::hardfork;
use tempo_hardfork::TempoHardfork;

/// Defines [`NvnmHardfork`] the way `tempo_hardfork!` defines `TempoHardfork`: `is_<fork>()`
/// helpers, [`nvnm_post_genesis_hardforks!`] for per-fork code downstream, and tests.
macro_rules! nvnm_hardfork {
    (
        $(#[$enum_meta:meta])*
        NvnmHardfork {
            $(#[$baseline_meta:meta])* Baseline,
            $( $(#[$meta:meta])* $variant:ident ),* $(,)?
        }
    ) => {
        hardfork!(
            $(#[$enum_meta])*
            NvnmHardfork {
                $(#[$baseline_meta])* Baseline,
                $( $(#[$meta])* $variant ),*
            }
        );

        impl NvnmHardfork {
            paste::paste! {
                $(
                    #[doc = concat!("Returns true if this fork is ", stringify!($variant), " or later.")]
                    pub const fn [<is_ $variant:lower>](&self) -> bool {
                        *self as u8 >= Self::$variant as u8
                    }
                )*

                /// The genesis key holding this fork's activation time; `Baseline` has none.
                pub const fn genesis_key(&self) -> Option<&'static str> {
                    match self {
                        Self::Baseline => None,
                        $(Self::$variant => Some(concat!(stringify!([<$variant:lower>]), "Time")),)*
                    }
                }
            }
        }

        /// Invokes the given macro with every NVNM fork after `Baseline`.
        #[macro_export]
        macro_rules! nvnm_post_genesis_hardforks {
            ($callback:ident) => {
                $callback! { $($variant),* }
            };
        }

        #[cfg(test)]
        mod generated_tests {
            use super::*;

            #[test]
            fn names_are_the_variants() {
                assert_eq!(NvnmHardfork::Baseline.name(), "Baseline");
                $(assert_eq!(NvnmHardfork::$variant.name(), stringify!($variant));)*
            }

            paste::paste! {
                $(
                    #[test]
                    fn [<is_ $variant:lower _holds_from_its_fork_on>]() {
                        for fork in NvnmHardfork::VARIANTS {
                            assert_eq!(fork.[<is_ $variant:lower>](), *fork >= NvnmHardfork::$variant);
                        }
                    }
                )*
            }
        }
    };
}

nvnm_hardfork!(
    /// NVNM's own forks; each implies no [`TempoHardfork`].
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Default)]
    NvnmHardfork {
        /// No lane fork; `Genesis` is taken by [`TempoHardfork`].
        #[default]
        Baseline,
    }
);

impl NvnmHardfork {
    /// Returns the position of this fork in [`Self::VARIANTS`].
    pub const fn variant_index(&self) -> u8 {
        *self as u8
    }

    /// Returns the fork at the given [`Self::VARIANTS`] position, `None` past the end.
    pub const fn from_variant_index(index: u8) -> Option<Self> {
        if (index as usize) < Self::VARIANTS.len() {
            Some(Self::VARIANTS[index as usize])
        } else {
            None
        }
    }
}

/// The Tempo fork and the NVNM fork active at one block.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Forks {
    pub tempo: TempoHardfork,
    pub nvnm: NvnmHardfork,
}

/// A Tempo fork with the lane at `Baseline`.
impl From<TempoHardfork> for Forks {
    fn from(tempo: TempoHardfork) -> Self {
        Self {
            tempo,
            nvnm: NvnmHardfork::Baseline,
        }
    }
}

impl Forks {
    /// Both variant indices in one word, for an atomic.
    pub fn packed(&self) -> u16 {
        (u16::from(self.tempo.variant_index()) << 8) | u16::from(self.nvnm.variant_index())
    }

    /// Reverses [`Self::packed`]; `None` if either index is past its list.
    pub const fn from_packed(packed: u16) -> Option<Self> {
        let [tempo, nvnm] = packed.to_be_bytes();
        match (
            TempoHardfork::from_variant_index(tempo),
            NvnmHardfork::from_variant_index(nvnm),
        ) {
            (Some(tempo), Some(nvnm)) => Some(Self { tempo, nvnm }),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_has_no_genesis_key() {
        assert_eq!(NvnmHardfork::Baseline.genesis_key(), None);
        for fork in &NvnmHardfork::VARIANTS[1..] {
            let key = format!("{}Time", fork.name().to_lowercase());
            assert_eq!(fork.genesis_key(), Some(key.as_str()));
        }
    }

    #[test]
    fn packed_forks_round_trip() {
        for &tempo in TempoHardfork::VARIANTS {
            for &nvnm in NvnmHardfork::VARIANTS {
                let forks = Forks { tempo, nvnm };
                assert_eq!(Forks::from_packed(forks.packed()), Some(forks));
            }
        }
        assert_eq!(Forks::from_packed(u16::MAX), None);
    }

    #[test]
    #[cfg(feature = "serde")]
    fn serde_round_trips() {
        for fork in NvnmHardfork::VARIANTS {
            let json = serde_json::to_string(fork).unwrap();
            assert_eq!(serde_json::from_str::<NvnmHardfork>(&json).unwrap(), *fork);
        }
    }
}
