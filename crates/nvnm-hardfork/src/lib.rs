//! NVNM's hardfork lane: `N1`, `N2`, … scheduled by the genesis' `n1Time`, … apart from Tempo's
//! `T*` forks. A fork is added by hand: its variant here, its `n<k>_time` field in
//! `TempoGenesisInfo` and its `--n<k>-time` flag in `generate-genesis`; a variant without its
//! field does not compile.

#![cfg_attr(not(feature = "std"), no_std)]

use alloy_hardforks::hardfork;

/// Defines [`NvnmHardfork`] the way `tempo_hardfork!` defines `TempoHardfork`: `is_<fork>()`
/// helpers and [`nvnm_post_genesis_hardforks!`] for per-fork code downstream.
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
    };
}

nvnm_hardfork!(
    /// NVNM's own forks; each implies no Tempo fork.
    #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
    #[derive(Default)]
    NvnmHardfork {
        /// No lane fork; `Genesis` names Tempo's.
        #[default]
        Baseline,
    }
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn baseline_has_no_genesis_key() {
        for &fork in NvnmHardfork::VARIANTS {
            let key = (fork != NvnmHardfork::Baseline)
                .then(|| format!("{}Time", fork.name().to_lowercase()));
            assert_eq!(fork.genesis_key(), key.as_deref());
        }
    }
}
