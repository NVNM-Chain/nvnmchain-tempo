//! The Execution Extension that keeps the index level with the contract.
//!
//! Each round reads the registry count and the missing names out of state, never out of
//! blocks: one path serves the first backfill, a restart, a new block and a reorg, and the
//! dump-loaded corpus — which emitted no log — indexes like any other. No head is set, so
//! reth backfills nothing.

use alloy_consensus::BlockHeader as _;
use alloy_primitives::Address;
use futures::StreamExt as _;
use reth_ethereum::exex::{ExExContext, ExExEvent, ExExNotification};
use reth_node_api::{FullNodeComponents, NodeTypes};
use reth_storage_api::StateProviderFactory;
use tempo_primitives::TempoPrimitives;
use tracing::{debug, info, warn};

use crate::{
    state::{self, Storage, Words},
    store::{Store, Tip},
};

/// Registries read and written per batch; bounds what the first backfill holds in memory.
const CHUNK: u64 = 1_000;

/// Bring the index level with `words`; answers with how many registries that added.
///
/// `floor` is where a reorg cut the chain back to. Truncating to it first is what makes a
/// registry replaced under the same id be read again.
pub fn reconcile(
    words: &impl Words,
    store: &mut Store,
    floor: Option<u64>,
    tip: Option<Tip>,
) -> eyre::Result<u64> {
    if let Some(floor) = floor {
        store.truncate_above(floor)?;
    }

    let count = state::registry_count(words)?;
    store.truncate_above(count)?;

    let mut last = store.last_id()?;
    let added = count.saturating_sub(last);
    while last < count {
        let upto = count.min(last + CHUNK);
        let mut rows = Vec::with_capacity((upto - last) as usize);
        for id in last + 1..=upto {
            rows.push((id, state::registry_name(words, id)?));
        }
        store.insert(&rows)?;
        last = upto;
    }

    if let Some(tip) = tip {
        store.record_tip(tip)?;
    }
    Ok(added)
}

/// Run the index until the node shuts down.
pub async fn run<Node>(
    mut ctx: ExExContext<Node>,
    mut store: Store,
    contract: Address,
) -> eyre::Result<()>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = TempoPrimitives>>,
{
    let latest = ctx.provider().latest()?;
    let added = reconcile(&Storage::new(&*latest, contract), &mut store, None, None)?;
    // A state provider pins a read transaction; not one to hold for the node's lifetime.
    drop(latest);
    info!(
        target: "tempo::anchoring_index",
        added,
        last_id = store.last_id()?,
        "anchoring name index caught up with the contract",
    );

    while let Some(notification) = ctx.notifications.next().await {
        let notification = notification?;
        match follow(&ctx, &mut store, contract, &notification) {
            Ok(0) => {}
            Ok(added) => debug!(target: "tempo::anchoring_index", added, "indexed new registries"),
            // The next block reconciles from state again, so this costs freshness, not rows.
            Err(error) => {
                warn!(target: "tempo::anchoring_index", %error, "anchoring name index did not follow this block");
                continue;
            }
        }

        if let Some(committed) = notification.committed_chain() {
            ctx.events
                .send(ExExEvent::FinishedHeight(committed.tip().num_hash()))?;
        }
    }

    info!(target: "tempo::anchoring_index", "anchoring name index stopped");
    Ok(())
}

/// Reconcile against the state one notification leaves canonical.
fn follow<Node>(
    ctx: &ExExContext<Node>,
    store: &mut Store,
    contract: Address,
    notification: &ExExNotification<TempoPrimitives>,
) -> eyre::Result<u64>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = TempoPrimitives>>,
{
    let reverted = notification.reverted_chain();
    let committed = notification.committed_chain();

    let floor = match reverted.as_deref() {
        Some(old) => {
            let before = ctx
                .provider()
                .state_by_block_hash(old.first().parent_hash())?;
            Some(state::registry_count(&Storage::new(&*before, contract))?)
        }
        None => None,
    };

    // The committed tip, or the parent of a revert that puts nothing back.
    let (number, hash) = match committed.as_deref() {
        Some(new) => {
            let tip = new.tip().num_hash();
            (tip.number, tip.hash)
        }
        None => {
            let first = reverted
                .as_deref()
                .ok_or_else(|| eyre::eyre!("a notification that neither commits nor reverts"))?
                .first();
            (first.number().saturating_sub(1), first.parent_hash())
        }
    };

    let state = ctx.provider().state_by_block_hash(hash)?;
    reconcile(
        &Storage::new(&*state, contract),
        store,
        floor,
        Some(Tip::new(number, hash)),
    )
}

#[cfg(test)]
mod tests {
    use crate::{
        state::fixture::Slots,
        store::{Mode, Store},
    };

    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("index")).unwrap();
        (dir, store)
    }

    /// The contract after `names` were added, oldest first.
    fn contract(names: &[&str]) -> Slots {
        let mut slots = Slots::default();
        slots.count(names.len() as u64);
        for (i, name) in names.iter().enumerate() {
            slots.registry(i as u64 + 1, name, "");
        }
        slots
    }

    #[test]
    fn a_round_adds_only_what_the_index_is_missing() {
        let (_dir, mut store) = store();

        assert_eq!(
            reconcile(
                &contract(&["Fund Alpha", "Beta Fund"]),
                &mut store,
                None,
                None
            )
            .unwrap(),
            2
        );
        assert_eq!(
            reconcile(
                &contract(&["Fund Alpha", "Beta Fund", "Gamma Fund"]),
                &mut store,
                None,
                None,
            )
            .unwrap(),
            1
        );
        assert_eq!(store.last_id().unwrap(), 3);
        assert_eq!(
            store.reader().search(Mode::Suffix, "fund", 0, 50).unwrap(),
            vec![2, 3]
        );
    }

    #[test]
    fn a_backfill_longer_than_a_batch_lands_whole() {
        let (_dir, mut store) = store();
        let names: Vec<String> = (1..=CHUNK + 5).map(|id| format!("fund {id}")).collect();
        let names: Vec<&str> = names.iter().map(String::as_str).collect();

        assert_eq!(
            reconcile(&contract(&names), &mut store, None, None).unwrap(),
            CHUNK + 5
        );
        assert_eq!(store.last_id().unwrap(), CHUNK + 5);
    }

    /// Rows above the count go, with no floor passed.
    #[test]
    fn a_round_drops_registries_the_chain_gave_back() {
        let (_dir, mut store) = store();
        reconcile(
            &contract(&["Fund Alpha", "Beta Fund"]),
            &mut store,
            None,
            None,
        )
        .unwrap();

        reconcile(&contract(&["Fund Alpha"]), &mut store, None, None).unwrap();
        assert_eq!(store.last_id().unwrap(), 1);
        assert!(
            store
                .reader()
                .search(Mode::Exact, "beta fund", 0, 50)
                .unwrap()
                .is_empty()
        );
    }

    /// The reorg the count alone cannot see: the same id, a different registry.
    #[test]
    fn a_floor_makes_a_replaced_registry_be_read_again() {
        let (_dir, mut store) = store();
        reconcile(
            &contract(&["Fund Alpha", "Beta Fund"]),
            &mut store,
            None,
            None,
        )
        .unwrap();

        let replaced = contract(&["Fund Alpha", "Delta Fund"]);
        reconcile(&replaced, &mut store, Some(1), None).unwrap();

        let reader = store.reader();
        assert!(
            reader
                .search(Mode::Exact, "beta fund", 0, 50)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            reader.search(Mode::Exact, "delta fund", 0, 50).unwrap(),
            vec![2]
        );
    }
}
