//! The Execution Extension that keeps [`Store`] in step with the canonical chain.
//!
//! Three rules, each a place a hand-rolled ExEx goes wrong:
//!
//! 1. Read reorgs through `reverted_chain()`/`committed_chain()`, never by matching the
//!    three variants. `ChainReorged` carries *both* chains, and code that matches by hand
//!    tends to log it -- keeping the orphans and missing their replacements.
//! 2. Send `FinishedHeight` only after the write commits. It lets reth prune its WAL, so
//!    sending it early turns a retryable error into silent, permanent loss.
//! 3. Resume with a head ([`resume_head`]), or reth never backfills what was missed.

// `Typed2718` for `ty()`.
use alloy_consensus::transaction::TxHashRef as _;
use alloy_consensus::{BlockHeader as _, Typed2718 as _};
use alloy_primitives::{Address, TxKind};
use futures::{FutureExt as _, StreamExt};
use reth_ethereum::exex::{ExExContext, ExExEvent, ExExHead, ExExNotification};
use reth_ethereum::provider::BlockHashReader;
use reth_execution_types::Chain;
use reth_node_api::{FullNodeComponents, NodeTypes};
use tracing::{debug, info, warn};

use tempo_primitives::{TempoPrimitives, TempoTxEnvelope};

use crate::store::{IndexedTx, Plan, Position, Store, Tip};

/// Every address a transaction calls, in call order and without repeats.
///
/// A native tempo transaction is a *batch*, and `TempoTxEnvelope::kind()` answers with
/// the first call's target only. Indexing that alone meant a `to` filter on any later
/// call's address came back empty -- indistinguishable, to the caller, from there being
/// no such transactions. `calls()` gives the whole batch, and one call each for the
/// ordinary transaction types, so both shapes read the same way here.
///
/// A creation targets no existing address and so contributes nothing, which is what
/// leaves a pure creation with an empty list.
fn targets_of(tx: &TempoTxEnvelope) -> Vec<Address> {
    let mut targets = Vec::new();
    for (kind, _) in tx.calls() {
        if let TxKind::Call(to) = kind
            && !targets.contains(&to)
        {
            targets.push(to);
        }
    }
    targets
}

/// Who paid for `tx` — the sponsor where one signed, the sender otherwise.
///
/// Only a sponsored transaction costs a signature recovery: `fee_payer` returns the
/// sender outright when there is no fee-payer signature to recover from.
///
/// A recovery that fails leaves the column unset rather than failing the whole batch.
/// Execution already accepted the transaction, so this should not happen; if it does,
/// one unindexed column is a smaller loss than an indexer that stops.
fn fee_payer_of(tx: &TempoTxEnvelope, sender: Address) -> Option<Address> {
    match tx.fee_payer(sender) {
        Ok(payer) => Some(payer),
        Err(error) => {
            warn!(
                target: "tempo::indexer",
                %error,
                hash = ?tx.tx_hash(),
                "fee payer did not recover; leaving it unindexed",
            );
            None
        }
    }
}

/// Flatten a chain's blocks into index rows.
///
/// Concrete in [`TempoPrimitives`] rather than generic over `NodePrimitives`: the
/// generic form needs a pile of bounds to say "transactions have a hash and a type",
/// and tempo is only ever a tempo-primitives node.
fn rows_of(chain: &Chain<TempoPrimitives>) -> Vec<IndexedTx> {
    let mut rows = Vec::new();
    for block in chain.blocks_iter() {
        let block_num = block.num_hash().number;
        // Senders were recovered during execution, so pairing them off the block here
        // never re-derives a signature.
        for (tx_index, (sender, tx)) in block.transactions_with_sender().enumerate() {
            rows.push(IndexedTx {
                position: Position::new(block_num, tx_index as u32),
                hash: *tx.tx_hash(),
                from: *sender,
                to: targets_of(tx),
                tx_type: tx.ty(),
                fee_token: tx.fee_token(),
                fee_payer: fee_payer_of(tx, *sender),
            });
        }
    }
    rows
}

fn tip_of(chain: &Chain<TempoPrimitives>) -> Tip {
    let num_hash = chain.tip().num_hash();
    Tip::new(num_hash.number, num_hash.hash)
}

/// Translate one notification into a single atomic [`Store::apply`].
///
/// The only place a notification is read: [`run`] consumes this and never looks again,
/// so the reorg semantics stay testable without a node and cannot drift between readings.
pub fn plan(notification: &ExExNotification<TempoPrimitives>) -> Plan {
    // Revert from the first reverted block, so the whole orphaned range goes at once.
    let reverted = notification.reverted_chain();
    let committed = notification.committed_chain();

    let committed_tip = committed.as_deref().map(tip_of);

    // A commit ends at its own tip; a revert with nothing to put back ends at the
    // *parent* of what it dropped. Recording that parent is what keeps the stored tip
    // canonical -- and reth errors on a resume head whose hash it cannot find.
    let tip = committed_tip.or_else(|| {
        let first = reverted.as_deref()?.first();
        // Genesis is never reverted; `checked_sub` rather than assert so a malformed
        // notification cannot panic the node.
        Some(Tip::new(
            first.number().checked_sub(1)?,
            first.parent_hash(),
        ))
    });

    Plan {
        revert_from: reverted.as_deref().map(|old| *old.range().start()),
        rows: committed.as_deref().map(rows_of).unwrap_or_default(),
        tip,
        committed: committed_tip,
    }
}

/// The head to resume from: the indexed tip, or genesis when the index is empty.
///
/// Genesis rather than no head at all. Head-less, reth delivers only future blocks and
/// never backfills, so an empty or lagging index stays that way -- silently, since a
/// short answer looks exactly like a correct one.
fn resume_head<Node>(ctx: &ExExContext<Node>, store: &Store) -> eyre::Result<ExExHead>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = TempoPrimitives>>,
{
    let block = match store.indexed_tip()? {
        Some(tip) => (tip.block_num, tip.hash).into(),
        None => {
            let genesis = ctx
                .provider()
                .block_hash(0)?
                .ok_or_else(|| eyre::eyre!("genesis block hash is missing from the database"))?;
            (0u64, genesis).into()
        }
    };
    Ok(ExExHead { block })
}

/// Run the indexer ExEx until the node shuts down.
pub async fn run<Node>(mut ctx: ExExContext<Node>, mut store: Store) -> eyre::Result<()>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = TempoPrimitives>>,
{
    // A head is what makes reth backfill the gap between the index and the node: the
    // difference between an index that recovers from being deleted, lagging, or switched
    // on mid-chain, and one that silently never does.
    let head = resume_head(&ctx, &store)?;
    info!(
        target: "tempo::indexer",
        number = head.block.number,
        hash = ?head.block.hash,
        "indexer ExEx started; resuming from",
    );
    ctx.set_notifications_with_head(head);

    // How many queued notifications may fold into one write. At sub-second block
    // times the chain outruns a write-per-block loop, so everything already queued
    // merges into the same atomic `apply` — one batch write and one acknowledgement
    // instead of one of each per block. The cap only bounds memory while far
    // behind; caught up, the queue is empty and batches are naturally size one.
    const MAX_BATCH: usize = 256;

    let mut ended = false;
    while !ended {
        let Some(notification) = ctx.notifications.next().await else {
            break;
        };
        let mut merged = plan(&notification?);
        let mut batched = 1;

        while batched < MAX_BATCH {
            // Only what is already queued: `now_or_never` never waits, so folding
            // adds no latency when the indexer is keeping up.
            match ctx.notifications.next().now_or_never() {
                Some(Some(notification)) => {
                    merged.merge(plan(&notification?));
                    batched += 1;
                }
                Some(None) => {
                    // Stream ended mid-batch; write what we have, then stop —
                    // without polling a finished stream again.
                    ended = true;
                    break;
                }
                None => break,
            }
        }

        // Write first; only then acknowledge. See rule 2 in the module docs.
        store.apply(&merged)?;

        if let Some(from) = merged.revert_from {
            debug!(target: "tempo::indexer", from, "reverted index");
        }
        if let Some(committed) = merged.committed {
            debug!(
                target: "tempo::indexer",
                block = committed.block_num,
                transactions = merged.rows.len(),
                batched,
                "indexed committed chain",
            );
            ctx.events.send(ExExEvent::FinishedHeight(
                (committed.block_num, committed.hash).into(),
            ))?;
        }
    }

    info!(target: "tempo::indexer", "indexer ExEx stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use alloy_consensus::Header;
    use alloy_consensus::{Signed, TxEip1559};
    use alloy_primitives::{Address, Signature, TxKind, U256};
    use reth_execution_types::Chain;
    use reth_primitives_traits::RecoveredBlock;
    use tempo_primitives::transaction::tempo_transaction::{Call, TempoTransaction};
    use tempo_primitives::transaction::tt_signature::{PrimitiveSignature, TempoSignature};
    use tempo_primitives::transaction::tt_signed::AASigned;
    use tempo_primitives::{Block, BlockBody, TempoHeader, TempoTxEnvelope};

    use super::*;
    use crate::store::{Filter, Order, Store};

    fn eip1559(nonce: u64) -> TempoTxEnvelope {
        let tx = TxEip1559 {
            chain_id: 1337,
            nonce,
            to: TxKind::Call(Address::from([0xbb; 20])),
            value: U256::ZERO,
            ..Default::default()
        };
        TempoTxEnvelope::Eip1559(Signed::new_unhashed(tx, Signature::test_signature()))
    }

    fn call_to(target: u8) -> Call {
        Call {
            to: TxKind::Call(Address::from([target; 20])),
            value: U256::ZERO,
            input: Default::default(),
        }
    }

    /// A block of `transactions` at `number`, all sent by `sender`.
    fn block(number: u64, sender: u8, transactions: Vec<TempoTxEnvelope>) -> RecoveredBlock<Block> {
        let senders = vec![Address::from([sender; 20]); transactions.len()];
        let block = Block {
            header: TempoHeader {
                inner: Header {
                    number,
                    ..Default::default()
                },
                ..Default::default()
            },
            body: BlockBody {
                transactions,
                ..Default::default()
            },
        };
        RecoveredBlock::new_unhashed(block, senders)
    }

    fn chain(blocks: Vec<RecoveredBlock<Block>>) -> Arc<Chain<TempoPrimitives>> {
        Arc::new(Chain::new(blocks, Default::default(), Default::default()))
    }

    /// Apply a plan the way [`run`] does, so the tests exercise that same shuffle.
    fn apply(store: &mut Store, plan: Plan) {
        store.apply(&plan).unwrap();
    }

    /// A throwaway on-disk store; RocksDB has no in-memory mode.
    fn temp_store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path().join("indexer")).unwrap();
        (dir, store)
    }

    #[test]
    fn commit_indexes_every_transaction() {
        let notification = ExExNotification::ChainCommitted {
            new: chain(vec![
                block(1, 0xaa, vec![eip1559(1)]),
                block(2, 0xaa, vec![eip1559(2)]),
            ]),
        };
        let plan = plan(&notification);
        assert_eq!(plan.revert_from, None);
        assert_eq!(plan.rows.len(), 2);
        assert_eq!(plan.tip.unwrap().block_num, 2);
        assert_eq!(
            plan.committed, plan.tip,
            "a commit acknowledges its own tip"
        );
        assert_eq!(plan.rows[0].position, Position::new(1, 0));
        assert_eq!(plan.rows[0].from, Address::from([0xaa; 20]));
    }

    /// An AA transaction carrying `calls`, signed well enough to be indexed.
    fn aa(calls: Vec<Call>) -> TempoTxEnvelope {
        let tx = TempoTransaction {
            chain_id: 1337,
            calls,
            ..Default::default()
        };
        let signature =
            TempoSignature::Primitive(PrimitiveSignature::Secp256k1(Signature::test_signature()));
        TempoTxEnvelope::AA(AASigned::new_unhashed(tx, signature))
    }

    #[test]
    fn a_batched_transaction_is_indexed_under_every_call() {
        // A native transaction is a batch. Indexing only `kind()` -- the first call --
        // meant a `to` filter on any later target came back empty, which a caller
        // cannot tell apart from there being no such transactions.
        let notification = ExExNotification::ChainCommitted {
            new: chain(vec![block(
                1,
                0xaa,
                vec![aa(vec![call_to(0xc1), call_to(0xc2)])],
            )]),
        };
        let rows = plan(&notification).rows;

        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].to,
            vec![Address::from([0xc1; 20]), Address::from([0xc2; 20])],
            "every call's target belongs to the transaction",
        );
    }

    #[test]
    fn a_repeated_call_target_is_listed_once() {
        let notification = ExExNotification::ChainCommitted {
            new: chain(vec![block(
                1,
                0xaa,
                vec![aa(vec![call_to(0xc1), call_to(0xc1)])],
            )]),
        };
        assert_eq!(
            plan(&notification).rows[0].to,
            vec![Address::from([0xc1; 20])],
        );
    }

    #[test]
    fn an_ordinary_transaction_has_one_target() {
        // `calls()` reads the same for both shapes, so the single-call types come
        // through as a one-element list rather than needing their own path.
        let notification = ExExNotification::ChainCommitted {
            new: chain(vec![block(1, 0xaa, vec![eip1559(1)])]),
        };
        assert_eq!(
            plan(&notification).rows[0].to,
            vec![Address::from([0xbb; 20])],
        );
    }

    #[test]
    fn a_creation_targets_no_address() {
        let notification = ExExNotification::ChainCommitted {
            new: chain(vec![block(
                1,
                0xaa,
                vec![aa(vec![Call {
                    to: TxKind::Create,
                    value: U256::ZERO,
                    input: Default::default(),
                }])],
            )]),
        };
        assert!(plan(&notification).rows[0].to.is_empty());
    }

    #[test]
    fn the_sender_pays_unless_someone_signed_for_it() {
        // "Who paid" is recorded for every transaction, not only sponsored ones: a
        // column that answered for some and stayed empty for the rest could not be
        // filtered on honestly.
        let notification = ExExNotification::ChainCommitted {
            new: chain(vec![block(
                1,
                0xaa,
                vec![eip1559(1), aa(vec![call_to(0xc1)])],
            )]),
        };
        let rows = plan(&notification).rows;
        for row in &rows {
            assert_eq!(
                row.fee_payer,
                Some(Address::from([0xaa; 20])),
                "unsponsored, the sender paid",
            );
        }
        assert!(
            rows.iter().all(|row| row.fee_token.is_none()),
            "no fee token was named, so gas was paid in the native currency",
        );
    }

    #[test]
    fn revert_plans_a_delete_and_no_insert() {
        let old = chain(vec![
            block(2, 0xaa, vec![eip1559(2)]),
            block(3, 0xaa, vec![eip1559(3)]),
        ]);
        let parent_of_dropped = old.first().parent_hash();
        let notification = ExExNotification::ChainReverted { old: old.clone() };

        let plan = plan(&notification);
        assert_eq!(
            plan.revert_from,
            Some(2),
            "must drop from the first reverted block"
        );
        assert!(plan.rows.is_empty());
        assert_eq!(
            plan.committed, None,
            "a pure revert must acknowledge no height: FinishedHeight lets reth prune",
        );

        // The tip moves *back* to the parent of the dropped range rather than staying
        // where it was. Leaving it at 3 would name a block that is no longer canonical,
        // and reth resolves a resume head by hash -- it would not find it, and errors.
        let tip = plan.tip.expect("a revert still leaves a resumable tip");
        assert_eq!(tip.block_num, 1);
        assert_eq!(tip.hash, parent_of_dropped);
    }

    #[test]
    fn reorg_both_reverts_and_commits() {
        // The bug this exists to prevent: matching the three notification variants by
        // hand tends to log a reorg and do neither half, keeping the orphans and
        // missing their replacements.
        let notification = ExExNotification::ChainReorged {
            old: chain(vec![block(2, 0xaa, vec![eip1559(2)])]),
            new: chain(vec![
                block(2, 0xbb, vec![eip1559(9)]),
                block(3, 0xbb, vec![eip1559(10)]),
            ]),
        };
        let plan = plan(&notification);

        assert_eq!(
            plan.revert_from,
            Some(2),
            "the orphaned range must be dropped"
        );
        assert_eq!(plan.rows.len(), 2, "the replacement blocks must be indexed");
        assert_eq!(plan.tip.unwrap().block_num, 3);
        assert_eq!(plan.committed, plan.tip, "and acknowledges that same tip");
        assert!(
            plan.rows
                .iter()
                .all(|row| row.from == Address::from([0xbb; 20]))
        );
    }

    #[test]
    fn a_reorg_applied_to_the_store_leaves_no_orphans() {
        let (_dir, mut store) = temp_store();
        apply(
            &mut store,
            plan(&ExExNotification::ChainCommitted {
                new: chain(vec![block(1, 0xaa, vec![eip1559(1)])]),
            }),
        );
        let orphaned = store
            .reader()
            .query(&Filter::default(), None, Order::Ascending, 10)
            .unwrap();
        assert_eq!(orphaned.len(), 1);
        assert_eq!(orphaned[0].position.block_num, 1);

        apply(
            &mut store,
            plan(&ExExNotification::ChainReorged {
                old: chain(vec![block(1, 0xaa, vec![eip1559(1)])]),
                new: chain(vec![block(1, 0xbb, vec![eip1559(2)])]),
            }),
        );

        let canonical = store
            .reader()
            .query(&Filter::default(), None, Order::Ascending, 10)
            .unwrap();
        assert_eq!(canonical.len(), 1, "the orphan must not survive its reorg");
        assert_eq!(canonical[0].from, Address::from([0xbb; 20]));
    }
}
