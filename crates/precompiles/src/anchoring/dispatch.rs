//! ABI dispatch for the [`Anchoring`] precompile.

use crate::{
    Precompile, anchoring::Anchoring, charge_input_cost, dispatch, mutate, mutate_void, view,
};
use alloy::primitives::Address;
use revm::precompile::PrecompileResult;
use tempo_contracts::precompiles::IAnchoring;

impl Precompile for Anchoring {
    fn call(&mut self, calldata: &[u8], msg_sender: Address) -> PrecompileResult {
        if let Some(err) = charge_input_cost(&mut self.storage, calldata) {
            return err;
        }

        dispatch!(
            calldata,
            |call| match call {
                IAnchoring::IAnchoringCalls {
                    // Writes. `mutate*` rejects STATICCALL; each handler starts with
                    // `ensure_eoa_write`, which rejects value-bearing and non-EOA calls.
                    addRegistry(call) => mutate(call, msg_sender, |s, c| self.add_registry(s, c)),
                    addRecord(call) => mutate(call, msg_sender, |s, c| self.add_record(s, c)),
                    updateRecordStatus(call) => mutate_void(call, msg_sender, |s, c| {
                        self.update_record_status(s, c)
                    }),
                    grantRole(call) => mutate_void(call, msg_sender, |s, c| self.grant_role(s, c)),
                    revokeRole(call) => mutate_void(call, msg_sender, |s, c| {
                        self.revoke_role(s, c)
                    }),
                    // Queries, unrestricted.
                    records(call) => view(call, |c| self.records(c)),
                    registries(call) => view(call, |c| self.registries(c)),
                }
            }
        )
    }
}
