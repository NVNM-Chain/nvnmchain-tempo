crate::sol! {
    /// Evidence that a validator signed conflicting consensus votes. `ValidatorConfigV2` answers
    /// at its own address, from the first block in which votes carry their signer's signature.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IEquivocation {
        /// The validator whose consensus key signed both votes in `evidence`, their round, and
        /// how many epochs ago it was.
        ///
        /// Reverts with the registry's `InvalidSignature` if the votes do not conflict or the key
        /// did not sign both on this chain, and with its `ValidatorNotFound` if the registry did
        /// not hold the key in that epoch.
        function equivocator(bytes calldata evidence)
            external
            view
            returns (address validator, uint64 epoch, uint64 viewNumber, uint64 epochsAgo);
    }
}
