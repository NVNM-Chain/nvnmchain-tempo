crate::sol! {
    /// Attributable consensus votes. `ValidatorConfigV2` answers at its own address: the vote
    /// keys from T12 where the genesis schedules such votes, and the evidence check from the
    /// first block in which votes carry their signer's signature.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IEquivocation {
        /// The validator at `index` has registered `key` for the validator key `publicKey`.
        event VoteKeySet(uint64 indexed index, bytes32 indexed publicKey, bytes key);

        /// Registers, once, the BLS key the validator at `idx` signs its consensus votes with: a
        /// compressed G2 point and its proof of possession for this validator on this chain. Only
        /// the validator's own address may send it. Until an epoch starts with the key, the
        /// validator's votes do not count.
        ///
        /// Reverts with the registry's `PublicKeyAlreadyExists` if the validator has a vote key or
        /// the key is another's, `InvalidPublicKey` if `key` is not one, and `InvalidSignature`
        /// if `proof` is not its proof.
        function setVoteKey(uint64 idx, bytes calldata key, bytes calldata proof) external;

        /// The vote key registered for the validator key `publicKey`; empty if none.
        function voteKey(bytes32 publicKey) external view returns (bytes memory key);

        /// The validator whose consensus key signed both votes in `evidence`, their round, and
        /// how many epochs ago it was.
        ///
        /// Reverts with the registry's `InvalidSignature` if the votes do not conflict or the
        /// validator's vote key did not sign both on this chain, and with its `ValidatorNotFound`
        /// if the registry did not hold the key in that epoch, or holds no vote key for it.
        function equivocator(bytes calldata evidence)
            external
            view
            returns (address validator, uint64 epoch, uint64 viewNumber, uint64 epochsAgo);
    }
}
