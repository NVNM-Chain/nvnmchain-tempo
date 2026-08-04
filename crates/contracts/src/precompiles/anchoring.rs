pub use IAnchoring::{IAnchoringErrors as AnchoringError, IAnchoringEvents as AnchoringEvent};

crate::sol! {
    /// Caller-partitioned commitment log.
    ///
    /// An append-only, time-stamped commitment log partitioned by the calling address. Any
    /// EOA or contract anchors a `bytes32` commitment under its own address and proves it
    /// later via `latest(address, key)`. The caller *is* the namespace, so there is no
    /// authorization logic: permissionless by construction, permissioned on demand by
    /// routing through a wrapper contract whose address becomes the namespace.
    ///
    /// State is exactly one word per `(namespace, key)` — the latest commitment. History,
    /// payloads, and version order live in the `Anchored` log for indexers to derive.
    /// Re-writing the commitment already stored reverts, so every successful anchor is a
    /// real state change and every event is a distinct one.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IAnchoring {
        /// Anchors `commitment` under the caller's namespace at `key`.
        ///
        /// `metadata` is never stored, only emitted; it is opaque to the protocol.
        function anchor(bytes32 key, bytes32 commitment, bytes calldata metadata) external;

        /// Anchors `keccak256(metadata)`, which makes the emitted event self-verifying.
        function anchorAndHash(bytes32 key, bytes calldata metadata) external;

        /// Returns the latest commitment for `(namespace, key)`, or zero if never anchored.
        function latest(address namespace, bytes32 key) external view returns (bytes32 commitment);

        /// Emitted on every successful anchor. Block number and timestamp are inherent to
        /// the log and deliberately not duplicated as fields; indexers derive the version
        /// from canonical log order.
        event Anchored(address indexed caller, bytes32 indexed key, bytes32 commitment, bytes metadata);

        /// The write would leave the commitment unchanged.
        error CommitmentUnchanged();
    }
}
