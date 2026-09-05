pub use IAnchoring::{IAnchoringErrors as AnchoringError, IAnchoringEvents as AnchoringEvent};

crate::sol! {
    /// Caller-partitioned Merkle Mountain Range: one append-only tree per address.
    ///
    /// The caller *is* the namespace, so there is no authorization logic — anyone appends
    /// under their own address, and a contract wanting a policy forwards the call, its own
    /// address becoming the namespace.
    ///
    /// An append carries no witness, so several fit one transaction. What a leaf commits to
    /// is the caller's business: `metadata` is never stored, only emitted, and every event
    /// carries the peaks, so a proof needs the log and nothing else.
    ///
    /// Hashing: a leaf is `keccak256("leaf" ‖ commitment)`, a merge
    /// `keccak256("merge" ‖ left ‖ right)`, and the root bags the peaks highest first,
    /// `keccak256("bag" ‖ acc ‖ peak)`, zero when empty.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IAnchoring {
        /// Appends one leaf to the caller's MMR.
        function appendLeaf(bytes32 commitment, bytes calldata metadata) external returns (bytes32 root);

        /// Appends a batch as the roots of aligned perfect subtrees, in leaf order: a chunk of
        /// height `h` merges only when the count is a multiple of `2^h`, which is what makes
        /// the batch reach the root the leaves reach one by one.
        function appendLeaves(bytes32[] calldata chunkRoots, uint8[] calldata chunkHeights, bytes calldata metadata) external returns (bytes32 root);

        /// The root of `namespace`'s MMR, or zero if nothing was ever appended.
        function root(address namespace) external view returns (bytes32);

        /// The leaf count and the peaks, highest first — what a proof is checked against.
        function state(address namespace) external view returns (uint256 count, bytes32[] memory peaks);

        /// One leaf landed at `index`.
        event LeafAppended(address indexed namespace, uint256 indexed index, bytes32 commitment, bytes32 root, bytes32[] peaks, bytes metadata);

        /// A batch landed from `firstLeaf`, bringing the leaf count to `count`.
        event LeavesAppended(address indexed namespace, uint256 indexed firstLeaf, uint256 count, bytes32[] chunkRoots, uint8[] chunkHeights, bytes32 root, bytes32[] peaks, bytes metadata);

        /// A chunk of `height` at `count`, which is not a multiple of its size.
        error ChunkNotAligned(uint256 count, uint256 height);
        /// `chunkRoots` and `chunkHeights` differ in length.
        error ChunksMismatch();
        /// `appendLeaves` was given no chunks.
        error EmptyBatch();
        /// A zero chunk root, which nothing hashes to.
        error ZeroChunkRoot();
    }
}
