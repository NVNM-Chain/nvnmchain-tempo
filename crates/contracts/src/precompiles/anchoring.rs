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
    /// carries the peaks, so a leaf appended on its own proves from the log alone. A batch's
    /// leaves reach the log only as chunk roots, so proving one needs the file it was cut from.
    ///
    /// Hashing: a leaf is `keccak256("leaf" ‖ commitment)`, a merge
    /// `keccak256("merge" ‖ left ‖ right)`, and the root bags the peaks highest first,
    /// `keccak256("bag" ‖ acc ‖ peak)`, zero when empty.
    #[derive(Debug, PartialEq, Eq)]
    #[sol(abi)]
    interface IAnchoring {
        /// Appends one leaf to the caller's MMR. Nothing comes back: the root is what the
        /// event's peaks bag to, or `root(namespace)`.
        function appendLeaf(bytes32 commitment, bytes calldata metadata) external;

        /// An aligned perfect subtree to append: its root and height.
        struct Chunk {
            bytes32 root;
            uint8 height;
        }

        /// Appends a batch as the roots of aligned perfect subtrees, in leaf order: a chunk of
        /// height `h` merges only when the count is a multiple of `2^h`, which is what makes
        /// the batch reach the root the leaves reach one by one. An empty batch is a no-op.
        function appendLeaves(Chunk[] calldata chunks, bytes calldata metadata) external;

        /// The root of `namespace`'s MMR, or zero if nothing was ever appended.
        function root(address namespace) external view returns (bytes32);

        /// The leaf count and the peaks, highest first — what a proof is checked against.
        function state(address namespace) external view returns (uint256 count, bytes32[] memory peaks);

        /// One leaf landed at `index`.
        event LeafAppended(address indexed namespace, uint256 indexed index, bytes32 commitment, bytes32[] peaks, bytes metadata);

        /// A batch landed from `firstLeaf`, bringing the leaf count to `count`.
        event LeavesAppended(address indexed namespace, uint256 indexed firstLeaf, uint256 count, Chunk[] chunks, bytes32[] peaks, bytes metadata);

        /// A chunk of `height` at `count`, which is not a multiple of its size.
        error ChunkNotAligned(uint256 count, uint256 height);
        /// A zero chunk root, which nothing hashes to.
        error ZeroChunkRoot();
    }
}
