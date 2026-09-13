// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title OmniTrust Ledger anchor
/// @notice Records 32-byte Merkle roots of OmniTrust commitments on a local development chain.
/// @dev Deliberately minimal. It stores and emits hashes only: no documents, no personal data,
/// no keys, no value transfer and no tokens. An anchor shows that a root existed by a block; it
/// says nothing about who anyone is. Only the deploying account can anchor, and a root can be
/// anchored once.
contract OmniTrustAnchor {
    address public immutable owner;

    /// @notice The block in which a root was anchored, or zero if it never was.
    mapping(bytes32 => uint256) public anchoredAtBlock;

    event Anchored(bytes32 indexed root, uint32 leafCount, uint256 blockNumber, uint256 timestamp);

    error NotOwner();
    error EmptyRoot();
    error AlreadyAnchored(bytes32 root);

    constructor() {
        owner = msg.sender;
    }

    function anchor(bytes32 root, uint32 leafCount) external {
        if (msg.sender != owner) revert NotOwner();
        if (root == bytes32(0)) revert EmptyRoot();
        if (anchoredAtBlock[root] != 0) revert AlreadyAnchored(root);
        anchoredAtBlock[root] = block.number;
        emit Anchored(root, leafCount, block.number, block.timestamp);
    }
}
