// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

contract SharedStorage {
    uint256 internal constant _unlocked = uint256(1);
    uint256 internal constant _locked = uint256(2);

    bytes32 internal constant _unlockedB32 = bytes32(uint256(1));
    bytes32 internal constant _disabledB32 = bytes32(uint256(2));

    address internal constant _disabledAddr = address(1);

    //      wrapper    commit
    mapping(address => bytes32) public wrappers;

    //      sender              nonce      wrapper
    mapping(address => mapping(uint256 => address)) public nonces;

    //      commit      wrapper
    mapping(bytes32 => address) public commits;

    //      wrapper    gas allowance
    mapping(address => uint256) public gas_allowances;

    //      wrapper    value allowance
    mapping(address => uint256) public value_allowances;

    //      wrapper    uses remaining
    mapping(address => uint256) public uses_remaining;

    // TODO: convert both to transient storage
    uint256 internal _authLock; // an inner lock to prevent reentering the auth func to bypass bans on batching
    bytes32 internal _commitLock; // the outer / main lock

    address[] hooks; // hooks that execute around the authcall. if hooks[n] is address(0), hook is skipped
}
