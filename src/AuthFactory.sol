// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import { GeneralizedInterpretableAuth } from "./GeneralizedInterpretableAuth.sol";
import { AuthType, AuthTypeLib } from "./AuthType.sol";
import { AuthWrapper } from "./AuthWrapper.sol";
import { SharedStorage } from "./SharedStorage.sol";

interface IAuthWrapper {
    function SENDER() external returns (address);
    function AUTH_NONCE() external returns (uint256);
}

contract AuthFactory is GeneralizedInterpretableAuth {
    using AuthTypeLib for AuthType;

    bytes32 public immutable SALT;

    constructor() {
        SALT = keccak256(abi.encodePacked(block.chainid, address(this), "AuthFactory 1.0"));
    }

    function isAuthorized(address wrapper) public view returns (bool) {
        bytes32 commit = wrappers[wrapper];
        return commit != bytes32(0) && commit != _disabledB32;
    }

    function isAuthorized(bytes32 commit) public view returns (bool) {
        address wrapper = commits[commit];
        return wrapper != address(0) && wrapper != _disabledAddr;
    }

    function isNonceAvailable(address sender, uint256 auth_nonce) public view returns (bool) {
        return nonces[sender][auth_nonce] == address(0);
    }

    function createAuthWrapper(AuthType memory authType, bytes32 commit, uint8 v, bytes32 r, bytes32 s)
        external
        returns (address wrapper)
    {
        if (authType.getHash() != commit) revert();
        if (nonces[authType.sender][authType.auth_nonce] != address(0)) revert();
        if (commits[commit] != address(0)) revert();
        if (_commitLock != _unlockedB32) revert();

        wrapper = getAuthWrapperAddress(authType, commit, v, r, s);

        if (wrappers[wrapper] != bytes32(0)) revert();
        if (wrapper.code.length != 0) revert();

        // The authType-specific checks are handled in the constructor of the wrapper contract.
        AuthWrapper newWrapper = new AuthWrapper{ salt: SALT }(authType, commit, v, r, s);
        if (address(newWrapper) != wrapper) revert();

        wrappers[wrapper] = commit;
        nonces[authType.sender][authType.auth_nonce] = wrapper;
        commits[commit] = wrapper;
    }

    function disableAuthWrapper(AuthType memory authType) external {
        // NOTE: This can proactively disable an authType
        // NOTE: If this is proactive, remember that the auth_nonce of the
        // disabled commit can still be used in a different commit
        if (msg.sender != authType.sender) revert();

        bytes32 commit = authType.getHash();
        address wrapper = commits[commit];
        if (wrapper == _disabledAddr) revert();

        // Only invalidate nonce if nonce already exists and is tied to this wrapper
        if (wrapper != address(0) && nonces[authType.sender][authType.auth_nonce] == wrapper) {
            nonces[authType.sender][authType.auth_nonce] = _disabledAddr;
        }

        wrappers[wrapper] = _disabledB32;
        commits[commit] = _disabledAddr;
    }

    function disableAuthWrapper(uint256 auth_nonce) external {
        // NOTE: This can proactively disable a nonce.
        address wrapper = nonces[msg.sender][auth_nonce];
        bytes32 commit = wrappers[wrapper];

        wrappers[wrapper] = _disabledB32;
        nonces[msg.sender][auth_nonce] = _disabledAddr;
        commits[commit] = _disabledAddr;
    }

    function disableAuthWrapper(bytes32 commit) external {
        // NOTE: This cannot proactively disable a commit.
        address wrapper = commits[commit];
        if (wrapper == _disabledAddr || wrapper == address(0)) revert();

        address sender = IAuthWrapper(wrapper).SENDER();
        if (sender != msg.sender) revert();

        uint256 auth_nonce = IAuthWrapper(wrapper).AUTH_NONCE();
        nonces[msg.sender][auth_nonce];

        wrappers[wrapper] = _disabledB32;
        nonces[msg.sender][auth_nonce] = _disabledAddr;
        commits[commit] = _disabledAddr;
    }

    function disableAuthWrapper(address wrapper) external {
        // NOTE: This cannot proactively disable a commit.
        bytes32 commit = wrappers[wrapper];
        if (commit == _disabledB32 || commit == bytes32(0)) revert();

        address sender = IAuthWrapper(wrapper).SENDER();
        if (sender != msg.sender) revert();

        uint256 auth_nonce = IAuthWrapper(wrapper).AUTH_NONCE();
        nonces[msg.sender][auth_nonce];

        wrappers[wrapper] = _disabledB32;
        nonces[msg.sender][auth_nonce] = _disabledAddr;
        commits[commit] = _disabledAddr;
    }

    function getAuthWrapperAddress(
        AuthType memory authType,
        bytes32 commit,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public returns (address wrapper) {
        wrapper = address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff),
                            address(this),
                            SALT,
                            keccak256(
                                abi.encodePacked(
                                    type(AuthWrapper).creationCode, abi.encode(authType, commit, v, r, s)
                                )
                            )
                        )
                    )
                )
            )
        );
    }
}
