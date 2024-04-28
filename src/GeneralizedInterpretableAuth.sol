// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import { BaseAuth } from "./BaseAuth.sol";
import { SharedStorage } from "./SharedStorage.sol";
import { AuthFactory } from "./AuthFactory.sol";
import { AuthType } from "./AuthType.sol";

interface IAuthWrapper {
    function authCallWrapperSingle(address to, bytes calldata data, uint256 value, uint256 gas)
        external
        returns (bool, bytes memory);

    function authCallWrapperBatch(
        address[] calldata to,
        bytes[] calldata data,
        uint256[] calldata value,
        uint256[] calldata gas
    ) external returns (bool[] memory successes, bytes[] memory returndatas);

    function handleSingleFailure(uint256 gasUsed) external returns (bool, bytes memory);

    function handleBatchFailure(uint256 gasUsed, uint256 callCount) external returns (bool[] memory, bytes[] memory);
}

contract GeneralizedInterpretableAuth is BaseAuth, SharedStorage {
    //////////////////////////////////////////////////////////
    ///                ENTRY FUNCTIONS                     ///
    //////////////////////////////////////////////////////////

    // Entry function for single authcall
    function safeAuthCall(bytes32 commit, address to, bytes calldata data, uint256 value, uint256 gas)
        public
        returns (bool success, bytes memory returndata)
    {
        address wrapper = _getWrapperFromCommit(commit);
        return _safeAuthCall(wrapper, commit, to, data, value, gas);
    }

    // Entry function for single authcall
    function safeAuthCall(address wrapper, address to, bytes calldata data, uint256 value, uint256 gas)
        public
        returns (bool success, bytes memory returndata)
    {
        bytes32 commit = _getCommitFromWrapper(wrapper);
        return _safeAuthCall(wrapper, commit, to, data, value, gas);
    }

    // Entry function for batched authcalls
    function safeAuthCalls(
        bytes32 commit,
        address[] calldata tos,
        bytes[] calldata datumses,
        uint256[] calldata values,
        uint256[] calldata gases
    )
        public
        returns (
            bool batchSuccess,
            bool[] memory successes,
            bytes[] memory returndatumses // aka returndatas
        )
    {
        address wrapper = _getWrapperFromCommit(commit);
        return _safeAuthCalls(wrapper, commit, tos, datumses, values, gases);
    }

    // Entry function for batched authcalls
    function safeAuthCalls(
        address wrapper,
        address[] calldata tos,
        bytes[] calldata datumses,
        uint256[] calldata values,
        uint256[] calldata gases
    )
        public
        returns (
            bool batchSuccess,
            bool[] memory successes,
            bytes[] memory returndatumses // aka returndatas
        )
    {
        bytes32 commit = _getCommitFromWrapper(wrapper);
        return _safeAuthCalls(wrapper, commit, tos, datumses, values, gases);
    }

    //////////////////////////////////////////////////////////
    ///             INTERNAL FUNCTIONS                     ///
    //////////////////////////////////////////////////////////

    function _safeAuthCall(address wrapper, bytes32 commit, address to, bytes calldata data, uint256 value, uint256 gas)
        internal
        returns (bool success, bytes memory returndata)
    {
        _setCommitLock(commit, wrapper);

        uint256 gasUsed = gasleft();

        (success, returndata) = wrapper.delegatecall(
            abi.encodeWithSelector(IAuthWrapper.authCallWrapperSingle.selector, abi.encode(to, data, value, gas))
        );

        if (!success) {
            gasUsed -= gasleft();

            (success, returndata) = wrapper.delegatecall(
                abi.encodeWithSelector(IAuthWrapper.handleSingleFailure.selector, abi.encode(gasUsed))
            );
            if (!success) revert(); // should be unreachable
        }

        _releaseCommitLock();

        return abi.decode(returndata, (bool, bytes));
    }

    function _safeAuthCalls(
        address wrapper,
        bytes32 commit,
        address[] calldata tos,
        bytes[] calldata datas,
        uint256[] calldata values,
        uint256[] calldata gases
    )
        internal
        returns (
            bool batchSuccess,
            bool[] memory successes,
            bytes[] memory returndatumses // aka returndatas
        )
    {
        _setCommitLock(commit, wrapper);

        uint256 gasUsed = gasleft();

        bytes memory returndata;
        (batchSuccess, returndata) = wrapper.delegatecall(
            abi.encodeWithSelector(IAuthWrapper.authCallWrapperBatch.selector, abi.encode(tos, datas, values, gases))
        );

        if (!batchSuccess) {
            gasUsed -= gasleft();

            bool success;
            (success, returndata) = wrapper.delegatecall(
                abi.encodeWithSelector(IAuthWrapper.handleBatchFailure.selector, abi.encode(gasUsed, tos.length))
            );
            if (!success) revert(); // should be unreachable
        }

        _releaseCommitLock();

        (successes, returndatumses) = abi.decode(returndata, (bool[], bytes[]));

        return (batchSuccess, successes, returndatumses);
    }

    function _getWrapperFromCommit(bytes32 commit) internal returns (address wrapper) {
        wrapper = commits[commit];
    }

    function _getCommitFromWrapper(address wrapper) internal returns (bytes32 commit) {
        commit = wrappers[wrapper];
    }

    function _setCommitLock(bytes32 commit, address wrapper) internal {
        if (commit == _unlockedB32 || commit == bytes32(0) || commit == _disabledB32) revert();
        if (wrapper == address(0) || wrapper == _disabledAddr) revert();
        if (_commitLock != _unlockedB32) revert();

        _commitLock = commit;
    }

    function _releaseCommitLock() internal {
        _commitLock = _unlockedB32;
    }

    //////////////////////////////////////////////////////////
    ///          THE NESTED AUTH FUNCTION                  ///
    //////////////////////////////////////////////////////////
    function safeAuth(
        address wrapper,
        address to,
        bytes calldata data,
        uint256 value,
        uint256 gasLimit,
        address authority,
        bytes32 commit,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external returns (bool success, bytes memory returndata) {
        if (msg.sender != address(this)) revert();
        if (commit != _commitLock) revert();
        if (_authLock != _unlocked) revert();
        _authLock = _locked;
        success = authSimple(authority, commit, v, r, s);
        if (!success) revert(); // revert early if auth fails
        (success, returndata) = authCallSimple(to, data, value, gasLimit);
        _authLock = _unlocked;
    }
}
