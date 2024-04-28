// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

/// @title BaseAuth
/// @author Anna Carroll <https://github.com/anna-carroll/3074>
abstract contract BaseAuth {
    /// @notice magic byte to disambiguate EIP-3074 signature payloads
    uint8 constant MAGIC = 0x04;

    /// @notice produce a digest for the authorizer to sign
    /// @param commit - any 32-byte value used to commit to transaction validity conditions
    /// @return digest - sign the `digest` to authorize the invoker to execute the `calls`
    /// @dev signing `digest` authorizes this contact to execute code on behalf of the signer
    ///      the logic of the inheriting contract should encode rules which respect the information within `commit`
    /// @dev the authorizer includes `commit` in their signature to ensure the authorized contract will only execute intended actions(s).
    ///      the Invoker logic MUST implement constraints on the contract execution based on information in the `commit`;
    ///      otherwise, any EOA that signs an AUTH for the Invoker will be compromised
    /// @dev per EIP-3074, digest = keccak256(MAGIC || chainId || paddedInvokerAddress || commit)
    function getDigest(bytes32 commit) public view returns (bytes32 digest) {
        digest =
            keccak256(abi.encodePacked(MAGIC, bytes32(block.chainid), bytes32(uint256(uint160(address(this)))), commit));
    }

    function authSimple(address authority, bytes32 commit, uint8 v, bytes32 r, bytes32 s)
        internal
        returns (bool success)
    {
        bytes memory authArgs = abi.encodePacked(yParity(v), r, s, commit);
        assembly {
            success := auth(authority, add(authArgs, 0x20), mload(authArgs))
        }
    }

    function authCallSimple(address to, bytes memory data, uint256 value, uint256 gasLimit)
        internal
        returns (bool success, bytes memory returndata)
    {
        // heavily modified by Thogard who is admittedly not the best w/ assembly
        assembly {
            success := authcall(gasLimit, to, value, 0, add(data, 0x20), mload(data), 0, 0)

            returndata := mload(0x40) // assign offset from free memory pointer
            mstore(returndata, returndatasize()) // store length
            returndatacopy(add(returndata, 0x20), 0, returndatasize()) // copy returndata
            mstore(0x40, add(returndata, add(returndatasize(), 0x20))) // update free memory pointer
        }
    }

    /// @dev Internal helper to convert `v` to `yParity` for `AUTH`
    function yParity(uint8 v) private pure returns (uint8 yParity_) {
        assembly {
            switch lt(v, 35)
            case true { yParity_ := eq(v, 28) }
            default { yParity_ := mod(sub(v, 35), 2) }
        }
    }
}
