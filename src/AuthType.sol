// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

struct AuthType {
    address invoker; // Invoker contract
    address sender; // User
    address authorized; // Contract that can use authcall for user. 0 = anyone can call, 1 = must be entrypoint
    address to; // User sets the "to" of the authcall. If 0, authorized sets the "to"
    uint256 auth_nonce; // The nonce of the auth. This is NOT the transaction's nonce - it's used to track multiple concurrent auths per user.
    bool allow_batch; // multiple authcalls in one tx
    bool allow_hooks; // allow hooks to execute around the authcall
    bool allow_reverts; // allows reverts - useful for try/catch
    bool get_args_from_hooks; // get the calldata arguments for authcall from the preceeding hook
    bool give_returndata_to_hooks; // the args for hook n+1 is the returndata from authcall n
    uint256 max_uses; // max number of times the AUTH can be used (a batch usage counts as a single use), 0 = unlimited
    uint256 max_value; // max value of sender's that authorized can use in a single call
    uint256 total_value; // cumulative value of sender's that authorized can use in all calls
    uint256 max_gas; // max gas that authorized can use per call
    uint256 total_gas; // cumulative gas that authorized can use per call
    address[] hooks; // hooks that execute around the authcall. if hooks[n] is address(0), hook is skipped
    bytes data; // User sets the "data" of the authcall. If 0, either authorized or a hook sets the "data"
}

library AuthTypeLib {
    function getHash(AuthType memory authType) internal pure returns (bytes32) {
        return keccak256(abi.encode(authType));
    }
}
