// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import { GeneralizedInterpretableAuth } from "./GeneralizedInterpretableAuth.sol";
import { AuthType, AuthTypeLib } from "./AuthType.sol";
import { SharedStorage } from "./SharedStorage.sol";

interface ISafeAuth {
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
    ) external returns (bool success, bytes memory returndata);
}

contract AuthWrapper is SharedStorage {
    using AuthTypeLib for AuthType;

    address public immutable SAFE_AUTH; // Address of the invoker (also Factory)
    address public immutable THIS_WRAPPER; // Address of this wrapper

    address public immutable SENDER; // User
    address public immutable AUTHORIZED; // Contract that can use authcall for user. 0 = anyone can call, 1 = must be an entrypoint
    address public immutable TO; // User sets the "to" of the authcall. If 0, authorized sets the "to"
    uint256 public immutable AUTH_NONCE; // The nonce of the auth. This is NOT the user's nonce - it's used to track multiple concurrent auths.
    bool public immutable ALLOW_BATCH; // multiple authcalls in one tx
    bool public immutable ALLOW_UNLIMITED_REUSE; // unlimited calls or txs per auth
    bool public immutable ALLOW_HOOKS; // allow hooks to execute around the authcall
    bool public immutable ALLOW_REVERTS; // allows reverts - useful for try/catch
    bool public immutable GET_ARGS_FROM_HOOKS; // get the calldata arguments for authcall from the preceeding hook
    bool public immutable GIVE_RETURNDATA_TO_HOOKS; // the args for hook n+1 is the returndata from authcall n
    uint256 public immutable MAX_VALUE; // max value of sender's that authorized can use
    uint256 public immutable MAX_GAS; // max gas that authorized can use per call
    bytes32 public immutable DATA_HASH; // Hash of the user-set "data" of the authcall. If 0, either authorized or a hook sets the "data"

    bytes32 public immutable COMMIT;
    uint8 public immutable V;
    bytes32 public immutable R;
    bytes32 public immutable S;

    bool public immutable USES_FIXED_TO;
    bool public immutable USES_FIXED_DATA;
    bool public immutable USES_FIXED_AUTHORIZED;
    bool public immutable MUST_BE_ENTRYPOINT;
    bool public immutable HAS_MAX_VALUE;
    bool public immutable HAS_TOTAL_VALUE;
    bool public immutable HAS_MAX_GAS;
    bool public immutable HAS_TOTAL_GAS;

    uint256 public immutable HOOK_COUNT;

    // TODO: storage is yucky - just hardcode and set a cap.

    constructor(AuthType memory authType, bytes32 commit, uint8 v, bytes32 r, bytes32 s) {
        if (authType.invoker != msg.sender) revert();

        SAFE_AUTH = msg.sender; // SAFE_AUTH = FACTORY
        THIS_WRAPPER = address(this);

        SENDER = authType.sender;
        AUTHORIZED = authType.authorized;
        TO = authType.to;
        AUTH_NONCE = authType.auth_nonce;
        ALLOW_BATCH = authType.allow_batch;
        ALLOW_UNLIMITED_REUSE = authType.max_uses == 0;
        ALLOW_HOOKS = authType.allow_hooks;
        ALLOW_REVERTS = authType.allow_reverts;
        MAX_VALUE = authType.max_value;
        MAX_GAS = authType.max_gas;
        DATA_HASH = keccak256(authType.data);

        COMMIT = commit;
        V = v;
        R = r;
        S = s;

        USES_FIXED_TO = TO != address(0);
        USES_FIXED_DATA = DATA_HASH != keccak256(new bytes(0));
        USES_FIXED_AUTHORIZED = AUTHORIZED != address(0) && AUTHORIZED != address(1);
        MUST_BE_ENTRYPOINT = AUTHORIZED == address(1);

        HAS_MAX_VALUE = authType.max_value != type(uint256).max;
        HAS_MAX_GAS = authType.max_gas != type(uint256).max;

        if (authType.total_value != type(uint256).max) {
            HAS_TOTAL_VALUE = true;
            value_allowances[THIS_WRAPPER] = authType.total_value;
        } else {
            HAS_TOTAL_VALUE = false;
        }

        if (authType.total_gas != type(uint256).max) {
            HAS_TOTAL_GAS = true;
            gas_allowances[THIS_WRAPPER] = authType.total_gas;
        } else {
            HAS_TOTAL_GAS = false;
        }

        // CASE: Hooks allowed
        if (ALLOW_HOOKS) {
            if (authType.get_args_from_hooks) {
                if (USES_FIXED_DATA) revert();
                GET_ARGS_FROM_HOOKS = true;
            } else {
                GET_ARGS_FROM_HOOKS = false;
            }

            GIVE_RETURNDATA_TO_HOOKS = authType.give_returndata_to_hooks;
            if (authType.hooks.length == 0) revert();

            for (uint256 i; i < authType.hooks.length; i++) {
                if (authType.hooks[i] != address(0) && authType.hooks[i].codehash == bytes32(0)) revert(); // Hook contracts must already exist
                hooks.push(authType.hooks[i]);
            }
            HOOK_COUNT = authType.hooks.length;
        } else {
            // CASE: Hooks not allowed
            if (authType.hooks.length > 0) revert();
            if (authType.get_args_from_hooks) revert();
            if (authType.give_returndata_to_hooks) revert();
            GET_ARGS_FROM_HOOKS = false;
            GIVE_RETURNDATA_TO_HOOKS = false;
            HOOK_COUNT = 0;
        }

        if (!ALLOW_UNLIMITED_REUSE) {
            uses_remaining[THIS_WRAPPER] = authType.max_uses;
        }
    }

    function authCallWrapperSingle(address to, bytes calldata data, uint256 value, uint256 gas)
        external
        sharedChecks
        reuseCheck
        returns (bool, bytes memory)
    {
        uint256 _gasMeter;
        if (HAS_TOTAL_GAS) {
            if (gas > gas_allowances[THIS_WRAPPER]) return (false, new bytes(0));
            _gasMeter = gasleft();
        }

        // case: call is valid - may or may not be successful
        try this.authCallOuter(to, data, value, gas) returns (bool success, bytes memory returndata) {
            if (HAS_TOTAL_GAS) gas_allowances[THIS_WRAPPER] -= (_gasMeter - gasleft());
            return (success, returndata);

            // case: call is invalid
        } catch {
            // Count the gas used by reverts
            if (HAS_TOTAL_GAS) gas_allowances[THIS_WRAPPER] -= (_gasMeter - gasleft());
            return (false, new bytes(0));
        }
    }

    function authCallWrapperBatch(
        address[] calldata to,
        bytes[] calldata data,
        uint256[] calldata value,
        uint256[] calldata gas
    )
        external
        batchChecks(to, data, value, gas)
        sharedChecks
        reuseCheck
        returns (
            bool[] memory successes,
            bytes[] memory returndatumses // returndatumses aka returndatas
        )
    {
        successes = new bool[](to.length);
        returndatumses = new bytes[](to.length);

        bytes memory _data;

        for (uint256 i; i < to.length; i++) {
            _data = data[i];

            if (ALLOW_HOOKS) {
                address _hook = hooks[i]; // intentionally revert on overflow
                if (_hook != address(0)) {
                    if (!_checkHook(_hook)) revert();

                    bool success;
                    bytes memory returndata;

                    // case: Call the hook with the previous AUTHCALL's returndata
                    if (GIVE_RETURNDATA_TO_HOOKS && i > 0) {
                        (success, returndata) = _hook.call(returndatumses[i - 1]);

                        // case: Call the hook with the AUTHCALL's calldata
                        // NOTE: This occurs when GIVE_RETURNDATA_TO_HOOKS = true and i = 0
                    } else {
                        (success, returndata) = _hook.call(_data);
                    }

                    if (!ALLOW_REVERTS && !success) revert();

                    // Set the AUTHCALL's calldata if it's meant to be the hook's returndata
                    if (GET_ARGS_FROM_HOOKS) _data = returndata;
                }
            }

            uint256 _gasMeter;
            if (HAS_TOTAL_GAS) {
                _gasMeter = gasleft();

                // Treat the entire batch as invalid if the gas allowance is exceeded
                if (gas[i] > gas_allowances[THIS_WRAPPER]) revert();
            }

            // case: call is valid - may or may not be successful
            try this.authCallOuter(to[i], _data, value[i], gas[i]) returns (bool success, bytes memory returndata) {
                if (HAS_TOTAL_GAS) gas_allowances[THIS_WRAPPER] -= (_gasMeter - gasleft());

                // Treat the entire batch as invalid if a single authcall is invalid
                if (!ALLOW_REVERTS && !success) revert();

                // Save the result in the returned arrays
                (successes[i], returndatumses[i]) = (success, returndata);

                // case: call is invalid
            } catch {
                // Treat the entire batch as invalid if a single authcall is invalid
                revert();
            }
        }

        // Do the final hook. NOTE that hooks.length = to.length + 1

        if (ALLOW_HOOKS) {
            uint256 i = to.length;
            address _hook = hooks[i]; // intentionally revert on overflow
            if (_hook != address(0)) {
                if (!_checkHook(_hook)) revert();

                bool success;

                // case: Call the hook with the previous AUTHCALL's returndata
                if (GIVE_RETURNDATA_TO_HOOKS && i > 0) {
                    (success,) = _hook.call(returndatumses[i - 1]);

                    // case: Call the hook with the AUTHCALL's calldata
                } else {
                    (success,) = _hook.call(data[i - 1]);
                }

                if (!ALLOW_REVERTS && !success) revert();
            }
        }

        return (successes, returndatumses);
    }

    // This function is called by the invoker to handle failure-case accounting for batch calls
    function handleBatchFailure(uint256 gasUsed, uint256 callCount)
        external
        sharedChecks
        returns (bool[] memory, bytes[] memory)
    {
        if (HAS_TOTAL_GAS) {
            uint256 _allowance = gas_allowances[THIS_WRAPPER];
            gas_allowances[THIS_WRAPPER] = gasUsed > _allowance ? 0 : _allowance - gasUsed;
        }

        if (!ALLOW_UNLIMITED_REUSE) {
            if (uses_remaining[THIS_WRAPPER] > 0) uses_remaining[THIS_WRAPPER] -= 1;
        }

        return (new bool[](callCount), new bytes[](callCount));
    }

    // This function is called by the invoker to handle failure-case accounting for batch calls
    function handleSingleFailure(uint256 gasUsed) external sharedChecks returns (bool, bytes memory) {
        if (HAS_TOTAL_GAS) {
            uint256 _allowance = gas_allowances[THIS_WRAPPER];
            gas_allowances[THIS_WRAPPER] = gasUsed > _allowance ? 0 : _allowance - gasUsed;
        }

        if (!ALLOW_UNLIMITED_REUSE) {
            if (uses_remaining[THIS_WRAPPER] > 0) uses_remaining[THIS_WRAPPER] -= 1;
        }

        return (false, new bytes(0));
    }

    function authCallOuter(address to, bytes calldata data, uint256 value, uint256 gas)
        external
        returns (bool success, bytes memory returndata)
    {
        // Reverts allowed in authCallOuter but not _authCallInner
        if (msg.sender != address(this) || to == address(this)) revert();
        bool valid;
        (valid, success, returndata) = _authCallInner(to, data, value, gas);
        if (!valid) revert();
        if (!ALLOW_REVERTS && !success) revert();
    }

    function _authCallInner(address to, bytes memory data, uint256 value, uint256 gas)
        internal
        returns (bool valid, bool success, bytes memory returndata)
    {
        // No reverts in _authCallInner so that we can differentiate between invalid authcalls and failed authcalls
        if (USES_FIXED_TO && to != TO) return (false, false, new bytes(0));
        if (USES_FIXED_DATA && keccak256(data) != DATA_HASH) return (false, false, new bytes(0));
        if (HAS_MAX_VALUE && value > MAX_VALUE) return (false, false, new bytes(0));
        if (HAS_MAX_GAS && gas > MAX_GAS) return (false, false, new bytes(0));
        if (HAS_TOTAL_VALUE) {
            if (value > value_allowances[THIS_WRAPPER]) return (false, false, new bytes(0));
            value_allowances[THIS_WRAPPER] -= value;
        }

        (success, returndata) =
            ISafeAuth(SAFE_AUTH).safeAuth(THIS_WRAPPER, to, data, value, gas, SAFE_AUTH, COMMIT, V, R, S);

        if (!success && HAS_TOTAL_VALUE) value_allowances[THIS_WRAPPER] += value;

        return (true, success, returndata);
    }

    function _checkHook(address hook) internal returns (bool) {
        if (hook == address(this)) return false;
        if (hook == THIS_WRAPPER) return false;
        return true;
    }

    modifier sharedChecks() {
        // This should be improved, if possible - other 3074 invokers could bamboozle this one.
        if (MUST_BE_ENTRYPOINT && (msg.sender != tx.origin || msg.sender.code.length > 0)) revert();

        if (USES_FIXED_AUTHORIZED && msg.sender != AUTHORIZED) revert();

        // Wrappers are delegatecalled
        if (address(this) != SAFE_AUTH) revert();
        if (_commitLock != COMMIT) revert();
        if (commits[COMMIT] != THIS_WRAPPER) revert(); // redundant

        _;
    }

    modifier reuseCheck() {
        if (!ALLOW_UNLIMITED_REUSE) {
            if (uses_remaining[THIS_WRAPPER] == 0) revert();
            uses_remaining[THIS_WRAPPER] -= 1;
        }
        _;
    }

    modifier batchChecks(
        address[] calldata to,
        bytes[] calldata data,
        uint256[] calldata value,
        uint256[] calldata gas
    ) {
        if (to.length != data.length) revert();
        if (to.length != value.length) revert();
        if (to.length != gas.length) revert();
        if (ALLOW_HOOKS && hooks.length != to.length + 1) revert();
        _;
    }
}
