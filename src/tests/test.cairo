
// Nimbora yields contracts
use nimbora_yields::pooling_manager::pooling_manager::{PoolingManager};
use nimbora_yields::pooling_manager::interface::{IPoolingManagerDispatcher, IPoolingManagerDispatcherTrait, StrategyReportL1};
use nimbora_yields::factory::factory::{Factory};
use nimbora_yields::factory::interface::{IFactoryDipsatcher, IFactoryDipsatcherTrait};
use nimbora_yields::token_manager::token_manager::{TokenManager};
use nimbora_yields::token_manager::interface::{ITokenManagerDispatcher, ITokenManagerDispatcherTrait, WithdrawalInfo, StrategyReportL2};

// Utils peripheric contracts
use nimbora_yields::token_bridge::token_bridge::{TokenBridge};
use nimbora_yields::token_bridge::token_mock::{TokenMock};
use nimbora_yields::token_bridge::interface::{ITokenBridgeDispatcher, IMintableTokenDispatcher, IMintableTokenDispatcherTrait};

use openzeppelin::{
    token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
    access::accesscontrol::{
        AccessControlComponent, interface::{IAccessControlDispatcher, IAccessControlDispatcherTrait}
    };
};

use starknet::{
    get_contract_address, deploy_syscall, ClassHash, contract_address_const, ContractAddress,
    get_block_timestamp, EthAddress
};
use starknet::class_hash::Felt252TryIntoClassHash;
use starknet::account::{Call};
use traits::{TryInto};
use result::{Result, ResultTrait};
use option::{OptionTrait};
use snforge_std::{declare, ContractClassTrait, start_prank, CheatTarget, ContractClass, PrintTrait, stop_prank, start_warp, stop_warp};


fn deploy_tokens(
    class: ContractClass, initial_supply: u256, recipient: ContractAddress
) -> (ERC20ABIDispatcher, ERC20ABIDispatcher, ERC20ABIDispatcher) {
    let contract = declare('TokenMock');

    let mut constructor_args: Array<felt252> = ArrayTrait::new();
    Serde::serialize(@initial_supply, ref constructor_args);
    Serde::serialize(@recipient, ref constructor_args);
    let contract_address_1 = class.deploy(@constructor_args).unwrap();
    let contract_address_2 = class.deploy(@constructor_args).unwrap();
    let contract_address_3 = class.deploy(@constructor_args).unwrap();

    return (ERC20ABIDispatcher { contract_address: contract_address_1 }, ERC20ABIDispatcher { contract_address: contract_address_2 }, ERC20ABIDispatcher { contract_address: contract_address_3 });
}


fn deploy_token_bridge(l2_address_1: ContractAddress, l1_bridge_1: felt252, l2_address_2: ContractAddress, l1_bridge_2: felt252, l2_address_3: ContractAddress, l1_bridge_3: felt252) -> (ITokenBridgeDispatcher, ITokenBridgeDispatcher, ITokenBridgeDispatcher) {
    let contract = declare('TokenBridge');

    let mut constructor_args_1: Array<felt252> = ArrayTrait::new();
    Serde::serialize(@l2_address_1, ref constructor_args);
    Serde::serialize(@l1_bridge_1, ref constructor_args);
    let contract_address_1 = contract.deploy(@constructor_args_1).unwrap();

    let mut constructor_args_2: Array<felt252> = ArrayTrait::new();
    Serde::serialize(@l2_address_2, ref constructor_args);
    Serde::serialize(@l1_bridge_2, ref constructor_args);
    let contract_address_2 = contract.deploy(@constructor_args_2).unwrap();

    let mut constructor_args_3: Array<felt252> = ArrayTrait::new();
    Serde::serialize(@l2_address_3, ref constructor_args);
    Serde::serialize(@l1_bridge_3, ref constructor_args);
    let contract_address_3 = contract.deploy(@constructor_args_3).unwrap();

    return (ITokenBridgeDispatcher { contract_address: contract_address_1 }, ITokenBridgeDispatcher { contract_address: contract_address_2 }, ITokenBridgeDispatcher { contract_address: contract_address_3 });
}

fn deploy_pooling_manager(
    owner: ContractAddress
) -> IPoolingManagerDispatcher {
    let contract = declare('PoolingManager');
    let mut constructor_args: Array<felt252> = ArrayTrait::new();
    Serde::serialize(@owner, ref constructor_args);
    let contract_address = contract.deploy(@constructor_args).unwrap();
    return IPoolingManagerDispatcher { contract_address: contract_address };
}

fn deploy_factory(
    pooling_manager: ContractAddress,
    token_class_hash: ClassHash,
    token_manager_class_hash: ClassHash
) -> IFactoryDipsatcher {
    let contract = declare('Factory');
    let mut constructor_args: Array<felt252> = ArrayTrait::new();
    Serde::serialize(@pooling_manager, ref constructor_args);
    Serde::serialize(@token_class_hash, ref constructor_args);
    Serde::serialize(@token_manager_class_hash, ref constructor_args);
    let contract_address = contract.deploy(@constructor_args).unwrap();
    return IFactoryDipsatcher { contract_address: contract_address };
}


#[test]
fn test_deploy() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    let fw_ownable_disp = IOwnableDispatcher { contract_address: fw.contract_address };
    let owner = fw_ownable_disp.owner();
    assert(owner == contract_address_const::<2300>(), 'owner');
    let fees = fw.get_fees();
    assert(fees == 10239, 'fees');
    let gas_token = fw.get_gas_token();
    assert(gas_token.contract_address == contract_address_const::<2500>(), 'gas_token');
    let l1_gas_price_oracle_address = fw.get_l1_gas_price_oracle_address();
    assert(
        l1_gas_price_oracle_address == contract_address_const::<6500>(),
        'l1_gas_price_oracle_address'
    );
    let selector_l1_gas_price = fw.get_selector_l1_gas_price();
    assert(selector_l1_gas_price == 3332, 'selector_l1_gas_price');
    let l2_relayer = fw.get_l2_relayer();
    assert(l2_relayer == contract_address_const::<22>(), 'l2_relayer');
    let protocol_fees = fw.get_protocol_fees();
    assert(protocol_fees == 223, 'protocol_fees');
    let protocol_fees_recipient = fw.get_protocol_fees_recipient();
    assert(protocol_fees_recipient == contract_address_const::<90>(), 'fees_recipient');
    let pragma = fw.get_pragma();
    assert(pragma == contract_address_const::<2900>(), 'pragma');
}


//
//// Setters
//

#[test]
#[should_panic(expected: ('Caller is not the owner',))]
fn test_set_protocol_fees_owner() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    fw.set_protocol_fees(10239);
}

#[test]
#[should_panic(expected: ('ZERO_AMOUNT_ERROR',))]
fn test_set_protocol_fees_zero() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_protocol_fees(0);
}

#[test]
fn test_set_protocol_fees() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_protocol_fees(1);
    let protocol_fees = fw.get_protocol_fees();
    assert(protocol_fees == 1, 'protocol_fees');
}


// protocol fees recipient

#[test]
#[should_panic(expected: ('Caller is not the owner',))]
fn test_set_protocol_fee_recipient_owner() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    fw.set_protocol_fee_recipient(contract_address_const::<5000>());
}

#[test]
#[should_panic(expected: ('ZERO_ADDRESS_ERROR',))]
fn test_set_protocol_fee_recipient_zero() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_protocol_fee_recipient(contract_address_const::<0>());
}

#[test]
fn test_set_protocol_fee_recipient() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_protocol_fee_recipient(contract_address_const::<23>());
    let protocol_fees_recipient = fw.get_protocol_fees_recipient();
    assert(protocol_fees_recipient == contract_address_const::<23>(), 'protocol_fees_recipient');
}


#[test]
#[should_panic(expected: ('Caller is not the owner',))]
fn test_set_pragma_owner() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    fw.set_pragma(IOracleABIDispatcher { contract_address: contract_address_const::<2300>() });
}

#[test]
#[should_panic(expected: ('ZERO_ADDRESS_ERROR',))]
fn test_set_pragma_zero() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_pragma(IOracleABIDispatcher { contract_address: contract_address_const::<0>() });
}

#[test]
fn test_set_pragma() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_pragma(IOracleABIDispatcher { contract_address: contract_address_const::<292>() });
    let pragma = fw.get_pragma();
    assert(pragma == contract_address_const::<292>(), 'pragma');
}


// set_fees

#[test]
#[should_panic(expected: ('Caller is not the owner',))]
fn test_set_fees_owner() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    fw.set_fees(5000);
}


#[test]
#[should_panic(expected: ('ZERO_AMOUNT_ERROR',))]
fn test_set_fees_zero() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_fees(0);
}

#[test]
fn test_set_fees() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_fees(23);
    let fees = fw.get_fees();
    assert(fees == 23, 'fees');
}

// set_l1_gas_price_oracle_address

#[test]
#[should_panic(expected: ('Caller is not the owner',))]
fn test_set_l1_gas_price_oracle_address_owner() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    fw.set_l1_gas_price_oracle_address(contract_address_const::<1995>());
}

#[test]
#[should_panic(expected: ('ZERO_ADDRESS_ERROR',))]
fn test_set_l1_gas_price_oracle_address_zero() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_l1_gas_price_oracle_address(contract_address_const::<0>());
}

#[test]
fn test_set_l1_gas_price_oracle_address() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_l1_gas_price_oracle_address(contract_address_const::<1995>());
    let l1_gas_price_oracle_address = fw.get_l1_gas_price_oracle_address();
    assert(
        l1_gas_price_oracle_address == contract_address_const::<1995>(),
        'l1_gas_price_oracle_address'
    );
}

// set_l2_relayer

#[test]
#[should_panic(expected: ('Caller is not the owner',))]
fn test_set_l2_relayer_owner() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    fw.set_l2_relayer(contract_address_const::<1995>());
}

#[test]
#[should_panic(expected: ('ZERO_ADDRESS_ERROR',))]
fn test_set_l2_relayer_zero() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_l2_relayer(contract_address_const::<0>());
}

#[test]
fn test_set_l2_relayer() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    fw.set_l2_relayer(contract_address_const::<1995>());
    let l2_relayer = fw.get_l2_relayer();
    assert(l2_relayer == contract_address_const::<1995>(), 'l1_gas_price_oracle_address');
}


#[test]
#[should_panic(expected: ('Caller is not the owner',))]
fn test_register_token_owner() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 3.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 10000, high: 0 },
        period_threshold: 922,
        amount_threshold: 200,
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
}

#[test]
#[should_panic(expected: ('ZERO_ADDRESS_ERROR',))]
fn test_register_token_owner_zero_0() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<0>(),
        l1_fw: 3.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 10000, high: 0 },
        period_threshold: 922,
        amount_threshold: 200,
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
}

#[test]
#[should_panic(expected: ('ZERO_L1_ADDRESS_ERROR',))]
fn test_register_token_owner_zero_1() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 0.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 10000, high: 0 },
        period_threshold: 922,
        amount_threshold: 200,
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
}

#[test]
#[should_panic(expected: ('ZERO_AMOUNT_ERROR',))]
fn test_register_token_owner_zero_2() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 0, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 10000, high: 0 },
        period_threshold: 922,
        amount_threshold: 200,
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
}


#[test]
#[should_panic(expected: ('ZERO_AMOUNT_ERROR',))]
fn test_register_token_owner_zero_3() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 0, high: 0 },
        gas_unit_per_user: u256 { low: 10000, high: 0 },
        period_threshold: 922,
        amount_threshold: 200,
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
}

#[test]
#[should_panic(expected: ('INVALID_DEPOSIT_LIMIT_ERROR',))]
fn test_register_token_owner_zero_4() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 1000, high: 0 },
        gas_unit_per_user: u256 { low: 10000, high: 0 },
        period_threshold: 922,
        amount_threshold: 200,
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
}

#[test]
#[should_panic(expected: ('ZERO_AMOUNT_ERROR',))]
fn test_register_token_owner_zero_5() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 0, high: 0 },
        period_threshold: 922,
        amount_threshold: 200,
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
}

#[test]
#[should_panic(expected: ('ZERO_TIMESTAMP_ERROR',))]
fn test_register_token_owner_zero_6() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 0,
        amount_threshold: 200,
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
}

#[test]
#[should_panic(expected: ('ZERO_AMOUNT_ERROR',))]
fn test_register_token_owner_zero_7() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 0, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
}

#[test]
fn test_register_token() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    let info = fw.get_token_info_or_revert(contract_address_const::<1995>());
    assert(token_info == info, 'register_token');
}

// set_deposit_limit

#[test]
#[should_panic(expected: ('Caller is not the owner',))]
fn test_set_deposit_limit_owner() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<1>());
    fw
        .set_deposit_limit(
            contract_address_const::<1995>(), u256 { low: 10, high: 0 }, u256 { low: 2500, high: 0 }
        )
}


#[test]
#[should_panic(expected: ('ZERO_AMOUNT_ERROR',))]
fn test_set_deposit_limit_zero_0() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    fw
        .set_deposit_limit(
            contract_address_const::<1995>(), u256 { low: 0, high: 0 }, u256 { low: 1, high: 0 }
        )
}

#[test]
#[should_panic(expected: ('ZERO_AMOUNT_ERROR',))]
fn test_set_deposit_limit_zero_1() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    fw
        .set_deposit_limit(
            contract_address_const::<1995>(), u256 { low: 1, high: 0 }, u256 { low: 0, high: 0 }
        )
}

#[test]
#[should_panic(expected: ('ZERO_AMOUNT_ERROR',))]
fn test_set_deposit_limit_zero_2() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    fw
        .set_deposit_limit(
            contract_address_const::<1995>(), u256 { low: 1, high: 0 }, u256 { low: 0, high: 0 }
        )
}

#[test]
#[should_panic(expected: ('INVALID_DEPOSIT_LIMIT_ERROR',))]
fn test_set_deposit_limit_zero_3() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    fw
        .set_deposit_limit(
            contract_address_const::<1995>(), u256 { low: 3, high: 0 }, u256 { low: 2, high: 0 }
        )
}

#[test]
fn test_set_deposit_limit() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    fw
        .set_deposit_limit(
            contract_address_const::<1995>(), u256 { low: 2, high: 0 }, u256 { low: 3, high: 0 }
        );
    let info = fw.get_token_info_or_revert(contract_address_const::<1995>());
    let new_token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2, high: 0 },
        max_deposit: u256 { low: 3, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    assert(info == new_token_info, 'deposit_limit');
}


// set_gas_unit_per_user

#[test]
#[should_panic(expected: ('Caller is not the owner',))]
fn test_set_gas_unit_per_user_owner() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<1>());
    fw.set_gas_unit_per_user(contract_address_const::<1995>(), u256 { low: 3, high: 0 })
}


#[test]
#[should_panic(expected: ('ZERO_AMOUNT_ERROR',))]
fn test_set_gas_unit_per_user_zero() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    fw.set_gas_unit_per_user(contract_address_const::<1995>(), u256 { low: 0, high: 0 })
}

#[test]
fn test_set_gas_unit_per_user() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    fw.set_gas_unit_per_user(contract_address_const::<1995>(), u256 { low: 3, high: 0 });
    let info = fw.get_token_info_or_revert(contract_address_const::<1995>());
    let new_token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 3, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    assert(info == new_token_info, 'deposit_limit');
}


// set_rebalancing_threshold

#[test]
#[should_panic(expected: ('Caller is not the owner',))]
fn test_set_rebalancing_threshold_owner() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<1>());
    fw.set_rebalancing_threshold(contract_address_const::<1995>(), 2024, u256 { low: 3, high: 0 })
}

#[test]
#[should_panic(expected: ('ZERO_AMOUNT_ERROR',))]
fn test_set_rebalancing_threshold_zero_0() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    fw.set_rebalancing_threshold(contract_address_const::<1995>(), 2024, u256 { low: 0, high: 0 })
}

#[test]
#[should_panic(expected: ('ZERO_TIMESTAMP_ERROR',))]
fn test_set_rebalancing_threshold_zero_1() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    fw.set_rebalancing_threshold(contract_address_const::<1995>(), 0, u256 { low: 0, high: 5 })
}

#[test]
fn test_set_rebalancing_threshold() {
    let fw = deploy(
        10239,
        contract_address_const::<2300>(),
        contract_address_const::<2500>(),
        contract_address_const::<6500>(),
        3332,
        contract_address_const::<22>(),
        223,
        contract_address_const::<90>(),
        contract_address_const::<2900>()
    );
    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    fw.register_token(contract_address_const::<1995>(), token_info);
    fw.set_rebalancing_threshold(contract_address_const::<1995>(), 2024, u256 { low: 3, high: 0 });
    let info = fw.get_token_info_or_revert(contract_address_const::<1995>());
    let new_token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 2500, high: 0 },
        max_deposit: u256 { low: 5000, high: 0 },
        gas_unit_per_user: u256 { low: 20, high: 0 },
        period_threshold: 2024,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };
    assert(info == new_token_info, 'set_rebalancing_threshold');
}

#[test]
fn test_gas_to_token() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let usdc = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let pragma = deploy_mock_pragma();

    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 2
    };

    fw.register_token(usdc.contract_address, token_info);

    let gas_to_token = fw
        .gas_to_token(usdc.contract_address, u256 { low: 1000000000000000000, high: 0 });
    assert(gas_to_token == 2000000000000000000000, 'gas_to_token')
}


#[test]
fn test_gas_price() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let usdc = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let pragma = deploy_mock_pragma();

    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 2
    };

    fw.register_token(usdc.contract_address, token_info);

    let gas_to_token = fw
        .gas_to_token(usdc.contract_address, u256 { low: 1000000000000000000, high: 0 });
    assert(gas_to_token == 2000000000000000000000, 'gas_to_token');

    let (gas_fee, gas_fee_token) = fw.get_gas_fee(usdc.contract_address);
    let gas_fee_expected: u256 = 70000 * 24000000000;
    assert(gas_fee == gas_fee_expected, 'gas_fee_expected');
    assert(gas_fee_token == (gas_fee_expected * 2000), 'gas_fee_expected_token');
}

#[test]
#[should_panic(expected: ('DEPOSIT_FROZEN_ERROR',))]
fn test_deposit_fail_0() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let usdc = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let pragma = deploy_mock_pragma();

    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 2
    };

    fw.register_token(usdc.contract_address, token_info);

    let (gas_fee, gas_fee_token) = fw.get_gas_fee(usdc.contract_address);

    fw.set_allowed_freezer(contract_address_const::<2300>());
    fw.freeze_token_deposit(usdc.contract_address);
    usdc.approve(fw.contract_address, 10000000000000000000 + gas_fee_token);
    fw.deposit(usdc.contract_address, 10000000000000000000 + gas_fee_token, 100.try_into().unwrap());
}

#[test]
#[should_panic(expected: ('INVALID_DEPOSIT_ERROR',))]
fn test_deposit_fail_1() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let usdc = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let pragma = deploy_mock_pragma();

    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 2
    };

    fw.register_token(usdc.contract_address, token_info);

    let (gas_fee, gas_fee_token) = fw.get_gas_fee(usdc.contract_address);

    usdc.approve(fw.contract_address, 10000000000000000000 + gas_fee_token);
    fw.deposit(usdc.contract_address, 0, 100.try_into().unwrap());
}


#[test]
#[should_panic(expected: ('TOKEN_NOT_FOUND_ERROR',))]
fn test_deposit_fail_2() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let usdc = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());
    let rdm = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let pragma = deploy_mock_pragma();

    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 2
    };

    fw.register_token(usdc.contract_address, token_info);

    let (gas_fee, gas_fee_token) = fw.get_gas_fee(usdc.contract_address);

    usdc.approve(fw.contract_address, 10000000000000000000 + gas_fee_token);
    fw.deposit(rdm.contract_address, 800, 100.try_into().unwrap());
}

#[test]
#[should_panic(expected: ('INVALID_DEPOSIT_ERROR',))]
fn test_deposit_fail_3() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let usdc = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let pragma = deploy_mock_pragma();

    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 5, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 2
    };

    fw.register_token(usdc.contract_address, token_info);

    let (gas_fee, gas_fee_token) = fw.get_gas_fee(usdc.contract_address);

    usdc.approve(fw.contract_address, 10000000000000000000 + gas_fee_token);
    fw.deposit(usdc.contract_address, 1, 100.try_into().unwrap());
}


#[test]
#[should_panic(expected: ('INVALID_DEPOSIT_ERROR',))]
fn test_deposit_fail_4() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let usdc = deploy_token(contract, 1000000000000000000, contract_address_const::<2500>());

    let pragma = deploy_mock_pragma();

    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 5, high: 0 },
        max_deposit: u256 { low: 15, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 2
    };

    fw.register_token(usdc.contract_address, token_info);

    let (gas_fee, gas_fee_token) = fw.get_gas_fee(usdc.contract_address);

    usdc.approve(fw.contract_address, 10000000000000000000 + gas_fee_token);
    fw.deposit(usdc.contract_address, 20, 100.try_into().unwrap());
}

#[test]
fn test_deposit() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 100000000000000000000000, contract_address_const::<2300>());

    let usdc = deploy_token(contract, 100000000000000000000000, contract_address_const::<2300>());

    let pragma = deploy_mock_pragma();

    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 10000000000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 2
    };

    fw.register_token(usdc.contract_address, token_info);

    let (gas_fee, gas_fee_token) = fw.get_gas_fee(usdc.contract_address);
    let owner_balance_usdc = usdc.balanceOf(contract_address_const::<2300>());
    let owner_balance_gas_token = token_gas.balanceOf(contract_address_const::<2300>());
    start_prank(CheatTarget::One(usdc.contract_address), contract_address_const::<2300>());
    usdc.approve(fw.contract_address, 10000000000000000000);
    stop_prank(CheatTarget::One(usdc.contract_address));
    fw.deposit(usdc.contract_address, 10000000000000000000, 100.try_into().unwrap());

    let gas_fee_relayer_balance = usdc.balanceOf(contract_address_const::<22>());
    assert(gas_fee_relayer_balance == gas_fee_token, 'invalid_gas_fees');

    let acc_token = fw.get_accumulated_token(usdc.contract_address);
    assert(acc_token == 10000000000000000000 - gas_fee_token, 'invalid_acc_tokens');
}



#[test]
#[should_panic(expected: ('BATCH_FROZEN_ERROR',))]
fn test_batch_fail_0() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 100000000000000000000000, contract_address_const::<2300>());

    let usdc = deploy_token(contract, 100000000000000000000000, contract_address_const::<2300>());

    let pragma = deploy_mock_pragma();

    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 10000000000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 2
    };
    fw.register_token(usdc.contract_address, token_info);
    fw.freeze_batch(usdc.contract_address);
    stop_prank(CheatTarget::One(fw.contract_address));
    fw.batch(usdc.contract_address);
}


#[test]
#[should_panic(expected: ('REBALANCE_UNAVAILABLE_ERROR',))]
fn test_batch_fail_1() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 100000000000000000000000, contract_address_const::<2300>());

    let usdc = deploy_token(contract, 100000000000000000000000, contract_address_const::<2300>());

    let pragma = deploy_mock_pragma();

    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 10000000000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 2
    };
    fw.register_token(usdc.contract_address, token_info);
    stop_prank(CheatTarget::One(fw.contract_address));
    fw.batch(usdc.contract_address);
}


#[test]
#[should_panic(expected: ('REBALANCE_UNAVAILABLE_ERROR',))]
fn test_batch_fail_2() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 100000000000000000000000, contract_address_const::<2300>());

    let usdc = deploy_token(contract, 100000000000000000000000, contract_address_const::<2300>());

    let pragma = deploy_mock_pragma();

    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 10000000000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 20000000000000000000, high: 0 },
        pricefeed_key: 2
    };
    fw.register_token(usdc.contract_address, token_info);

    let (gas_fee, gas_fee_token) = fw.get_gas_fee(usdc.contract_address);
    let owner_balance_usdc = usdc.balanceOf(contract_address_const::<2300>());
    let owner_balance_gas_token = token_gas.balanceOf(contract_address_const::<2300>());
    start_prank(CheatTarget::One(usdc.contract_address), contract_address_const::<2300>());
    usdc.approve(fw.contract_address, 10000000000000000000 + gas_fee_token);
    stop_prank(CheatTarget::One(usdc.contract_address));
    start_warp(CheatTarget::One(fw.contract_address), 1000);
    fw.deposit(usdc.contract_address, 10000000000000000000, 100.try_into().unwrap());
    stop_prank(CheatTarget::One(fw.contract_address));
    start_warp(CheatTarget::One(fw.contract_address), 1002);
    fw.batch(usdc.contract_address);
}


#[test]
#[should_panic(expected: ('REBALANCE_UNAVAILABLE_ERROR',))]
fn test_batch() {
    let contract = declare('TokenMock');

    // Deploy tokens
    let token_gas = deploy_token(contract, 100000000000000000000000, contract_address_const::<2300>());

    let usdc = deploy_token(contract, 100000000000000000000000, contract_address_const::<2300>());

    let pragma = deploy_mock_pragma();

    let token_bridge = deploy_token_bridge(usdc.contract_address, 6373);


    pragma
        .set_data_median(
            1,
            PragmaPricesResponse {
                price: 200000000000_u128,
                decimals: 8,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    pragma
        .set_data_median(
            2,
            PragmaPricesResponse {
                price: 1000000_u128,
                decimals: 6,
                last_updated_timestamp: 100,
                num_sources_aggregated: 2,
                expiration_timestamp: Option::None
            }
        );

    // Deploy Gas GasOracle
    let gas_oracle = deploy_gas_oracle(
        contract_address_const::<2500>(), contract_address_const::<2500>(), 24000000000
    ); // 24 GWei

    // Deploy FW
    let fw = deploy(
        10000000000000000, // 10**16 fees
        contract_address_const::<2300>(),
        token_gas.contract_address,
        gas_oracle.contract_address,
        0x02b36f46b7114008b5cacc0021e919d4303c396beea93c03111312b4a273388f,
        contract_address_const::<22>(),
        100000000000000000, // 10% Protocol fees
        contract_address_const::<90>(),
        pragma.contract_address
    );

    start_prank(CheatTarget::One(fw.contract_address), contract_address_const::<2300>());
    let token_info_gas = TokenInfo {
        bridge: token_bridge.contract_address,
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 150000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 12,
        amount_threshold: u256 { low: 3, high: 0 },
        pricefeed_key: 1
    };

    fw.register_token(token_gas.contract_address, token_info_gas);
    // Register token
    let token_info = TokenInfo {
        bridge: contract_address_const::<2>(),
        l1_fw: 2.try_into().unwrap(),
        min_deposit: u256 { low: 1, high: 0 },
        max_deposit: u256 { low: 10000000000000000000000000, high: 0 },
        gas_unit_per_user: u256 { low: 70000, high: 0 },
        period_threshold: 2023,
        amount_threshold: u256 { low: 10000000000000000, high: 0 },
        pricefeed_key: 2
    };
    fw.register_token(usdc.contract_address, token_info);

    let (gas_fee, gas_fee_token) = fw.get_gas_fee(usdc.contract_address);
    let owner_balance_usdc = usdc.balanceOf(contract_address_const::<2300>());
    let owner_balance_gas_token = token_gas.balanceOf(contract_address_const::<2300>());
    start_prank(CheatTarget::One(usdc.contract_address), contract_address_const::<2300>());
    usdc.approve(fw.contract_address, 10000000000000000000 + gas_fee_token);
    stop_prank(CheatTarget::One(usdc.contract_address));
    start_warp(CheatTarget::One(fw.contract_address), 1000);
    fw.deposit(usdc.contract_address, 10000000000000000000, 100.try_into().unwrap());
    stop_prank(CheatTarget::One(fw.contract_address));
    start_warp(CheatTarget::One(fw.contract_address), 1002);
    fw.batch(usdc.contract_address);

    let protocol_fee_recipient_balance = usdc.balanceOf(contract_address_const::<90>());
    assert(protocol_fee_recipient_balance == 10000000000000000, 'invalid_protocol_fees'); // 1% * 10%

    let acc_token = fw.get_accumulated_token(usdc.contract_address);
    assert(acc_token == 0, 'invalid_acc_tokens');

    let last_ts = fw.get_last_init_timestamp(usdc.contract_address);
    assert(last_ts == 0, 'invalid_last_ts');

    let rebalance_batch_counter = fw.get_rebalance_batch_counter(usdc.contract_address);
    assert(rebalance_batch_counter == 1, 'invalid_rebalance_batch_counter');
}