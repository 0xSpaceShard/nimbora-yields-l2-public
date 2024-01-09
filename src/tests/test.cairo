// Nimbora yields contracts
use nimbora_yields::pooling_manager::pooling_manager::{PoolingManager};
use nimbora_yields::pooling_manager::interface::{
    IPoolingManagerDispatcher, IPoolingManagerDispatcherTrait, StrategyReportL1
};
use nimbora_yields::factory::factory::{Factory};
use nimbora_yields::factory::interface::{IFactoryDispatcher, IFactoryDispatcherTrait};
use nimbora_yields::token_manager::token_manager::{TokenManager};
use nimbora_yields::token_manager::interface::{
    ITokenManagerDispatcher, ITokenManagerDispatcherTrait, WithdrawalInfo, StrategyReportL2
};

// Utils peripheric contracts
use nimbora_yields::token_bridge::token_bridge::{TokenBridge};
use nimbora_yields::token_bridge::token_mock::{TokenMock};
use nimbora_yields::token_bridge::interface::{
    ITokenBridgeDispatcher, IMintableTokenDispatcher, IMintableTokenDispatcherTrait
};

use openzeppelin::{
    token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
    access::accesscontrol::{
        AccessControlComponent, interface::{IAccessControlDispatcher, IAccessControlDispatcherTrait}
    }
};

use starknet::{
    get_contract_address, deploy_syscall, ClassHash, contract_address_const, ContractAddress,
    get_block_timestamp, EthAddress, Zeroable
};
use starknet::class_hash::Felt252TryIntoClassHash;
use starknet::account::{Call};
use snforge_std::{
    declare, ContractClassTrait, start_prank, CheatTarget, ContractClass, PrintTrait, stop_prank,
    start_warp, stop_warp
};


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

    return (
        ERC20ABIDispatcher { contract_address: contract_address_1 },
        ERC20ABIDispatcher { contract_address: contract_address_2 },
        ERC20ABIDispatcher { contract_address: contract_address_3 }
    );
}


fn deploy_token_bridge(
    l2_address_1: ContractAddress,
    l1_bridge_1: felt252,
    l2_address_2: ContractAddress,
    l1_bridge_2: felt252,
    l2_address_3: ContractAddress,
    l1_bridge_3: felt252
) -> (ITokenBridgeDispatcher, ITokenBridgeDispatcher, ITokenBridgeDispatcher) {
    let contract = declare('TokenBridge');

    let mut constructor_args_1: Array<felt252> = ArrayTrait::new();
    Serde::serialize(@l2_address_1, ref constructor_args_1);
    Serde::serialize(@l1_bridge_1, ref constructor_args_1);
    let contract_address_1 = contract.deploy(@constructor_args_1).unwrap();

    let mut constructor_args_2: Array<felt252> = ArrayTrait::new();
    Serde::serialize(@l2_address_2, ref constructor_args_2);
    Serde::serialize(@l1_bridge_2, ref constructor_args_2);
    let contract_address_2 = contract.deploy(@constructor_args_2).unwrap();

    let mut constructor_args_3: Array<felt252> = ArrayTrait::new();
    Serde::serialize(@l2_address_3, ref constructor_args_3);
    Serde::serialize(@l1_bridge_3, ref constructor_args_3);
    let contract_address_3 = contract.deploy(@constructor_args_3).unwrap();

    return (
        ITokenBridgeDispatcher { contract_address: contract_address_1 },
        ITokenBridgeDispatcher { contract_address: contract_address_2 },
        ITokenBridgeDispatcher { contract_address: contract_address_3 }
    );
}

fn deploy_pooling_manager(owner: ContractAddress) -> IPoolingManagerDispatcher {
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
) -> IFactoryDispatcher {
    let contract = declare('Factory');
    let mut constructor_args: Array<felt252> = ArrayTrait::new();
    Serde::serialize(@pooling_manager, ref constructor_args);
    Serde::serialize(@token_class_hash, ref constructor_args);
    Serde::serialize(@token_manager_class_hash, ref constructor_args);
    let contract_address = contract.deploy(@constructor_args).unwrap();
    return IFactoryDispatcher { contract_address: contract_address };
}

fn setup() -> (ContractAddress, IPoolingManagerDispatcher, IFactoryDispatcher) {
    let owner = contract_address_const::<2300>();
    let pooling_manager = deploy_pooling_manager(owner);
    let token_hash = declare('Token');
    let token_manager_hash = declare('TokenManager');
    let factory = deploy_factory(pooling_manager.contract_address, token_hash.class_hash, token_manager_hash.class_hash);
    (owner, pooling_manager, factory)
}


#[test]
fn test_setup() {
    ///let (owner, pooling_manager, factory) = setup();
    ///let pooling_manager_access_disp = IAccessControlDispatcher{ contract_address: pooling_manager.contract_address };
    ///let has_role = pooling_manager_access_disp.has_role(0, owner);
    ///assert(has_role == true, 'Invalid owner role');
    let owner = contract_address_const::<2300>();
    let pooling_manager = deploy_pooling_manager(owner);
    let pooling_manager_access_disp = IAccessControlDispatcher{ contract_address: pooling_manager.contract_address };
    let eee = pooling_manager_access_disp.has_role(0, owner);  
    let has_role = pooling_manager.factory();  
    assert(has_role.is_zero(), 'Invalid owner role');
}

