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
    initial_supply: u256, recipient: ContractAddress
) -> (ERC20ABIDispatcher, ERC20ABIDispatcher, ERC20ABIDispatcher) {
    let contract = declare('TokenMock');

    let mut constructor_args: Array<felt252> = ArrayTrait::new();
    Serde::serialize(@initial_supply, ref constructor_args);
    Serde::serialize(@recipient, ref constructor_args);
    let contract_address_1 = contract.deploy(@constructor_args).unwrap();
    let contract_address_2 = contract.deploy(@constructor_args).unwrap();
    let contract_address_3 = contract.deploy(@constructor_args).unwrap();

    return (
        ERC20ABIDispatcher { contract_address: contract_address_1 },
        ERC20ABIDispatcher { contract_address: contract_address_2 },
        ERC20ABIDispatcher { contract_address: contract_address_3 }
    );
}


fn deploy_token_bridges(
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

fn setup_0() -> (
    ContractAddress,
    ContractAddress,
    EthAddress,
    IPoolingManagerDispatcher,
    IFactoryDispatcher,
    ClassHash,
    ClassHash
) {
    let owner = contract_address_const::<2300>();
    let fees_recipient = contract_address_const::<2400>();
    let l1_pooling_manager: EthAddress = 1.try_into().unwrap();
    let pooling_manager = deploy_pooling_manager(owner);
    let token_hash = declare('Token');
    let token_manager_hash = declare('TokenManager');
    let factory = deploy_factory(
        pooling_manager.contract_address, token_hash.class_hash, token_manager_hash.class_hash
    );
    (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash.class_hash,
        token_manager_hash.class_hash
    )
}

#[test]
fn deploy() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    // Constructor state update test
    let pooling_manager_access_disp = IAccessControlDispatcher {
        contract_address: pooling_manager.contract_address
    };
    let has_role = pooling_manager_access_disp.has_role(0, owner);
    let token_hash_from_pooling_manager = factory.token_class_hash();
    let token_manager_from_pooling_manager = factory.token_manager_class_hash();
    assert(has_role == true, 'Invalid owner role');
    assert(token_hash_from_pooling_manager == token_hash, 'Invalid token hash');
    assert(token_manager_from_pooling_manager == token_manager_hash, 'Invalid token manager hash');
}


#[test]
#[should_panic(expected: ('Caller is missing role',))]
fn set_fees_recipient_wrong_caller() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    pooling_manager.set_fees_recipient(fees_recipient);
}

#[test]
#[should_panic(expected: ('Zero address',))]
fn set_fees_recipient_zero_address() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.set_fees_recipient(Zeroable::zero());
    stop_prank(CheatTarget::One(pooling_manager.contract_address));
}

#[test]
fn set_fees_recipient() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.set_fees_recipient(fees_recipient);
    stop_prank(CheatTarget::One(pooling_manager.contract_address));

    let fees_recipient_from_pooling_manager = pooling_manager.fees_recipient();
    assert(fees_recipient_from_pooling_manager == fees_recipient, 'invalid fees recipient');
}

#[test]
#[should_panic(expected: ('Caller is missing role',))]
fn set_l1_pooling_manager_wrong_caller() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    pooling_manager.set_l1_pooling_manager(l1_pooling_manager);
}

#[test]
#[should_panic(expected: ('Zero address',))]
fn set_l1_pooling_manager_zero_address() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.set_l1_pooling_manager(Zeroable::zero());
    stop_prank(CheatTarget::One(pooling_manager.contract_address));
}

#[test]
fn set_l1_pooling_manager() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.set_l1_pooling_manager(l1_pooling_manager);
    stop_prank(CheatTarget::One(pooling_manager.contract_address));

    let l1_pooling_manager_from_pooling_manager = pooling_manager.l1_pooling_manager();
    assert(
        l1_pooling_manager_from_pooling_manager == l1_pooling_manager, 'invalid l1 pooling manager'
    );
}

#[test]
#[should_panic(expected: ('Caller is missing role',))]
fn set_factory_wrong_caller() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    pooling_manager.set_factory(factory.contract_address);
}

#[test]
#[should_panic(expected: ('Zero address',))]
fn set_factory_zero_address() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.set_factory(Zeroable::zero());
    stop_prank(CheatTarget::One(pooling_manager.contract_address));
}

#[test]
fn set_factory() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.set_factory(factory.contract_address);
    stop_prank(CheatTarget::One(pooling_manager.contract_address));

    let factory_from_pooling_manager = pooling_manager.factory();
    assert(factory_from_pooling_manager == factory.contract_address, 'invalid factory');
}

#[test]
#[should_panic(expected: ('Not initialised',))]
fn handle_mass_report_not_initialised() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    let empty_array: Array<StrategyReportL1> = ArrayTrait::new();
    pooling_manager.handle_mass_report(empty_array.span());
}

#[test]
fn is_initialised() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.set_factory(factory.contract_address);
    pooling_manager.set_fees_recipient(fees_recipient);
    pooling_manager.set_l1_pooling_manager(l1_pooling_manager);
    stop_prank(CheatTarget::One(pooling_manager.contract_address));

    let is_initialised = pooling_manager.is_initialised();
    assert(is_initialised == true, 'initialisation failed');
}

fn setup_1(
    owner: ContractAddress,
    l1_pooling_manager: EthAddress,
    pooling_manager: IPoolingManagerDispatcher,
    fees_recipient: ContractAddress,
    factory: IFactoryDispatcher
) -> (
    ERC20ABIDispatcher,
    ERC20ABIDispatcher,
    ERC20ABIDispatcher,
    ITokenBridgeDispatcher,
    ITokenBridgeDispatcher,
    ITokenBridgeDispatcher
) {
    // Initialise
    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.set_fees_recipient(fees_recipient);
    pooling_manager.set_l1_pooling_manager(l1_pooling_manager);
    pooling_manager.set_factory(factory.contract_address);
    stop_prank(CheatTarget::One(pooling_manager.contract_address));

    // Deploy tokens and bridges
    let (l1_bridge_1, l1_bridge_2, l1_bridge_3) = (
        111.try_into().unwrap(), 112.try_into().unwrap(), 113.try_into().unwrap()
    );
    let (token_1, token_2, token_3) = deploy_tokens(1000000000000000000, owner);
    let (bridge_1, bridge_2, bridge_3) = deploy_token_bridges(
        token_1.contract_address,
        l1_bridge_1,
        token_2.contract_address,
        l1_bridge_2,
        token_3.contract_address,
        l1_bridge_3
    );
    (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3)
}


#[test]
#[should_panic(expected: ('Invalid caller',))]
fn set_token_class_hash_wrong_caller() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    factory.set_token_class_hash(token_hash);
}

#[test]
#[should_panic(expected: ('Hash is zero',))]
fn set_token_class_hash_zero_hash() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    start_prank(CheatTarget::One(factory.contract_address), owner);
    factory.set_token_class_hash(Zeroable::zero());
    stop_prank(CheatTarget::One(factory.contract_address));
}

#[test]
fn set_token_class_hash() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
        owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
    );

    start_prank(CheatTarget::One(factory.contract_address), owner);
    factory.set_token_class_hash(token_manager_hash);
    stop_prank(CheatTarget::One(factory.contract_address));

    let token_class_hash_from_factory = factory.token_class_hash();
    assert(token_class_hash_from_factory == token_manager_hash, 'invalid token class hash')
}

#[test]
#[should_panic(expected: ('Invalid caller',))]
fn set_token_manager_class_hash_wrong_caller() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    factory.set_token_manager_class_hash(token_hash);
}

#[test]
#[should_panic(expected: ('Hash is zero',))]
fn set_token_manager_class_hash_zero_hash() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    start_prank(CheatTarget::One(factory.contract_address), owner);
    factory.set_token_manager_class_hash(Zeroable::zero());
    stop_prank(CheatTarget::One(factory.contract_address));
}

#[test]
fn set_token_manager_class_hash() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
        owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
    );

    start_prank(CheatTarget::One(factory.contract_address), owner);
    factory.set_token_manager_class_hash(token_hash);
    stop_prank(CheatTarget::One(factory.contract_address));

    let token_manager_class_hash_from_factory = factory.token_manager_class_hash();
    assert(token_manager_class_hash_from_factory == token_hash, 'invalid token class hash')
}


#[test]
#[should_panic(expected: ('Caller is missing role',))]
fn register_underlying_wrong_caller() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
        owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
    );
    pooling_manager.register_underlying(token_1.contract_address, bridge_1.contract_address);
}

#[test]
#[should_panic(expected: ('Zero address',))]
fn register_underlying_zero_address_1() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
        owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
    );

    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.register_underlying(Zeroable::zero(), bridge_1.contract_address);
    stop_prank(CheatTarget::One(pooling_manager.contract_address));
}

#[test]
#[should_panic(expected: ('Zero address',))]
fn register_underlying_zero_address_2() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
        owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
    );

    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.register_underlying(token_1.contract_address, Zeroable::zero());
    stop_prank(CheatTarget::One(pooling_manager.contract_address));
}

#[test]
fn register_underlying() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
        owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
    );

    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.register_underlying(token_1.contract_address, bridge_1.contract_address);
    stop_prank(CheatTarget::One(pooling_manager.contract_address));

    let underlying_to_bridge = pooling_manager.underlying_to_bridge(token_1.contract_address);
    assert(underlying_to_bridge == bridge_1.contract_address, 'wrong bridge for underlying')
}


fn setup_2(
    pooling_manager: IPoolingManagerDispatcher,
    owner: ContractAddress,
    token_1: ContractAddress,
    token_2: ContractAddress,
    token_3: ContractAddress,
    bridge_1: ContractAddress,
    bridge_2: ContractAddress,
    bridge_3: ContractAddress
) {
    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
    pooling_manager.register_underlying(token_1, bridge_1);
    pooling_manager.register_underlying(token_2, bridge_2);
    pooling_manager.register_underlying(token_3, bridge_3);
    stop_prank(CheatTarget::One(pooling_manager.contract_address));
}


#[test]
#[should_panic(expected: ('Invalid caller',))]
fn deploy_strategy_wrong_caller() {
    let (
        owner,
        fees_recipient,
        l1_pooling_manager,
        pooling_manager,
        factory,
        token_hash,
        token_manager_hash
    ) =
        setup_0();
    let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
        owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
    );
    setup_2(
        pooling_manager,
        owner,
        token_1.contract_address,
        token_2.contract_address,
        token_3.contract_address,
        bridge_1.contract_address,
        bridge_2.contract_address,
        bridge_3.contract_address
    );
    let l1_strategy_1: EthAddress = 2.try_into().unwrap();
    let performance_fees_strategy_1 = 200000000000000000;
    let min_deposit_1 = 100000000000000000;
    let max_deposit_1 = 10000000000000000000;
    let min_withdraw_1 = 200000000000000000;
    let max_withdraw_1 = 2000000000000000000000000;
    let withdrawal_epoch_delay_1 = 2;
    let dust_limit_1 = 1000000000000000000;
    let name_1 = 10;
    let symbol_1 = 1000;
    factory
        .deploy_strategy(
            l1_strategy_1,
            token_1.contract_address,
            name_1,
            symbol_1,
            performance_fees_strategy_1,
            min_deposit_1,
            max_deposit_1,
            min_withdraw_1,
            max_withdraw_1,
            withdrawal_epoch_delay_1,
            dust_limit_1
        );
}
//fn setup_full(owner: ContractAddress, pooling_manager: IPoolingManagerDispatcher, factory: IFactoryDispatcher, token_1: ERC20ABIDispatcher, token_2: ERC20ABIDispatcher, token_3: ERC20ABIDispatcher, bridge_1: ITokenBridgeDispatcher, bridge_2: ITokenBridgeDispatcher, bridge_3: ITokenBridgeDispatcher) -> (ContractAddress, ContractAddress, ContractAddress, ContractAddress, ContractAddress, ContractAddress) {
//    // Register underlyings
//    start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
//    pooling_manager.register_underlying(token_1.contract_address, bridge_1.contract_address);
//    pooling_manager.register_underlying(token_2.contract_address, bridge_2.contract_address);
//    pooling_manager.register_underlying(token_3.contract_address, bridge_3.contract_address);
//    stop_prank(CheatTarget::One(pooling_manager.contract_address));
//
//    // Deploy and register strategies
//    let l1_strategy_1 : EthAddress = 2.try_into().unwrap();
//    let l1_strategy_2 : EthAddress = 3.try_into().unwrap();
//    let l1_strategy_3 : EthAddress= 4.try_into().unwrap();
//    let (performance_fees_strategy_1, performance_fees_strategy_2, performance_fees_strategy_3) = (200000000000000000, 400000000000000000, 100000000000000000);
//    let (min_deposit_1, min_deposit_2, min_deposit_3) = (100000000000000000, 200000000000000000, 300000000000000000);
//    let (max_deposit_1, max_deposit_2, max_deposit_3) = (10000000000000000000, 20000000000000000000, 30000000000000000000);
//    let (min_withdraw_1, min_withdraw_2, min_withdraw_3) = (200000000000000000, 400000000000000000, 600000000000000000);
//    let (max_withdraw_1, max_withdraw_2, max_withdraw_3) = (20000000000000000000, 40000000000000000000, 60000000000000000000);
//    let (withdrawal_epoch_delay_1, withdrawal_epoch_delay_2, withdrawal_epoch_delay_3) = (2, 3, 4);
//    let (dust_limit_1, dust_limit_2, dust_limit_3) = (1000000000000000000, 2000000000000000000, 3000000000000000000);
//    let (name_1, name_2, name_3) = (10, 20, 30);
//    let (symbol_1, symbol_2, symbol_3) = (1000, 2000, 3000);
//
//    start_prank(CheatTarget::One(factory.contract_address), owner);
//    let (nimbora_token_manager_1, nimbora_token_1) = factory.deploy_strategy(l1_strategy_1, token_1.contract_address, name_1, symbol_1, performance_fees_strategy_1, min_deposit_1, max_deposit_1, min_withdraw_1, max_withdraw_1, withdrawal_epoch_delay_1, dust_limit_1);
//    let (nimbora_token_manager_2, nimbora_token_2) = factory.deploy_strategy(l1_strategy_2, token_2.contract_address, name_2, symbol_2, performance_fees_strategy_2, min_deposit_2, max_deposit_2, min_withdraw_2, max_withdraw_2, withdrawal_epoch_delay_2, dust_limit_2);
//    let (nimbora_token_manager_3, nimbora_token_3) = factory.deploy_strategy(l1_strategy_3, token_3.contract_address, name_3, symbol_3, performance_fees_strategy_3, min_deposit_3, max_deposit_3, min_withdraw_3, max_withdraw_3, withdrawal_epoch_delay_3, dust_limit_3);
//    stop_prank(CheatTarget::One(factory.contract_address));
//    (nimbora_token_manager_1, nimbora_token_manager_2, nimbora_token_manager_3, nimbora_token_1, nimbora_token_2, nimbora_token_3)
//}


