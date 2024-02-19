#[cfg(test)]
mod testFactory {
    use core::fmt::Formatter;
    use core::option::OptionTrait;
    use core::traits::Into;
    use core::traits::TryInto;
    use nimbora_yields::factory::factory::{Factory};
    use nimbora_yields::factory::interface::{IFactoryDispatcher, IFactoryDispatcherTrait};
    use nimbora_yields::pooling_manager::interface::{
        IPoolingManagerDispatcher, IPoolingManagerDispatcherTrait, StrategyReportL1
    };
    // Nimbora yields contracts
    use nimbora_yields::pooling_manager::pooling_manager::{PoolingManager};

    use nimbora_yields::tests::test_utils::{
        deploy_tokens, deploy_factory, deploy_pooling_manager, deploy_strategy, setup_0, setup_1, setup_2
    };
    use nimbora_yields::token_bridge::interface::{
        ITokenBridgeDispatcher, IMintableTokenDispatcher, IMintableTokenDispatcherTrait
    };

    // Utils peripheric contracts
    use nimbora_yields::token_bridge::token_bridge::{TokenBridge};
    use nimbora_yields::token_manager::interface::{
        ITokenManagerDispatcher, ITokenManagerDispatcherTrait, WithdrawalInfo, StrategyReportL2
    };
    use nimbora_yields::token_manager::token_manager::{TokenManager};

    use openzeppelin::{
        token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
        access::accesscontrol::{
            AccessControlComponent, interface::{IAccessControlDispatcher, IAccessControlDispatcherTrait}
        },
        upgrades::interface::{IUpgradeableDispatcher, IUpgradeable, IUpgradeableDispatcherTrait}
    };
    use snforge_std::{
        declare, ContractClassTrait, get_class_hash, start_prank, CheatTarget, ContractClass, PrintTrait, stop_prank,
        start_warp, stop_warp
    };
    use starknet::account::{Call};
    use starknet::class_hash::Felt252TryIntoClassHash;

    use starknet::{
        get_contract_address, deploy_syscall, ClassHash, contract_address_const, ContractAddress, get_block_timestamp,
        EthAddress, Zeroable
    };

    #[test]
    fn deploy() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let pooling_manager_from_factory = factory.pooling_manager();
        assert(pooling_manager_from_factory == pooling_manager.contract_address, 'Invalid pooling manager');
        let pooling_manager_access_disp = IAccessControlDispatcher {
            contract_address: pooling_manager.contract_address
        };
        let has_role = pooling_manager_access_disp.has_role(0, owner);
        let token_hash_from_factory = factory.token_class_hash();
        let token_manager_from_factory = factory.token_manager_class_hash();
        assert(has_role == true, 'Invalid owner role');
        assert(token_hash_from_factory == token_hash, 'Invalid token hash');
        assert(token_manager_from_factory == token_manager_hash, 'Invalid token manager hash');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn set_token_class_hash_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        factory.set_token_class_hash(token_hash);
    }

    #[test]
    #[should_panic(expected: ('Hash is zero',))]
    fn set_token_class_hash_zero_hash() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(factory.contract_address), owner);
        factory.set_token_class_hash(Zeroable::zero());
        stop_prank(CheatTarget::One(factory.contract_address));
    }

    #[test]
    fn set_token_class_hash() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
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
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        factory.set_token_manager_class_hash(token_hash);
    }

    #[test]
    #[should_panic(expected: ('Hash is zero',))]
    fn set_token_manager_class_hash_zero_hash() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(factory.contract_address), owner);
        factory.set_token_manager_class_hash(Zeroable::zero());
        stop_prank(CheatTarget::One(factory.contract_address));
    }

    #[test]
    fn set_token_manager_class_hash() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
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
    #[should_panic(expected: ('Invalid caller',))]
    fn deploy_strategy_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        factory.deploy_strategy(0.try_into().unwrap(), 0.try_into().unwrap(), 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }

    #[test]
    fn deploy_strategy_test() {
        deploy_strategy();
    }

    #[test]
    fn upgrade_factory() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(factory.contract_address), owner);
        let mock_contract = declare('MockRandom');
        let old_class_hash = get_class_hash(factory.contract_address);
        IUpgradeableDispatcher { contract_address: factory.contract_address }.upgrade(mock_contract.class_hash);
        assert(get_class_hash(factory.contract_address) == mock_contract.class_hash, 'Incorrect class hash');
        stop_prank(CheatTarget::One(factory.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn upgrade_factory_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let mock_contract = declare('MockRandom');
        let old_class_hash = get_class_hash(factory.contract_address);
        IUpgradeableDispatcher { contract_address: factory.contract_address }.upgrade(mock_contract.class_hash);
    }

    #[test]
    #[should_panic(expected: ('Class hash cannot be zero',))]
    fn upgrade_factory_zero_class_hash() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(factory.contract_address), owner);
        let old_class_hash = get_class_hash(factory.contract_address);
        IUpgradeableDispatcher { contract_address: factory.contract_address }.upgrade(Zeroable::zero());
        stop_prank(CheatTarget::One(factory.contract_address));
    }

    #[test]
    fn compute_salt_for_strategy_test() {
        let l1_strategy_1: EthAddress = 2.try_into().unwrap();
        let underlying: ContractAddress = 3.try_into().unwrap();
        let token_name: felt252 = 'SALT TEST';
        let token_symbol: felt252 = 'TST';

        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(factory.contract_address), owner);

        let (token_manager_salt, token_salt) = factory
            .compute_salt_for_strategy(l1_strategy_1, underlying, token_name, token_symbol);
        stop_prank(CheatTarget::One(factory.contract_address));
        assert(
            token_manager_salt == 3507869891580383237970689100696794466542664252822280202621281872691686091895,
            'Wrong Token Manager salt'
        );
        assert(
            token_salt == 3305534806328825153934527835553716725195638617032434864480544972300445592680,
            'Wrong Token salt'
        );
    }

    #[test]
    fn compute_salt_for_strategy_large_data() {
        let l1_strategy_1: EthAddress = 2.try_into().unwrap();
        let underlying: ContractAddress = 3.try_into().unwrap();
        let token_name: felt252 = 0 - 1; // MAX_FELT252
        let token_symbol: felt252 = 0 - 1; // MAX_FELT252

        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(factory.contract_address), owner);
        let (token_manager_salt, token_salt) = factory
            .compute_salt_for_strategy(l1_strategy_1, underlying, token_name, token_symbol);
        stop_prank(CheatTarget::One(factory.contract_address));
        assert(
            token_manager_salt == 3507869891580383237970689100696794466542664252822280202621281872691686091895,
            'Wrong Token Manager salt'
        );
        assert(
            token_salt == 460088522663583137184306939526693975980690994165448964699804522180012853325,
            'Wrong Token salt'
        );
    }
}
