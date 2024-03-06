#[cfg(test)]
mod testPoolingManager {
    use core::array::ArrayTrait;
    use core::num::traits::one::One;
    use core::num::traits::zero::Zero;
    use core::option::OptionTrait;
    use core::result::ResultTrait;
    use core::traits::Into;
    use core::traits::TryInto;
    use nimbora_yields::factory::factory::{Factory};
    use nimbora_yields::factory::interface::{IFactoryDispatcher, IFactoryDispatcherTrait};
    use nimbora_yields::pooling_manager::interface::{
        BridgeInteractionInfo, IPoolingManagerDispatcher, IPoolingManagerDispatcherTrait, StrategyReportL1
    };
    // Nimbora yields contracts
    use nimbora_yields::pooling_manager::pooling_manager::{PoolingManager};

    use nimbora_yields::tests::test_utils::{
        deploy_tokens, deploy_factory, deploy_pooling_manager, deploy_strategy, setup_0, setup_1, setup_2, between,
        deposit_and_handle_mass, deploy_two_strategy
    };
    use nimbora_yields::token_bridge::interface::{
        ITokenBridgeDispatcher, IMintableTokenDispatcher, IMintableTokenDispatcherTrait
    };

    // Utils peripheric contracts
    use nimbora_yields::token_bridge::token_bridge::{TokenBridge};
    use nimbora_yields::token_bridge::token_mock::{TokenMock};
    use nimbora_yields::token_manager::interface::{
        ITokenManagerDispatcher, ITokenManagerDispatcherTrait, WithdrawalInfo, StrategyReportL2
    };
    use nimbora_yields::token_manager::token_manager::{TokenManager};

    use openzeppelin::{
        introspection::interface::ISRC5Dispatcher,
        token::erc20::interface::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
        access::accesscontrol::{
            AccessControlComponent, interface::{IAccessControlDispatcher, IAccessControlDispatcherTrait}
        },
        upgrades::interface::{IUpgradeableDispatcher, IUpgradeable, IUpgradeableDispatcherTrait}
    };
    use snforge_std::cheatcodes::events::EventFetcher;
    use snforge_std::{
        declare, ContractClassTrait, get_class_hash, start_prank, CheatTarget, ContractClass, PrintTrait, stop_prank,
        start_warp, stop_warp, L1HandlerTrait, spy_events, SpyOn, event_name_hash
    };
    use starknet::account::{Call};
    use starknet::class_hash::Felt252TryIntoClassHash;

    use starknet::{
        get_contract_address, deploy_syscall, ClassHash, contract_address_const, ContractAddress, get_block_timestamp,
        EthAddress, Zeroable
    };


    #[test]
    #[should_panic(expected: ('Caller is missing role',))]
    fn set_fees_recipient_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        pooling_manager.set_fees_recipient(fees_recipient);
    }

    #[test]
    #[should_panic(expected: ('Zero address',))]
    fn set_fees_recipient_zero_address() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_fees_recipient(Zeroable::zero());
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    fn set_fees_recipient() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
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
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        pooling_manager.set_l1_pooling_manager(l1_pooling_manager);
    }

    #[test]
    #[should_panic(expected: ('Zero address',))]
    fn set_l1_pooling_manager_zero_address() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_l1_pooling_manager(Zeroable::zero());
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    fn set_l1_pooling_manager() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_l1_pooling_manager(l1_pooling_manager);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        let l1_pooling_manager_from_pooling_manager = pooling_manager.l1_pooling_manager();
        assert(l1_pooling_manager_from_pooling_manager == l1_pooling_manager, 'invalid l1 pooling manager');
    }

    #[test]
    #[should_panic(expected: ('Caller is missing role',))]
    fn set_factory_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        pooling_manager.set_factory(factory.contract_address);
    }

    #[test]
    #[should_panic(expected: ('Zero address',))]
    fn set_factory_zero_address() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_factory(Zeroable::zero());
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    fn set_factory() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_factory(factory.contract_address);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        let factory_from_pooling_manager = pooling_manager.factory();
        assert(factory_from_pooling_manager == factory.contract_address, 'invalid factory');
    }

    #[test]
    #[should_panic(expected: ('Caller is missing role',))]
    fn set_allowance_wrong_caller() {
        let spender = contract_address_const::<2301>();
        let (token_manager, token, pooling_manager, _) = deploy_strategy();
        pooling_manager.set_allowance(spender, token, 10000);
    }

    #[test]
    #[should_panic(expected: ('Zero address',))]
    fn set_allowance_spender_zero_address() {
        let (token_manager, token, pooling_manager, owner) = deploy_strategy();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_allowance(Zeroable::zero(), token, 10000);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Zero address',))]
    fn set_allowance_token_zero_address() {
        let (token_manager, token, pooling_manager, owner) = deploy_strategy();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_allowance(owner, Zeroable::zero(), 10000);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    fn set_allowance() {
        let (token_manager, token, pooling_manager, owner) = deploy_strategy();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_allowance(owner, token, 10000);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Not initialised',))]
    fn handle_mass_report_not_initialised() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let empty_array: Array<StrategyReportL1> = ArrayTrait::new();
        pooling_manager.handle_mass_report(empty_array.span());
    }

    #[test]
    #[should_panic(expected: ('Invalid data',))]
    fn handle_mass_executions_invalid_data() {
        let (token_manager_1, token_1, pooling_manager, _) = deploy_strategy();

        let l1_strategy_1: EthAddress = 2.try_into().unwrap();
        let l1_net_asset_value_1: u256 = 1000000000000000000;
        let underlying_bridge_amount_1: u256 = 1000000000000000000;
        let processed: bool = true;

        let strategy_report_1 = StrategyReportL1 {
            l1_strategy: l1_strategy_1,
            l1_net_asset_value: l1_net_asset_value_1,
            underlying_bridged_amount: underlying_bridge_amount_1,
            processed: processed
        };
        let mut strategies = ArrayTrait::new();
        strategies.append(strategy_report_1);

        pooling_manager.handle_mass_report(strategies.span());
    }

    #[test]
    #[should_panic(expected: ('Not initialised',))]
    fn handle_mass_executions_not_initialized() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let l1_strategy_1: EthAddress = 2.try_into().unwrap();
        let l1_net_asset_value_1: u256 = 1000000000000000000;
        let underlying_bridge_amount_1: u256 = 1000000000000000000;
        let processed: bool = true;

        // let mut strategies = ArrayTrait::new();

        let strategies = ArrayTrait::new();
        pooling_manager.handle_mass_report(strategies.span());
    }

    #[test]
    #[should_panic(expected: ('Buffer is null',))]
    fn handle_mass_executions_buffer_is_null() {
        let (token_manager_1, token_1, pooling_manager, _) = deploy_strategy();

        let mut strategies = ArrayTrait::new();
        pooling_manager.handle_mass_report(strategies.span());
    }

    #[test]
    #[should_panic(expected: ('No l1 report',))]
    fn handle_mass_executions_no_l1_report() {
        let (token_manager, token_address, pooling_manager, event) = deposit_and_handle_mass(Option::None);

        let l1_strategy_1: EthAddress = 2.try_into().unwrap();
        let l1_net_asset_value_1: u256 = 1000000000000000000;
        let underlying_bridge_amount_1: u256 = 1000000000000000000;
        let processed: bool = true;

        let strategy_report = StrategyReportL1 {
            l1_strategy: l1_strategy_1,
            l1_net_asset_value: l1_net_asset_value_1,
            underlying_bridged_amount: underlying_bridge_amount_1,
            processed: processed
        };

        let mut strategies = ArrayTrait::new();
        strategies.append(strategy_report);
        pooling_manager.handle_mass_report(strategies.span());
    }

    #[test]
    #[should_panic(expected: ('Invalid data',))]
    fn handle_mass_executions_invalid_hash() {
        let (token_manager, token_address, pooling_manager, event) = deposit_and_handle_mass(Option::None);

        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
        let l1_strategy_1: EthAddress = 2.try_into().unwrap();
        let l1_net_asset_value_1: u256 = 1000000000000000000;
        let underlying_bridge_amount_1: u256 = 1000000000000000000;
        let processed: bool = true;

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        // L1 handler
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: 200000000000000000,
                underlying_bridged_amount: 0,
                processed: true,
            }
        ];

        let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
        let epoch: u256 = 1;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];
        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        l1_handler.execute();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));
        spy.fetch_events();
        let (from, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('NewL1ReportHash'), 'Wrong event name');

        let strategy_report = StrategyReportL1 {
            l1_strategy: l1_strategy_1,
            l1_net_asset_value: l1_net_asset_value_1,
            underlying_bridged_amount: underlying_bridge_amount_1,
            processed: processed
        };

        let mut strategies = ArrayTrait::new();
        strategies.append(strategy_report);
        pooling_manager.handle_mass_report(strategies.span());
    }

    #[test]
    fn handle_mass_executions() {
        let (token_manager, token_address, pooling_manager, event) = deposit_and_handle_mass(Option::None);

        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        // L1 handler
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: 200000000000000000,
                underlying_bridged_amount: 0,
                processed: true,
            }
        ];

        let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
        let epoch: u256 = 1;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];
        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        l1_handler.execute();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));
        spy.fetch_events();
        let (from, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('NewL1ReportHash'), 'Wrong event name');

        let strategy_report = StrategyReportL1 {
            l1_strategy: 2.try_into().unwrap(),
            l1_net_asset_value: 200000000000000000,
            underlying_bridged_amount: 0,
            processed: true,
        };

        let mut strategies = ArrayTrait::new();
        strategies.append(strategy_report);
        pooling_manager.handle_mass_report(strategies.span());
    }

    #[test]
    fn handle_response_invalid_caller() {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let l1_pooling_manager: EthAddress = 101.try_into().unwrap();

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        // L1 handler
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: 200000000000000000,
                underlying_bridged_amount: 0,
                processed: true,
            }
        ];

        let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
        let epoch: u256 = 1;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];
        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        match l1_handler.execute() {
            Result::Ok(_) => {},
            Result::Err(reverted_transaction) => {
                assert(reverted_transaction.panic_data.at(0).is_non_zero(), 'Transaction did not revert');
                spy.fetch_events();
                assert(spy.events.is_empty(), 'Event was emitted');
            }
        }
    }

    #[test]
    fn handle_response_invalid_epoch() {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let l1_pooling_manager: EthAddress = 101.try_into().unwrap();

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        // L1 handler
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: 200000000000000000,
                underlying_bridged_amount: 0,
                processed: true,
            }
        ];

        let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
        let epoch: u256 = 1000;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];
        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        match l1_handler.execute() {
            Result::Ok(_) => {},
            Result::Err(reverted_transaction) => {
                assert(reverted_transaction.panic_data.at(0).is_non_zero(), 'Transaction did not revert');
                spy.fetch_events();
                assert(spy.events.is_empty(), 'Event was emitted');
            }
        }
    }

    #[test]
    fn handle_response_pending_hash() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();

        let l1_pooling_manager: EthAddress = 101.try_into().unwrap();

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        // L1 handler
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: 200000000000000000,
                underlying_bridged_amount: 0,
                processed: true,
            }
        ];

        let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
        let epoch: u256 = 1;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];
        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        match l1_handler.execute() {
            Result::Ok(_) => {},
            Result::Err(reverted_transaction) => {
                assert(reverted_transaction.panic_data.at(0).is_non_zero(), 'Transaction did not revert');
                spy.fetch_events();
                assert(spy.events.is_empty(), 'Event was emitted');
            }
        }
    }

    #[test]
    fn handle_response() {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let l1_pooling_manager: EthAddress = 101.try_into().unwrap();

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        // L1 handler
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: 200000000000000000,
                underlying_bridged_amount: 0,
                processed: true,
            }
        ];

        let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
        let epoch: u256 = 1;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];
        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        match l1_handler.execute() {
            Result::Ok(_) => {
                spy.fetch_events();
                let (_, event) = spy.events.at(0);
                assert(event.keys.at(0) == @event_name_hash('NewL1ReportHash'), 'Event was not emitted');
            },
            Result::Err(_) => {}
        }
    }

    #[test]
    fn is_initialised() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_factory(factory.contract_address);
        pooling_manager.set_fees_recipient(fees_recipient);
        pooling_manager.set_l1_pooling_manager(l1_pooling_manager);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        let is_initialised = pooling_manager.is_initialised();
        assert(is_initialised == true, 'initialisation failed');
    }

    #[test]
    #[should_panic(expected: ('Caller is missing role',))]
    fn register_underlying_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
            owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
        );
        pooling_manager.register_underlying(token_1.contract_address, bridge_1.contract_address, 5);
    }

    #[test]
    #[should_panic(expected: ('Zero address',))]
    fn register_underlying_zero_address() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
            owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
        );

        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.register_underlying(Zeroable::zero(), bridge_1.contract_address, 5);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Zero address',))]
    fn register_underlying_zero_address_bridge() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
            owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
        );

        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.register_underlying(token_1.contract_address, Zeroable::zero(), 5);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Zero address',))]
    fn register_underlying_zero_address_l1_bridge() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
            owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
        );

        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.register_underlying(token_1.contract_address, bridge_1.contract_address, Zeroable::zero());
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    fn register_underlying() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let (token_1, token_2, token_3, bridge_1, bridge_2, bridge_3) = setup_1(
            owner, l1_pooling_manager, pooling_manager, fees_recipient, factory
        );

        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.register_underlying(token_1.contract_address, bridge_1.contract_address, 5);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        let underlying_to_bridge = pooling_manager.underlying_to_bridge(token_1.contract_address);
        assert(underlying_to_bridge == bridge_1.contract_address, 'wrong bridge for underlying')
    }

    #[test]
    fn hash_l2_data_collision() {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let epoch: u256 = 1;

        let bridge_deposit_info_1 = BridgeInteractionInfo {
            l1_bridge: 11.try_into().unwrap(), amount: 100000000000000000000
        };

        let bridge_deposit_info_2 = BridgeInteractionInfo {
            l1_bridge: 1.try_into().unwrap(), amount: 1100000000000000000000
        };

        let strategy_report_1 = StrategyReportL2 {
            l1_strategy: 1.try_into().unwrap(), action_id: 15, amount: 10000, processed: false, new_share_price: 50000000000000
        };

        let strategy_report_2 = StrategyReportL2 {
            l1_strategy: 2.try_into().unwrap(), action_id: 1, amount: 510000, processed: false, new_share_price: 50000000000000
        };

        let bridge_withdrawal_info_1 = BridgeInteractionInfo {
            l1_bridge: 1.try_into().unwrap(), amount: 2100000000000000000000
        };

        let bridge_withdrawal_info_2 = BridgeInteractionInfo {
            l1_bridge: 12.try_into().unwrap(), amount: 100000000000000000000
        };

        let hash_data_1 = pooling_manager
            .hash_l2_data(
                epoch,
                array![bridge_deposit_info_1].span(),
                array![strategy_report_1].span(),
                array![bridge_withdrawal_info_1].span()
            );

        let hash_data_2 = pooling_manager
            .hash_l2_data(
                epoch,
                array![bridge_deposit_info_2].span(),
                array![strategy_report_2].span(),
                array![bridge_withdrawal_info_2].span()
            );

        assert(hash_data_1 != hash_data_2, 'Hash collision detected');
    }

    #[test]
    #[fuzzer(runs: 20, seed: 200)]
    fn hash_l2_data_empty_deposit(y: u256, z: u256, u: u256) {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let epoch: u256 = between(1, 1000000, u);
        let withdrawal_amount: u256 = between(100000000000000000000, 1000000000000000000000000, y);
        let new_share_price: u256 = between(50000000000000, 5000000000000000000000000, z);

        let strategy_report = StrategyReportL2 {
            l1_strategy: 2.try_into().unwrap(), action_id: 1, amount: 10000, processed: false, new_share_price: new_share_price
        };

        let bridge_withdrawal_info = BridgeInteractionInfo {
            l1_bridge: 1.try_into().unwrap(), amount: withdrawal_amount
        };

        let hash_data = pooling_manager
            .hash_l2_data(
                epoch, array![].span(), array![strategy_report].span(), array![bridge_withdrawal_info].span()
            );

        assert(hash_data != 0, 'Wrong hash data');
    }

    #[test]
    #[fuzzer(runs: 20, seed: 200)]
    fn hash_l2_data_empty_strategy_report(x: u256, y: u256, u: u256) {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let epoch: u256 = between(1, 1000000, u);
        let deposit_amount: u256 = between(1000000000000000000000, 1000000000000000000000000, x);
        let withdrawal_amount: u256 = between(100000000000000000000, 1000000000000000000000000, y);

        let bridge_deposit_info = BridgeInteractionInfo { l1_bridge: 1.try_into().unwrap(), amount: deposit_amount };

        let bridge_withdrawal_info = BridgeInteractionInfo {
            l1_bridge: 1.try_into().unwrap(), amount: withdrawal_amount
        };

        let hash_data = pooling_manager
            .hash_l2_data(
                epoch, array![bridge_deposit_info].span(), array![].span(), array![bridge_withdrawal_info].span()
            );

        assert(hash_data != 0, 'Wrong hash data');
    }

    #[test]
    #[fuzzer(runs: 20, seed: 200)]
    fn hash_l2_data_empty_withdrawal(x: u256, z: u256, u: u256) {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let epoch: u256 = between(1, 1000000, u);
        let deposit_amount: u256 = between(1000000000000000000000, 1000000000000000000000000, x);
        let new_share_price: u256 = between(50000000000000, 5000000000000000000000000, z);

        let strategy_report = StrategyReportL2 {
            l1_strategy: 2.try_into().unwrap(), action_id: 1, amount: 10000, processed: false, new_share_price: new_share_price,
        };
        let bridge_deposit_info = BridgeInteractionInfo { l1_bridge: 1.try_into().unwrap(), amount: deposit_amount };

        let hash_data = pooling_manager
            .hash_l2_data(epoch, array![bridge_deposit_info].span(), array![strategy_report].span(), array![].span());

        assert(hash_data != 0, 'Wrong hash data');
    }

    #[test]
    #[fuzzer(runs: 20, seed: 200)]
    fn hash_l2_data_empty_all(u: u256) {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let epoch: u256 = between(1, 1000000, u);

        let hash_data = pooling_manager.hash_l2_data(epoch, array![].span(), array![].span(), array![].span());

        assert(hash_data != 0, 'Wrong hash data');
    }

    #[test]
    fn hash_l2_data_old_epoch() {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let epoch: u256 = 0;

        let hash_data = pooling_manager.hash_l2_data(epoch, array![].span(), array![].span(), array![].span());

        assert(hash_data != 0, 'Wrong hash data');
    }

    #[test]
    fn hash_l1_data() {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let strategy_report_l1 = StrategyReportL1 {
            l1_strategy: 2.try_into().unwrap(),
            l1_net_asset_value: 200000000000000000,
            underlying_bridged_amount: 0,
            processed: true,
        };

        let hash_data = pooling_manager.hash_l1_data(array![strategy_report_l1].span());

        assert(hash_data != 0, 'Wrong hash data');
    }

    #[test]
    fn hash_l1_data_empty_strategy() {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let hash_data = pooling_manager.hash_l1_data(array![].span());
        assert(hash_data != 0, 'Wrong hash data');
    }

    #[test]
    fn hash_l1_data_collision() {
        let (token_manager, token_address, pooling_manager, _) = deposit_and_handle_mass(Option::None);

        let strategy_report_l1_1 = StrategyReportL1 {
            l1_strategy: 2.try_into().unwrap(),
            l1_net_asset_value: 2000000000000000001,
            underlying_bridged_amount: 0,
            processed: true,
        };

        let strategy_report_l1_2 = StrategyReportL1 {
            l1_strategy: 2.try_into().unwrap(),
            l1_net_asset_value: 200000000000000000,
            underlying_bridged_amount: 10,
            processed: true,
        };

        let hash_data_1 = pooling_manager.hash_l1_data(array![strategy_report_l1_1].span());
        let hash_data_2 = pooling_manager.hash_l1_data(array![strategy_report_l1_2].span());

        assert(hash_data_1 != hash_data_2, 'Hash data collision');
    }

    #[test]
    fn hash_l1_data() {
        let (
            token_manager, 
            token_address, 
            pooling_manager, 
            _
        ) = deposit_and_handle_mass(Option::None);

        let strategy_report_l1 = StrategyReportL1 {
            l1_strategy: 2.try_into().unwrap(),
            l1_net_asset_value: 200000000000000000,
            underlying_bridged_amount: 0,
            processed: true,
        };

        let hash_data = pooling_manager.hash_l1_data(array![strategy_report_l1].span());

        assert(hash_data != 0, 'Wrong hash data');
    }

    #[test]
    fn hash_l1_data_empty_strategy() {
        let (
            token_manager, 
            token_address, 
            pooling_manager, 
            _
        ) = deposit_and_handle_mass(Option::None);

        let hash_data = pooling_manager.hash_l1_data(array![].span());
        assert(hash_data != 0, 'Wrong hash data');
    }

    #[test]
    fn hash_l1_data_collision() {
        let (
            token_manager, 
            token_address, 
            pooling_manager, 
            _
        ) = deposit_and_handle_mass(Option::None);

        let strategy_report_l1_1 = StrategyReportL1 {
            l1_strategy: 2.try_into().unwrap(),
            l1_net_asset_value: 2000000000000000001,
            underlying_bridged_amount: 0,
            processed: true,
        };

        let strategy_report_l1_2 = StrategyReportL1 {
            l1_strategy: 2.try_into().unwrap(),
            l1_net_asset_value: 200000000000000000,
            underlying_bridged_amount: 10,
            processed: true,
        };

        let hash_data_1 = pooling_manager.hash_l1_data(array![strategy_report_l1_1].span());
        let hash_data_2 = pooling_manager.hash_l1_data(array![strategy_report_l1_2].span());

        assert(hash_data_1 != hash_data_2, 'Hash data collision');
    }

    #[test]
    fn upgrade_pooling_manager() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        let mock_contract = declare('MockRandom');
        let old_class_hash = get_class_hash(pooling_manager.contract_address);
        IUpgradeableDispatcher { contract_address: pooling_manager.contract_address }.upgrade(mock_contract.class_hash);
        assert(get_class_hash(pooling_manager.contract_address) == mock_contract.class_hash, 'Incorrect class hash');
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Caller is missing role',))]
    fn upgrade_pooling_manager_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let mock_contract = declare('MockRandom');
        let old_class_hash = get_class_hash(pooling_manager.contract_address);
        IUpgradeableDispatcher { contract_address: pooling_manager.contract_address }.upgrade(mock_contract.class_hash);
    }

    #[test]
    #[should_panic(expected: ('Class hash cannot be zero',))]
    fn upgrade_pooling_manager_zero_class_hash() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        let old_class_hash = get_class_hash(pooling_manager.contract_address);
        IUpgradeableDispatcher { contract_address: pooling_manager.contract_address }.upgrade(Zeroable::zero());
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn register_strategy_wrong_caller() {
        let (token_manager, token, pooling_manager, _) = deploy_strategy();
        pooling_manager.register_strategy(token_manager, token, 1.try_into().unwrap(), token_manager, 1, 100);
    }

    #[test]
    #[should_panic(expected: ('Token not supported',))]
    fn register_strategy_zero_bridge() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
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
        let tvl_limit = 100000000000000000;
        let withdrawal_epoch_delay_1 = 2;
        let dust_limit_1 = 1000000000000000000;
        let name_1 = 10;
        let symbol_1 = 1000;

        start_prank(CheatTarget::One(factory.contract_address), owner);
        let (token_manager_deployed_address, token_deployed_address) = factory
            .deploy_strategy(
                l1_strategy_1,
                token_1.contract_address,
                name_1,
                symbol_1,
                performance_fees_strategy_1,
                tvl_limit,
                withdrawal_epoch_delay_1,
                dust_limit_1
            );
        stop_prank(CheatTarget::One(factory.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), factory.contract_address);
        pooling_manager
            .register_strategy(
                token_manager_deployed_address,
                token_deployed_address,
                l1_strategy_1,
                Zeroable::zero(),
                performance_fees_strategy_1,
                tvl_limit,
            );
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Strategy already registered',))]
    fn register_strategy_duplicated() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
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
        let tvl_limit = 10000000000000000000;
        let withdrawal_epoch_delay_1 = 2;
        let dust_limit_1 = 1000000000000000000;
        let name_1 = 10;
        let symbol_1 = 1000;

        start_prank(CheatTarget::One(factory.contract_address), owner);
        let (token_manager_deployed_address, token_deployed_address) = factory
            .deploy_strategy(
                l1_strategy_1,
                token_1.contract_address,
                name_1,
                symbol_1,
                performance_fees_strategy_1,
                tvl_limit,
                withdrawal_epoch_delay_1,
                dust_limit_1
            );
        stop_prank(CheatTarget::One(factory.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), factory.contract_address);
        pooling_manager
            .register_strategy(
                token_manager_deployed_address,
                token_deployed_address,
                l1_strategy_1,
                token_1.contract_address,
                performance_fees_strategy_1,
                tvl_limit,
            );
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Caller is missing role',))]
    fn delete_all_pending_strategies_wrong_caller() {
        let (token_manager, token, pooling_manager, _) = deploy_strategy();
        pooling_manager.delete_all_pending_strategy();
    }

    #[test]
    fn delete_all_pending_strategies() {
        let (token_manager, token, pooling_manager, owner) = deploy_strategy();
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        let pending_before_delete = pooling_manager.pending_strategies_to_initialize();
        assert(pending_before_delete.len() > 0, 'no pending strategies');
        pooling_manager.delete_all_pending_strategy();
        let pending_after_delete = pooling_manager.pending_strategies_to_initialize();
        assert(pending_after_delete.len() == 0, 'pending strategies not deleted');
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn emit_tvl_limit_updated_event_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let l2_strategy = contract_address_const::<230>();
        pooling_manager.emit_tvl_limit_updated_event(l1_pooling_manager, l2_strategy, 100);
    }

    #[test]
    fn emit_deposit_limit_updated_event() {
        let (token_manager, token, pooling_manager, _) = deploy_strategy();
        let l1_strategy: EthAddress = 2.try_into().unwrap();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), token_manager);
        pooling_manager.emit_tvl_limit_updated_event(l1_strategy, token_manager, 200);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        spy.fetch_events();
        let (_, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('TvlLimitUpdated'), 'Event was not emitted');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn emit_performance_fees_updated_event_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let l2_strategy = contract_address_const::<230>();
        pooling_manager.emit_performance_fees_updated_event(l1_pooling_manager, l2_strategy, 100);
    }

    #[test]
    fn emit_performance_fees_updated_event() {
        let (token_manager, token, pooling_manager, _) = deploy_strategy();
        let l1_strategy: EthAddress = 2.try_into().unwrap();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), token_manager);
        pooling_manager.emit_performance_fees_updated_event(l1_strategy, token_manager, 100);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        spy.fetch_events();
        let (_, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('PerformanceFeesUpdated'), 'Event was not emitted');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn emit_deposit_event_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let l2_strategy = contract_address_const::<230>();
        pooling_manager.emit_deposit_event(l1_pooling_manager, l2_strategy, owner, owner, 100, 200, owner);
    }

    #[test]
    fn emit_deposit_event() {
        let (token_manager, token, pooling_manager, owner) = deploy_strategy();
        let l1_strategy: EthAddress = 2.try_into().unwrap();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), token_manager);
        pooling_manager.emit_deposit_event(l1_strategy, token_manager, owner, owner, 100, 200, owner);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        spy.fetch_events();
        let (_, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('Deposit'), 'Event was not emitted');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn emit_request_withdrawal_event_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let l2_strategy = contract_address_const::<230>();
        pooling_manager.emit_request_withdrawal_event(l1_pooling_manager, l2_strategy, owner, 100, 200, 1, 1);
    }

    #[test]
    fn emit_request_withdrawal_event() {
        let (token_manager, token, pooling_manager, owner) = deploy_strategy();
        let l1_strategy: EthAddress = 2.try_into().unwrap();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), token_manager);
        pooling_manager.emit_request_withdrawal_event(l1_strategy, token_manager, owner, 100, 200, 1, 1);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        spy.fetch_events();
        let (_, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('RequestWithdrawal'), 'Event was not emitted');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn emit_claim_withdrawal_event_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let l2_strategy = contract_address_const::<230>();

        pooling_manager.emit_claim_withdrawal_event(l1_pooling_manager, l2_strategy, owner, 1, 200);
    }

    #[test]
    fn emit_claim_withdrawal_event() {
        let (token_manager, token, pooling_manager, owner) = deploy_strategy();
        let l1_strategy: EthAddress = 2.try_into().unwrap();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), token_manager);
        pooling_manager.emit_claim_withdrawal_event(l1_strategy, token_manager, owner, 1, 200);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        spy.fetch_events();
        let (_, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('ClaimWithdrawal'), 'Event was not emitted');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn emit_withdrawal_epoch_delay_updated_event_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();
        let l2_strategy = contract_address_const::<230>();

        pooling_manager.emit_withdrawal_epoch_delay_updated_event(l1_pooling_manager, l2_strategy, 100);
    }

    #[test]
    fn emit_withdrawal_epoch_delay_updated_event() {
        let (token_manager, token, pooling_manager, owner) = deploy_strategy();
        let l1_strategy: EthAddress = 2.try_into().unwrap();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), token_manager);
        pooling_manager.emit_withdrawal_epoch_delay_updated_event(l1_strategy, token_manager, 100);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        spy.fetch_events();
        let (_, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('WithdrawalEpochUpdated'), 'Event was not emitted');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn emit_dust_limit_updated_event_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();

        pooling_manager.emit_dust_limit_updated_event(l1_pooling_manager, 10);
    }

    #[test]
    fn emit_dust_limit_updated_event() {
        let (token_manager, token, pooling_manager, owner) = deploy_strategy();
        let l1_strategy: EthAddress = 2.try_into().unwrap();
        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), token_manager);
        pooling_manager.emit_dust_limit_updated_event(l1_strategy, 10);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        spy.fetch_events();
        let (_, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('DustLimitUpdated'), 'Event was not emitted');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn emit_token_manager_class_hash_updated_event_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();

        pooling_manager.emit_token_manager_class_hash_updated_event(token_manager_hash);
    }

    #[test]
    fn emit_token_manager_class_hash_updated_event() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();

        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_factory(factory.contract_address);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), factory.contract_address);
        pooling_manager.emit_token_manager_class_hash_updated_event(token_manager_hash);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        spy.fetch_events();
        let (_, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('TokenManagerClassHashUpdated'), 'Event was not emitted');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn emit_token_class_hash_updated_event_wrong_caller() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();

        pooling_manager.emit_token_class_hash_updated_event(token_hash);
    }

    #[test]
    fn emit_token_class_hash_updated_event() {
        let (owner, fees_recipient, l1_pooling_manager, pooling_manager, factory, token_hash, token_manager_hash) =
            setup_0();

        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_factory(factory.contract_address);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), factory.contract_address);
        pooling_manager.emit_token_class_hash_updated_event(token_hash);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        spy.fetch_events();
        let (_, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('TokenClassHashUpdated'), 'Event was not emitted');
    }
}
