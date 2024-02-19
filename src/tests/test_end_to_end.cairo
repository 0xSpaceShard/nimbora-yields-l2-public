#[cfg(test)]
mod testEndToEnd {
    use core::array::ArrayTrait;
    use core::clone::Clone;
    use core::debug::PrintTrait;
    use core::fmt::Debug;
    use core::option::OptionTrait;
    use core::result::ResultTrait;
    use core::serde::Serde;
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
        deploy_tokens, deploy_token_manager, deploy_strategy, deploy_two_strategy, deploy_three_strategy,
        approve_to_contract, multiple_approve_to_contract, transfer_to_users, deposit, deposit_and_handle_mass
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
        token::erc20::interface::{IERC20, ERC20ABIDispatcher, ERC20ABIDispatcherTrait},
        access::accesscontrol::{
            AccessControlComponent, interface::{IAccessControlDispatcher, IAccessControlDispatcherTrait}
        },
        upgrades::interface::{IUpgradeableDispatcher, IUpgradeable, IUpgradeableDispatcherTrait}
    };
    use snforge_std::cheatcodes::contract_class::RevertedTransactionTrait;
    use snforge_std::{
        declare, ContractClassTrait, start_prank, CheatTarget, ContractClass, stop_prank, start_warp, stop_warp,
        L1Handler, L1HandlerTrait, get_class_hash, event_name_hash, spy_events, SpyOn, EventSpy, EventFetcher, Event
    };
    use starknet::account::{Call};
    use starknet::class_hash::Felt252TryIntoClassHash;

    use starknet::{
        get_contract_address, deploy_syscall, ClassHash, contract_address_const, ContractAddress, get_block_timestamp,
        EthAddress, Zeroable
    };


    #[test]
    fn test_simple_l1_handler() {
        let (token_manager_address, token_address, pooling_manager, event) = deposit_and_handle_mass(Option::None);

        let owner = contract_address_const::<2300>();
        let receiver = contract_address_const::<24>();
        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
        let assets = 200000000000000000;

        let token_contract = ERC20ABIDispatcher { contract_address: token_address };
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let underlying_token_address = token_manager.underlying();
        let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };

        let mut i = 0;
        let mut arr = ArrayTrait::new();
        loop {
            if (i == event.data.len()) {
                break;
            }
            arr.append(*event.data.at(i));
            i += 1;
        };

        assert(event.keys.at(0) == @event_name_hash('NewL2Report'), 'Wrong event name');

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

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        l1_handler.execute().unwrap();

        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));
        spy.fetch_events();
        let (from, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('NewL1ReportHash'), 'Wrong event name');
        i = 0;
        arr = ArrayTrait::new();
        loop {
            if (i == event.data.len()) {
                break;
            }
            arr.append(*event.data.at(i));
            i += 1;
        };

        assert(*arr.at(0) == hash.low.into() && *arr.at(1) == hash.high.into(), 'Wrong hash');

        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);

        let fee_receip = pooling_manager.fees_recipient();

        let balance_before_token = token_contract.balance_of(fee_receip);
        assert(balance_before_token == 0, 'Wrong balance before');

        pooling_manager.handle_mass_report(calldata.span());
        spy.fetch_events();

        let (from, event) = spy.events.at(0);
        let mut i = 0;
        let mut arr = ArrayTrait::new();
        loop {
            if (i == event.data.len()) {
                break;
            }
            arr.append(*event.data.at(i));
            i += 1;
        };

        let balance_after_token = token_contract.balance_of(fee_receip);
        assert(balance_after_token == 0, 'Wrong Balance');

        assert(event.keys.at(0) == @event_name_hash('NewL2Report'), 'Wrong event name');
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    #[should_panic(expected: ('Invalid data',))]
    fn test_handle_report_wrong_data() {
        let (token_manager_address, token_address, pooling_manager, event) = deposit_and_handle_mass(Option::None);

        let owner = contract_address_const::<2300>();
        let receiver = contract_address_const::<24>();
        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
        let assets = 200000000000000000;

        let token_contract = ERC20ABIDispatcher { contract_address: token_address };
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let underlying_token_address = token_manager.underlying();
        let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };

        let mut i = 0;
        let mut arr = ArrayTrait::new();
        loop {
            if (i == event.data.len()) {
                break;
            }
            arr.append(*event.data.at(i));
            i += 1;
        };

        assert(event.keys.at(0) == @event_name_hash('NewL2Report'), 'Wrong event name');

        // L1 handler
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: 20000000000000000,
                underlying_bridged_amount: 0,
                processed: true
            }
        ];

        let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
        let epoch: u256 = 1;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        l1_handler.execute().unwrap();

        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));
        spy.fetch_events();
        let (from, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('NewL1ReportHash'), 'Wrong event name');
        i = 0;
        arr = ArrayTrait::new();
        loop {
            if (i == event.data.len()) {
                break;
            }
            arr.append(*event.data.at(i));
            i += 1;
        };

        assert(*arr.at(0) == hash.low.into() && *arr.at(1) == hash.high.into(), 'Wrong hash');

        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: 2000000000000000,
                underlying_bridged_amount: 0,
                processed: true
            }
        ];

        pooling_manager.handle_mass_report(calldata.span());
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    #[should_panic(expected: ('No l1 report',))]
    fn test_handle_report_no_l1() {
        let (token_manager_address, token_address, pooling_manager, event) = deposit_and_handle_mass(Option::None);

        let owner = contract_address_const::<2300>();
        let receiver = contract_address_const::<24>();
        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
        let assets = 200000000000000000;

        let token_contract = ERC20ABIDispatcher { contract_address: token_address };
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let underlying_token_address = token_manager.underlying();
        let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };

        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: 20000000000000000,
                underlying_bridged_amount: 0,
                processed: true
            }
        ];

        pooling_manager.handle_mass_report(calldata.span());
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    #[test]
    fn test_l1_handler_wrong_caller() {
        let (token_manager_address, token_address, pooling_manager, event) = deposit_and_handle_mass(Option::None);
        let owner = contract_address_const::<2300>();
        // L1 handler
        let hash: u256 = 0x0;
        let epoch: u256 = 0;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        l1_handler.from_address = owner.into();
        l1_handler.payload = data.span();

        let error = l1_handler.execute().unwrap_err();
        assert(error.first() == 'Invalid caller', 'Wrong error');
    }

    #[test]
    fn test_l1_handler_pending_hash() {
        let (token_manager_address, token_address, pooling_manager, event) = deposit_and_handle_mass(Option::None);
        let owner = contract_address_const::<2300>();
        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
        // L1 handler
        let hash: u256 = 0x012;
        let epoch: u256 = 1;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();
        l1_handler.execute().unwrap();

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        let error = l1_handler.execute().unwrap_err();
        assert(error.first() == 'Pending hash', 'Wrong error');
    }

    #[test]
    fn test_l1_handler_wrong_epoch() {
        let (token_manager_address, token_address, pooling_manager, event) = deposit_and_handle_mass(Option::None);

        let owner = contract_address_const::<2300>();
        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();

        // L1 handler
        let hash: u256 = 0x0;
        let epoch: u256 = 0;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');
        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();
        let error = l1_handler.execute().unwrap_err();
        assert(error.first() == 'Invalid Epoch', 'Wrong error');
    }

    #[test]
    fn test_handle_report_with_bigger_asset_value() {
        let (token_manager_address, token_address, pooling_manager, event) = deposit_and_handle_mass(Option::None);

        let owner = contract_address_const::<2300>();
        let receiver = contract_address_const::<24>();
        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
        let assets = 200000000000000000;

        let token_contract = ERC20ABIDispatcher { contract_address: token_address };
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let underlying_token_address = token_manager.underlying();
        let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };

        let mut i = 0;
        let mut arr = ArrayTrait::new();
        loop {
            if (i == event.data.len()) {
                break;
            }
            arr.append(*event.data.at(i));
            i += 1;
        };

        assert(event.keys.at(0) == @event_name_hash('NewL2Report'), 'Wrong event name');

        // L1 handler
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: 210000000000000000000000000,
                underlying_bridged_amount: 0,
                processed: true
            }
        ];

        let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
        let epoch: u256 = 1;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        l1_handler.execute().unwrap();

        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));
        spy.fetch_events();
        let (from, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('NewL1ReportHash'), 'Wrong event name');
        i = 0;
        arr = ArrayTrait::new();
        loop {
            if (i == event.data.len()) {
                break;
            }
            arr.append(*event.data.at(i));
            i += 1;
        };

        assert(*arr.at(0) == hash.low.into() && *arr.at(1) == hash.high.into(), 'Wrong hash');

        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));
        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);

        let fee_receip = pooling_manager.fees_recipient();

        let balance_before_token = token_contract.balance_of(fee_receip);
        assert(balance_before_token == 0, 'Wrong balance before');

        pooling_manager.handle_mass_report(calldata.span());
        spy.fetch_events();

        let (from, event) = spy.events.at(0);

        let balance_after_token = token_contract.balance_of(fee_receip);
        assert(balance_after_token > balance_before_token, 'Wrong Balance');

        assert(event.keys.at(0) == @event_name_hash('NewL2Report'), 'Wrong event name');
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }


    // Test simple handle_mass_report with a request_withdrawal of all assets
    #[test]
    fn test_handle_report() {
        let (token_manager_address, token_address, pooling_manager, owner) = deploy_strategy();
        let receiver = contract_address_const::<24>();
        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
        let assets = 200000000000000000;

        let token_contract = ERC20ABIDispatcher { contract_address: token_address };
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let underlying_token_address = token_manager.underlying();
        let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };

        start_prank(CheatTarget::One(underlying_token.contract_address), owner);
        underlying_token.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(underlying_token.contract_address));
        deposit(token_manager_address, owner, assets, receiver);

        let balance = underlying_token.balance_of(token_manager_address);
        assert(balance == assets, 'Wrong underlying balance');

        let balance = token_contract.balance_of(receiver);
        assert(balance == assets, 'Wrong token balance');

        start_prank(CheatTarget::One(token_contract.contract_address), receiver);
        token_contract.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(token_contract.contract_address));

        start_prank(CheatTarget::One(token_manager.contract_address), receiver);
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        token_manager.request_withdrawal(assets);
        stop_prank(CheatTarget::One(token_manager.contract_address));

        let balance = token_contract.balance_of(receiver);
        assert(balance == 0, 'Wrong new token balance');

        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        let calldata: Array<StrategyReportL1> = array![];

        pooling_manager.handle_mass_report(calldata.span());
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    // Test handle_mass_report after 2 deposits and one request_withdrawal of 200000000000000000
    #[test]
    fn test_handle_report_2_deposit() {
        let (token_manager_address, token_address, pooling_manager, owner) = deploy_strategy();
        let user2 = contract_address_const::<2301>();

        let receiver = contract_address_const::<24>();
        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
        let assets = 200000000000000000;
        let l1_strategy: EthAddress = 2.try_into().unwrap();

        let token_contract = ERC20ABIDispatcher { contract_address: token_address };
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let underlying_token_address = token_manager.underlying();
        let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };

        start_prank(CheatTarget::One(underlying_token.contract_address), owner);
        underlying_token.approve(token_manager_address, 1000000000000000000002);
        underlying_token.transfer(user2, 300000000000000000);
        stop_prank(CheatTarget::One(underlying_token.contract_address));

        start_prank(CheatTarget::One(underlying_token.contract_address), user2);
        underlying_token.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(underlying_token.contract_address));

        deposit(token_manager_address, owner, assets, receiver);
        deposit(token_manager_address, user2, assets, receiver);

        start_prank(CheatTarget::One(token_contract.contract_address), receiver);
        token_contract.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(token_contract.contract_address));

        start_prank(CheatTarget::One(token_manager.contract_address), receiver);
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        token_manager.request_withdrawal(assets);
        stop_prank(CheatTarget::One(token_manager.contract_address));

        let balance = token_contract.balance_of(receiver);
        assert(balance == 200000000000000000, 'Wrong new token balance');
    }

    // Test handle_mass_report after 5 deposits
    #[test]
    fn test_handle_report_5_deposit() {
        let (token_manager_address, token_address, pooling_manager, owner) = deploy_strategy();
        let user2 = contract_address_const::<2301>();
        let user3 = contract_address_const::<2302>();
        let user4 = contract_address_const::<2303>();
        let user5 = contract_address_const::<2304>();

        let receiver = contract_address_const::<24>();
        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
        let assets = 200000000000000000;
        let l1_strategy: EthAddress = 2.try_into().unwrap();

        let token_contract = ERC20ABIDispatcher { contract_address: token_address };
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let underlying_token_address = token_manager.underlying();
        let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };

        start_prank(CheatTarget::One(underlying_token.contract_address), owner);
        underlying_token.approve(token_manager_address, 1000000000000000000002);
        underlying_token.transfer(user2, 300000000000000000);
        underlying_token.transfer(user3, 300000000000000000);
        underlying_token.transfer(user4, 300000000000000000);
        underlying_token.transfer(user5, 300000000000000000);
        stop_prank(CheatTarget::One(underlying_token.contract_address));

        start_prank(CheatTarget::One(underlying_token.contract_address), user2);
        underlying_token.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(underlying_token.contract_address));

        start_prank(CheatTarget::One(underlying_token.contract_address), user3);
        underlying_token.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(underlying_token.contract_address));

        start_prank(CheatTarget::One(underlying_token.contract_address), user4);
        underlying_token.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(underlying_token.contract_address));

        start_prank(CheatTarget::One(underlying_token.contract_address), user5);
        underlying_token.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(underlying_token.contract_address));

        deposit(token_manager_address, owner, assets, receiver);
        deposit(token_manager_address, user2, assets, receiver);
        deposit(token_manager_address, user3, assets + 10000000000000000, receiver);
        deposit(token_manager_address, user4, assets + 15000000000000000, receiver);
        deposit(token_manager_address, user5, assets, receiver);

        let balance = underlying_token.balance_of(token_manager_address);
        assert(balance == ((assets * 5) + 25000000000000000), 'Wrong underlying balance');

        let balance = token_contract.balance_of(receiver);
        assert(balance == ((assets * 5) + 25000000000000000), 'Wrong token balance');

        start_prank(CheatTarget::One(token_contract.contract_address), receiver);
        token_contract.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(token_contract.contract_address));

        start_prank(CheatTarget::One(token_manager.contract_address), receiver);
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        token_manager.request_withdrawal(assets * 5);
        stop_prank(CheatTarget::One(token_manager.contract_address));

        let balance = token_contract.balance_of(receiver);
        assert(balance == 25000000000000000, 'Wrong new token balance');
    }

    // Test handle_mass_report with deposit into multiple strategy and 
    // request_withdrawal of total assets (for first strategy) and partial assets for the second
    #[test]
    fn test_handle_report_multiple_strategy() {
        let (token_manager_address, token_address, pooling_manager, token_manager_address2, token_address2) =
            deploy_two_strategy();
        let owner = contract_address_const::<2300>();
        let receiver = contract_address_const::<24>();
        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
        let assets = 200000000000000000;

        let token_contract = ERC20ABIDispatcher { contract_address: token_address };
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let token_contract2 = ERC20ABIDispatcher { contract_address: token_address2 };
        let token_manager2 = ITokenManagerDispatcher { contract_address: token_manager_address2 };
        let underlying_token_address = token_manager.underlying();
        let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };
        let underlying_token_address2 = token_manager2.underlying();
        let underlying_token2 = ERC20ABIDispatcher { contract_address: underlying_token_address2 };

        start_prank(CheatTarget::One(underlying_token.contract_address), owner);
        underlying_token.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(underlying_token.contract_address));

        start_prank(CheatTarget::One(underlying_token2.contract_address), owner);
        underlying_token2.approve(token_manager_address2, 1000000000000000000002);
        stop_prank(CheatTarget::One(underlying_token2.contract_address));

        deposit(token_manager_address, owner, assets, receiver);
        deposit(token_manager_address2, owner, assets + 10000000, receiver);

        let balance = underlying_token.balance_of(token_manager_address);
        assert(balance == assets, 'Wrong underlying balance');

        let balance = token_contract.balance_of(receiver);
        assert(balance == assets, 'Wrong token balance');

        let balance = underlying_token2.balance_of(token_manager_address2);
        assert(balance == (assets + 10000000), 'Wrong underlying balance');

        let balance = token_contract2.balance_of(receiver);
        assert(balance == (assets + 10000000), 'Wrong token balance');

        start_prank(CheatTarget::One(token_contract.contract_address), receiver);
        token_contract.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(token_contract.contract_address));

        start_prank(CheatTarget::One(token_contract2.contract_address), receiver);
        token_contract2.approve(token_manager_address2, 1000000000000000000002);
        stop_prank(CheatTarget::One(token_contract2.contract_address));

        start_prank(CheatTarget::One(token_manager.contract_address), receiver);
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        token_manager.request_withdrawal(assets);
        stop_prank(CheatTarget::One(token_manager.contract_address));

        start_prank(CheatTarget::One(token_manager2.contract_address), receiver);
        let token_manager2 = ITokenManagerDispatcher { contract_address: token_manager_address2 };
        token_manager2.request_withdrawal(assets);
        stop_prank(CheatTarget::One(token_manager2.contract_address));

        let balance = token_contract.balance_of(receiver);
        assert(balance == 0, 'Wrong new token balance');

        let balance = token_contract2.balance_of(receiver);
        assert(balance == 10000000, 'Wrong new token balance');
    }

    // Test handle_mass_report with multiple deposits into multiple strategy and 
    // request_withdrawal of some assets for every strategy
    //#[test]
    //fn test_handle_report_5_deposit_3_strategy() {
    //    let (
    //        token_manager_address,
    //        token_address,
    //        pooling_manager,
    //        token_manager_address2,
    //        token_address2,
    //        token_manager_address3,
    //        token_address3
    //    ) =
    //        deploy_three_strategy();
    //
    //    let owner = contract_address_const::<2300>();
    //    let user2 = contract_address_const::<2301>();
    //    let user3 = contract_address_const::<2302>();
    //    let user4 = contract_address_const::<2303>();
    //    let user5 = contract_address_const::<2304>();
    //
    //    let receiver = contract_address_const::<24>();
    //    let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
    //    let assets = 200000000000000000;
    //
    //    let l1_strategy_1: EthAddress = 2.try_into().unwrap();
    //    let l1_strategy_2: EthAddress = 3.try_into().unwrap();
    //    let l1_strategy_3: EthAddress = 4.try_into().unwrap();
    //
    //    let token_contract = ERC20ABIDispatcher { contract_address: token_address };
    //    let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
    //    let token_contract2 = ERC20ABIDispatcher { contract_address: token_address2 };
    //    let token_manager2 = ITokenManagerDispatcher { contract_address: token_manager_address2 };
    //    let token_contract3 = ERC20ABIDispatcher { contract_address: token_address3 };
    //    let token_manager3 = ITokenManagerDispatcher { contract_address: token_manager_address3 };
    //    let underlying_token_address = token_manager.underlying();
    //    let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };
    //    let underlying_token_address2 = token_manager2.underlying();
    //    let underlying_token2 = ERC20ABIDispatcher { contract_address: underlying_token_address2 };
    //    let underlying_token_address3 = token_manager3.underlying();
    //    let underlying_token3 = ERC20ABIDispatcher { contract_address: underlying_token_address3 };
    //
    //    let user_array = @array![owner, user2, user3, user4, user5];
    //    let token_manager_array = @array![token_manager, token_manager2, token_manager3];
    //    let token_array = @array![token_contract, token_contract2, token_contract3];
    //
    //    transfer_to_users(owner, 3000000000000000000, user_array, underlying_token);
    //    transfer_to_users(owner, 3000000000000000000, user_array, underlying_token2);
    //    transfer_to_users(owner, 3000000000000000000, user_array, underlying_token3);
    //
    //    multiple_approve_to_contract(
    //        1000000000000000000002, user_array, underlying_token, token_manager_array
    //    );
    //    multiple_approve_to_contract(
    //        1000000000000000000002, user_array, underlying_token2, token_manager_array
    //    );
    //    multiple_approve_to_contract(
    //        1000000000000000000002, user_array, underlying_token3, token_manager_array
    //    );
    //
    //    // Deposite to token_manager
    //    let mut i = 0;
    //    loop {
    //        if (i == user_array.len()) {
    //            break ();
    //        }
    //        let mut j = 0;
    //        let user = *user_array.at(i);
    //        loop {
    //            if (j == token_manager_array.len()) {
    //                break ();
    //            }
    //            let token_manager_contract = *token_manager_array.at(j);
    //            start_prank(CheatTarget::One(token_manager_contract.contract_address), user);
    //            if (user == user3) {
    //                token_manager_contract
    //                    .deposit(
    //                        assets + 10000000000000000, receiver, contract_address_const::<23>()
    //                    );
    //            } else if (user == user4) {
    //                token_manager_contract
    //                    .deposit(
    //                        assets + 15000000000000000, receiver, contract_address_const::<23>()
    //                    );
    //            } else {
    //                token_manager_contract
    //                    .deposit(assets, receiver, contract_address_const::<23>());
    //            }
    //            stop_prank(CheatTarget::One(token_manager_contract.contract_address));
    //            j += 1;
    //        };
    //        i += 1;
    //    };
    //
    //    let balance = underlying_token.balance_of(token_manager_address);
    //    assert(balance == ((assets * 5) + 25000000000000000), 'Wrong underlying balance');
    //
    //    let balance = token_contract.balance_of(receiver);
    //    assert(balance == ((assets * 5) + 25000000000000000), 'Wrong token balance');
    //
    //    let balance = underlying_token2.balance_of(token_manager_address2);
    //    assert(balance == ((assets * 5) + 25000000000000000), 'Wrong underlying balance');
    //
    //    let balance = token_contract2.balance_of(receiver);
    //    assert(balance == ((assets * 5) + 25000000000000000), 'Wrong token balance');
    //
    //    let balance = underlying_token3.balance_of(token_manager_address3);
    //    assert(balance == ((assets * 5) + 25000000000000000), 'Wrong underlying balance');
    //
    //    let balance = token_contract3.balance_of(receiver);
    //    assert(balance == ((assets * 5) + 25000000000000000), 'Wrong token balance');
    //
    //    // Approve receiver for all token contract
    //    approve_to_contract(1000000000000000000002, receiver, token_contract, token_manager);
    //    approve_to_contract(1000000000000000000002, receiver, token_contract2, token_manager2);
    //    approve_to_contract(1000000000000000000002, receiver, token_contract3, token_manager3);
    //
    //    // Handle first mass report epoch 0
    //    start_prank(CheatTarget::One(pooling_manager.contract_address), receiver);
    //    let empty_calldata = array![];
    //    pooling_manager.handle_mass_report(empty_calldata.span());
    //    stop_prank(CheatTarget::One(pooling_manager.contract_address));
    //
    //    // Request Withdrawal for token_manager
    //    start_prank(CheatTarget::One(token_manager.contract_address), receiver);
    //    token_manager.request_withdrawal(assets * 5);
    //    stop_prank(CheatTarget::One(token_manager.contract_address));
    //
    //    let balance = token_contract.balance_of(receiver);
    //    assert(balance == 25000000000000000, 'Wrong new token balance');
    //
    //    // Request Withdrawal for token_manager2
    //    start_prank(CheatTarget::One(token_manager2.contract_address), receiver);
    //    token_manager2.request_withdrawal(assets * 5);
    //    stop_prank(CheatTarget::One(token_manager2.contract_address));
    //
    //    let balance = token_contract2.balance_of(receiver);
    //    assert(balance == 25000000000000000, 'Wrong new token balance');
    //
    //    // Request Withdrawal for token_manager3
    //    start_prank(CheatTarget::One(token_manager3.contract_address), receiver);
    //    token_manager3.request_withdrawal(assets * 5);
    //    stop_prank(CheatTarget::One(token_manager3.contract_address));
    //
    //    let balance = token_contract3.balance_of(receiver);
    //    assert(balance == 25000000000000000, 'Wrong new token balance');
    //
    //
    //
    //
    //
    //
    //
    //
    //    start_prank(CheatTarget::One(pooling_manager.contract_address), receiver);
    //    let calldata: Array<StrategyReportL1> = array![
    //        StrategyReportL1 {
    //            l1_strategy: l1_strategy_1,
    //            l1_net_asset_value: (assets * 5) + 25000000000000000,
    //            underlying_bridged_amount: 0,
    //            processed: true
    //        }
    //    ];
    //
    //    let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
    //    let epoch: u256 = 1;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //    let epoch: u256 = 2;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //    let epoch: u256 = 3;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //    let epoch: u256 = 4;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //
    //    let calldata: Array<StrategyReportL1> = array![
    //        StrategyReportL1 {
    //            l1_strategy: l1_strategy_2,
    //            l1_net_asset_value: (assets * 5) + 25000000000000000,
    //            underlying_bridged_amount: 0,
    //            processed: true
    //        }
    //    ];
    //
    //    let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
    //    let epoch: u256 = 5;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //    let epoch: u256 = 6;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //    let epoch: u256 = 7;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //    let epoch: u256 = 8;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //    
    //
    //    let calldata: Array<StrategyReportL1> = array![
    //        StrategyReportL1 {
    //            l1_strategy: l1_strategy_3,
    //            l1_net_asset_value: (assets * 5) + 25000000000000000,
    //            underlying_bridged_amount: 0,
    //            processed: true
    //        }
    //    ];
    //
    //    let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
    //    let epoch: u256 = 9;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //    let epoch: u256 = 10;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //    let epoch: u256 = 11;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //    let epoch: u256 = 12;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //    stop_prank(CheatTarget::One(pooling_manager.contract_address));
    //
    //
    //
    //    start_prank(CheatTarget::One(underlying_token.contract_address), owner);
    //    underlying_token.transfer(pooling_manager.contract_address, (assets * 5));
    //    stop_prank(CheatTarget::One(underlying_token.contract_address));
    //
    //    start_prank(CheatTarget::One(underlying_token2.contract_address), owner);
    //    underlying_token2.transfer(pooling_manager.contract_address, (assets * 5));
    //    stop_prank(CheatTarget::One(underlying_token2.contract_address));
    //
    //    start_prank(CheatTarget::One(underlying_token3.contract_address), owner);
    //    underlying_token3.transfer(pooling_manager.contract_address, (assets * 5));
    //    stop_prank(CheatTarget::One(underlying_token3.contract_address));
    //
    //    start_prank(CheatTarget::One(pooling_manager.contract_address), receiver);
    //    let calldata: Array<StrategyReportL1> = array![
    //        StrategyReportL1 {
    //            l1_strategy: l1_strategy_1,
    //            l1_net_asset_value: 25000000000000000,
    //            underlying_bridged_amount: (assets * 5),
    //            processed: true
    //        }
    //    ];
    //    let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
    //    let epoch: u256 = 13;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    let balance_before = underlying_token.balance_of(pooling_manager.contract_address);
    //    pooling_manager.handle_mass_report(calldata.span());
    //    let balance = underlying_token.balance_of(pooling_manager.contract_address);
    //    
    //
    //    let calldata: Array<StrategyReportL1> = array![
    //        StrategyReportL1 {
    //            l1_strategy: l1_strategy_2,
    //            l1_net_asset_value: 25000000000000000,
    //            underlying_bridged_amount: (assets * 5),
    //            processed: true
    //        }
    //    ];
    //    let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
    //    let epoch: u256 = 14;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //    let calldata: Array<StrategyReportL1> = array![
    //        StrategyReportL1 {
    //            l1_strategy: l1_strategy_3,
    //            l1_net_asset_value: 25000000000000000,
    //            underlying_bridged_amount: (assets * 5),
    //            processed: true
    //        }
    //    ];
    //    let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
    //    let epoch: u256 = 15;
    //    let data: Array<felt252> = array![
    //        epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()
    //    ];
    //
    //    let mut l1_handler = L1HandlerTrait::new(
    //        pooling_manager.contract_address, function_name: 'handle_response'
    //    );
    //
    //    l1_handler.from_address = l1_pooling_manager.into();
    //    l1_handler.payload = data.span();
    //
    //    l1_handler.execute().unwrap();
    //    
    //    pooling_manager.handle_mass_report(calldata.span());
    //
    //
    //    stop_prank(CheatTarget::One(pooling_manager.contract_address));
    //
    //    //  start_prank(CheatTarget::One(underlying_token.contract_address), owner);
    //    // underlying_token.transfer(token_manager.contract_address, (assets * 5));
    //    // stop_prank(CheatTarget::One(underlying_token.contract_address));
    //    start_prank(CheatTarget::One(token_manager.contract_address), receiver);
    //    // let info = token_manager.withdrawal_info(receiver, 0);
    //    // let ep = token_manager.handled_epoch_withdrawal_len();
    //
    //    let balance_before = underlying_token.balance_of(token_manager.contract_address);
    //    // assert(balance_before == 2000000000000000002, 'Wrong balance before');
    //
    //    token_manager.claim_withdrawal(0);
    //
    //    let balance_after = underlying_token.balance_of(token_manager.contract_address);
    //    //assert(balance_after == 0, 'Wrong balance after');
    //    stop_prank(CheatTarget::One(token_manager.contract_address));
    //
    //}

    // Request Withdrawal and claim
    #[test]
    #[should_panic(expected: ('Withdrawal not ready',))]
    fn test_request_withdrawal_and_claim_not_ready() {
        let (token_manager_address, token_address, pooling_manager, owner) = deploy_strategy();
        let receiver = contract_address_const::<24>();
        let assets = 200000000000000002;

        let token_contract = ERC20ABIDispatcher { contract_address: token_address };
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let underlying_token_address = token_manager.underlying();
        let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };

        start_prank(CheatTarget::One(underlying_token.contract_address), owner);
        underlying_token.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(underlying_token.contract_address));

        deposit(token_manager_address, owner, assets, receiver);

        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));
        start_prank(CheatTarget::One(pooling_manager.contract_address), token_manager_address);

        start_prank(CheatTarget::One(token_manager.contract_address), receiver);
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        token_manager.request_withdrawal(assets);

        let balance = token_contract.balance_of(receiver);
        assert(balance == 0, 'Wrong new token balance');

        spy.fetch_events();

        let (from, event) = spy.events.at(0);
        assert(event.keys.at(0) == @event_name_hash('RequestWithdrawal'), 'Wrong event name');

        token_manager.claim_withdrawal(0);

        stop_prank(CheatTarget::One(token_manager.contract_address));
        stop_prank(CheatTarget::One(pooling_manager.contract_address));
    }

    // Test deposit handle_mass_report and claim requested withdrawal
    #[test]
    fn test_request_withdrawal_and_claim() {
        let (token_manager_address, token_address, pooling_manager, owner) = deploy_strategy();
        let receiver = contract_address_const::<24>();
        let l1_pooling_manager: EthAddress = 100.try_into().unwrap();
        let assets = 2000000000000000002;

        let token_contract = ERC20ABIDispatcher { contract_address: token_address };
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let underlying_token_address = token_manager.underlying();
        let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };

        start_prank(CheatTarget::One(underlying_token.contract_address), owner);
        underlying_token.approve(token_manager_address, 1000000000000000000002);
        stop_prank(CheatTarget::One(underlying_token.contract_address));

        deposit(token_manager_address, owner, assets, receiver);
        deposit(token_manager_address, owner, assets, receiver);
        deposit(token_manager_address, owner, assets, receiver);

        start_prank(CheatTarget::One(pooling_manager.contract_address), receiver);
        let empty_calldata = array![];
        pooling_manager.handle_mass_report(empty_calldata.span());
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(token_manager.contract_address), receiver);
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        token_manager.request_withdrawal(assets);
        let balance = token_contract.balance_of(receiver);
        assert(balance == assets * 2, 'Wrong token balance');

        stop_prank(CheatTarget::One(token_manager.contract_address));

        start_prank(CheatTarget::One(pooling_manager.contract_address), receiver);
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: (2000000000000000002 * 3),
                underlying_bridged_amount: 0,
                processed: true
            }
        ];

        let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
        let epoch: u256 = 1;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        l1_handler.execute().unwrap();
        pooling_manager.handle_mass_report(calldata.span());

        let epoch: u256 = 2;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        l1_handler.execute().unwrap();

        pooling_manager.handle_mass_report(calldata.span());

        let epoch: u256 = 3;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        l1_handler.execute().unwrap();
        pooling_manager.handle_mass_report(calldata.span());

        let epoch: u256 = 4;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        l1_handler.execute().unwrap();
        pooling_manager.handle_mass_report(calldata.span());
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(underlying_token.contract_address), owner);
        underlying_token.transfer(pooling_manager.contract_address, 2000000000000000002);
        stop_prank(CheatTarget::One(underlying_token.contract_address));

        let mut spy = spy_events(SpyOn::One(pooling_manager.contract_address));
        start_prank(CheatTarget::One(pooling_manager.contract_address), receiver);
        let calldata: Array<StrategyReportL1> = array![
            StrategyReportL1 {
                l1_strategy: 2.try_into().unwrap(),
                l1_net_asset_value: (2000000000000000002 * 2),
                underlying_bridged_amount: 2000000000000000002,
                processed: true
            }
        ];
        let hash: u256 = pooling_manager.hash_l1_data(calldata.span());
        let epoch: u256 = 5;
        let data: Array<felt252> = array![epoch.low.into(), epoch.high.into(), hash.low.into(), hash.high.into()];

        let mut l1_handler = L1HandlerTrait::new(pooling_manager.contract_address, function_name: 'handle_response');

        l1_handler.from_address = l1_pooling_manager.into();
        l1_handler.payload = data.span();

        l1_handler.execute().unwrap();

        pooling_manager.handle_mass_report(calldata.span());

        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        start_prank(CheatTarget::One(token_manager.contract_address), receiver);

        let balance_before = underlying_token.balance_of(token_manager.contract_address);
        assert(balance_before == 2000000000000000002, 'Wrong balance before');

        token_manager.claim_withdrawal(0);

        let balance_after = underlying_token.balance_of(token_manager.contract_address);
        assert(balance_after == 0, 'Wrong balance after');

        stop_prank(CheatTarget::One(token_manager.contract_address));
    }
}

