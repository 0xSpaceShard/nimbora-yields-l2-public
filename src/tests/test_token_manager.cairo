#[cfg(test)]
mod testTokenManager {
    use core::debug::PrintTrait;
    use core::option::OptionTrait;
    use core::result::ResultTrait;
    use core::traits::Into;
    use core::traits::TryInto;
    use integer::{BoundedInt};
    use nimbora_yields::mocks::mock_mintable_token::{MockMintableToken};
    use nimbora_yields::pooling_manager::interface::{IPoolingManagerDispatcher, IPoolingManagerDispatcherTrait};
    use nimbora_yields::tests::test_utils::{
        deploy_tokens, deploy_token_manager, deploy_token_manager_and_provide_args, deploy_strategy,
        deploy_two_strategy, deploy_three_strategy, approve_to_contract, multiple_approve_to_contract,
        transfer_to_users, deposit, deposit_and_handle_mass, between, deploy_mock_mintable_token, setup_0,
        deploy_mock_transfer
    };
    use nimbora_yields::token::interface::{ITokenDispatcher, ITokenDispatcherTrait};
    use nimbora_yields::token_bridge::interface::{
        ITokenBridgeDispatcher, IMintableTokenDispatcher, IMintableTokenDispatcherTrait
    };

    // Utils peripheric contracts
    use nimbora_yields::token_bridge::token_bridge::{TokenBridge};
    use nimbora_yields::token_bridge::token_mock::{TokenMock};
    use nimbora_yields::token_manager::interface::{
        ITokenManagerDispatcher, ITokenManagerDispatcherTrait, WithdrawalInfo
    };
    use nimbora_yields::token_manager::token_manager::TokenManager::{
        InternalTrait, epochContractMemberStateTrait, l1_net_asset_valueContractMemberStateTrait,
        underlying_transitContractMemberStateTrait, bufferContractMemberStateTrait,
        handled_epoch_withdrawal_lenContractMemberStateTrait, withdrawal_infoContractMemberStateTrait,
        withdrawal_poolContractMemberStateTrait, withdrawal_shareContractMemberStateTrait,
        user_withdrawal_lenContractMemberStateTrait, tokenContractMemberStateTrait,
        performance_feesContractMemberStateTrait, pooling_managerContractMemberStateTrait,
        dust_limitContractMemberStateTrait, underlyingContractMemberStateTrait
    };

    // Nimbora yields contracts
    use nimbora_yields::token_manager::token_manager::{TokenManager};
    use nimbora_yields::utils::{CONSTANTS, MATH};

    use openzeppelin::{
        token::erc20::interface::{IERC20, ERC20ABIDispatcher, ERC20ABIDispatcherTrait}, token::erc20::{ERC20Component},
        access::accesscontrol::{
            AccessControlComponent, interface::{IAccessControlDispatcher, IAccessControlDispatcherTrait}
        },
        upgrades::interface::{IUpgradeableDispatcher, IUpgradeable, IUpgradeableDispatcherTrait}
    };
    use snforge_std::cheatcodes::contract_class::RevertedTransactionTrait;
    use snforge_std::{
        declare, ContractClassTrait, start_prank, CheatTarget, ContractClass, stop_prank, start_warp, stop_warp,
        L1Handler, L1HandlerTrait, get_class_hash, event_name_hash, spy_events, SpyOn, EventSpy, EventFetcher, Event,
        store, map_entry_address
    };
    use starknet::account::{Call};
    use starknet::class_hash::Felt252TryIntoClassHash;

    use starknet::{
        get_contract_address, deploy_syscall, ClassHash, contract_address_const, ContractAddress, get_block_timestamp,
        EthAddress, Zeroable
    };


    /// Test Internal

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_withdrawal_exchange_rate(x: u256, y: u256) {
        let mut state = TokenManager::contract_state_for_testing();
        let epoch_used = 92;
        let withdrawal_pool = between(0, BoundedInt::max() / (10 * CONSTANTS::WAD), x);
        let withdrawal_share = between(0, BoundedInt::max() / (10 * CONSTANTS::WAD), y);
        state.withdrawal_pool.write(epoch_used, withdrawal_pool);
        state.withdrawal_share.write(epoch_used, withdrawal_share);
        let value = state._withdrawal_exchange_rate(epoch_used);
        assert(value == (withdrawal_pool + 1) * CONSTANTS::WAD / (withdrawal_share + 1), 'Incorrect exchange rate');
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_total_underlying_due(x: u256, y: u256, z: u256) {
        let mut state = TokenManager::contract_state_for_testing();

        let current_epoch = between(0, 300, x);
        let handled_epoch_withdrawal_len = between(0, current_epoch, y);

        let mut i = handled_epoch_withdrawal_len;
        let mut acc = 0;
        loop {
            if (i > current_epoch) {
                break ();
            }
            let random_value = between(0, CONSTANTS::WAD, z);
            state.withdrawal_pool.write(i, random_value);
            acc += random_value;
            i += 1;
        };
        let res = state._total_underlying_due(handled_epoch_withdrawal_len, current_epoch);
        assert(res == acc, 'Incorrect underlying due');
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_total_assets(x: u256, y: u256, z: u256, a: u256, b: u256, c: u256) {
        let mut state = TokenManager::contract_state_for_testing();
        let current_epoch = between(0, 300, x);
        let handled_epoch_withdrawal_len = between(0, current_epoch, y);
        state.epoch.write(current_epoch);
        state.handled_epoch_withdrawal_len.write(handled_epoch_withdrawal_len);
        let mut i = handled_epoch_withdrawal_len;
        let mut acc = 0;
        loop {
            if (i > current_epoch) {
                break ();
            }
            let random_value = between(0, CONSTANTS::WAD, z);
            state.withdrawal_pool.write(i, random_value);
            acc += random_value;
            i += 1;
        };
        let buffer = between(0, BoundedInt::max() / CONSTANTS::WAD, a) + acc;
        state.buffer.write(buffer);
        let l1_net_asset_value = between(0, BoundedInt::max() / CONSTANTS::WAD, b);
        state.l1_net_asset_value.write(l1_net_asset_value);
        let underlying_transit = between(0, BoundedInt::max() / CONSTANTS::WAD, c);
        state.underlying_transit.write(underlying_transit);
        let total_assets = state._total_assets();
        assert(total_assets == underlying_transit + l1_net_asset_value + buffer - acc, 'wrong total_assets');
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_convert_to_shares(x: u256, y: u256, z: u256, a: u256, b: u256, c: u256, d: u256, e: u256) {
        let total_supply = between(0, 300, d);
        let (token_1, _, _) = deploy_tokens(total_supply, contract_address_const::<24>());

        let mut state = TokenManager::contract_state_for_testing();
        state.token.write(token_1.contract_address);

        let current_epoch = between(0, 300, x);
        let handled_epoch_withdrawal_len = between(0, current_epoch, y);
        state.epoch.write(current_epoch);
        state.handled_epoch_withdrawal_len.write(handled_epoch_withdrawal_len);
        let mut i = handled_epoch_withdrawal_len;
        let mut acc = 0;
        loop {
            if (i > current_epoch) {
                break ();
            }
            let random_value = between(0, CONSTANTS::WAD, z);
            state.withdrawal_pool.write(i, random_value);
            acc += random_value;
            i += 1;
        };

        let buffer = between(0, BoundedInt::max() / CONSTANTS::WAD, a) + acc;
        state.buffer.write(buffer);
        let l1_net_asset_value = between(0, BoundedInt::max() / CONSTANTS::WAD, b);
        state.l1_net_asset_value.write(l1_net_asset_value);
        let underlying_transit = between(0, BoundedInt::max() / CONSTANTS::WAD, c);
        state.underlying_transit.write(underlying_transit);
        let total_assets = underlying_transit + l1_net_asset_value + buffer - acc;

        let assets = between(0, CONSTANTS::WAD, e);
        let shares_obtained = state._convert_to_shares(assets);
        assert(shares_obtained == (assets * (total_supply + 1)) / (total_assets + 1), 'Wrong convert shares')
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_convert_to_assets(x: u256, y: u256, z: u256, a: u256, b: u256, c: u256, d: u256, e: u256) {
        let total_supply = between(0, 300, d);
        let (token_1, _, _) = deploy_tokens(total_supply, contract_address_const::<24>());

        let mut state = TokenManager::contract_state_for_testing();
        state.token.write(token_1.contract_address);

        let current_epoch = between(0, 300, x);
        let handled_epoch_withdrawal_len = between(0, current_epoch, y);
        state.epoch.write(current_epoch);
        state.handled_epoch_withdrawal_len.write(handled_epoch_withdrawal_len);
        let mut i = handled_epoch_withdrawal_len;
        let mut acc = 0;
        loop {
            if (i > current_epoch) {
                break ();
            }
            let random_value = between(0, CONSTANTS::WAD, z);
            state.withdrawal_pool.write(i, random_value);
            acc += random_value;
            i += 1;
        };

        let buffer = between(0, BoundedInt::max() / (CONSTANTS::WAD * CONSTANTS::WAD), a) + acc;
        state.buffer.write(buffer);
        let l1_net_asset_value = between(0, BoundedInt::max() / (CONSTANTS::WAD * CONSTANTS::WAD), b);
        state.l1_net_asset_value.write(l1_net_asset_value);
        let underlying_transit = between(0, BoundedInt::max() / (CONSTANTS::WAD * CONSTANTS::WAD), c);
        state.underlying_transit.write(underlying_transit);
        let total_assets = underlying_transit + l1_net_asset_value + buffer - acc;

        let shares = between(0, CONSTANTS::WAD, e);
        let assets_obtained = state._convert_to_assets(shares);
        assert(assets_obtained == (shares * (total_assets + 1)) / (total_supply + 1), 'Wrong convert assets')
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_calculate_profit_and_handle_loss_profit_case(x: u256, y: u256, z: u256) {
        let mut state = TokenManager::contract_state_for_testing();
        let l1_net_asset_value_last_epoch = between(0, CONSTANTS::WAD * CONSTANTS::WAD, x);
        let underlying_transit_last_epoch = between(0, CONSTANTS::WAD * CONSTANTS::WAD, y);
        state.l1_net_asset_value.write(l1_net_asset_value_last_epoch);
        state.underlying_transit.write(underlying_transit_last_epoch);
        let sent_to_l1 = l1_net_asset_value_last_epoch + underlying_transit_last_epoch;
        let received_from_l1 = between(sent_to_l1, 10 * CONSTANTS::WAD * CONSTANTS::WAD, z);
        let profit = state._calculate_profit_and_handle_loss(0, 0, received_from_l1, 0);
        assert(profit == received_from_l1 - sent_to_l1, 'wrong profit');
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_calculate_profit_and_handle_loss_loss_case(
        x: u256, y: u256, z: u256, a: u256, b: u256, c: u256, d: u256
    ) {
        let mut state = TokenManager::contract_state_for_testing();
        let l1_net_asset_value_last_epoch = between(1, CONSTANTS::WAD * CONSTANTS::WAD, x);
        let underlying_transit_last_epoch = between(1, CONSTANTS::WAD * CONSTANTS::WAD, y);
        state.l1_net_asset_value.write(l1_net_asset_value_last_epoch);
        state.underlying_transit.write(underlying_transit_last_epoch);
        let sent_to_l1 = l1_net_asset_value_last_epoch + underlying_transit_last_epoch;
        let received_from_l1 = between(0, sent_to_l1, z);

        let buffer = between(0, CONSTANTS::WAD * CONSTANTS::WAD, a);

        let handled_epoch_withdrawal_len = between(0, 10, b);
        let epoch = between(handled_epoch_withdrawal_len, 20, c);

        let mut i = handled_epoch_withdrawal_len;
        let mut withdrawal_pool_amount_array = ArrayTrait::<u256>::new();

        loop {
            if (i > epoch) {
                break ();
            }
            let withdrawal_pool_amount = between(0, CONSTANTS::WAD, d) * (i + 1);
            state.withdrawal_pool.write(i, withdrawal_pool_amount);
            withdrawal_pool_amount_array.append(withdrawal_pool_amount);
            i += 1;
        };

        state._calculate_profit_and_handle_loss(epoch, handled_epoch_withdrawal_len, received_from_l1, buffer);
        let amount_to_consider = buffer + sent_to_l1;
        let loss = (l1_net_asset_value_last_epoch + underlying_transit_last_epoch) - received_from_l1;
        let mut j = 0;
        loop {
            if (j >= withdrawal_pool_amount_array.len()) {
                break ();
            }
            let current_elem = *withdrawal_pool_amount_array.at(j.try_into().unwrap());
            let current_elem_loss = (loss * current_elem) / amount_to_consider;
            let current_elem_after_loss = current_elem - current_elem_loss;
            let current_elem_after_loss_from_call = state.withdrawal_pool.read(j.into() + handled_epoch_withdrawal_len);
            assert(current_elem_after_loss == current_elem_after_loss_from_call, 'wrong elem loss');
            j += 1;
        };
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_handle_withdrawals_epoch_lt_delay(x: u256, y: u256, z: u256, a: u256) {
        let mut state = TokenManager::contract_state_for_testing();
        let withdrawal_epoch_delay = between(1, BoundedInt::max(), x);
        let epoch = between(0, withdrawal_epoch_delay - 1, y);
        let underlying_bridged_amount = between(0, BoundedInt::max() / 2, z);
        let buffer = between(0, BoundedInt::max() / 2, a);
        let (remaining_assets, needed_assets) = state
            ._handle_withdrawals(epoch, 0, withdrawal_epoch_delay, underlying_bridged_amount, buffer);
        assert(remaining_assets == underlying_bridged_amount + buffer, 'wrong remaining');
        assert(needed_assets == 0, 'wrong needed');
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_handle_withdrawals(x: u256, y: u256, z: u256, a: u256, b: u256) {
        let mut state = TokenManager::contract_state_for_testing();
        let withdrawal_epoch_delay = between(1, 10, x);
        let epoch = between(withdrawal_epoch_delay, 20, y);
        let limit_epoch = epoch - withdrawal_epoch_delay;
        let handled_epoch_withdrawal_len = between(0, limit_epoch, z);

        let underlying_bridged_amount = between(0, BoundedInt::max() / 2, z);
        let buffer = between(0, BoundedInt::max() / 2, a);

        let mut j = handled_epoch_withdrawal_len;
        let mut new_handled_epoch_withdrawal_len = handled_epoch_withdrawal_len;

        let mut remaining_assets = underlying_bridged_amount + buffer;
        let mut needed_assets = 0;
        loop {
            if (j > limit_epoch) {
                break ();
            }
            let withdrawal_pool_amount = between(0, CONSTANTS::WAD, b) * (j + 1);
            state.withdrawal_pool.write(j, withdrawal_pool_amount);
            if (remaining_assets >= withdrawal_pool_amount) {
                remaining_assets -= withdrawal_pool_amount;
                new_handled_epoch_withdrawal_len += 1;
            } else {
                needed_assets += withdrawal_pool_amount - remaining_assets;
            }
            j += 1;
        };
        let (remaining_assets_from_call, needed_assets_from_call) = state
            ._handle_withdrawals(
                epoch, handled_epoch_withdrawal_len, withdrawal_epoch_delay, underlying_bridged_amount, buffer
            );
        assert(remaining_assets == remaining_assets_from_call, 'wrong remaining');
        assert(needed_assets == needed_assets_from_call, 'wrong needed');
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_handle_result_withdrawal(x: u256, y: u256, z: u256, a: u256) {
        let mut state = TokenManager::contract_state_for_testing();
        let remaining_assets = between(0, BoundedInt::max() - 1, x);
        let needed_assets = between(1, BoundedInt::max() - 1, y);
        let prev_underlying_transit = between(1, BoundedInt::max() - 1, z);
        state.underlying_transit.write(prev_underlying_transit);
        let prev_buffer = between(0, BoundedInt::max() - 1, a);
        state.buffer.write(prev_buffer);
        let (action_id, amount) = state._handle_result(remaining_assets, needed_assets, 0);
        assert(action_id == CONSTANTS::WITHDRAWAL, 'wrong action id');
        assert(amount == needed_assets, 'wrong amount');
        let new_underlying_transit = state.underlying_transit.read();
        assert(new_underlying_transit == 0, 'wrong transit');
        let new_buffer = state.buffer.read();
        assert(new_buffer == remaining_assets, 'wrong buffer');
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_handle_result_report(x: u256, y: u256, z: u256, a: u256, b: u256) {
        let mut state = TokenManager::contract_state_for_testing();
        let dust_limit_factor = between(1, CONSTANTS::WAD, x);
        let new_l1_net_asset_value = between((CONSTANTS::WAD * 100), BoundedInt::max() / (CONSTANTS::WAD * 100), y);
        let dust_limit = (new_l1_net_asset_value * dust_limit_factor) / CONSTANTS::WAD;
        state.dust_limit.write(dust_limit_factor);
        let remaining_assets = between(0, dust_limit - 1, z);
        let needed_assets = 0;
        let prev_underlying_transit = between(1, BoundedInt::max() - 1, a);
        state.underlying_transit.write(prev_underlying_transit);
        let prev_buffer = between(0, BoundedInt::max() - 1, b);
        state.buffer.write(prev_buffer);
        let (action_id, amount) = state._handle_result(remaining_assets, needed_assets, new_l1_net_asset_value);
        assert(action_id == CONSTANTS::REPORT, 'wrong action id');
        assert(amount == 0, 'wrong amount');
        let new_underlying_transit = state.underlying_transit.read();
        assert(new_underlying_transit == 0, 'wrong transit');
        let new_buffer = state.buffer.read();
        assert(new_buffer == remaining_assets, 'wrong buffer');
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_internal_handle_result_deposit(x: u256, y: u256, z: u256, a: u256, b: u256) {
        let mut state = TokenManager::contract_state_for_testing();
        let token_transfer_mock = deploy_mock_transfer();
        state.underlying.write(token_transfer_mock);
        let dust_limit_factor = between(1, CONSTANTS::WAD, x);
        let new_l1_net_asset_value = between(1, BoundedInt::max() / (CONSTANTS::WAD * 100), y);
        let dust_limit = (new_l1_net_asset_value * dust_limit_factor) / CONSTANTS::WAD;
        state.dust_limit.write(dust_limit_factor);
        let remaining_assets = between(dust_limit, BoundedInt::max() - 1, z);
        let needed_assets = 0;
        let prev_underlying_transit = between(1, BoundedInt::max() - 1, a);
        state.underlying_transit.write(prev_underlying_transit);
        let prev_buffer = between(0, BoundedInt::max() - 1, b);
        state.buffer.write(prev_buffer);
        let (action_id, amount) = state._handle_result(remaining_assets, needed_assets, new_l1_net_asset_value);
        assert(action_id == CONSTANTS::DEPOSIT, 'wrong action id');
        assert(amount == remaining_assets, 'wrong amount');
        let new_underlying_transit = state.underlying_transit.read();
        assert(new_underlying_transit == remaining_assets, 'wrong transit');
        let new_buffer = state.buffer.read();
        assert(new_buffer == 0, 'wrong buffer');
    }


    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_check_profit_and_mint(x: u256, y: u256) {
        let (owner, fees_recipient, _, pooling_manager, _, _, _) = setup_0();

        start_prank(CheatTarget::One(pooling_manager.contract_address), owner);
        pooling_manager.set_fees_recipient(fees_recipient);
        stop_prank(CheatTarget::One(pooling_manager.contract_address));

        let mut state = TokenManager::contract_state_for_testing();

        let mintable_token = deploy_mock_mintable_token();

        let performance_fees = between(0, CONSTANTS::WAD, x);
        state.performance_fees.write(performance_fees);
        state.pooling_manager.write(pooling_manager.contract_address);
        state.token.write(mintable_token.contract_address);

        let underlying_profit = between(0, CONSTANTS::WAD * CONSTANTS::WAD, y);
        state._check_profit_and_mint(underlying_profit, mintable_token.contract_address);

        let balance_minted = mintable_token.balanceOf(fees_recipient);

        if (underlying_profit == 0) {
            assert(balance_minted == 0, 'wrong mint zero');
        } else {
            assert(balance_minted == (underlying_profit * performance_fees) / CONSTANTS::WAD, 'wrong mint');
        }
    }


    /// Test Init

    #[test]
    fn deploy_token_manager_test_initial_values() {
        let (
            token_manager,
            _,
            pooling_manager,
            l1_strategy,
            underlying,
            performance_fees,
            tvl_limit,
            withdrawal_epoch_delay,
            dust_limit
        ) =
            deploy_token_manager_and_provide_args();
        assert(token_manager.pooling_manager() == pooling_manager, 'Wrong pooling manager');
        assert(token_manager.l1_strategy() == l1_strategy, 'Wrong l1 strategy');
        assert(token_manager.underlying() == underlying, 'Wrong underlying');
        assert(token_manager.performance_fees() == performance_fees, 'Wrong performance fees');
        assert(token_manager.tvl_limit() == tvl_limit, 'Wrong tvl limit');
        assert(token_manager.withdrawal_epoch_delay() == withdrawal_epoch_delay, 'Wrong withdrawal epoch delay');
        assert(token_manager.dust_limit() == dust_limit, 'Wrong withdrawal dust limit');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn initialize_token_manager_wrong_caller() {
        let (token_manager, _, _, _, _, _, _, _, _,) = deploy_token_manager_and_provide_args();
        token_manager.initialiser(3.try_into().unwrap());
    }

    #[test]
    fn initialize_token_manager() {
        let (token_manager, _, pooling_manager, _, _, _, _, _, _) = deploy_token_manager_and_provide_args();
        let nimbora_token: ContractAddress = 3.try_into().unwrap();
        start_prank(CheatTarget::One(token_manager.contract_address), pooling_manager);
        token_manager.initialiser(nimbora_token);
        stop_prank(CheatTarget::One(token_manager.contract_address));
        assert(token_manager.token() == nimbora_token, 'Wrong nimbora token');
    }


    /// Test token_manager upgrade

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn upgrade_token_manager_wrong_caller() {
        let (token_manager_address, _, _, _) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let mock_contract = declare('MockRandom');
        IUpgradeableDispatcher { contract_address: token_manager.contract_address }.upgrade(mock_contract.class_hash);
    }

    #[test]
    #[should_panic(expected: ('Class hash cannot be zero',))]
    fn upgrade_token_manager_zero_class_hash() {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        IUpgradeableDispatcher { contract_address: token_manager.contract_address }.upgrade(Zeroable::zero());
        stop_prank(CheatTarget::One(token_manager.contract_address));
    }

    #[test]
    fn upgrade_token_manager() {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let mock_contract = declare('MockRandom');
        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        IUpgradeableDispatcher { contract_address: token_manager.contract_address }.upgrade(mock_contract.class_hash);
        stop_prank(CheatTarget::One(token_manager.contract_address));
    }


    /// Test token_manager setters

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn token_manager_set_performance_fees_wrong_caller() {
        let (token_manager_address, _, _, _) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        token_manager.set_performance_fees(1000000000000000);
    }

    // Test set_performance_fee with too high value
    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    #[should_panic(expected: ('Fee amount too high',))]
    fn token_manager_set_performance_fees_too_high(x: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };

        let performance_fees = between(CONSTANTS::WAD, BoundedInt::max(), x);
        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.set_performance_fees(performance_fees);
        stop_prank(CheatTarget::One(token_manager.contract_address));
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn token_manager_set_performance_fees(x: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };

        let performance_fees = between(0, CONSTANTS::WAD, x);

        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.set_performance_fees(performance_fees);
        stop_prank(CheatTarget::One(token_manager.contract_address));
        assert(token_manager.performance_fees() == performance_fees, 'Wrong performance fees');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn token_manager_set_deposit_limit_wrong_caller() {
        let (token_manager_address, _, _, _) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        token_manager.set_tvl_limit(2000000000);
    }

    #[test]
    #[should_panic(expected: ('Amount nul',))]
    fn token_manager_set_deposit_limit_zero() {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.set_tvl_limit(0);
        stop_prank(CheatTarget::One(token_manager.contract_address));
    }

    #[test]
    #[fuzzer(runs: 22, seed: 2)]
    fn token_manager_set_tvl_limit(x: u256, y: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };

        let tvl_limit = between(1, BoundedInt::max(), y) + 1;
        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.set_tvl_limit(tvl_limit);
        stop_prank(CheatTarget::One(token_manager.contract_address));

        let tvl_limit = token_manager.tvl_limit();
        assert(tvl_limit == tvl_limit, 'Wrong tvl limit');
    }

    // test set_withdrawal_epoch_delay with wrong caller
    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn token_manager_set_withdrawal_epoch_delay_wrong_caller() {
        let (token_manager_address, _, _, _) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        token_manager.set_withdrawal_epoch_delay(10000000000000);
    }

    #[test]
    #[should_panic(expected: ('Amount nul',))]
    fn token_manager_set_withdrawal_epoch_delay_zero_epoch() {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };

        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.set_withdrawal_epoch_delay(0);
        stop_prank(CheatTarget::One(token_manager.contract_address));
    }

    #[test]
    #[fuzzer(runs: 22, seed: 2)]
    fn token_manager_set_withdrawal_epoch_delay(x: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let withdrawal_epoch_delay = between(1, BoundedInt::max(), x);

        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.set_withdrawal_epoch_delay(withdrawal_epoch_delay);
        stop_prank(CheatTarget::One(token_manager.contract_address));

        let epoch_delay = token_manager.withdrawal_epoch_delay();
        assert(epoch_delay == withdrawal_epoch_delay, 'Wrong withdrawal epoch delay');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn token_manager_set_dust_limit_wrong_caller() {
        let (token_manager_address, _, _, _) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        token_manager.set_dust_limit(10000000000000);
    }

    #[test]
    #[should_panic(expected: ('Amount nul',))]
    fn token_manager_set_dust_limit_zero() {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.set_dust_limit(0);
        stop_prank(CheatTarget::One(token_manager.contract_address));
    }

    #[test]
    #[fuzzer(runs: 22, seed: 2)]
    fn token_manager_set_dust_limit(x: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let dust_limit = between(1, BoundedInt::max(), x);
        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.set_dust_limit(dust_limit);
        stop_prank(CheatTarget::One(token_manager.contract_address));
        let dust_limit_from_call = token_manager.dust_limit();
        assert(dust_limit_from_call == dust_limit, 'Wrong dust limit');
    }

    #[test]
    #[fuzzer(runs: 22, seed: 2)]
    #[should_panic(expected: ('Tvl limit reached',))]
    fn test_deposit_tvl_limit_reached(x: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let receiver = contract_address_const::<24>();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let tvl_limit = 10000000000000000000 + 1;
        let assets = between(tvl_limit, BoundedInt::max(), x);
        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.deposit(assets, receiver, receiver);
        stop_prank(CheatTarget::One(token_manager.contract_address));
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_deposit(x: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let receiver = contract_address_const::<24>();

        let tvl_limit = 10000000000000000000;
        let assets = between(1, tvl_limit, x);
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let underlying_token_address = token_manager.underlying();
        let underlying_token = ERC20ABIDispatcher { contract_address: underlying_token_address };

        let balance_before_owner = underlying_token.balance_of(owner);
        deposit(token_manager_address, owner, assets, receiver);
        let balance_after_owner = underlying_token.balance_of(owner);

        assert(balance_before_owner - balance_after_owner == assets, 'Wrong underlying balance');

        let balance_token_manager = underlying_token.balance_of(token_manager_address);
        assert(balance_token_manager == assets, 'Wrong underlying balance');

        let nimbora_token_address = token_manager.token();
        let nimbora_token = ERC20ABIDispatcher { contract_address: nimbora_token_address };

        let balance_receiver_nimbora_token = nimbora_token.balance_of(receiver);
        assert(balance_receiver_nimbora_token == assets, 'Wrong nimbora token balance');

        let token_manager_buffer = token_manager.buffer();
        assert(token_manager_buffer == assets, 'Wrong buffer');
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_request_withdrawal(x: u256, y: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();

        let receiver = contract_address_const::<24>();
        let tvl_limit = 10000000000000000000;

        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let nimbora_token = token_manager.token();
        let nimbora_token_disp = ERC20ABIDispatcher { contract_address: nimbora_token };

        let assets = between(1, tvl_limit, x);
        deposit(token_manager_address, owner, assets, receiver);

        let shares_to_withdraw = between(1, assets, y);
        start_prank(CheatTarget::One(token_manager.contract_address), receiver);
        token_manager.request_withdrawal(shares_to_withdraw);
        stop_prank(CheatTarget::One(token_manager.contract_address));

        let balance_receiver_after_withdraw_request = nimbora_token_disp.balanceOf(receiver);

        assert(balance_receiver_after_withdraw_request == assets - shares_to_withdraw, 'Wrong nimbora token balance');

        let withdrawal_pool = token_manager.withdrawal_pool(0);
        assert(withdrawal_pool == shares_to_withdraw, 'Wrong withdrawal pool');

        let withdrawal_share = token_manager.withdrawal_share(0);
        assert(withdrawal_share == shares_to_withdraw, 'Wrong withdrawal shares');

        let user_withdrawal_len = token_manager.user_withdrawal_len(receiver);
        assert(user_withdrawal_len == 1, 'Wrong withdrawal len');

        let withdrawal_info = token_manager.withdrawal_info(receiver, 0);
        assert(withdrawal_info.epoch == 0, 'Wrong epoch withdraw');
        assert(withdrawal_info.shares == shares_to_withdraw, 'Wrong shares withdraw');
        assert(withdrawal_info.claimed == false, 'Wrong claim withdraw');
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    #[should_panic(expected: ('Invalid Id',))]
    fn test_claim_withdrawal_invalid_id(x: u256, y: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let user_withdrawal_len = between(0, CONSTANTS::WAD / 2, x);
        let user_withdrawal_len_array_key: Array<felt252> = array![owner.into()];
        let user_withdrawal_len_array_value: Array<felt252> = array![
            user_withdrawal_len.low.into(), user_withdrawal_len.high.into()
        ];
        store(
            token_manager_address,
            map_entry_address(selector!("user_withdrawal_len"), user_withdrawal_len_array_key.span(),),
            user_withdrawal_len_array_value.span()
        );
        let id = between(user_withdrawal_len, CONSTANTS::WAD, y);
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };

        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.claim_withdrawal(id);
        stop_prank(CheatTarget::One(token_manager.contract_address));
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    #[should_panic(expected: ('Already claimed',))]
    fn test_claim_withdrawal_already_claimed(x: u256, y: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let user_withdrawal_len = between(1, CONSTANTS::WAD, x);
        let id = between(0, user_withdrawal_len - 1, y);
        let user_withdrawal_len_array_key: Array<felt252> = array![owner.into()];
        let user_withdrawal_len_array_value: Array<felt252> = array![
            user_withdrawal_len.low.into(), user_withdrawal_len.high.into()
        ];
        store(
            token_manager_address,
            map_entry_address(selector!("user_withdrawal_len"), user_withdrawal_len_array_key.span(),),
            user_withdrawal_len_array_value.span()
        );

        let mapping_key: Array<felt252> = array![owner.into(), id.low.into(), id.high.into()];
        let mapping_value: Span<felt252> = (WithdrawalInfo { epoch: 0, shares: 1, claimed: true }).into();
        store(
            token_manager_address, map_entry_address(selector!("withdrawal_info"), mapping_key.span(),), mapping_value
        );
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };

        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.claim_withdrawal(id);
        stop_prank(CheatTarget::One(token_manager.contract_address));
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    #[should_panic(expected: ('Withdrawal not ready',))]
    fn test_claim_withdrawal_not_ready(x: u256, y: u256, a: u256, b: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let user_withdrawal_len = between(1, CONSTANTS::WAD, x);
        let id = between(0, user_withdrawal_len - 1, y);
        let user_withdrawal_len_array_key: Array<felt252> = array![owner.into()];
        let user_withdrawal_len_array_value: Array<felt252> = array![
            user_withdrawal_len.low.into(), user_withdrawal_len.high.into()
        ];
        store(
            token_manager_address,
            map_entry_address(selector!("user_withdrawal_len"), user_withdrawal_len_array_key.span(),),
            user_withdrawal_len_array_value.span()
        );

        let handled_epoch_withdrawal_len = between(0, CONSTANTS::WAD / 2, a);
        let withdrawal_user_epoch = between(handled_epoch_withdrawal_len, CONSTANTS::WAD, b);
        let handled_epoch_withdrawal_len_array_value: Array<felt252> = array![
            handled_epoch_withdrawal_len.low.into(), handled_epoch_withdrawal_len.high.into()
        ];
        store(
            token_manager_address,
            selector!("handled_epoch_withdrawal_len"),
            handled_epoch_withdrawal_len_array_value.span()
        );

        let mapping_key: Array<felt252> = array![owner.into(), id.low.into(), id.high.into()];
        let mapping_value: Span<felt252> = (WithdrawalInfo { epoch: withdrawal_user_epoch, shares: 1, claimed: false })
            .into();
        store(
            token_manager_address, map_entry_address(selector!("withdrawal_info"), mapping_key.span(),), mapping_value
        );
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };

        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.claim_withdrawal(id);
        stop_prank(CheatTarget::One(token_manager.contract_address));
    }

    #[test]
    #[fuzzer(runs: 22, seed: 1)]
    fn test_claim_withdrawal(x: u256, y: u256, a: u256, b: u256, c: u256, d: u256, e: u256) {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let user_withdrawal_len = between(1, CONSTANTS::WAD, x);
        let id = between(0, user_withdrawal_len - 1, y);
        let user_withdrawal_len_array_key: Array<felt252> = array![owner.into()];
        let user_withdrawal_len_array_value: Array<felt252> = array![
            user_withdrawal_len.low.into(), user_withdrawal_len.high.into()
        ];
        store(
            token_manager_address,
            map_entry_address(selector!("user_withdrawal_len"), user_withdrawal_len_array_key.span(),),
            user_withdrawal_len_array_value.span()
        );

        let withdrawal_share = between(CONSTANTS::WAD / 100, CONSTANTS::WAD * 100, c);
        let withdrawal_pool = between(CONSTANTS::WAD / 100, CONSTANTS::WAD * 100, d);
        let user_withdrawal_share = between(0, withdrawal_share, e);

        let withdrawal_user_epoch = between(0, CONSTANTS::WAD / 2, a);
        let handled_epoch_withdrawal_len = between(withdrawal_user_epoch + 1, CONSTANTS::WAD, b);

        let mapping_key_withdrawal_share_and_pool: Array<felt252> = array![
            withdrawal_user_epoch.low.into(), withdrawal_user_epoch.high.into()
        ];
        let mapping_value_withdrawal_share: Array<felt252> = array![
            withdrawal_share.low.into(), withdrawal_share.high.into()
        ];
        store(
            token_manager_address,
            map_entry_address(selector!("withdrawal_share"), mapping_key_withdrawal_share_and_pool.span()),
            mapping_value_withdrawal_share.span()
        );

        let mapping_value_withdrawal_pool: Array<felt252> = array![
            withdrawal_pool.low.into(), withdrawal_pool.high.into()
        ];
        store(
            token_manager_address,
            map_entry_address(selector!("withdrawal_pool"), mapping_key_withdrawal_share_and_pool.span()),
            mapping_value_withdrawal_pool.span()
        );
        let handled_epoch_withdrawal_len_array_value: Array<felt252> = array![
            handled_epoch_withdrawal_len.low.into(), handled_epoch_withdrawal_len.high.into()
        ];
        store(
            token_manager_address,
            selector!("handled_epoch_withdrawal_len"),
            handled_epoch_withdrawal_len_array_value.span()
        );

        let mapping_key: Array<felt252> = array![owner.into(), id.low.into(), id.high.into()];
        let mapping_value: Span<felt252> = (WithdrawalInfo {
            epoch: withdrawal_user_epoch, shares: user_withdrawal_share, claimed: false
        })
            .into();
        store(
            token_manager_address, map_entry_address(selector!("withdrawal_info"), mapping_key.span(),), mapping_value
        );
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let underlying = token_manager.underlying();
        let underlying_disp = ERC20ABIDispatcher { contract_address: underlying };

        start_prank(CheatTarget::One(underlying), owner);
        underlying_disp.transfer(token_manager_address, CONSTANTS::WAD * 100);
        stop_prank(CheatTarget::One(underlying));

        let previous_owner_balance = underlying_disp.balanceOf(owner);

        start_prank(CheatTarget::One(token_manager.contract_address), owner);
        token_manager.claim_withdrawal(id);
        stop_prank(CheatTarget::One(token_manager.contract_address));

        let new_withdrawal_pool = token_manager.withdrawal_pool(withdrawal_user_epoch);
        let new_withdrawal_share = token_manager.withdrawal_share(withdrawal_user_epoch);
        let new_owner_balance = underlying_disp.balanceOf(owner);
        let new_owner_withdrawal_info = token_manager.withdrawal_info(owner, id);

        let rate = ((withdrawal_pool + 1) * CONSTANTS::WAD) / (withdrawal_share + 1);
        let assets_claimed = (rate * user_withdrawal_share) / CONSTANTS::WAD;

        assert(new_owner_balance - previous_owner_balance == assets_claimed, 'invalid balance');
        assert(new_withdrawal_pool == withdrawal_pool - assets_claimed, 'invalid pool');
        assert(new_withdrawal_share == withdrawal_share - user_withdrawal_share, 'invalid share');
        assert(new_owner_withdrawal_info.epoch == withdrawal_user_epoch, 'invalid epoch');
        assert(new_owner_withdrawal_info.shares == user_withdrawal_share, 'invalid shares');
        assert(new_owner_withdrawal_info.claimed == true, 'invalid claimed');
    }

    #[test]
    #[should_panic(expected: ('Invalid caller',))]
    fn test_handle_report_invalid_caller() {
        let (token_manager_address, _, _, owner) = deploy_strategy();
        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        token_manager.handle_report(1, 1);
    }

    #[test]
    fn test_convert_to_shares() {
        let shares: u256 = 10000000;
        let (token_manager_address, token_address, _, owner) = deploy_strategy();

        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let token = ITokenDispatcher { contract_address: token_address };
        start_prank(CheatTarget::One(token.contract_address), token_manager.contract_address);
        let balance = token.mint(owner, 10000000);
        stop_prank(CheatTarget::One(token_manager.contract_address));

        let shares = token_manager.convert_to_shares(shares);
        assert(shares == 100000010000000, 'No interaction');
    }

    #[test]
    fn convert_to_assets() {
        let assets: u256 = 10000000;
        let (token_manager_address, token_address, _, owner) = deploy_strategy();

        let token_manager = ITokenManagerDispatcher { contract_address: token_manager_address };
        let token = ITokenDispatcher { contract_address: token_address };
        start_prank(CheatTarget::One(token.contract_address), token_manager.contract_address);
        let balance = token.mint(owner, 10000000);
        stop_prank(CheatTarget::One(token_manager.contract_address));

        let assets = token_manager.convert_to_assets(assets);
        assert(assets == 0, 'No interaction');
    }
}
