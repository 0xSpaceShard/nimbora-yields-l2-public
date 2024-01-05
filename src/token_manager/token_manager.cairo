#[starknet::contract]
mod Token {
    use starknet::{
        ContractAddress, get_caller_address, get_contract_address, eth_address::EthAddress, Zeroable
    };


    use openzeppelin::token::erc20::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
    use openzeppelin::token::erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait};
    use openzeppelin::access::accesscontrol::interface::{
        IAccessControlDispatcher, IAccessControlDispatcherTrait
    };

    use nimbora_yields::token_manager::interface::{ITokenManager, WithdrawalInfo, StrategyReportL2};
    use nimbora_yields::token::interface::{ITokenDispatcher, ITokenDispatcherTrait};
    use nimbora_yields::token_withdrawal::interface::{
        ITokenWithdrawalDispatcher, ITokenWithdrawalDispatcherTrait
    };
    use nimbora_yields::pooling_manager::interface::{
        IPoolingManagerDispatcher, IPoolingManagerDispatcherTrait
    };

    use nimbora_yields::utils::{CONSTANTS};


    #[storage]
    struct Storage {
        pooling_manager: ContractAddress,
        l1_strategy: EthAddress,
        underlying: ContractAddress,
        performance_fees: u256,
        deposit_limit_low: u256,
        deposit_limit_high: u256,
        withdrawal_limit_low: u256,
        withdrawal_limit_high: u256,
        withdrawal_epoch_delay: u256,
        token: ContractAddress,
        token_withdrawal: ContractAddress,
        epoch: u256,
        epoch_share_price: LegacyMap<u256, u256>,
        l1_net_asset_value: u256,
        underlying_transit: u256,
        buffer: u256,
        finalized_withdrawal_len: u256,
        withdrawal_len: u256,
        withdrawal_info: LegacyMap<u256, WithdrawalInfo>,
        dust_limit: u256
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {}


    mod Errors {
        const INVALID_CALLER: felt252 = 'Invalid caller';
        const INVALID_FEES: felt252 = 'Fee amount too high';
        const ZERO_AMOUNT: felt252 = 'Amount nul';
        const INVALID_LIMIT: felt252 = 'Invalid limit';
        const LOW_LIMIT: felt252 = 'Low limit reacher';
        const HIGH_LIMIT: felt252 = 'High limit reacher';
        const NOT_OWNER: felt252 = 'Not owner';
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        pooling_manager: ContractAddress,
        l1_strategy: EthAddress,
        underlying: ContractAddress,
        performance_fees: u256,
        min_deposit: u256,
        max_deposit: u256,
        min_withdrawal: u256,
        max_withdrawal: u256,
        withdrawal_epoch_delay: u256,
        dust_limit: u256
    ) {
        self.pooling_manager.write(pooling_manager);
        self.l1_strategy.write(l1_strategy);
        self.underlying.write(underlying);
        self._set_performance_fees(performance_fees);
        self._set_deposit_limit(min_deposit, max_deposit);
        self._set_withdrawal_limit(min_withdrawal, max_withdrawal);
        self._set_withdrawal_epoch_delay(withdrawal_epoch_delay);
        self._set_dust_limit(dust_limit);
    }


    #[abi(embed_v0)]
    impl TokenManager of ITokenManager<ContractState> {
        fn pooling_manager(self: @ContractState) -> ContractAddress {
            self.pooling_manager.read()
        }

        fn l1_strategy(self: @ContractState) -> EthAddress {
            self.l1_strategy.read()
        }

        fn underlying(self: @ContractState) -> ContractAddress {
            self.underlying.read()
        }

        fn token(self: @ContractState) -> ContractAddress {
            self.token.read()
        }

        fn token_withdrawal(self: @ContractState) -> ContractAddress {
            self.token_withdrawal.read()
        }

        fn performance_fees(self: @ContractState) -> u256 {
            self.performance_fees.read()
        }

        fn deposit_limit_low(self: @ContractState) -> u256 {
            self.deposit_limit_low.read()
        }

        fn deposit_limit_high(self: @ContractState) -> u256 {
            self.deposit_limit_high.read()
        }

        fn withdrawal_limit_low(self: @ContractState) -> u256 {
            self.withdrawal_limit_low.read()
        }

        fn withdrawal_limit_high(self: @ContractState) -> u256 {
            self.withdrawal_limit_high.read()
        }

        fn withdrawal_epoch_delay(self: @ContractState) -> u256 {
            self.withdrawal_epoch_delay.read()
        }

        fn epoch(self: @ContractState) -> u256 {
            self.epoch.read()
        }

        fn epoch_share_price(self: @ContractState, epoch: u256) -> u256 {
            self.epoch_share_price.read(epoch)
        }

        fn l1_net_asset_value(self: @ContractState) -> u256 {
            self.l1_net_asset_value.read()
        }

        fn underlying_transit(self: @ContractState) -> u256 {
            self.underlying_transit.read()
        }

        fn buffer(self: @ContractState) -> u256 {
            self.buffer.read()
        }

        fn finalized_withdrawal_len(self: @ContractState) -> u256 {
            self.finalized_withdrawal_len.read()
        }

        fn withdrawal_len(self: @ContractState) -> u256 {
            self.withdrawal_len.read()
        }

        fn withdrawal_info(self: @ContractState, id: u256) -> WithdrawalInfo {
            self.withdrawal_info.read(id)
        }

        fn dust_limit(self: @ContractState) -> u256 {
            self.dust_limit.read()
        }

        fn total_assets(self: @ContractState) -> u256 {
            self._total_assets()
        }


        fn initialiser(
            ref self: ContractState, token: ContractAddress, token_withdrawal: ContractAddress
        ) {
            self._assert_only_pool_manager();
            self.token.write(token);
            self.token_withdrawal.write(token_withdrawal);
        }

        fn set_performance_fees(ref self: ContractState, new_performance_fees: u256) {
            self._assert_only_owner();
            self._set_performance_fees(new_performance_fees);
            let l1_strategy = self.l1_strategy.read();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher {
                contract_address: pooling_manager
            };
            pooling_manager_disp
                .emit_performance_fees_updated_event(l1_strategy, new_performance_fees);
        }

        fn set_deposit_limit(
            ref self: ContractState, new_deposit_limit_low: u256, new_deposit_limit_high: u256
        ) {
            self._assert_only_owner();
            self._set_deposit_limit(new_deposit_limit_low, new_deposit_limit_high);
            let l1_strategy = self.l1_strategy.read();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher {
                contract_address: pooling_manager
            };
            pooling_manager_disp
                .emit_deposit_limit_updated_event(
                    l1_strategy, new_deposit_limit_low, new_deposit_limit_high
                );
        }

        fn set_withdrawal_limit(
            ref self: ContractState, new_withdrawal_limit_low: u256, new_withdrawal_limit_high: u256
        ) {
            self._assert_only_owner();
            self._set_withdrawal_limit(new_withdrawal_limit_low, new_withdrawal_limit_high);
            let l1_strategy = self.l1_strategy.read();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher {
                contract_address: pooling_manager
            };
            pooling_manager_disp
                .emit_withdrawal_limit_updated_event(
                    l1_strategy, new_withdrawal_limit_low, new_withdrawal_limit_high
                );
        }

        fn set_withdrawal_epoch_delay(ref self: ContractState, new_withdrawal_epoch_delay: u256) {
            self._assert_only_owner();
            self._set_withdrawal_epoch_delay(new_withdrawal_epoch_delay);
            let l1_strategy = self.l1_strategy.read();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher {
                contract_address: pooling_manager
            };
            pooling_manager_disp
                .emit_withdrawal_epoch_delay_updated_event(l1_strategy, new_withdrawal_epoch_delay);
        }

        fn set_dust_limit(ref self: ContractState, new_dust_limit: u256) {
            self._assert_only_owner();
            self._set_dust_limit(new_dust_limit);
            let l1_strategy = self.l1_strategy.read();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher {
                contract_address: pooling_manager
            };
            pooling_manager_disp.emit_dust_limit_updated_event(l1_strategy, new_dust_limit);
        }

        fn deposit(
            ref self: ContractState,
            assets: u256,
            receiver: ContractAddress,
            referal: ContractAddress
        ) {
            let deposit_limit_low = self.deposit_limit_low.read();
            let deposit_limit_high = self.deposit_limit_high.read();

            assert(assets >= deposit_limit_low, Errors::LOW_LIMIT);
            assert(assets <= deposit_limit_high, Errors::HIGH_LIMIT);

            let underlying = self.underlying.read();
            let erc20_disp = ERC20ABIDispatcher { contract_address: underlying };
            let caller = get_caller_address();
            let this = get_contract_address();
            erc20_disp.transferFrom(caller, this, assets);
            let buffer = self.buffer.read();
            let new_buffer = buffer + assets;
            self.buffer.write(new_buffer);

            let shares = self._convert_to_shares(assets);
            let token = self.token.read();
            let token_disp = ITokenDispatcher { contract_address: token };
            token_disp.mint(receiver, shares);

            let l1_strategy = self.l1_strategy.read();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher {
                contract_address: pooling_manager
            };
            pooling_manager_disp
                .emit_deposit_event(l1_strategy, caller, receiver, assets, shares, referal);
        }

        fn request_withdrawal(ref self: ContractState, shares: u256, receiver: ContractAddress,) {
            let withdrawal_limit_low = self.withdrawal_limit_low.read();
            let withdrawal_limit_high = self.withdrawal_limit_high.read();
            assert(shares >= withdrawal_limit_low, Errors::LOW_LIMIT);
            assert(shares <= withdrawal_limit_high, Errors::HIGH_LIMIT);

            let token = self.token.read();
            let erc20_disp = ERC20ABIDispatcher { contract_address: token };
            let caller = get_caller_address();
            let this = get_contract_address();
            erc20_disp.transferFrom(caller, this, shares);

            let epoch = self.epoch.read();
            let withdrawal_len = self.withdrawal_len.read();
            self
                .withdrawal_info
                .write(
                    withdrawal_len, WithdrawalInfo { shares: shares, epoch: epoch, to_claim: 0 }
                );
            self.withdrawal_len.write(withdrawal_len + 1);

            let token_withdrawal = self.token_withdrawal.read();
            let token_withdrawal_disp = ITokenWithdrawalDispatcher {
                contract_address: token_withdrawal
            };
            token_withdrawal_disp.mint(receiver, withdrawal_len);

            let l1_strategy = self.l1_strategy.read();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher {
                contract_address: pooling_manager
            };
            pooling_manager_disp
                .emit_request_withdrawal_event(l1_strategy, caller, receiver, shares, epoch);
        }

        fn claim_withdrawal(ref self: ContractState, id: u256) {
            let caller = get_caller_address();
            let token_withdrawal = self.token_withdrawal.read();
            let erc721_disp = ERC721ABIDispatcher { contract_address: token_withdrawal };
            let owner = erc721_disp.ownerOf(id);
            assert(caller == owner, Errors::NOT_OWNER);

            let info = self.withdrawal_info.read(id);
            assert(info.to_claim.is_non_zero(), Errors::ZERO_AMOUNT);

            let token_withdraw_disp = ITokenWithdrawalDispatcher {
                contract_address: token_withdrawal
            };
            token_withdraw_disp.burn(id);

            let underlying = self.underlying.read();
            let underlying_disp = ERC20ABIDispatcher { contract_address: underlying };
            underlying_disp.transfer(caller, info.to_claim);

            let l1_strategy = self.l1_strategy.read();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher {
                contract_address: pooling_manager
            };
            pooling_manager_disp
                .emit_claim_withdrawal_event(l1_strategy, caller, id, info.to_claim);
        }


        fn handle_report(
            ref self: ContractState, l1_net_asset_value: u256, underlying_bridged_amount: u256
        ) -> StrategyReportL2 {
            self._assert_only_pool_manager();

            let epoch = self.epoch.read();
            let previous_epoch_share_price = self._convert_to_assets(CONSTANTS::WAD);
            self.epoch_share_price.write(epoch, previous_epoch_share_price);
            let new_epoch = epoch + 1;
            self.epoch.write(new_epoch);

            let buffer_mem = self.buffer.read() + underlying_bridged_amount;

            let finalized_withdrawal_len = self.finalized_withdrawal_len.read();
            let withdrawal_len = self.withdrawal_len.read();

            let withdrawal_epoch_delay = self.withdrawal_epoch_delay.read();

            let mut remaining_buffer_mem = buffer_mem;
            let mut cumulatif_due_underlying = 0;
            let mut can_cover_withdrawals = true;

            let mut new_finalized_withdrawal_len = finalized_withdrawal_len;
            let mut i = finalized_withdrawal_len;

            if (finalized_withdrawal_len < withdrawal_len && new_epoch >= withdrawal_epoch_delay) {
                let simulated_share_price = self
                    ._simulated_share_price(buffer_mem + underlying_bridged_amount);
                let token = self.token.read();
                let token_disp = ITokenDispatcher { contract_address: token };
                let this = get_contract_address();

                loop {
                    if i == withdrawal_len {
                        break ();
                    }

                    let info = self.withdrawal_info.read(i);
                    if (info.epoch > new_epoch - withdrawal_epoch_delay) {
                        break ();
                    }

                    let share_price_withdrawal = self.epoch_share_price.read(info.epoch);
                    let mut final_share_price_withdrawal = share_price_withdrawal;
                    if (share_price_withdrawal >= simulated_share_price) {
                        final_share_price_withdrawal = simulated_share_price;
                    }

                    let due_underlying = (info.shares * final_share_price_withdrawal)
                        / (CONSTANTS::WAD);
                    cumulatif_due_underlying += due_underlying;

                    if (can_cover_withdrawals) {
                        if (due_underlying > remaining_buffer_mem) {
                            new_finalized_withdrawal_len = i;
                            can_cover_withdrawals = false;
                        } else {
                            remaining_buffer_mem -= due_underlying;
                            token_disp.burn(this, info.shares);
                            self
                                .withdrawal_info
                                .write(
                                    i,
                                    WithdrawalInfo {
                                        shares: info.shares, epoch: epoch, to_claim: due_underlying
                                    }
                                );
                        }
                    }

                    i += 1;
                }
            }

            self.l1_net_asset_value.write(l1_net_asset_value);
            let l1_strategy = self.l1_strategy.read();

            if (!can_cover_withdrawals) {
                self.finalized_withdrawal_len.write(new_finalized_withdrawal_len);
                let underlying_request_amount = cumulatif_due_underlying - remaining_buffer_mem;
                self.underlying_transit.write(0);
                self.buffer.write(remaining_buffer_mem);

                StrategyReportL2 {
                    l1_strategy: l1_strategy,
                    action_id: 2,
                    amount: underlying_request_amount,
                    previous_epoch_share_price: previous_epoch_share_price
                }
            } else {
                self.finalized_withdrawal_len.write(i);
                let dust_limit_factor = self.dust_limit.read();
                let dust_limit = (l1_net_asset_value * dust_limit_factor) / CONSTANTS::WAD;
                if (dust_limit > remaining_buffer_mem) {
                    self.buffer.write(remaining_buffer_mem);
                    self.underlying_transit.write(0);
                    StrategyReportL2 {
                        l1_strategy: l1_strategy,
                        action_id: 1,
                        amount: 0,
                        previous_epoch_share_price: previous_epoch_share_price
                    }
                } else {
                    self.buffer.write(0);
                    self.underlying_transit.write(remaining_buffer_mem);
                    StrategyReportL2 {
                        l1_strategy: l1_strategy,
                        action_id: 0,
                        amount: remaining_buffer_mem,
                        previous_epoch_share_price: previous_epoch_share_price
                    }
                }
            }
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _assert_only_pool_manager(self: @ContractState) {
            let caller = get_caller_address();
            let pooling_manager = self.pooling_manager.read();
            assert(caller == pooling_manager, Errors::INVALID_CALLER);
        }

        fn _assert_only_owner(self: @ContractState) {
            let caller = get_caller_address();
            let pooling_manager = self.pooling_manager.read();
            let access_disp = IAccessControlDispatcher { contract_address: pooling_manager };
            let has_role = access_disp.has_role(0, caller);
            assert(has_role, Errors::INVALID_CALLER);
        }

        fn _total_assets(self: @ContractState) -> u256 {
            let buffer = self.buffer.read();
            let l1_net_asset_value = self.l1_net_asset_value.read();
            let underlying_transit = self.underlying_transit.read();
            buffer + l1_net_asset_value + underlying_transit
        }

        fn _convert_to_shares(self: @ContractState, assets: u256) -> u256 {
            let token = self.token.read();
            let erc20_disp = ERC20ABIDispatcher { contract_address: token };
            let total_supply = erc20_disp.total_supply();
            let total_assets = self._total_assets();
            (assets * (total_supply + 1)) / (total_assets + 1)
        }

        fn _simulated_share_price(self: @ContractState, total_assets: u256) -> u256 {
            let token = self.token.read();
            let erc20_disp = ERC20ABIDispatcher { contract_address: token };
            let total_supply = erc20_disp.total_supply();
            (CONSTANTS::WAD * (total_assets + 1)) / (total_supply + 1)
        }

        fn _convert_to_assets(self: @ContractState, shares: u256) -> u256 {
            let token = self.token.read();
            let erc20_disp = ERC20ABIDispatcher { contract_address: token };
            let total_supply = erc20_disp.total_supply();
            let total_assets = self._total_assets();
            (shares * (total_assets + 1)) / (total_supply + 1)
        }


        fn _set_performance_fees(ref self: ContractState, new_performance_fees: u256) {
            assert(new_performance_fees < CONSTANTS::WAD, Errors::INVALID_FEES);
            self.performance_fees.write(new_performance_fees);
        }

        fn _set_deposit_limit(
            ref self: ContractState, new_deposit_limit_low: u256, new_deposit_limit_high: u256
        ) {
            assert(new_deposit_limit_low > 0, Errors::ZERO_AMOUNT);
            assert(new_deposit_limit_high > new_deposit_limit_low, Errors::INVALID_LIMIT);
            self.deposit_limit_low.write(new_deposit_limit_low);
            self.deposit_limit_high.write(new_deposit_limit_high);
        }

        fn _set_withdrawal_limit(
            ref self: ContractState, new_withdrawal_limit_low: u256, new_withdrawal_limit_high: u256
        ) {
            assert(new_withdrawal_limit_low > 0, Errors::ZERO_AMOUNT);
            assert(new_withdrawal_limit_high > new_withdrawal_limit_low, Errors::INVALID_LIMIT);
            self.withdrawal_limit_low.write(new_withdrawal_limit_low);
            self.withdrawal_limit_high.write(new_withdrawal_limit_high);
        }

        fn _set_withdrawal_epoch_delay(ref self: ContractState, new_withdrawal_epoch_delay: u256) {
            assert(new_withdrawal_epoch_delay.is_non_zero(), Errors::ZERO_AMOUNT);
            self.withdrawal_epoch_delay.write(new_withdrawal_epoch_delay);
        }

        fn _set_dust_limit(ref self: ContractState, new_dust_limit: u256) {
            assert(new_dust_limit.is_non_zero(), Errors::ZERO_AMOUNT);
            self.dust_limit.write(new_dust_limit);
        }
    }
}
