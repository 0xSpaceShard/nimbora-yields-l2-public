#[starknet::contract]
mod TokenManager {
    use nimbora_yields::pooling_manager::interface::{IPoolingManagerDispatcher, IPoolingManagerDispatcherTrait};
    use nimbora_yields::token::interface::{ITokenDispatcher, ITokenDispatcherTrait};


    use nimbora_yields::token_manager::interface::{ITokenManager, WithdrawalInfo, StrategyReportL2};

    use nimbora_yields::utils::{CONSTANTS, MATH};
    use openzeppelin::access::accesscontrol::interface::{IAccessControlDispatcher, IAccessControlDispatcherTrait};


    use openzeppelin::token::erc20::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
    use openzeppelin::token::erc721::interface::{ERC721ABIDispatcher, ERC721ABIDispatcherTrait};
    use openzeppelin::upgrades::UpgradeableComponent;
    use starknet::{
        ContractAddress, get_caller_address, get_contract_address, eth_address::EthAddress, Zeroable, ClassHash
    };

    // Components
    component!(path: UpgradeableComponent, storage: upgradeable, event: UpgradeableEvent);

    impl InternalUpgradeableImpl = UpgradeableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        upgradeable: UpgradeableComponent::Storage,
        pooling_manager: ContractAddress,
        l1_strategy: EthAddress,
        underlying: ContractAddress,
        performance_fees: u256,
        tvl_limit: u256,
        withdrawal_epoch_delay: u256,
        token: ContractAddress,
        epoch: u256,
        l1_net_asset_value: u256,
        underlying_transit: u256,
        buffer: u256,
        handled_epoch_withdrawal_len: u256,
        withdrawal_info: LegacyMap<(ContractAddress, u256), WithdrawalInfo>,
        dust_limit: u256,
        withdrawal_pool: LegacyMap<u256, u256>,
        withdrawal_share: LegacyMap<u256, u256>,
        user_withdrawal_len: LegacyMap<ContractAddress, u256>
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        UpgradeableEvent: UpgradeableComponent::Event
    }


    mod Errors {
        const INVALID_CALLER: felt252 = 'Invalid caller';
        const INVALID_FEES: felt252 = 'Fee amount too high';
        const ZERO_AMOUNT: felt252 = 'Amount nul';
        const ZERO_ADDRESS: felt252 = 'Address is zero';
        const TVL_LIMIT: felt252 = 'Tvl limit reached';
        const INVALID_TVL_LIMIT: felt252 = 'Tvl limit reached';
        const NOT_OWNER: felt252 = 'Not owner';
        const WITHDRAWAL_NOT_REDY: felt252 = 'Withdrawal not ready';
        const ALREADY_CLAIMED: felt252 = 'Already claimed';
        const INVALID_ID: felt252 = 'Invalid Id';
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        pooling_manager: ContractAddress,
        l1_strategy: EthAddress,
        underlying: ContractAddress,
        performance_fees: u256,
        tvl_limit: u256,
        withdrawal_epoch_delay: u256,
        dust_limit: u256
    ) {
        self.pooling_manager.write(pooling_manager);
        assert(l1_strategy.is_non_zero(), Errors::ZERO_ADDRESS);
        self.l1_strategy.write(l1_strategy);
        self.underlying.write(underlying);
        self._set_performance_fees(performance_fees);
        self._set_tvl_limit(tvl_limit);
        self._set_withdrawal_epoch_delay(withdrawal_epoch_delay);
        self._set_dust_limit(dust_limit);
    }

    /// @notice Upgrade contract
    /// @param New contract class hash
    #[external(v0)]
    fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
        self._assert_only_owner();
        self.upgradeable._upgrade(new_class_hash);
    }

    #[abi(embed_v0)]
    impl TokenManager of ITokenManager<ContractState> {
        /// @notice Returns the pooling manager address
        /// @return The contract address of the pooling manager
        fn pooling_manager(self: @ContractState) -> ContractAddress {
            self.pooling_manager.read()
        }

        /// @notice Returns the L1 strategy address
        /// @return The Ethereum address of the L1 strategy
        fn l1_strategy(self: @ContractState) -> EthAddress {
            self.l1_strategy.read()
        }

        /// @notice Returns the underlying asset address
        /// @return The contract address of the underlying asset
        fn underlying(self: @ContractState) -> ContractAddress {
            self.underlying.read()
        }

        /// @notice Returns the token address
        /// @return The contract address of the token
        fn token(self: @ContractState) -> ContractAddress {
            self.token.read()
        }

        /// @notice Returns the current performance fees
        /// @return The performance fees as a u256 value
        fn performance_fees(self: @ContractState) -> u256 {
            self.performance_fees.read()
        }

        /// @notice Reads the tvl limit
        /// @return The current max limit for tvl
        fn tvl_limit(self: @ContractState) -> u256 {
            self.tvl_limit.read()
        }

        /// @notice Reads the withdrawal epoch delay
        /// @return The current delay in epochs for withdrawals
        fn withdrawal_epoch_delay(self: @ContractState) -> u256 {
            self.withdrawal_epoch_delay.read()
        }


        /// @notice Reads the current epoch
        /// @return The current epoch value
        fn epoch(self: @ContractState) -> u256 {
            self.epoch.read()
        }

        /// @notice Reads the net asset value from L1
        /// @return The net asset value from L1
        fn l1_net_asset_value(self: @ContractState) -> u256 {
            self.l1_net_asset_value.read()
        }

        /// @notice Reads the underlying asset in transit
        /// @return The amount of underlying asset currently in transit
        fn underlying_transit(self: @ContractState) -> u256 {
            self.underlying_transit.read()
        }

        /// @notice Reads the buffer value
        /// @return The current buffer value
        fn buffer(self: @ContractState) -> u256 {
            self.buffer.read()
        }

        /// @notice Reads the length of handled epoch withdrawals
        /// @return The length of handled epoch withdrawals
        fn handled_epoch_withdrawal_len(self: @ContractState) -> u256 {
            self.handled_epoch_withdrawal_len.read()
        }

        /// @notice Reads withdrawal information for a given user and ID
        /// @param user The address of the user
        /// @param id The unique identifier of the withdrawal
        /// @return Withdrawal information corresponding to the user and ID
        fn withdrawal_info(self: @ContractState, user: ContractAddress, id: u256) -> WithdrawalInfo {
            self.withdrawal_info.read((user, id))
        }

        /// @notice Reads the length of withdrawals for a user
        /// @param user The address of the user
        /// @return The number of withdrawals associated with the user
        fn user_withdrawal_len(self: @ContractState, user: ContractAddress) -> u256 {
            self.user_withdrawal_len.read(user)
        }

        /// @notice Reads the dust limit
        /// @return The current dust limit
        fn dust_limit(self: @ContractState) -> u256 {
            self.dust_limit.read()
        }

        /// @notice Calculates the total assets
        /// @return The total assets calculated
        fn total_assets(self: @ContractState) -> u256 {
            self._total_assets()
        }

        /// @notice Calculates the total underlying due
        /// @return The total underlying due calculated
        fn total_underlying_due(self: @ContractState) -> u256 {
            let handled_epoch_withdrawal_len = self.handled_epoch_withdrawal_len.read();
            let epoch = self.epoch.read();
            self._total_underlying_due(handled_epoch_withdrawal_len, epoch)
        }

        /// @notice Calculates the withdrawal exchange rate for a given epoch
        /// @param epoch The epoch for which to calculate the exchange rate
        /// @return The withdrawal exchange rate for the specified epoch
        fn withdrawal_exchange_rate(self: @ContractState, epoch: u256) -> u256 {
            self._withdrawal_exchange_rate(epoch)
        }

        /// @notice Reads the withdrawal pool for a given epoch
        /// @param epoch The epoch for which to read the withdrawal pool
        /// @return The withdrawal pool for the specified epoch
        fn withdrawal_pool(self: @ContractState, epoch: u256) -> u256 {
            self.withdrawal_pool.read(epoch)
        }

        /// @notice Reads the withdrawal share for a given epoch
        /// @param epoch The epoch for which to read the withdrawal share
        /// @return The withdrawal share for the specified epoch
        fn withdrawal_share(self: @ContractState, epoch: u256) -> u256 {
            self.withdrawal_share.read(epoch)
        }

        /// @notice Converts a given amount of assets to shares
        /// @param amount The amount of assets to convert
        /// @return The equivalent amount of shares
        fn convert_to_shares(self: @ContractState, amount: u256) -> u256 {
            self._convert_to_shares(amount)
        }

        /// @notice Converts a given amount of shares to assets
        /// @param amount The amount of shares to convert
        /// @return asset amount
        fn convert_to_assets(self: @ContractState, shares: u256) -> u256 {
            self._convert_to_assets(shares)
        }

        /// @notice Sets the token for this contract
        /// @dev Only callable by the pooling manager
        /// @param token The contract address of the token
        fn initialiser(ref self: ContractState, token: ContractAddress) {
            self._assert_only_pooling_manager();
            self.token.write(token);
        }

        /// @notice Sets new performance fees
        /// @dev Only callable by the owner of the contract
        /// @param new_performance_fees The new performance fees value to be set
        fn set_performance_fees(ref self: ContractState, new_performance_fees: u256) {
            self._assert_only_owner();
            self._set_performance_fees(new_performance_fees);
            let l1_strategy = self.l1_strategy.read();
            let l2_strategy = get_contract_address();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher { contract_address: pooling_manager };
            pooling_manager_disp.emit_performance_fees_updated_event(l1_strategy, l2_strategy, new_performance_fees);
        }

        /// @notice Sets new tvl limits
        /// @dev Only callable by the owner of the contract
        /// @param new_tvl_limit The new limit for tvl
        fn set_tvl_limit(ref self: ContractState, new_tvl_limit: u256) {
            self._assert_only_owner();
            self._set_tvl_limit(new_tvl_limit);
            let l1_strategy = self.l1_strategy.read();
            let l2_strategy = get_contract_address();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher { contract_address: pooling_manager };
            pooling_manager_disp.emit_tvl_limit_updated_event(l1_strategy, l2_strategy, new_tvl_limit);
        }

        /// @notice Sets a new withdrawal epoch delay
        /// @dev Only callable by the owner of the contract
        /// @param new_withdrawal_epoch_delay The new withdrawal epoch delay to be set
        fn set_withdrawal_epoch_delay(ref self: ContractState, new_withdrawal_epoch_delay: u256) {
            self._assert_only_owner();
            self._set_withdrawal_epoch_delay(new_withdrawal_epoch_delay);
            let l1_strategy = self.l1_strategy.read();
            let l2_strategy = get_contract_address();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher { contract_address: pooling_manager };
            pooling_manager_disp
                .emit_withdrawal_epoch_delay_updated_event(l1_strategy, l2_strategy, new_withdrawal_epoch_delay);
        }

        /// @notice Sets a new dust limit
        /// @dev Only callable by the owner of the contract
        /// @param new_dust_limit The new dust limit to be set
        fn set_dust_limit(ref self: ContractState, new_dust_limit: u256) {
            self._assert_only_owner();
            self._set_dust_limit(new_dust_limit);
            let l1_strategy = self.l1_strategy.read();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher { contract_address: pooling_manager };
            pooling_manager_disp.emit_dust_limit_updated_event(l1_strategy, new_dust_limit);
        }


        /// @notice Allows a user to deposit assets into the contract
        /// @dev Checks if the deposit amount is within the set limits before accepting the deposit
        /// @param assets The amount of assets to deposit
        /// @param receiver The address to receive the minted shares
        /// @param referal The referral address for the deposit
        fn deposit(ref self: ContractState, assets: u256, receiver: ContractAddress, referal: ContractAddress) {
            assert(assets + self._total_assets() <= self.tvl_limit.read(), Errors::TVL_LIMIT);

            let underlying = self.underlying.read();
            let erc20_disp = ERC20ABIDispatcher { contract_address: underlying };
            let caller = get_caller_address();
            let this = get_contract_address();
            erc20_disp.transferFrom(caller, this, assets);

            let shares = self._convert_to_shares(assets);

            let buffer = self.buffer.read();
            let new_buffer = buffer + assets;
            self.buffer.write(new_buffer);

            let token = self.token.read();
            let token_disp = ITokenDispatcher { contract_address: token };
            token_disp.mint(receiver, shares);

            let l1_strategy = self.l1_strategy.read();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher { contract_address: pooling_manager };
            pooling_manager_disp.emit_deposit_event(l1_strategy, this, caller, receiver, assets, shares, referal);
        }

        /// @notice Allows a user to request a withdrawal from the contract
        /// @dev Checks if the withdrawal amount is within the set limits before processing the withdrawal
        /// @param shares The amount of shares to withdraw
        fn request_withdrawal(ref self: ContractState, shares: u256) {
            let token = self.token.read();
            let token_disp = ITokenDispatcher { contract_address: token };
            let caller = get_caller_address();

            let epoch = self.epoch.read();
            let assets = self._convert_to_assets(shares);
            token_disp.burn(caller, shares);

            let withdrawal_pool = self.withdrawal_pool.read(epoch);
            let withdrawal_share = self.withdrawal_share.read(epoch);

            let withdrawal_pool_share = (assets * CONSTANTS::WAD)
                / self._withdrawal_exchange_rate_calc(withdrawal_pool, withdrawal_share);

            self.withdrawal_pool.write(epoch, withdrawal_pool + assets);
            self.withdrawal_share.write(epoch, withdrawal_share + withdrawal_pool_share);

            let user_withdrawal_len = self.user_withdrawal_len.read(caller);
            self
                .withdrawal_info
                .write((caller, user_withdrawal_len), WithdrawalInfo { shares: shares, epoch: epoch, claimed: false });
            self.user_withdrawal_len.write(caller, user_withdrawal_len + 1);

            let l1_strategy = self.l1_strategy.read();
            let l2_strategy = get_contract_address();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher { contract_address: pooling_manager };
            pooling_manager_disp
                .emit_request_withdrawal_event(
                    l1_strategy, l2_strategy, caller, assets, shares, user_withdrawal_len, epoch
                );
        }


        /// @notice Allows a user to claim a withdrawal
        /// @dev Validates that the withdrawal is ready to be claimed and processes it
        /// @param id The unique identifier of the withdrawal request
        fn claim_withdrawal(ref self: ContractState, user: ContractAddress, id: u256) {
            let user_withdrawal_len = self.user_withdrawal_len(user);
            assert(user_withdrawal_len > id, Errors::INVALID_ID);
            let withdrawal_info = self.withdrawal_info.read((user, id));
            assert(!withdrawal_info.claimed, Errors::ALREADY_CLAIMED);
            let handled_epoch_withdrawal_len = self.handled_epoch_withdrawal_len.read();
            assert(handled_epoch_withdrawal_len > withdrawal_info.epoch, Errors::WITHDRAWAL_NOT_REDY);

            self
                .withdrawal_info
                .write(
                    (user, id),
                    WithdrawalInfo { shares: withdrawal_info.shares, epoch: withdrawal_info.epoch, claimed: true }
                );

            let withdrawal_pool = self.withdrawal_pool.read(withdrawal_info.epoch);
            let withdrawal_share = self.withdrawal_share.read(withdrawal_info.epoch);
            let rate = self._withdrawal_exchange_rate_calc(withdrawal_pool, withdrawal_share);
            let assets = (rate * withdrawal_info.shares) / CONSTANTS::WAD;

            self.withdrawal_pool.write(withdrawal_info.epoch, withdrawal_pool - assets);
            self.withdrawal_share.write(withdrawal_info.epoch, withdrawal_share - withdrawal_info.shares);

            let underlying = self.underlying.read();
            let underlying_disp = ERC20ABIDispatcher { contract_address: underlying };
            underlying_disp.transfer(user, assets);

            let l1_strategy = self.l1_strategy.read();
            let l2_strategy = get_contract_address();
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher { contract_address: pooling_manager };
            pooling_manager_disp.emit_claim_withdrawal_event(l1_strategy, l2_strategy, user, id, assets);
        }

        /// @notice Handles the report from the L1 strategy
        /// @dev Only callable by the pooling manager, processes the report and updates the contract state
        /// @param new_l1_net_asset_value The net asset value reported from L1
        /// @param underlying_bridged_amount The amount of underlying asset bridged
        /// @return StrategyReportL2 object containing the strategy report data
        fn handle_report(
            ref self: ContractState, new_l1_net_asset_value: u256, underlying_bridged_amount: u256
        ) -> StrategyReportL2 {
            self._assert_only_pooling_manager();
            let epoch = self.epoch.read();
            let handled_epoch_withdrawal_len = self.handled_epoch_withdrawal_len.read();
            let buffer = self.buffer.read();
            let profit = self
                ._calculate_profit_and_handle_loss(
                    epoch, handled_epoch_withdrawal_len, new_l1_net_asset_value + underlying_bridged_amount, buffer
                );
            let withdrawal_epoch_delay = self.withdrawal_epoch_delay.read();
            let (remaining_assets, needed_assets) = self
                ._handle_withdrawals(
                    epoch, handled_epoch_withdrawal_len, withdrawal_epoch_delay, underlying_bridged_amount, buffer
                );
            let (action_id, amount) = self._handle_result(remaining_assets, needed_assets, new_l1_net_asset_value);
            self.epoch.write(epoch + 1);
            self.l1_net_asset_value.write(new_l1_net_asset_value);
            let token = self.token.read();
            self._check_profit_and_mint(profit, token);
            let token_disp = ERC20ABIDispatcher { contract_address: token };
            let decimals = token_disp.decimals();
            let one_share_unit = MATH::pow(10, decimals.into());
            let new_share_price = self._convert_to_assets(one_share_unit);
            StrategyReportL2 {
                l1_strategy: self.l1_strategy.read(),
                action_id: action_id,
                amount: amount,
                processed: true,
                new_share_price: new_share_price
            }
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        /// @notice Asserts that the caller is the pooling manager
        fn _assert_only_pooling_manager(self: @ContractState) {
            let caller = get_caller_address();
            let pooling_manager = self.pooling_manager.read();
            assert(caller == pooling_manager, Errors::INVALID_CALLER);
        }

        /// @notice Asserts that the caller has the owner role
        fn _assert_only_owner(self: @ContractState) {
            let caller = get_caller_address();
            let pooling_manager = self.pooling_manager.read();
            let access_disp = IAccessControlDispatcher { contract_address: pooling_manager };
            let has_role = access_disp.has_role(0, caller);
            assert(has_role, Errors::INVALID_CALLER);
        }

        /// @notice Calculates the total underlying due up to the current epoch
        /// @param handled_epoch_withdrawal_len The length of the handled epoch withdrawal
        /// @param current_epoch The current epoch
        /// @return The total underlying due
        fn _total_underlying_due(
            self: @ContractState, handled_epoch_withdrawal_len: u256, current_epoch: u256
        ) -> u256 {
            let mut i = handled_epoch_withdrawal_len;
            let mut acc = 0;
            loop {
                if (i > current_epoch) {
                    break ();
                }
                let withdrawal_pool = self.withdrawal_pool.read(i);
                acc += withdrawal_pool;
                i += 1;
            };
            acc
        }


        /// @notice Calculates the total assets of the contract
        /// @return The total assets
        fn _total_assets(self: @ContractState) -> u256 {
            let epoch = self.epoch.read();
            let handled_epoch_withdrawal_len = self.handled_epoch_withdrawal_len.read();
            let total_underlying_due = self._total_underlying_due(handled_epoch_withdrawal_len, epoch);
            let buffer = self.buffer.read();
            let l1_net_asset_value = self.l1_net_asset_value.read();
            let underlying_transit = self.underlying_transit.read();
            (buffer + l1_net_asset_value + underlying_transit) - total_underlying_due
        }


        /// @notice Converts a given amount of assets to shares
        /// @param assets The amount of assets to convert
        /// @return The equivalent amount of shares
        fn _convert_to_shares(self: @ContractState, assets: u256) -> u256 {
            let token = self.token.read();
            let erc20_disp = ERC20ABIDispatcher { contract_address: token };
            let total_supply = erc20_disp.total_supply();
            let total_assets = self._total_assets();
            (assets * (total_supply + 1)) / (total_assets + 1)
        }

        /// @notice Converts a given amount of shares to assets
        /// @param shares The amount of shares to convert
        /// @return The equivalent amount of assets
        fn _convert_to_assets(self: @ContractState, shares: u256) -> u256 {
            let token = self.token.read();
            let erc20_disp = ERC20ABIDispatcher { contract_address: token };
            let total_supply = erc20_disp.total_supply();
            let total_assets = self._total_assets();
            (shares * (total_assets + 1)) / (total_supply + 1)
        }

        /// @notice Calculates the withdrawal exchange rate for a given epoch
        /// @param epoch The epoch for which to calculate the rate
        /// @return The withdrawal exchange rate
        fn _withdrawal_exchange_rate(self: @ContractState, epoch: u256) -> u256 {
            let withdrawal_pool = self.withdrawal_pool.read(epoch);
            let withdrawal_share = self.withdrawal_share.read(epoch);
            self._withdrawal_exchange_rate_calc(withdrawal_pool, withdrawal_share)
        }

        /// @notice Calculates the withdrawal exchange rate
        /// @param withdrawal_pool the amount of assets in the withdrawal pool for an epoch
        /// @param withdrawal_share the amount of shares in the withdrawal pool for an epoch
        /// @return The withdrawal exchange rate
        fn _withdrawal_exchange_rate_calc(self: @ContractState, withdrawal_pool: u256, withdrawal_share: u256) -> u256 {
            ((withdrawal_pool + 1) * CONSTANTS::WAD) / (withdrawal_share + 1)
        }


        /// @notice Sets the performance fees for the contract
        /// @param new_performance_fees The new performance fees
        fn _set_performance_fees(ref self: ContractState, new_performance_fees: u256) {
            assert(new_performance_fees < CONSTANTS::WAD, Errors::INVALID_FEES);
            self.performance_fees.write(new_performance_fees);
        }

        /// @notice Sets the tvl limit max for the contract
        /// @param new_tvl_limit The new limit for tvl
        fn _set_tvl_limit(ref self: ContractState, new_tvl_limit: u256) {
            assert(new_tvl_limit.is_non_zero(), Errors::ZERO_AMOUNT);
            assert(self._total_assets() < new_tvl_limit, Errors::INVALID_TVL_LIMIT);
            self.tvl_limit.write(new_tvl_limit);
        }

        /// @notice Sets the withdrawal epoch delay for the contract
        /// @param new_withdrawal_epoch_delay The new withdrawal epoch delay
        fn _set_withdrawal_epoch_delay(ref self: ContractState, new_withdrawal_epoch_delay: u256) {
            assert(new_withdrawal_epoch_delay.is_non_zero(), Errors::ZERO_AMOUNT);
            self.withdrawal_epoch_delay.write(new_withdrawal_epoch_delay);
        }

        /// @notice Sets the dust limit for the contract
        /// @param new_dust_limit The new dust limit
        fn _set_dust_limit(ref self: ContractState, new_dust_limit: u256) {
            assert(new_dust_limit.is_non_zero(), Errors::ZERO_AMOUNT);
            self.dust_limit.write(new_dust_limit);
        }

        /// @notice Calculates profit or loss and handles loss if incurred.
        /// @param epoch The current epoch.
        /// @param handled_epoch_withdrawal_len The length of handled epoch withdrawals.
        /// @param new_l1_net_asset_value The new L1 net asset value.
        /// @param underlying_bridged_amount The amount of underlying asset bridged.
        /// @param buffer The buffer amount.
        /// @return profit The calculated profit or zero in case of a loss.
        fn _calculate_profit_and_handle_loss(
            ref self: ContractState,
            epoch: u256,
            handled_epoch_withdrawal_len: u256,
            received_from_l1: u256,
            buffer: u256
        ) -> u256 {
            let sent_to_l1 = self.l1_net_asset_value.read() + self.underlying_transit.read();
            if (received_from_l1 < sent_to_l1) {
                let loss = sent_to_l1 - received_from_l1;
                let amount_to_consider = buffer + sent_to_l1;
                let mut i = handled_epoch_withdrawal_len;
                loop {
                    if (i > epoch) {
                        break ();
                    }
                    let withdrawal_pool = self.withdrawal_pool.read(i);
                    let withdrawal_epoch_loss_incured = (loss * withdrawal_pool) / amount_to_consider;
                    self.withdrawal_pool.write(i, withdrawal_pool - withdrawal_epoch_loss_incured);
                    i += 1;
                };
                0
            } else {
                received_from_l1 - sent_to_l1
            }
        }

        /// @notice Handles withdrawals for a given epoch.
        /// @dev Calculates the remaining and needed assets after processing withdrawals.
        /// @param epoch The current epoch for which withdrawals are being processed.
        /// @param handled_epoch_withdrawal_len The length of withdrawals already handled in the current epoch.
        /// @param withdrawal_epoch_delay The delay after which withdrawals can be processed.
        /// @param underlying_bridged_amount The amount of underlying assets bridged to the contract.
        /// @param buffer The buffer amount in the contract.
        /// @return A tuple containing the remaining assets after withdrawals and the additional assets needed.
        fn _handle_withdrawals(
            ref self: ContractState,
            epoch: u256,
            handled_epoch_withdrawal_len: u256,
            withdrawal_epoch_delay: u256,
            underlying_bridged_amount: u256,
            buffer: u256
        ) -> (u256, u256) {
            let mut remaining_assets = underlying_bridged_amount + buffer;
            let mut needed_assets = 0;

            if (epoch >= withdrawal_epoch_delay) {
                let mut new_handled_epoch_withdrawal_len = handled_epoch_withdrawal_len;
                let mut j = handled_epoch_withdrawal_len;
                let limit_epoch = epoch - withdrawal_epoch_delay;
                loop {
                    if (j > limit_epoch) {
                        break ();
                    }

                    let withdrawal_pool = self.withdrawal_pool.read(j);

                    if (remaining_assets >= withdrawal_pool) {
                        remaining_assets -= withdrawal_pool;
                        new_handled_epoch_withdrawal_len += 1;
                    } else {
                        needed_assets += withdrawal_pool - remaining_assets;
                    }

                    j += 1;
                };
                if (new_handled_epoch_withdrawal_len > handled_epoch_withdrawal_len) {
                    self.handled_epoch_withdrawal_len.write(new_handled_epoch_withdrawal_len);
                }
            }
            (remaining_assets, needed_assets)
        }


        /// @notice Handles the result of withdrawal and deposit operations.
        /// @dev Updates the contract state based on the remaining and needed assets, and performs necessary transfers.
        /// @param remaining_assets The remaining assets after processing withdrawals.
        /// @param needed_assets The additional assets needed to fulfill all withdrawals.
        /// @param new_l1_net_asset_value The new net asset value on L1.
        /// @return A tuple indicating the operation type (withdrawal or deposit) and the amount involved.
        fn _handle_result(
            ref self: ContractState, remaining_assets: u256, needed_assets: u256, new_l1_net_asset_value: u256
        ) -> (u256, u256) {
            if (needed_assets > 0) {
                self.buffer.write(remaining_assets);
                self.underlying_transit.write(0);
                (CONSTANTS::WITHDRAWAL, needed_assets)
            } else {
                let dust_limit_factor = self.dust_limit.read();
                let dust_limit = (new_l1_net_asset_value * dust_limit_factor) / CONSTANTS::WAD;
                if (dust_limit > remaining_assets) {
                    self.buffer.write(remaining_assets);
                    self.underlying_transit.write(0);
                    (CONSTANTS::REPORT, 0)
                } else {
                    self.buffer.write(0);
                    self.underlying_transit.write(remaining_assets);
                    let underlying_disp = ERC20ABIDispatcher { contract_address: self.underlying.read() };
                    underlying_disp.transfer(self.pooling_manager.read(), remaining_assets);
                    (CONSTANTS::DEPOSIT, remaining_assets)
                }
            }
        }

        /// @notice Checks the profit made and mints new tokens as performance fees.
        /// @dev Mints new tokens proportional to the profit made and the performance fees.
        /// @param profit The profit made in the current epoch.
        /// @param token The address of the token contract to mint new tokens.
        fn _check_profit_and_mint(ref self: ContractState, profit: u256, token: ContractAddress) {
            if (profit > 0) {
                let performance_fees = self.performance_fees.read();
                let performance_fees_from_profit = (profit * performance_fees) / CONSTANTS::WAD;
                let shares_to_mint = self._convert_to_shares(performance_fees_from_profit);
                let pooling_manager = self.pooling_manager.read();
                let pooling_manager_disp = IPoolingManagerDispatcher { contract_address: pooling_manager };
                let fees_recipient = pooling_manager_disp.fees_recipient();
                let token_disp = ITokenDispatcher { contract_address: token };
                token_disp.mint(fees_recipient, shares_to_mint);
            }
        }
    }
}
