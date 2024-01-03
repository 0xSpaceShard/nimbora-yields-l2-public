#[starknet::contract]
mod Token {
    use starknet::{ContractAddress, get_caller_address, eth_address::EthAddress};
    use openzeppelin::token::erc20::{ERC20ABIDispatcher, ERC20ABIDispatcherTrait};
    use nimbora_yields::token::interface::{IToken};
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
        token: ContractAddress,
        token_withdraw: ContractAddress,
        epoch: u256,
        epoch_nav: LegacyMap<u256, u256>,
        buffer: u256
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        PerformanceFeesUpdated: PerformanceFeesUpdated,
        DepositLimitUpdated: DepositLimitUpdated,
        Deposit: Deposit,
        RequestWithdrawal: RequestWithdrawal
    }

    #[derive(Drop, starknet::Event)]
    struct PerformanceFeesUpdated {
        new_performance_fees: u256
    }

    #[derive(Drop, starknet::Event)]
    struct DepositLimitUpdated {
        new_limit_low: u256,
        new_limit_high: u256
    }

    #[derive(Drop, starknet::Event)]
    struct Deposit {
        caller: ContractAddress,
        receiver: ContractAddress,
        assets: u256,
        shares: u256,
        referal: ContractAddress
    }

    #[derive(Drop, starknet::Event)]
    struct RequestWithdrawal {
        caller: ContractAddress,
        receiver: ContractAddress,
        assets: u256,
        shares: u256,
        referal: ContractAddress
    }

    


    mod Errors {
        const INVALID_CALLER: felt252 = 'Invalid caller';
        const INVALID_FEES: felt252 = 'Fee amount too high';
        const ZERO_AMOUNT: felt252 = 'Amount nul';
        const INVALID_LIMIT: felt252 = 'Invalid limit';
        const LOW_LIMIT : felt252 = 'Low limit reacher';
        const HIGH_LIMIT : felt252 = 'High limit reacher';
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
        max_withdrawal: u256
    ) {
        self.pooling_manager.write(pooling_manager);
        self.l1_strategy.write(l1_strategy);
        self.underlying.write(underlying);
        self._set_performance_fees(performance_fees);
        self._set_deposit_limit(min_deposit, max_deposit);
        self._set_withdrawal_limit(min_withdrawal, max_withdrawal);
    }


    #[abi(embed_v0)]
    impl TokenManager of ITokenManager<ContractState> {

        fn buffer(self: @ContractState)  {
            self.buffer.read()
        }

        fn epoch(self: @ContractState)  {
            self.epoch.read()
        }

        fn epoch_nav(self: @ContractState, epoch: u256)  {
            self.epoch_nav.read(epoch)
        }

        fn preview_deposit(self: @ContractState, assets: u256)  {
            self._preview_deposit(assets)
        }

        fn deposit_limit(self: @ContractState, assets: u256) -> (u256, u256)  {
            let deposit_limit_low = self.deposit_limit_low.read();
            let deposit_limit_high = self.deposit_limit_high.read();
            (deposit_limit_low, deposit_limit_high)
        }

        fn withdrawal_limit(self: @ContractState, assets: u256) -> (u256, u256)  {
            let withdrawal_limit_low = self.withdrawal_limit_low.read();
            let withdrawal_limit_high = self.withdrawal_limit_high.read();
            (withdrawal_limit_low, withdrawal_limit_high)
        }


        fn initialise(
            ref self: ContractState,
            token: ContractAddress,
            token_withdraw: ContractAddress
        )  {
            self._assert_only_pool_manager();
            self.token.write(token);
            self.token_withdraw.write(token_withdraw);
        }

        fn deposit(
            ref self: ContractState,
            assets: u256,
            receiver: ContractAddress,
            referal: ContractAddress
        )  {

            let deposit_limit_low = self.deposit_limit_low.read();
            let deposit_limit_high = self.deposit_limit_high.read();

            assert(assets >= deposit_limit_low, Errors::LOW_LIMIT);
            assert(assets <= deposit_limit_high, Errors::HIGH_LIMIT);

            let underlying = self.underlying.read();
            let erc20_disp = ERC20ABIDispatcher{ contract_address: underlying };
            let caller = get_caller_address();
            let this = get_contract_address();
            erc20_disp.transferFrom(caller, this, assets);
            let buffer = self.buffer.read();
            let new_buffer = buffer + assets;
            self.buffer.write(new_buffer);

            let shares = self._convert_to_shares(assets);
            let token = self.token.read();
            let token_disp = ITokenDispatcher{ contract_address: token };
            token_disp.mint(receiver, shares);

            self.emit(Deposit { caller: caller, receiver: receiver, assets: assets, shares: shares, referal: referal });            
        }

        fn request_withdrawal(
            ref self: ContractState,
            shares: u256,
            receiver: ContractAddress,
        )  {

            let withdrawal_limit_low = self.withdrawal_limit_low.read();
            let withdrawal_limit_high = self.withdrawal_limit_high.read();
            assert(assets >= withdrawal_limit_low, Errors::LOW_LIMIT);
            assert(assets <= withdrawal_limit_high, Errors::HIGH_LIMIT);


            let token = self.token.read();
            let erc20_disp = ERC20ABIDispatcher{ contract_address: token };
            let caller = get_caller_address();
            let this = get_contract_address();
            erc20_disp.transferFrom(caller, this, shares);


            let token_withdraw = self.token_withdraw.read();
            let token_withdraw_disp = ITokenWithdrawDispatcher{ contract_address: token_withdraw };
            let epoch = self.epoch.read();
            token_withdraw_disp.create_request(epoch, shares, receiver);

            self.emit(RequestWithdrawal { caller: caller, receiver: receiver, shares: shares, epoch: epoch });            
        }


        fn set_performance_fees(
            ref self: ContractState,
            new_performance_fees: u256
        )  {
            self._assert_only_owner();
            self._set_performance_fees(new_performance_fees);
            self
                .emit(PerformanceFeesUpdated { new_performance_fees: new_performance_fees });
        }

        fn set_deposit_limit(
            ref self: ContractState,
            new_deposit_limit_low: u256,
            new_deposit_limit_high: u256
        )  {
            self._assert_only_owner();
            self._set_deposit_limit(deposit_limit_low, deposit_limit_high);
            self
                .emit(DepositLimitUpdated { new_limit_low: new_deposit_limit_low, new_limit_high: new_deposit_limit_high });
        }

        fn set_withdrawal_limit(
            ref self: ContractState,
            new_withdrawal_limit_low: u256,
            new_withdrawal_limit_high: u256
        )  {
            self._assert_only_owner();
            self._set_withdrawal_limit(withdrawal_limit_low, withdrawal_limit_high);
            self
                .emit(withdrawalLimitUpdated { new_limit_low: new_withdrawal_limit_low, new_limit_high: new_withdrawal_limit_high });
        }

    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {

        fn _assert_only_pool_manager(self: @ContractState){
            let caller = get_caller_address();
            let pooling_manager = self.pooling_manager.read();
            assert(caller == pooling_manager, Errors::INVALID_CALLER);
        }

        fn _assert_only_owner(self: @ContractState){
            let caller = get_caller_address();
            let pooling_manager = self.pooling_manager.read();
            let access_disp = IAccessControlDispatcher{ contract_address: pooling_manager };
            access_disp.assert_only_role(caller, 0);
        }

        fn _total_assets(self: @ContractState, assets: u256)  {
            let buffer = self.buffer.read();
            let reported_underlying = self.reported_underlying.read();
            buffer + reported_underlying
        }

        fn _convert_to_shares(self: @ContractState, assets: u256)  {
            let token = self.token.read();
            let erc20_disp = ERC20ABIDispatcher{ contract_address: token };
            let total_supply = erc20_disp.total_supply();
            let _total_assets = self._total_assets()
            (assets * (total_supply + 1)) / (_total_assets + 1)
        }

        fn _convert_to_assets(self: @ContractState, shares: u256)  {
            let token = self.token.read();
            let erc20_disp = ERC20ABIDispatcher{ contract_address: token };
            let total_supply = erc20_disp.total_supply();
            let _total_assets = self._total_assets()
            (shares * (_total_assets + 1)) / (total_supply + 1)
        }


        let token = self.token.read();
            let erc20_disp = ERC20ABIDispatcher{ contract_address: token };
            let supply = erc20_disp.total_supply();


        fn _set_performance_fees(
            ref self: ContractState,
            new_performance_fees: u256
        )  {
            assert(new_performance_fees < CONSTANTS::WAD, Errors::INVALID_FEES);
            self.performance_fees.write(new_performance_fees);
        }

        fn _set_deposit_limit(
            ref self: ContractState,
            deposit_limit_low: u256,
            deposit_limit_high: u256
        )  {
            assert(deposit_limit_low > 0, Errors::ZERO_AMOUNT);
            assert(deposit_limit_high > deposit_limit_low, Errors::INVALID_LIMIT);
            self.deposit_limit_low.write(deposit_limit_low);
            self.deposit_limit_high.write(deposit_limit_high);
        }

        fn _set_withdrawal_limit(
            ref self: ContractState,
            withdrawal_limit_low: u256,
            withdrawal_limit_high: u256
        )  {
            assert(withdrawal_limit_low > 0, Errors::ZERO_AMOUNT);
            assert(withdrawal_limit_high > withdrawal_limit_low, Errors::INVALID_LIMIT);
            self.withdrawal_limit_low.write(withdrawal_limit_low);
            self.withdrawal_limit_high.write(withdrawal_limit_high);
        }
        

    }


}