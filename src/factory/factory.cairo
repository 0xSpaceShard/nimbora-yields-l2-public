#[starknet::contract]
mod StrategyFactory {

    // Core lib imports.
    use core::result::ResultTrait;
    use starknet::{get_caller_address, ContractAddress, contract_address_const, ClassHash, eth_address::EthAddress};
    use starknet::syscalls::deploy_syscall;
    use poseidon::poseidon_hash_span;

    // OZ imports
    use openzeppelin::access::accesscontrol::interface::{
        IAccessControlDispatcher, IAccessControlDispatcherTrait
    };

    // Local imports.
    use nimbora_yields::factory::interface::{IStrategyFactory}
    use nimbora_yields::pooling_manager::interface::{IPoolingManagerDispatcher, IPoolingManagerDispatcherTrait}

    #[storage]
    struct Storage {
        manager: ContractAddress,
        token_hash: ClassHash,
        token_manager_hash: ClassHash,
        token_withdraw_hash: ClassHash
    }


    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TokenHashUpdated: TokenHashUpdated,
        TokenManagerHashUpdated: TokenManagerHashUpdated,
        TokenWithdrawHashUpdated: TokenWithdrawHashUpdated
    }

    #[derive(Drop, starknet::Event)]
    struct TokenHashUpdated {
        previous_hash: ClassHash,
        new_hash: ClassHash
    }

    #[derive(Drop, starknet::Event)]
    struct TokenManagerHashUpdated {
        previous_hash: ClassHash,
        new_hash: ClassHash
    }

    #[derive(Drop, starknet::Event)]
    struct TokenWithdrawHashUpdated {
        previous_hash: ClassHash,
        new_hash: ClassHash
    }

    

    mod Errors {
        const ZERO_ADDRESS: felt252 = 'Address is zero';
    }


    /// Constructor of the contract.
    /// # Arguments
    /// * `manager` - The address of the data store contract.
    /// * `token_hash` - The hash of the token contract.
    /// * `token_manager_hash` - The hash of the token manager contract.
    /// * `token_withdraw_hash` - The hash of the token withdraw contract.
    #[constructor]
    fn constructor(
        ref self: ContractState,
        manager: ContractAddress,
        token_hash: ClassHash,
        token_manager_hash: ClassHash,
        token_withdraw_hash: ClassHash
    ) {
        self.manager.write(IPoolingManagerDispatcher{ contract_address: manager });
        self._set_token_hash();
        self._set_token_manager_hash();
        self._set_token_withdraw_hash();
    }


    #[abi(embed_v0)]
    impl StrategyFactory of IStrategyFactory<ContractState> {

        fn deploy_strategy(
            ref self: ContractState,
            l1_strategy: EthAddress,
            underlying: ContractAddress,
            token_name: felt252,
            token_symbol: felt252,
            token_withdraw_name: felt252,
            token_withdraw_symbol: felt252,
            performance_fees: u256
        ) -> (ContractAddress, ContractAddress, ContractAddress) {

            let caller_address = get_caller_address();
            let manager = self.manager.read();
            let control_disp = IAccessControlDispatcher { contract_address: manager }
            control_disp.assert_only_role(caller_address, 0);
            let manager_disp = IPoolingManagerDispatcher {contract_address: manager };

            let (token_manager_salt, token_salt, token_withdraw_salt) = self._compute_salt_for_strategy(l1_strategy);

            let mut constructor_token_manager_calldata = array![
                manager,
                l1_strategy,
                underlying,
                performance_fees
            ];

            let (token_manager_deployed_address, ) = deploy_syscall(
                self._token_manager_hash.read(), token_manager_salt, constructor_token_manager_calldata.span(), false
            ).expect('failed to deploy token manager');


            let mut constructor_token_calldata = array![
                token_manager_deployed_address,
                token_name,
                token_symbol
            ];

            let mut constructor_token_withdraw_calldata = array![
                token_manager_deployed_address,
                token_withdraw_name,
                token_withdraw_symbol
            ];

            let (token_deployed_address, ) = deploy_syscall(
                self._token_hash.read(), token_salt, constructor_token_calldata.span(), false
            ).expect('failed to deploy token');

            let (token_withdraw_deployed_address, ) = deploy_syscall(
                self._token_withdraw_hash.read(), token_withdraw_salt, constructor_token_withdraw_calldata.span(), false
            ).expect('failed to deploy token withdraw');
            

            manager_disp.register_strategy(token_manager_deployed_address, token_deployed_address, token_withdraw_deployed_address);
            (token_manager_deployed_address, token_deployed_address, token_withdraw_deployed_address)
        }

        fn update_liquidity_pool_class_hash(
            ref self: ContractState, liquidity_pool_class_hash: ClassHash,
        ) {
            let caller_address = get_caller_address();
            self.config.read().assert_only_role(caller_address, 0);
            self.liquidity_pool_class_hash.write(liquidity_pool_class_hash);

            self
                .event_emitter
                .read()
                .emit_liquidity_pool_class_hash_updated(
                    old_liquidity_pool_class_hash, liquidity_pool_class_hash,
                );
        }
    }


    #[generate_trait]
    impl InternalImpl of InternalTrait {
        
        /// Compute a salt to use when deploying a new `LiquidityPool` contract.
        /// # Arguments
        fn _compute_salt_for_strategy(
            self: @ContractState,
            l1_strategy: EthAddress,
            underlying: ContractAddress,
            token_name: felt252,
            token_symbol: felt252,
            token_withdraw_name: felt252,
            token_withdraw_symbol: felt252,
            performance_fees: u256
        ) -> (felt252, felt252, felt252) {

            let mut token_manager_data = array![];
            token_manager_data.append('TOKEN_MANAGER');
            token_manager_data.append(l1_strategy.into());
            token_manager_data.append(underlying.into());
            token_manager_data.append(performance_fees.into());
            let token_manager_salt = poseidon_hash_span(token_manager_data.span());


            let mut token_data = array![];
            token_data.append('TOKEN');
            token_data.append(token_name.into());
            token_data.append(token_symbol.into());
            let token_salt = poseidon_hash_span(token_data.span());

            let mut token_withdraw_data = array![];
            token_withdraw_data.append('TOKEN');
            token_withdraw_data.append(token_name.into());
            token_withdraw_data.append(token_symbol.into());
            let token_withdraw_salt = poseidon_hash_span(token_withdraw_data.span());

            (token_manager_salt, token_salt, token_withdraw_salt)
        }

        fn _set_token_manager_hash(
            ref self: ContractState,
            token_manager_hash: ClassHash
        )  {
            assert(token_manager_hash != 0, Errors::ZERO_ADDRESS)
            self._token_manager_hash.write(token_manager_hash);
        }

        fn _set_token_hash(
            ref self: ContractState,
            token_hash: ClassHash
        )  {
            assert(token_hash != 0, Errors::ZERO_ADDRESS)
            self._token_hash.write(token_hash);
        }

        fn _set_token_withdraw_hash(
            ref self: ContractState,
            token_withdraw_hash: ClassHash
        )  {
            assert(token_withdraw_hash != 0, Errors::ZERO_ADDRESS)
            self._token_withdraw_hash.write(token_withdraw_hash);
        }


    }
}
