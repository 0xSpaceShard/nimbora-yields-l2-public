#[starknet::contract]
mod StrategyFactory {
    // Core lib imports.
    use core::result::ResultTrait;
    use starknet::{
        get_caller_address, ContractAddress, contract_address_const, ClassHash,
        eth_address::EthAddress, Zeroable
    };
    use starknet::syscalls::deploy_syscall;
    use core::poseidon::poseidon_hash_span;


    // OZ imports
    use openzeppelin::access::accesscontrol::interface::{
        IAccessControlDispatcher, IAccessControlDispatcherTrait
    };


    // Local imports.
    use nimbora_yields::factory::interface::{IFactory};
    use nimbora_yields::pooling_manager::interface::{
        IPoolingManagerDispatcher, IPoolingManagerDispatcherTrait
    };

    #[storage]
    struct Storage {
        pooling_manager: ContractAddress,
        token_class_hash: ClassHash,
        token_manager_class_hash: ClassHash
    }


    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        TokenHashUpdated: TokenHashUpdated,
        TokenManagerHashUpdated: TokenManagerHashUpdated
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


    mod Errors {
        const ZERO_ADDRESS: felt252 = 'Address is zero';
        const ZERO_HASH: felt252 = 'Hash is zero';
        const INVALID_CALLER: felt252 = 'Invalid caller';
    }


    #[constructor]
    fn constructor(
        ref self: ContractState,
        pooling_manager: ContractAddress,
        token_class_hash: ClassHash,
        token_manager_class_hash: ClassHash
    ) {
        assert(pooling_manager.is_non_zero(), Errors::ZERO_ADDRESS);
        self.pooling_manager.write(pooling_manager);
        self._set_token_class_hash(token_class_hash);
        self._set_token_manager_class_hash(token_manager_class_hash);
    }


    #[abi(embed_v0)]
    impl Factory of IFactory<ContractState> {
        fn token_manager_class_hash(self: @ContractState) -> ClassHash {
            self.token_manager_class_hash.read()
        }

        fn token_class_hash(self: @ContractState) -> ClassHash {
            self.token_class_hash.read()
        }


        fn deploy_strategy(
            ref self: ContractState,
            l1_strategy: EthAddress,
            underlying: ContractAddress,
            token_name: felt252,
            token_symbol: felt252,
            performance_fees: u256,
            min_deposit: u256,
            max_deposit: u256,
            min_withdrawal: u256,
            max_withdrawal: u256,
            withdrawal_epoch_delay: u256,
            dust_limit: u256
        ) -> (ContractAddress, ContractAddress) {
            self._assert_only_owner();
            let (token_manager_salt, token_salt) = self
                ._compute_salt_for_strategy(
                    l1_strategy,
                    underlying,
                    token_name,
                    token_symbol
                );
            let pooling_manager = self.pooling_manager.read();
            let mut constructor_token_manager_calldata = array![
                pooling_manager.into(),
                l1_strategy.into(),
                underlying.into(),
                performance_fees.low.into(),
                performance_fees.high.into(),
                min_deposit.low.into(),
                min_deposit.high.into(),
                max_deposit.low.into(),
                max_deposit.high.into(),
                min_withdrawal.low.into(),
                min_withdrawal.high.into(),
                max_withdrawal.low.into(),
                max_withdrawal.high.into(),
                withdrawal_epoch_delay.low.into(),
                withdrawal_epoch_delay.high.into(),
                dust_limit.low.into(),
                dust_limit.high.into()
            ];

            let (token_manager_deployed_address, _) = deploy_syscall(
                self.token_manager_class_hash.read(),
                token_manager_salt,
                constructor_token_manager_calldata.span(),
                false
            )
                .expect('failed to deploy tm');

            let mut constructor_token_calldata = array![
                token_manager_deployed_address.into(), token_name.into(), token_symbol.into()
            ];

            let (token_deployed_address, _) = deploy_syscall(
                self.token_class_hash.read(), token_salt, constructor_token_calldata.span(), false
            )
                .expect('failed to deploy t');

            let pooling_manager = self.pooling_manager.read();
            let manager_disp = IPoolingManagerDispatcher { contract_address: pooling_manager };
            manager_disp
                .register_strategy(
                    token_manager_deployed_address,
                    token_deployed_address,
                    l1_strategy,
                    underlying,
                    performance_fees,
                    min_deposit,
                    max_deposit,
                    min_withdrawal,
                    max_withdrawal
                );
            (
                token_manager_deployed_address,
                token_deployed_address
            )
        }


        fn set_token_manager_class_hash(
            ref self: ContractState, new_token_manager_class_hash: ClassHash,
        ) {
            self._assert_only_owner();
            self._set_token_manager_class_hash(new_token_manager_class_hash);
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher {
                contract_address: pooling_manager
            };
            pooling_manager_disp
                .emit_token_manager_class_hash_updated_event(new_token_manager_class_hash);
        }

        fn set_token_class_hash(ref self: ContractState, new_token_class_hash: ClassHash,) {
            self._assert_only_owner();
            self._set_token_class_hash(new_token_class_hash);
            let pooling_manager = self.pooling_manager.read();
            let pooling_manager_disp = IPoolingManagerDispatcher {
                contract_address: pooling_manager
            };
            pooling_manager_disp.emit_token_class_hash_updated_event(new_token_class_hash);
        }

    }


    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _assert_only_owner(self: @ContractState) {
            let caller = get_caller_address();
            let pooling_manager = self.pooling_manager.read();
            let access_disp = IAccessControlDispatcher { contract_address: pooling_manager };
            let has_role = access_disp.has_role(0, caller);
            assert(has_role, Errors::INVALID_CALLER);
        }

        fn _compute_salt_for_strategy(
            self: @ContractState,
            l1_strategy: EthAddress,
            underlying: ContractAddress,
            token_name: felt252,
            token_symbol: felt252
        ) -> (felt252, felt252) {
            let mut token_manager_data = array![];
            token_manager_data.append('TOKEN_MANAGER');
            token_manager_data.append(l1_strategy.into());
            token_manager_data.append(underlying.into());
            let token_manager_salt = poseidon_hash_span(token_manager_data.span());

            let mut token_data = array![];
            token_data.append('TOKEN');
            token_data.append(token_name.into());
            token_data.append(token_symbol.into());
            let token_salt = poseidon_hash_span(token_data.span());

            (token_manager_salt, token_salt)
        }

        fn _set_token_manager_class_hash(ref self: ContractState, token_manager_hash: ClassHash) {
            assert(token_manager_hash.is_non_zero(), Errors::ZERO_HASH);
            self.token_manager_class_hash.write(token_manager_hash);
        }

        fn _set_token_class_hash(ref self: ContractState, token_hash: ClassHash) {
            assert(token_hash.is_non_zero(), Errors::ZERO_HASH);
            self.token_class_hash.write(token_hash);
        }

    }
}
