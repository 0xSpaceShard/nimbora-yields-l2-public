#[starknet::contract]
mod Token {
    use openzeppelin::token::erc20::{ERC20Component, interface};
    use starknet::{ContractAddress, get_caller_address};

    use nimbora_yields::token::interface::{IToken};

    component!(path: ERC20Component, storage: erc20, event: ERC20Event);

    #[abi(embed_v0)]
    impl ERC20Impl = ERC20Component::ERC20Impl<ContractState>;
    #[abi(embed_v0)]
    impl ERC20MetadataImpl = ERC20Component::ERC20MetadataImpl<ContractState>;
    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
        token_manager: ContractAddress,
        decimals: u8
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event
    }

    mod Errors {
        const INVALID_CALLER: felt252 = 'Caller is not manager';
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        token_manager: ContractAddress,
        name: felt252,
        symbol: felt252,
        decimals: u8
    ) {
        self.erc20.initializer(name, symbol);
        self.token_manager.write(token_manager);
        self.decimals.write(decimals);
    }


    #[abi(embed_v0)]
    impl Token of IToken<ContractState> {
        fn mint(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            self._assert_only_token_manager();
            self.erc20._mint(recipient, amount);
        }

        fn burn(ref self: ContractState, acccount: ContractAddress, amount: u256){
            self._assert_only_token_manager();
            self.erc20._burn(acccount, amount);
        }

    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _assert_only_token_manager(
            ref self: ContractState)  {
            let caller = get_caller_address();
            assert(self.token_manager.read() == caller, Errors::INVALID_CALLER);
        }
    }

    // Override decimals
    impl ERC20Metadata of interface::IERC20Metadata<ContractState> {
        fn decimals(self: @ContractState) -> u8 {
            self.decimals.read()
        }

        fn name(self: @ContractState) -> felt252 {
            self.erc20.name()
        }

        /// Returns the ticker symbol of the token, usually a shorter version of the name.
        fn symbol(self: @ContractState) -> felt252 {
            self.erc20.symbol()
        }
    }

}