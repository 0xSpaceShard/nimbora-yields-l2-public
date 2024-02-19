#[starknet::contract]
mod MockMintableToken {
    use nimbora_yields::token::interface::{IToken};
    use openzeppelin::token::erc20::{ERC20Component, interface};

    use starknet::{ContractAddress, get_caller_address, ClassHash};

    component!(path: ERC20Component, storage: erc20, event: ERC20Event);


    #[abi(embed_v0)]
    impl ERC20Impl = ERC20Component::ERC20Impl<ContractState>;
    #[abi(embed_v0)]
    impl ERC20CamelOnlyImpl = ERC20Component::ERC20CamelOnlyImpl<ContractState>;
    #[abi(embed_v0)]
    impl ERC20MetadataImpl = ERC20Component::ERC20MetadataImpl<ContractState>;
    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event,
    }


    #[constructor]
    fn constructor(ref self: ContractState,) {
        self.erc20.initializer('mock', 'mock');
    }


    #[abi(embed_v0)]
    impl MockMintableToken of IToken<ContractState> {
        fn mint(ref self: ContractState, recipient: ContractAddress, amount: u256) {
            self.erc20._mint(recipient, amount);
        }
        fn burn(ref self: ContractState, account: ContractAddress, amount: u256) {
            self.erc20._burn(account, amount);
        }
    }
}
