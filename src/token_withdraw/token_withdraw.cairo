#[starknet::contract]
mod TokenWithdraw {
    use openzeppelin::token::erc721::ERC721Component;
    use openzeppelin::introspection::src5::SRC5Component;

    use starknet::{ContractAddress, get_caller_address};

    use nimbora_yields::token_withdraw::interface::{ITokenWithdraw}; 

    component!(path: SRC5Component, storage: src5, event: SRC5Event);
    component!(path: ERC721Component, storage: erc721, event: ERC721Event);

    #[abi(embed_v0)]
    impl ERC721Impl = ERC721Component::ERC721Impl<ContractState>;
    #[abi(embed_v0)]
    impl ERC721MetadataImpl = ERC721Component::ERC721MetadataImpl<ContractState>;
    impl ERC721InternalImpl = ERC721Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc721: ERC721Component::Storage,
        #[substorage(v0)]
        src5: SRC5Component::Storage,
        token_manager: ContractAddress,
        supply: u256
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC721Event: ERC721Component::Event,
        #[flat]
        SRC5Event: SRC5Component::Event
    }

    mod Errors {
        const INVALID_CALLER: felt252 = 'Caller is not manager';
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        token_manager: ContractAddress,
        name: felt252,
        symbol: felt252
    ) {
        self.erc721.initializer(name, symbol);
        self.token_manager.write(token_manager);
    }


    #[abi(embed_v0)]
    impl TokenWithdraw of ITokenWithdraw<ContractState> {

        fn mint(ref self: ContractState, to: ContractAddress) {
            self._assert_only_token_manager();
            let new_id = self.supply.read();
            self.erc721._mint(to, new_id);
            self.supply.write(new_id + 1);
        }

        fn burn(ref self: ContractState, id: u256){
            self._assert_only_token_manager();
            self.erc721._burn(id);
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


}