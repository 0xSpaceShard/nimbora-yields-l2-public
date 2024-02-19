#[starknet::contract]
mod MockTransfer {
    use starknet::{
        ContractAddress, get_caller_address, get_contract_address, eth_address::EthAddress, Zeroable, ClassHash
    };

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}

    #[external(v0)]
    fn transfer(ref self: ContractState, add: ContractAddress, am: u256) -> u256 {
        let a = 45;
        a
    }
}
