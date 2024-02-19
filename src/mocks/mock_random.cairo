#[starknet::contract]
mod MockRandom {
    use core::poseidon::poseidon_hash_span;
    use starknet::syscalls::deploy_syscall;
    use starknet::{
        get_caller_address, ContractAddress, contract_address_const, ClassHash, eth_address::EthAddress, Zeroable
    };

    #[storage]
    struct Storage {}

    #[constructor]
    fn constructor(ref self: ContractState) {}
}
