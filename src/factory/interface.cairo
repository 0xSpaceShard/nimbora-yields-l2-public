use starknet::{ContractAddress, ClassHash, eth_address::EthAddress};

#[starknet::interface]
trait IFactory<TContractState> {
    fn token_manager_class_hash(self: @TContractState) -> ClassHash;
    fn token_class_hash(self: @TContractState) -> ClassHash;
    fn token_withdrawal_class_hash(self: @TContractState) -> ClassHash;


    fn deploy_strategy(
        ref self: TContractState,
        l1_strategy: EthAddress,
        underlying: ContractAddress,
        token_name: felt252,
        token_symbol: felt252,
        token_withdrawal_name: felt252,
        token_withdrawal_symbol: felt252,
        performance_fees: u256,
        min_deposit: u256,
        max_deposit: u256,
        min_withdrawal: u256,
        max_withdrawal: u256,
        withdrawal_epoch_delay: u256,
        dust_limit: u256
    ) -> (ContractAddress, ContractAddress, ContractAddress);

    fn set_token_manager_class_hash(
        ref self: TContractState, new_token_manager_class_hash: ClassHash
    );

    fn set_token_class_hash(ref self: TContractState, new_token_class_hash: ClassHash);

    fn set_token_withdrawal_class_hash(
        ref self: TContractState, new_token_withdrawal_class_hash: ClassHash
    );
}
