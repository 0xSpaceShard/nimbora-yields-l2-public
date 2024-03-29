use starknet::{ContractAddress, ClassHash, eth_address::EthAddress};

#[starknet::interface]
trait IFactory<TContractState> {
    fn token_manager_class_hash(self: @TContractState) -> ClassHash;
    fn token_class_hash(self: @TContractState) -> ClassHash;
    fn pooling_manager(self: @TContractState) -> ContractAddress;
    fn compute_salt_for_strategy(
        self: @TContractState,
        l1_strategy: EthAddress,
        underlying: ContractAddress,
        token_name: felt252,
        token_symbol: felt252
    ) -> (felt252, felt252);

    fn deploy_strategy(
        ref self: TContractState,
        l1_strategy: EthAddress,
        underlying: ContractAddress,
        token_name: felt252,
        token_symbol: felt252,
        performance_fees: u256,
        tvl_limit: u256,
        withdrawal_epoch_delay: u256,
        dust_limit: u256
    ) -> (ContractAddress, ContractAddress);

    fn set_token_manager_class_hash(ref self: TContractState, new_token_manager_class_hash: ClassHash);

    fn set_token_class_hash(ref self: TContractState, new_token_class_hash: ClassHash);
}
