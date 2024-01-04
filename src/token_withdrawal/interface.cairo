use starknet::{ContractAddress, ClassHash};

#[starknet::interface]
trait ITokenWithdrawal<TContractState> {
    fn mint(ref self: TContractState, to: ContractAddress, id: u256);
    fn burn(ref self: TContractState, id: u256);
}
