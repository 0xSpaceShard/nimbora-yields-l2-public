use starknet::{ContractAddress, ClassHash};

#[starknet::interface]
trait ITokenWithdraw<TContractState> {

    fn mint(
        ref self: TContractState, to: ContractAddress
    );

    fn burn(
        ref self: TContractState, id: u256
    );

}
