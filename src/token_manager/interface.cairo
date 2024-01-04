use starknet::{ContractAddress, ClassHash, eth_address::EthAddress};


#[derive(Copy, Drop, Serde, starknet::Store)]
struct WithdrawalInfo {
    shares: u256,
    epoch: u256,
    to_claim: u256
}

#[derive(Copy, Drop, Serde)]
struct StrategyReport {
    l1_strategy: EthAddress,
    epoch: u256,
    action_id: u256,
    amount: u256
}


#[starknet::interface]
trait ITokenManager<TContractState> {
    fn pooling_manager(self: @TContractState) -> ContractAddress;
    fn l1_strategy(self: @TContractState) -> EthAddress;
    fn underlying(self: @TContractState) -> ContractAddress;
    fn token(self: @TContractState) -> ContractAddress;
    fn token_withdrawal(self: @TContractState) -> ContractAddress;
    fn performance_fees(self: @TContractState) -> u256;
    fn deposit_limit_low(self: @TContractState) -> u256;
    fn deposit_limit_high(self: @TContractState) -> u256;
    fn withdrawal_limit_low(self: @TContractState) -> u256;
    fn withdrawal_limit_high(self: @TContractState) -> u256;
    fn withdrawal_epoch_delay(self: @TContractState) -> u256;
    fn epoch(self: @TContractState) -> u256;
    fn epoch_share_price(self: @TContractState, epoch: u256) -> u256;
    fn l1_net_asset_value(self: @TContractState) -> u256;
    fn underlying_transit(self: @TContractState) -> u256;
    fn buffer(self: @TContractState) -> u256;
    fn finalized_withdrawal_len(self: @TContractState) -> u256;
    fn withdrawal_len(self: @TContractState) -> u256;
    fn withdrawal_info(self: @TContractState, id: u256) -> WithdrawalInfo;
    fn dust_limit(self: @TContractState) -> u256;


    fn initialiser(
        ref self: TContractState, token: ContractAddress, token_withdrawal: ContractAddress
    );

    fn set_performance_fees(ref self: TContractState, new_performance_fees: u256);

    fn set_deposit_limit(
        ref self: TContractState, new_deposit_limit_low: u256, new_deposit_limit_high: u256
    );

    fn set_withdrawal_limit(
        ref self: TContractState, new_withdrawal_limit_low: u256, new_withdrawal_limit_high: u256
    );

    fn set_withdrawal_epoch_delay(ref self: TContractState, new_withdrawal_epoch_delay: u256);

    fn set_dust_limit(ref self: TContractState, new_dust_limit: u256);

    fn deposit(
        ref self: TContractState, assets: u256, receiver: ContractAddress, referal: ContractAddress
    );

    fn request_withdrawal(ref self: TContractState, shares: u256, receiver: ContractAddress,);

    fn claim_withdrawal(ref self: TContractState, id: u256);

    fn handle_report(
        ref self: TContractState, l1_net_asset_value: u256, underlying_bridged_amount: u256
    ) -> StrategyReport;
}
