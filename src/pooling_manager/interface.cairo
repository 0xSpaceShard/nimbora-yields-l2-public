use nimbora_yields::token_manager::interface::{StrategyReportL2};
use starknet::{ContractAddress, ClassHash, eth_address::EthAddress};

#[derive(Copy, Drop, Serde, Hash)]
struct StrategyReportL1 {
    l1_strategy: EthAddress,
    l1_net_asset_value: u256,
    underlying_bridged_amount: u256,
    processed: bool
}

#[derive(Copy, Drop, Serde)]
struct BridgeInteractionInfo {
    l1_bridge: felt252,
    amount: u256
}

#[starknet::interface]
trait IPoolingManager<TContractState> {
    fn factory(self: @TContractState) -> ContractAddress;
    fn fees_recipient(self: @TContractState) -> ContractAddress;
    fn l1_strategy_to_token_manager(self: @TContractState, l1_strategy: EthAddress) -> ContractAddress;
    fn underlying_to_bridge(self: @TContractState, underlying: ContractAddress) -> ContractAddress;
    fn l2_bridge_to_l1_bridge(self: @TContractState, bridge: ContractAddress) -> felt252;


    fn l1_pooling_manager(self: @TContractState) -> EthAddress;
    fn is_initialised(self: @TContractState) -> bool;

    fn hash_l1_data(self: @TContractState, calldata: Span<StrategyReportL1>) -> u256;

    fn hash_l2_data(
        self: @TContractState,
        new_epoch: u256,
        bridge_deposit_info: Span<BridgeInteractionInfo>,
        strategy_report_l2: Span<StrategyReportL2>,
        bridge_withdrawal_info: Span<BridgeInteractionInfo>
    ) -> u256;

    fn l1_report_hash(self: @TContractState, general_epoch: u256) -> u256;
    fn general_epoch(self: @TContractState) -> u256;
    fn pending_strategies_to_initialize(self: @TContractState) -> Array<EthAddress>;
    fn set_fees_recipient(ref self: TContractState, new_fees_recipient: ContractAddress);
    fn set_l1_pooling_manager(ref self: TContractState, new_l1_pooling_manager: EthAddress);
    fn set_factory(ref self: TContractState, new_factory: ContractAddress);
    fn set_allowance(ref self: TContractState, spender: ContractAddress, token_address: ContractAddress, amount: u256);
    fn handle_mass_report(ref self: TContractState, calldata: Span<StrategyReportL1>);
    fn register_strategy(
        ref self: TContractState,
        token_manager_deployed_address: ContractAddress,
        token_deployed_address: ContractAddress,
        l1_strategy: EthAddress,
        underlying: ContractAddress,
        performance_fees: u256,
        tvl_limit: u256,
    );
    fn delete_all_pending_strategy(ref self: TContractState);

    fn register_underlying(
        ref self: TContractState, underlying: ContractAddress, bridge: ContractAddress, l1_bridge: felt252,
    );

    fn emit_tvl_limit_updated_event(
        ref self: TContractState, l1_strategy: EthAddress, l2_strategy: ContractAddress, new_tvl_limit: u256
    );

    fn emit_performance_fees_updated_event(
        ref self: TContractState, l1_strategy: EthAddress, l2_strategy: ContractAddress, new_performance_fees: u256
    );
    fn emit_withdrawal_epoch_delay_updated_event(
        ref self: TContractState,
        l1_strategy: EthAddress,
        l2_strategy: ContractAddress,
        new_withdrawal_epoch_delay: u256
    );

    fn emit_dust_limit_updated_event(ref self: TContractState, l1_strategy: EthAddress, new_dust_limit: u256);
    fn emit_deposit_event(
        ref self: TContractState,
        l1_strategy: EthAddress,
        l2_strategy: ContractAddress,
        caller: ContractAddress,
        receiver: ContractAddress,
        assets: u256,
        shares: u256,
        referal: ContractAddress
    );
    fn emit_request_withdrawal_event(
        ref self: TContractState,
        l1_strategy: EthAddress,
        l2_strategy: ContractAddress,
        caller: ContractAddress,
        assets: u256,
        shares: u256,
        id: u256,
        epoch: u256
    );

    fn emit_claim_withdrawal_event(
        ref self: TContractState,
        l1_strategy: EthAddress,
        l2_strategy: ContractAddress,
        caller: ContractAddress,
        id: u256,
        underlying_amount: u256
    );

    fn emit_token_manager_class_hash_updated_event(ref self: TContractState, new_token_manager_class_hash: ClassHash);

    fn emit_token_class_hash_updated_event(ref self: TContractState, new_token_class_hash: ClassHash);
}

