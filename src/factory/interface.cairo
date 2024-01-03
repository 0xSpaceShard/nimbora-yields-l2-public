use starknet::{ContractAddress, ClassHash};

#[starknet::interface]
trait ILiquidityPoolFactory<TContractState> {
    
    /// Create a new liquidity pool.
    /// # Arguments
    /// * `underlying_token` - The underlying token of the yield liquidity_pool.
    /// * `yield_token` - The yield token of the yield liquidity_pool.
    fn create_liquidity_pool(
        ref self: TContractState, underlying_token: ContractAddress, yield_token: ContractAddress
    ) -> ContractAddress;

    /// Update the class hash of the `LiquidityPool` contract to deploy 
    /// # Arguments
    /// * `liquidity_pool_class_hash` - The class hash of the `LiquidityPool` contract to deploy
    fn update_liquidity_pool_class_hash(
        ref self: TContractState, liquidity_pool_class_hash: ClassHash,
    );
}
