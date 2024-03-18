#[cfg(test)]
mod testF {
    use core::debug::PrintTrait;
    use core::option::OptionTrait;
    use core::result::ResultTrait;
    use core::traits::Into;
    use core::traits::TryInto;
    use integer::{BoundedInt};
    use nimbora_yields::mocks::mock_mintable_token::{MockMintableToken};
    use nimbora_yields::pooling_manager::interface::{IPoolingManagerDispatcher, IPoolingManagerDispatcherTrait};
    use nimbora_yields::tests::test_utils::{
        deploy_tokens, deploy_token_manager, deploy_token_manager_and_provide_args, deploy_strategy,
        deploy_two_strategy, deploy_three_strategy, approve_to_contract, multiple_approve_to_contract,
        transfer_to_users, deposit, deposit_and_handle_mass, between, deploy_mock_mintable_token, setup_0,
        deploy_mock_transfer
    };
    use nimbora_yields::token::interface::{ITokenDispatcher, ITokenDispatcherTrait};
    use nimbora_yields::token_bridge::interface::{
        ITokenBridgeDispatcher, ITokenBridgeDispatcherTrait, IMintableTokenDispatcher, IMintableTokenDispatcherTrait
    };

    // Utils peripheric contracts
    use nimbora_yields::token_bridge::token_bridge::{TokenBridge};
    use nimbora_yields::token_bridge::token_mock::{TokenMock};
    use nimbora_yields::token_manager::interface::{
        ITokenManagerDispatcher, ITokenManagerDispatcherTrait, WithdrawalInfo
    };
    use nimbora_yields::token_manager::token_manager::TokenManager::{
        InternalTrait, epochContractMemberStateTrait, l1_net_asset_valueContractMemberStateTrait,
        underlying_transitContractMemberStateTrait, bufferContractMemberStateTrait,
        handled_epoch_withdrawal_lenContractMemberStateTrait, withdrawal_infoContractMemberStateTrait,
        withdrawal_poolContractMemberStateTrait, withdrawal_shareContractMemberStateTrait,
        user_withdrawal_lenContractMemberStateTrait, tokenContractMemberStateTrait,
        performance_feesContractMemberStateTrait, pooling_managerContractMemberStateTrait,
        dust_limitContractMemberStateTrait, underlyingContractMemberStateTrait
    };

    // Nimbora yields contracts
    use nimbora_yields::token_manager::token_manager::{TokenManager};
    use nimbora_yields::utils::{CONSTANTS, MATH};

    use openzeppelin::{
        token::erc20::interface::{IERC20, ERC20ABIDispatcher, ERC20ABIDispatcherTrait}, token::erc20::{ERC20Component},
        access::accesscontrol::{
            AccessControlComponent, interface::{IAccessControlDispatcher, IAccessControlDispatcherTrait}
        },
        upgrades::interface::{IUpgradeableDispatcher, IUpgradeable, IUpgradeableDispatcherTrait}
    };
    use snforge_std::cheatcodes::contract_class::RevertedTransactionTrait;
    use snforge_std::{
        declare, ContractClassTrait, start_prank, CheatTarget, ContractClass, stop_prank, start_warp, stop_warp,
        L1Handler, L1HandlerTrait, get_class_hash, event_name_hash, spy_events, SpyOn, EventSpy, EventFetcher, Event,
        store, map_entry_address
    };
    use starknet::account::{Call};
    use starknet::class_hash::Felt252TryIntoClassHash;

    use starknet::{
        get_contract_address, deploy_syscall, ClassHash, contract_address_const, ContractAddress, get_block_timestamp,
        EthAddress, Zeroable
    };

    const thousand_ETH: u256 = 1000000000000000000000;

    fn setup() -> (
        IPoolingManagerDispatcher,
        ITokenManagerDispatcher,
        ITokenManagerDispatcher,
        ERC20ABIDispatcher,
        ERC20ABIDispatcher,
        ERC20ABIDispatcher,
        ERC20ABIDispatcher
    ) {
        let owner_f : felt252 = 0x01AE7268b79E13682c55729fa8a470cff3736D63Cbdb7Eac2F0F95c401832D16;
        let owner: ContractAddress = owner_f.try_into().unwrap();
        let eth_f : felt252 = 0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7;
        let eth : ContractAddress = eth_f.try_into().unwrap();
        let dai_f : felt252= 0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3;
        let dai : ContractAddress = dai_f.try_into().unwrap();

        let pooling_manager: ContractAddress = contract_address_const::<0x065a953f89a314a427e960114c4b9bb83e0e4195f801f12c25e4a323a76da0a9>();
        let token_manager_dai: ContractAddress = contract_address_const::<0x02ab4c62add88f102f1f1f3ff6185e5fc00a3ffccf1b7b85505615f68096feed>(); 
        let token_nimbora_dai: ContractAddress = contract_address_const::<0x23309ad3a5d9f7311460d6c65181dca024c4067a1fb68dfd6dae370551f2098>(); 
        let token_manager_eth: ContractAddress = contract_address_const::<0x0790370ce248020ee58e413a0d6c82e8250248aa346a90abc293c52d8bef9c1b>(); 
        let token_nimbora_eth: ContractAddress = contract_address_const::<0xe7cf77a75239f3e704ff11160ac5935971115e5c359a679fc9612900e8ce19>(); 
        let eth_bridge_f = 0x073314940630fd6dcda0d772d4c972c4e0a9946bef9dabf4ef84eda8ef542b82;
        let eth_bridge : ContractAddress = eth_bridge_f.try_into().unwrap();
        
        let eth_disp = IMintableTokenDispatcher{contract_address: eth};
        start_prank(CheatTarget::One(eth), eth_bridge);
        eth_disp.permissioned_mint(owner, thousand_ETH);
        stop_prank(CheatTarget::One(eth));

        let pooling_manager_disp = IPoolingManagerDispatcher{contract_address: pooling_manager};
        let token_manager_eth_disp = ITokenManagerDispatcher{contract_address: token_manager_eth};
        let token_manager_dai_disp = ITokenManagerDispatcher{contract_address: token_manager_dai};

        (
            pooling_manager_disp,
            token_manager_eth_disp,
            token_manager_dai_disp,
            ERC20ABIDispatcher{contract_address: eth},
            ERC20ABIDispatcher{contract_address: dai},
            ERC20ABIDispatcher{contract_address: token_nimbora_eth},
            ERC20ABIDispatcher{contract_address: token_nimbora_dai},
        )
    }

    #[test]
    #[fork("MAINNET_FORK_BEFORE")]
    fn setup_check_after() {
        let (pooling_manager, token_manager_eth, token_manager_dai, eth, dai, wsteth, sdai) = setup();
        
        ///'shr_prc'.print();
        ///let assetValue = token_manager_dai.convert_to_assets(CONSTANTS::WAD);
        ///assetValue.print();
///
        ///'und_tra'.print();
        ///let underlying_transit = token_manager_dai.underlying_transit();
        ///underlying_transit.print();
///
        ///'und_due'.print();
        ///let total_underlying_due = token_manager_dai.total_underlying_due();
        ///total_underlying_due.print();
///
        ///'l1_nav'.print();
        ///let l1_net_asset_value = token_manager_dai.l1_net_asset_value();
        ///l1_net_asset_value.print();
///
        ///'buffer'.print();
        ///let buffer = token_manager_dai.buffer();
        ///buffer.print();
///
        ///'tot_ass'.print();
        ///let total_assets = token_manager_dai.total_assets();
        ///total_assets.print();
///
        ///'tot_sup'.print();
        ///let total_supply = sdai.total_supply();
        ///total_supply.print();
///
        ///'epoch'.print();
        ///let epoch = token_manager_dai.epoch();
        ///epoch.print();
///
        ///'fw_len'.print();
        ///let handled_epoch_withdrawal_len = token_manager_dai.handled_epoch_withdrawal_len();
        ///handled_epoch_withdrawal_len.print();
///
        ///'wp_1'.print();
        ///let withdrawal_pool_1 = token_manager_dai.withdrawal_pool(3);
        ///withdrawal_pool_1.print();
///
        ///'wp_2'.print();
        ///let withdrawal_pool_2 = token_manager_dai.withdrawal_pool(4);
        ///withdrawal_pool_2.print();
///
        ///'wp_3'.print();
        ///let withdrawal_pool_3 = token_manager_dai.withdrawal_pool(5);
        ///withdrawal_pool_3.print();
    }

}


///0x885fc902cc63de48