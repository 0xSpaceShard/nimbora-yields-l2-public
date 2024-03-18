import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';
dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}` });
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function deploy_strategy() {
    const compiledContract = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_Factory.contract_class.json`).toString('ascii'));
    const factoryContract = new Contract(compiledContract.abi, process.env.FACTORY_ADDRESS as string, owner);

    //// SDAI STRATEGY EXEMPLE
    //const l1_strategy = "0xAFa27423F3bb4c0337946dDcd1802588807571bf";
    //const underlying = "0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3";
    //const token_name = "NimboraSDai";
    //const token_symbol = "NSDAI";
    //// performance fees = 20% rewards
    //const performance_fees = "200000000000000000";
    //// min deposit 0.1 DAI
    //const min_deposit = "100000000000000000";
    //// min deposit 1000 DAI
    //const max_deposit = "1000000000000000000000";
    //// min withdrawal 0.1 DAI
    //const min_withdrawal = "100000000000000000";
    //// max withdrawal 1000 DAI
    //const max_withdrawal = "1000000000000000000000";
    //const withdrawal_epoch_delay = "3";
    //// dust limit = 1% of l1 net asset value
    //const dust_limit_factor = "10000000000000000";

    // WSTETH STRATEGY EXEMPLE
    const l1_strategy = "0xE5e2134e536fbfD7513094646E27C401bbb03eF6";
    const underlying = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
    const token_name = "NimboraWSTEH";
    const token_symbol = "NWSTETH";
    // performance fees = 20% rewards
    const performance_fees = "200000000000000000";
    // tvl limit 100 ETH
    const tvl_limit = "100000000000000000000";
    const withdrawal_epoch_delay = "3";
    // dust limit = 1% of l1 net asset value
    const dust_limit_factor = "10000000000000000";


    await factoryContract.deploy_strategy(
        l1_strategy,
        underlying,
        token_name,
        token_symbol,
        performance_fees,
        tvl_limit,
        withdrawal_epoch_delay,
        dust_limit_factor);

    console.log('✅ Strategy deployed :', l1_strategy as string);
}


async function main() {
    await deploy_strategy();
}

main();