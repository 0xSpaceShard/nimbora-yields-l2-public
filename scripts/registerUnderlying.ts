import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}`});
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function registerUnderlying() {
    const compiledContract = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_poolingManager.contract_class.json`).toString('ascii'));
    const poolingManagerContract = new Contract(compiledContract.abi, process.env.POOLINGMANAGER_ADDRESS as string, owner);
    
    // DAI
    // const underlying = "0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3";
    // const l2_underlying_bridge = "0x075ac198e734e289a6892baa8dd14b21095f13bf8401900f5349d5569c3f6e60";
    // const l1_underlying_bridge = "0x9F96fE0633eE838D0298E8b8980E6716bE81388d";


    const underlying = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7";
    const l2_underlying_bridge = "0x073314940630fd6dcda0d772d4c972c4e0a9946bef9dabf4ef84eda8ef542b82";
    const l1_underlying_bridge = "0xae0Ee0A63A2cE6BaeEFFE56e7714FB4EFE48D419";
    
    await poolingManagerContract.register_underlying(underlying, l2_underlying_bridge, l1_underlying_bridge);
    console.log('✅ Underlying registered :', underlying, l2_underlying_bridge, l1_underlying_bridge);

    /// Only for dai bridge
    ///await poolingManagerContract.set_allowance(l2_underlying_bridge, underlying, "1000000000000000000000000000");
    ///console.log('✅ Allowance set to bridge :', l2_underlying_bridge, underlying, "1000000000000000000000000000");
}   




async function main() {
    await registerUnderlying();
}

main();