import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}`});
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function handle_mass_report() {
    const compiledContract = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_poolingManager.contract_class.json`).toString('ascii'));
    const poolingManagerContract = new Contract(compiledContract.abi, process.env.POOLINGMANAGER_ADDRESS as string, owner);
    
    const reportL1Array = [
        {
            l1_strategy: "0xafa27423f3bb4c0337946ddcd1802588807571bf",
            l1_net_asset_value:"18038409741259041932",
            underlying_bridged_amount: "0",
            processed: "1",
        },
        {
            l1_strategy: "0xe5e2134e536fbfd7513094646e27c401bbb03ef6",
            l1_net_asset_value: "41972634816891538",
            underlying_bridged_amount: "0",
            processed: "1",
        }
    ]
    
    await poolingManagerContract.handle_mass_report(reportL1Array);
    console.log('✅ handle report executed');
}   




async function main() {
    await handle_mass_report();
}

main();