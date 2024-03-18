import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}`});
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function initializePoolingManager() {
    const compiledContract = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_poolingManager.contract_class.json`).toString('ascii'));
    const poolingManagerContract = new Contract(compiledContract.abi, process.env.POOLINGMANAGER_ADDRESS as string, owner);
    await poolingManagerContract.set_l1_pooling_manager(process.env.L1_POOLINGMANAGER_ADDRESS as string);
    console.log('✅ L1 pooling manager set at :', process.env.L1_POOLINGMANAGER_ADDRESS as string);
    await poolingManagerContract.set_fees_recipient(owner.address);
    console.log('✅ fees recipient set at :', owner.address as string);
    await poolingManagerContract.set_factory(process.env.FACTORY_ADDRESS as string);
    console.log('✅ factory set at :', process.env.FACTORY_ADDRESS as string);
}   




async function main() {
    await initializePoolingManager();
}

main();