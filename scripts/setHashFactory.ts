import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';
dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}` });
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function setHashFactory() {
    const compiledContract = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_Factory.contract_class.json`).toString('ascii'));
    const factoryContract = new Contract(compiledContract.abi, process.env.FACTORY_ADDRESS as string, owner);
    const token_manager_class_hash = process.env.TOKENMANAGER_CLASS_HASH as string;
    const token_class_hash = process.env.TOKEN_CLASS_HASH as string;

    await factoryContract.set_token_manager_class_hash(token_manager_class_hash);
    await factoryContract.set_token_class_hash(token_class_hash);

    console.log('✅ token_manager_class_hash set :', token_manager_class_hash as string);
    console.log('✅ token_class_hash set :', token_class_hash as string);
}


async function main() {
    await setHashFactory();
}

main();