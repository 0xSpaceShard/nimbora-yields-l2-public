import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}`});
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function setFees() {

    // const new_class_hash = process.env.POOLINGMANAGER_CLASS_HASH as string;
    // const contract_address = process.env.POOLINGMANAGER_ADDRESS as string;

    const contract_address = process.env.TOKENMANAGER_ADDRESS_ETH as string;

    // const compiledContractPoolingManager = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_poolingManager.contract_class.json`).toString('ascii'));
    // const compiledFactory = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_Factory.contract_class.json`).toString('ascii'));
    const compiledTokenManager = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_TokenManager.contract_class.json`).toString('ascii'));
    
    const new_fees = "0";
    const contract = new Contract(compiledTokenManager.abi, contract_address, owner);
    await contract.set_performance_fees(new_fees);
    console.log('✅ contract fees updated:', new_fees);
}   




async function main() {
    await setFees();
}

main();