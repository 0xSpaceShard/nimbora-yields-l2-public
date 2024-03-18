import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}`});
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function setTvlLimit() {

    const tvl_limit = "30000000000000000000" // 3K
    const token_manager = process.env.TOKENMANAGER_ADDRESS_ETH as string;
    const compiledContractTokenManager = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_TokenManager.contract_class.json`).toString('ascii'));
    const tokenManagerContract = new Contract(compiledContractTokenManager.abi, token_manager, owner);
    await tokenManagerContract.set_tvl_limit(tvl_limit);
    console.log('✅ tvl_limit updated, amount:', tvl_limit);
}   




async function main() {
    await setTvlLimit();
}

main();