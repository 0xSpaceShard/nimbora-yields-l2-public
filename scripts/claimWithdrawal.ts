import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}`});
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function initializePoolingManager() {

    // SDAI
    //const amount = "5000000000000000000"
    //const token_manager = "0x02aB4C62aDD88F102f1f1F3Ff6185E5Fc00a3FfCcF1B7B85505615f68096FEed"

    // WSTETH
    const id = "0"
    const token_manager = "0x0790370cE248020ee58e413A0D6C82E8250248Aa346a90abc293C52d8bEf9C1b"

    const compiledContractTokenManager = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_TokenManager.contract_class.json`).toString('ascii'));
    const tokenManagerContract = new Contract(compiledContractTokenManager.abi, token_manager, owner);
    await tokenManagerContract.claim_withdrawal(id);
    console.log('✅ withdrawal request ececuted, id:', id);
}   



async function main() {
    await initializePoolingManager();
}

main();