import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}`});
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function initializePoolingManager() {

    // SDAI
    //const amount = "5000000000000000000"
    //const underlying = "0x00da114221cb83fa859dbdb4c44beeaa0bb37c7537ad5ae66fe5e0efd20e6eb3"
    //const token_manager = "0x02aB4C62aDD88F102f1f1F3Ff6185E5Fc00a3FfCcF1B7B85505615f68096FEed"

    // WSTETH
    const amount = "10000000000000000"
    const underlying = "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
    const token_manager = "0x0790370cE248020ee58e413A0D6C82E8250248Aa346a90abc293C52d8bEf9C1b"

    
    const compiledContractUnderlying = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_MockMintableToken.contract_class.json`).toString('ascii'));
    const underlyingContract = new Contract(compiledContractUnderlying.abi, underlying, owner);
    await underlyingContract.approve(token_manager, amount);
    console.log('✅ token approved, amount:', amount);

    const compiledContractTokenManager = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_TokenManager.contract_class.json`).toString('ascii'));
    const tokenManagerContract = new Contract(compiledContractTokenManager.abi, token_manager, owner);
    await tokenManagerContract.deposit(amount, owner.address, owner.address);
    console.log('✅ token deposited, amount:', amount);
}   




async function main() {
    await initializePoolingManager();
}

main();