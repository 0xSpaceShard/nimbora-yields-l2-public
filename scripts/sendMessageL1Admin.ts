
import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}`});
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function sendMessageToL1Admin() {
    const compiledContract = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_poolingManager.contract_class.json`).toString('ascii'));
    const poolingManagerContract = new Contract(compiledContract.abi, process.env.POOLINGMANAGER_ADDRESS as string, owner);
    
    const hash = "0xFB53439B1CF941DF70B022AF04C0146AC03A05B429E84FE6C28CF6F5A3145CE1"
    await poolingManagerContract.send_message_to_l1_admin(hash);
    console.log('✅ Message Sent registered :', hash);
}   


async function main() {
    await sendMessageToL1Admin();
}

main();