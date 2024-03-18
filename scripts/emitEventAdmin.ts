
import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}`});
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function sendMessageToL1Admin() {
    const compiledContract = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_poolingManager.contract_class.json`).toString('ascii'));
    const poolingManagerContract = new Contract(compiledContract.abi, process.env.POOLINGMANAGER_ADDRESS as string, owner);
    

    let epoch = "6"
    let bridge_deposit_info = [
        {
            l1_bridge: "0x9f96fe0633ee838d0298e8b8980e6716be81388d",
            amount: "1000000000000000000"
        },
        {
            l1_bridge: "0xae0ee0a63a2ce6baeeffe56e7714fb4efe48d419",
            amount: "103538446591102241"
        },
]

    let data_l2 = 
    [
        {
            l1_strategy: "0xafa27423f3bb4c0337946ddcd1802588807571bf",
            action_id: "0",
            amount: "1000000000000000000",
            processed: "1",
            new_share_price: "1001806076132256061"
        },
        {
            l1_strategy: "0xe5e2134e536fbfd7513094646e27c401bbb03ef6",
            action_id: "0",
            amount: "103538446591102241",
            processed: "1",
            new_share_price: "1000619673148117195"
        },
    ]

    let bridge_withdrawal_info: Array<Object> = []

    await poolingManagerContract.emit_event_admin(
            epoch,
            bridge_deposit_info,
            data_l2,
            bridge_withdrawal_info
    
    );
    console.log('✅ Message Sent registered :');
}   


async function main() {
    await sendMessageToL1Admin();
}

main();