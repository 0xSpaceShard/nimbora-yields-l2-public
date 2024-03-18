import { Account, Contract, json, RpcProvider } from "starknet";
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config({ path: __dirname + '/../.env' })

const provider = new RpcProvider({ nodeUrl: `https://starknet-${process.env.STARKNET_NETWORK}.infura.io/v3/${process.env.INFURA_API_KEY}`});
const owner = new Account(provider, process.env.ACCOUNT_ADDRESS as string, process.env.ACCOUNT_PK as string, "1");

async function deployPoolingManagerContract(): Promise<Contract> {
    
    const compiledContract = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_poolingManager.contract_class.json`).toString('ascii'));
    const { transaction_hash, contract_address } = await owner.deploy({
        classHash: process.env.POOLINGMANAGER_CLASS_HASH as string,
        constructorCalldata: {
            owner: owner.address,
        },
        salt: "3"
    });

    const contractAddress: any = contract_address[0];
    await provider.waitForTransaction(transaction_hash);

    const poolingManagerContract = new Contract(compiledContract.abi, contractAddress, owner);
    console.log('✅ Test PoolingManager contract connected at =', poolingManagerContract.address);

    fs.appendFile(__dirname + '/../.env', `\n${'POOLINGMANAGER'.toUpperCase()}_ADDRESS=${contractAddress}`, function (err) {
        if (err) throw err;
    });
    return poolingManagerContract;
}

async function deployFactoryContract(): Promise<Contract> {
    const compiledContract = await json.parse(fs.readFileSync(`./target/dev/nimbora_yields_Factory.contract_class.json`).toString('ascii'));

    const { transaction_hash, contract_address } = await owner.deploy({
        classHash: process.env.FACTORY_CLASS_HASH as string,
        constructorCalldata: {
            pooling_manager: process.env.POOLINGMANAGER_ADDRESS as string,
            token_class_hash: process.env.TOKEN_CLASS_HASH as string,
            token_manager_class_hash: process.env.TOKENMANAGER_CLASS_HASH as string,
        },
    });
    const [contractAddress] = contract_address;
    await provider.waitForTransaction(transaction_hash);

    const factoryContract = new Contract(compiledContract.abi, contractAddress, owner);
    console.log('✅ Test Factory contract connected at =', factoryContract.address);
    fs.appendFile(__dirname + '/../.env', `\n${'FACTORY'.toUpperCase()}_ADDRESS=${contractAddress}`, function (err) {
        if (err) throw err;
    });
    return factoryContract;
}




async function main() {

    const flag = process.argv[2];
    const action = process.argv[3];

    if (!flag || !action) {
        throw new Error("Missing --contract <contract_name>");
    }

    if (flag == "--contract") {
        switch (action) {
            case "PoolingManager":
                console.log("Deploying PoolingManager...");
                await deployPoolingManagerContract();
                break;

            case "Factory":
                console.log("Deploying Factory...");
                await deployFactoryContract();
                break;
        }
    } else if (flag == "--setup") {
        const contract_address = process.argv[4];
        if (!contract_address) {
            throw new Error("Error: Provide contract address");
        }
    }
}

main();