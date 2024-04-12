// Copyright 2020-2023 IOTA Stiftung
// SPDX-License-Identifier: Apache-2.0

import {
    IotaDID,
    IotaDocument,
    IotaIdentityClient,
    JwkMemStore,
    JwsAlgorithm,
    KeyIdMemStore,
    MethodScope,
    Storage,
    Credential,
    JwsSignatureOptions,
} from "@iota/identity-wasm/node";
import {
    AliasOutput,
    Client,
    IOutputsResponse,
    MnemonicSecretManager,
    SecretManager,
    SeedSecretManager,
    Utils,
} from "@iota/sdk-wasm/node";
import { InsufficientBalanceError } from "./errors/BalanceErorr";

export async function ensureAddressHasFunds(
    client: Client,
    addressBech32: string,
    amount: string,
    seed: string
) {
    let balance = await getAddressBalance(client, addressBech32);
    if (balance > BigInt(amount)) {
        return;
    }
    throw new InsufficientBalanceError(addressBech32, parseInt(amount), seed);
}

/** Returns the balance of the given Bech32-encoded address. */
async function getAddressBalance(
    client: Client,
    addressBech32: string
): Promise<bigint> {
    const outputIds: IOutputsResponse = await client.basicOutputIds([
        { address: addressBech32 },
        { hasExpiration: false },
        { hasTimelock: false },
        { hasStorageDepositReturn: false },
    ]);
    const outputs = await client.getOutputs(outputIds.items);

    let totalAmount = BigInt(0);
    for (const output of outputs) {
        totalAmount += output.output.getAmount();
    }

    return totalAmount;
}

/** Demonstrate how to create a DID Document and publish it in a new Alias Output. */
// export async function createIdentity(): Promise<any> {
//     const API_ENDPOINT = "https://api.testnet.shimmer.network";
//     const client = new Client({
//         primaryNode: API_ENDPOINT,
//         localPow: true,
//     });
//     const didClient = new IotaIdentityClient(client);

//     // Get the Bech32 human-readable part (HRP) of the network.
//     const networkHrp: string = await didClient.getNetworkHrp();

//     const mnemonic = Utils.generateMnemonic();
//     const seedSecretManager: SeedSecretManager = {
//         hexSeed:
//             "0xb5a1f0d7678c09dbeeebf523ba967fff7ca866f2cd9e6bedc52a11c040295fcb0274f1106feae255ffc263daff7d776185c795e17c10b797c27c7e54c4d0814a",
//         // mnemonic: mnemonic,
//     };

//     // Generate a random mnemonic for our wallet.
//     const secretManager: SecretManager = new SecretManager(seedSecretManager);

//     const walletAddressBech32 = (
//         await secretManager.generateEd25519Addresses({
//             accountIndex: 0,
//             range: {
//                 start: 0,
//                 end: 1,
//             },
//             bech32Hrp: networkHrp,
//         })
//     )[0];

//     const document = new IotaDocument(networkHrp);
//     const storage: Storage = new Storage(
//         new JwkMemStore(),
//         new KeyIdMemStore()
//     );

//     await document.generateMethod(
//         storage,
//         JwkMemStore.ed25519KeyType(),
//         JwsAlgorithm.EdDSA,
//         "#key-1",
//         MethodScope.VerificationMethod()
//     );

//     const address = Utils.parseBech32Address(walletAddressBech32);
//     const aliasOutput: AliasOutput = await didClient.newDidOutput(
//         address,
//         document
//     );

//     // Request funds for the wallet, if needed - only works on development networks.
//     await ensureAddressHasFunds(
//         client,
//         walletAddressBech32,
//         aliasOutput.amount,
//         see
//     );

//     // Create a new DID document with a placeholder DID.
//     // The DID will be derived from the Alias Id of the Alias Output after publishing.
//     // const document = await didClient.resolveDid(
//     //     IotaDID.parse(
//     //         "did:iota:rms:0x9bb46b58ed6aea72961bd1972124c9061012dcf721ada119837c2d2ac76c2383"
//     //     )
//     // );
//     console.log(document);
//     // Insert a new Ed25519 verification method in the DID document.
//     // Construct an Alias Output containing the DID document, with the wallet address
//     // set as both the state controller and governor.

//     console.log(aliasOutput);

//     const published = await didClient.publishDidOutput(
//         seedSecretManager,
//         aliasOutput
//     );
//     console.log("Published DID document:", JSON.stringify(published, null, 2));

//     const subject = {
//         id: "did:web:merul.org",
//         name: "Alice",
//         degreeName: "Bachelor of Science and Arts",
//         degreeType: "BachelorDegree",
//         GPA: "4.0",
//     };

//     // Create an unsigned `UniversityDegree` credential for Alice
//     const unsignedVc = new Credential({
//         id: "https://example.edu/credentials/3732",
//         type: "UniversityDegreeCredential",
//         issuer: published.id(),
//         credentialSubject: subject,
//     });

//     // Create signed JWT credential.
//     const credentialJwt = await published.createCredentialJwt(
//         storage,
//         "#key-1",
//         unsignedVc,
//         new JwsSignatureOptions()
//     );
//     console.log(`Credential JWT > ${credentialJwt.toString()}`);

//     // Before sending t
//     // console.log("Alias Output:", JSON.stringify(aliasOutput, null, 2));

//     // console.log(document);

//     // Publish the Alias Output and get the published DID document.

//     return {
//         didClient,
//         secretManager,
//         walletAddressBech32,
//         // did: published.id(),
//     };
// }
