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
    if (balance >= BigInt(amount)) {
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
