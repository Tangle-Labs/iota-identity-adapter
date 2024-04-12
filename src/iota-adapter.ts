import {
    IdentityAccount,
    IdentityAccountProps,
    CreateDidProps,
    DidCreationResult,
    NetworkAdapter,
    NetworkAdapterOptions,
    CreateCredentialProps,
    CredentialsManager,
    IVerificationResult,
    StorageSpec,
    IdentityConfig,
    bytesToString,
    stringToBytes,
    CreateBadgeProps,
} from "@tanglelabs/ssimon";
import { getPublicKeyAsync } from "@noble/ed25519";
import { nanoid } from "nanoid";

import { IotaJwkStore } from "./iota-store";
import {
    AliasOutput,
    Client,
    SecretManager,
    SeedSecretManager,
    Utils,
    Wallet,
} from "@iota/sdk-wasm/node";
import {
    IotaDID,
    IotaDocument,
    IotaIdentityClient,
    JwkMemStore,
    JwsAlgorithm,
    KeyIdMemStore,
    MethodScope,
    Storage,
} from "@iota/identity-wasm/node";
import { ensureAddressHasFunds } from "./utils";

export const clientConfig = {
    permanodes: [{ url: "https://chrysalis-chronicle.iota.org/api/mainnet/" }],
};

export class IotaAdapter<
    K extends StorageSpec<Record<string, any>, any>,
    T extends IotaAccount<K>
> implements NetworkAdapter
{
    store: StorageSpec<any, any>;

    private constructor() {}

    getMethodIdentifier(): string {
        return "iota";
    }

    public static async build(options: NetworkAdapterOptions) {
        const adapter = new IotaAdapter();
        adapter.store = options.driver;
        return adapter;
    }

    public async createDid<T extends StorageSpec<any, any>>(
        props: CreateDidProps<T>
    ): Promise<DidCreationResult> {
        const { store, seed, alias } = props;
        const generatedSeed = seed
            ? seed
            : Utils.mnemonicToHexSeed(Utils.generateMnemonic())
                  .split("0x")[1]
                  .substring(0, 64);
        const config = await this.store.findOne({ alias });
        const identity = await IotaAccount.build({
            seed: config.seed ?? seed ?? generatedSeed,
            isOld: !!seed,
            alias: props.alias,
            store: store,
            extras: {
                storage: this.store,
            },
        });
        return {
            identity,
            seed: generatedSeed,
        };
    }

    public async deserializeDid<
        T extends StorageSpec<Record<string, any>, any>
    >(config: IdentityConfig, store: T): Promise<DidCreationResult> {
        // const identity = await IotaAccount.build({
        //     seed: config.seed as string,
        //     isOld: true,
        //     alias: config.alias,
        //     store: store,
        //     extras: {
        //         storage: this.store,
        //     },
        // });
        //
        // return { identity, seed: config.seed as string };
        //

        throw new Error();
    }
}

export class IotaAccount<T extends StorageSpec<Record<string, any>, any>>
    implements IdentityAccount
{
    credentials: IotaCredentialsManager<T>;
    private secretManager: SecretManager;
    private walletAddr: string;
    private did: string;
    private document: IotaDocument;
    private tempDid: string;

    private constructor() {}

    async createPresentation(
        credentials: string[]
    ): Promise<Record<string, any>> {
        throw new Error("asdf");
        //     const key =
        //         parseBytesToString(this.keyPair.private()) +
        //         parseBytesToString(this.keyPair.public());
        //     const keyUint8Array = parseStringToBytes(key);

        //     const signer = didJWT.EdDSASigner(keyUint8Array);
        //     const vpIssuer: Issuer = {
        //         did: this.getDid(),
        //         signer,
        //         alg: "EdDSA",
        //     };

        //     const vpPayload: JwtPresentationPayload = {
        //         vp: {
        //             "@context": ["https://www.w3.org/2018/credentials/v1"],
        //             type: ["VerifiablePresentation"],
        //             verifiableCredential: credentials,
        //         },
        //     };

        //     const presentationJwt = await createVerifiablePresentationJwt(
        //         vpPayload,
        //         vpIssuer
        //     );

        //     return { vpPayload, presentationJwt };
    }

    public static async build<T extends StorageSpec<Record<string, any>, any>>(
        props: IdentityAccountProps<T> & { did?: string }
    ) {
        const { seed, isOld, store, extras, alias, did } = props;
        const { storage } = extras;

        const publicKey = bytesToString(
            await getPublicKeyAsync(stringToBytes(seed))
        );
        const hexSeed = "0x" + seed + publicKey;

        const API_ENDPOINT = "https://api.testnet.shimmer.network";
        const client = new Client({
            primaryNode: API_ENDPOINT,
            localPow: true,
        });
        const didClient = new IotaIdentityClient(client);

        // Get the Bech32 human-readable part (HRP) of the network.
        const networkHrp: string = await didClient.getNetworkHrp();

        const mnemonic = Utils.generateMnemonic();
        const seedSecretManager: SeedSecretManager = {
            hexSeed,
        };

        // Generate a random mnemonic for our wallet.
        const secretManager: SecretManager = new SecretManager(
            seedSecretManager
        );

        const walletAddressBech32 = (
            await secretManager.generateEd25519Addresses({
                accountIndex: 0,
                range: {
                    start: 0,
                    end: 1,
                },
                bech32Hrp: networkHrp,
            })
        )[0];

        const identity = new IotaAccount();
        identity.walletAddr = walletAddressBech32;
        identity.secretManager = secretManager;

        const iotaStorage: Storage = new Storage(
            // new JwkMemStore(),
            new IotaJwkStore(storage, alias),
            new KeyIdMemStore()
        );

        let document: IotaDocument;
        if (!isOld) {
            document = new IotaDocument(networkHrp);
            await document.generateMethod(
                iotaStorage,
                IotaJwkStore.ed25519KeyType(),
                JwsAlgorithm.EdDSA,
                "#key-1",
                MethodScope.VerificationMethod()
            );
            const address = Utils.parseBech32Address(walletAddressBech32);
            const aliasOutput: AliasOutput = await didClient.newDidOutput(
                address,
                document
            );

            await ensureAddressHasFunds(
                client,
                walletAddressBech32,
                aliasOutput.amount,
                seed
            );
            document = await didClient.publishDidOutput(
                seedSecretManager,
                aliasOutput
            );
        } else {
            document = await didClient.resolveDid(IotaDID.parse(did));
        }
        identity.document = document;

        return identity;

        // return new IotaAccount();

        // const key = KeyPair.tryFromPrivateKeyBytes(
        //     KeyType.Ed25519,
        //     stringToBytes(seed)
        // );
        // const account = new IotaAccount();
        // account.keyPair = key;
        // const clientConfig = {
        //     permanodes: [
        //         { url: "https://chrysalis-chronicle.iota.org/api/mainnet/" },
        //     ],
        // };
        // const credentials = await IotaCredentialsManager.build(store, account);
        // account.credentials = credentials;
        // account.builder = new AccountBuilder({
        //     autopublish: false,
        //     clientConfig: clientConfig,
        //     storage: new IotaStorage(storage),
        // });
        // const did = await account.builder.createIdentity({
        //     privateKey: key.private(),
        // });
        // // if seed does not exist it means the did was newly created :P
        // if (!isOld) {
        //     await storage.findOneAndUpdate(
        //         { alias },
        //         { did: did.did().toString() }
        //     );
        //     await did.createMethod({
        //         scope: MethodScope.VerificationMethod(),
        //         content: MethodContent.PrivateEd25519(key.private()),
        //         fragment: "#vc-signature",
        //     });
        //     const revocationBitmap = new RevocationBitmap();
        //     await did.createService({
        //         fragment: "#vc-bitmap",
        //         type: RevocationBitmap.type(),
        //         endpoint: revocationBitmap.toEndpoint(),
        //     });
        //     await did.publish();
        // } else {
        //     await did.fetchDocument();
        // }
        // account.account = did;
        // return account;
    }

    public getDid(): string {
        return this.document ? this.document.id().toString() : this.tempDid;
    }
    public getDocument(): Record<string, any> {
        throw new Error("asdf");
        // return this.account.document().toJSON();
    }
}

export class IotaCredentialsManager<
    T extends StorageSpec<Record<string, any>, any>
> implements CredentialsManager<T>
{
    createBadge(options: CreateBadgeProps): Promise<Record<string, any>> {
        throw new Error("Method not implemented.");
    }
    store: T;
    account: IotaAccount<T>;

    public static async build<T extends StorageSpec<Record<string, any>, any>>(
        store: T,
        account: IotaAccount<T>
    ) {
        // const credentialsManager = new IotaCredentialsManager();
        // credentialsManager.store = store;
        // credentialsManager.account = account;
        // return credentialsManager;
    }

    public isCredentialValid(cred: Record<string, unknown>): Promise<boolean> {
        // return isCredentialValid(cred);
        // return true;
        throw new Error();
    }
    public verify(cred: Record<string, unknown>): Promise<IVerificationResult> {
        // return verifyCredential(cred);
        throw new Error();
    }
    public async create(
        props: CreateCredentialProps
    ): Promise<Record<string, any>> {
        throw new Error("asfd");
        // const { id, recipientDid, body, type } = props;

        // const key =
        //     parseBytesToString(this.account.keyPair.private()) +
        //     parseBytesToString(this.account.keyPair.public());
        // const keyUint8Array = parseStringToBytes(key);

        // const signer = didJWT.EdDSASigner(keyUint8Array);
        // const vcIssuer: Issuer = {
        //     did: this.account.getDid(),
        //     signer,
        //     alg: "EdDSA",
        // };
        // const types = Array.isArray(type) ? [...type] : [type];

        // const credential: JwtCredentialPayload = {
        //     sub: recipientDid,
        //     nbf: Math.floor(Date.now() / 1000),
        //     id,
        //     vc: {
        //         "@context": ["https://www.w3.org/2018/credentials/v1"],
        //         type: ["VerifiableCredential", ...types],
        //         id,
        //         credentialSubject: {
        //             ...body,
        //         },
        //     },
        // };
        // const jwt = await createVerifiableCredentialJwt(credential, vcIssuer);

        // return { cred: jwt };
    }
}
