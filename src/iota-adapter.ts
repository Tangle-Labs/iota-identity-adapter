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

import { IotaJwkStore, IotaKidStore } from "./iota-store";
import {
    AliasOutput,
    Client,
    SecretManager,
    SeedSecretManager,
    Utils,
} from "@iota/sdk-wasm/node";
import {
    IotaDID,
    IotaDocument,
    IotaIdentityClient,
    Credential,
    JwsAlgorithm,
    KeyIdMemStore,
    MethodScope,
    Storage,
    JwsSignatureOptions,
    Timestamp,
    JwtCredentialValidator,
    EdDSAJwsVerifier,
    DecodedJwtCredential,
    Jwt,
    Resolver,
    JwtCredentialValidationOptions,
    FailFast,
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
        const identity = await IotaAccount.build({
            seed: config.seed as string,
            isOld: true,
            alias: config.alias,
            store: store,
            did: config.did,
            extras: {
                storage: this.store,
            },
        });

        return { identity, seed: config.seed as string };
    }
}

export class IotaAccount<T extends StorageSpec<Record<string, any>, any>>
    implements IdentityAccount
{
    credentials: IotaCredentialsManager<T>;
    document: IotaDocument;
    didClient: IotaIdentityClient;
    private secretManager: SecretManager;
    private walletAddr: string;
    private did: string;
    private tempDid: string;
    private storage: Storage;

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

    public getStorage() {
        return this.storage;
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
        identity.didClient = didClient;

        const jwkStore = await IotaJwkStore.build(storage, alias);
        const kidStore = await IotaKidStore.build(storage, alias);

        const iotaStorage: Storage = new Storage(jwkStore, kidStore);

        identity.storage = iotaStorage;

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
        const credentialsManager = await IotaCredentialsManager.build(
            store,
            identity
        );
        identity.credentials = credentialsManager;

        return identity;
    }

    public getDid(): string {
        return this.document ? this.document.id().toString() : this.tempDid;
    }
    public getDocument(): Record<string, any> {
        return this.document.toJSON();
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
        const credentialsManager = new IotaCredentialsManager();
        credentialsManager.store = store;
        credentialsManager.account = account;
        return credentialsManager;
    }

    public async isCredentialValid(
        cred: Record<string, unknown>
    ): Promise<boolean> {
        // return isCredentialValid(cred);
        // j
        // return true;
        //
        const issuer = JwtCredentialValidator.extractIssuerFromJwt(
            new Jwt(cred.cred as string)
        );

        const issuerDocument = await this.account.didClient.resolveDid(
            IotaDID.parse(issuer.toString())
        );
        const decoded_credential = new JwtCredentialValidator(
            new EdDSAJwsVerifier()
        ).validate(
            new Jwt(cred.cred as string),
            issuerDocument,
            new JwtCredentialValidationOptions(),
            FailFast.FirstError
        );

        return true;
    }
    public async verify(
        cred: Record<string, unknown>
    ): Promise<IVerificationResult> {
        return { vc: await this.isCredentialValid(cred), dvid: true };
    }
    public async create(
        props: CreateCredentialProps
    ): Promise<Record<string, any>> {
        const { id, recipientDid, body, type, expiryDate, extras } = props;

        const subject = {
            id: recipientDid,
            ...body,
        };

        const expiryString = expiryDate
            ? new Date(expiryDate).toISOString()
            : "";
        // Create an unsigned `UniversityDegree` credential for Alice
        const unsignedVc = new Credential({
            id,
            type,
            issuer: this.account.getDid(),
            credentialSubject: subject,
            expirationDate: expiryString
                ? Timestamp.parse(expiryString)
                : undefined,
            ...extras,
        });

        // Create signed JWT credential.
        const credentialJwt = (
            await this.account.document.createCredentialJwt(
                this.account.getStorage(),
                "#key-1",
                unsignedVc,
                new JwsSignatureOptions()
            )
        ).toString();

        return { cred: credentialJwt };
    }
}
