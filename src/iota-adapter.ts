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
} from "@tanglelabs/ssimon";
import {
    KeyPair,
    KeyType,
    AccountBuilder,
    Account,
    MethodContent,
    RevocationBitmap,
    Credential,
    ProofOptions,
    Resolver,
    CredentialValidator,
    DID,
    CredentialValidationOptions,
    FailFast,
    MethodScope,
} from "@iota/identity-wasm/node";
import {
    JwtCredentialPayload,
    createVerifiableCredentialJwt,
    Issuer,
    JwtPresentationPayload,
    createVerifiablePresentationJwt,
} from "did-jwt-vc";
import * as didJWT from "did-jwt";

import { resolveTxt } from "dns";
import { IotaStorage } from "./iota-store";
import { promisify } from "util";

export const clientConfig = {
    permanodes: [{ url: "https://chrysalis-chronicle.iota.org/api/mainnet/" }],
};

export const parseBytesToString = (bytes: Uint8Array) => {
    return Buffer.from(bytes).toString("hex");
};

export const parseStringToBytes = (str: string) => {
    return Uint8Array.from(Buffer.from(str, "hex"));
};

const dnsResolveTxt = promisify(resolveTxt);

export class IotaAdapter<
    K extends StorageSpec<Record<string, any>, any>,
    T extends IotaAccount<K>
> implements NetworkAdapter
{
    store: StorageSpec<any, any>;

    private constructor() {}

    public static async build(options: NetworkAdapterOptions) {
        const adapter = new IotaAdapter();
        adapter.store = options.driver;
        return adapter;
    }

    public async createDid<T extends StorageSpec<any, any>>(
        props: CreateDidProps<T>
    ): Promise<DidCreationResult> {
        const { store, seed } = props;
        const key = seed
            ? KeyPair.tryFromPrivateKeyBytes(
                  KeyType.Ed25519,
                  stringToBytes(seed)
              )
            : new KeyPair(KeyType.Ed25519);

        const generatedSeed = bytesToString(key.private());

        const identity = await IotaAccount.build({
            seed: seed ?? generatedSeed,
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
    keyPair: KeyPair;
    account: Account;
    private builder: AccountBuilder;
    private constructor() {}

    async createPresentation(
        credentials: string[]
    ): Promise<Record<string, any>> {
        const key =
            parseBytesToString(this.keyPair.private()) +
            parseBytesToString(this.keyPair.public());
        const keyUint8Array = parseStringToBytes(key);

        const signer = didJWT.EdDSASigner(keyUint8Array);
        const vpIssuer: Issuer = {
            did: this.getDid(),
            signer,
            alg: "EdDSA",
        };

        const vpPayload: JwtPresentationPayload = {
            vp: {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                type: ["VerifiablePresentation"],
                verifiableCredential: credentials,
            },
        };

        const presentationJwt = await createVerifiablePresentationJwt(
            vpPayload,
            vpIssuer
        );

        return { vpPayload, presentationJwt };
    }

    public static async build<T extends StorageSpec<Record<string, any>, any>>(
        props: IdentityAccountProps<T>
    ) {
        const { seed, isOld, store, extras, alias } = props;
        const { storage } = extras;
        const key = KeyPair.tryFromPrivateKeyBytes(
            KeyType.Ed25519,
            stringToBytes(seed)
        );
        const account = new IotaAccount();
        account.keyPair = key;
        const clientConfig = {
            permanodes: [
                { url: "https://chrysalis-chronicle.iota.org/api/mainnet/" },
            ],
        };

        const credentials = await IotaCredentialsManager.build(store, account);

        account.credentials = credentials;

        account.builder = new AccountBuilder({
            autopublish: false,
            clientConfig: clientConfig,
            storage: new IotaStorage(storage),
        });

        const did = await account.builder.createIdentity({
            privateKey: key.private(),
        });

        // if seed does not exist it means the did was newly created :P
        if (!isOld) {
            await storage.findOneAndUpdate(
                { alias },
                { did: did.did().toString() }
            );
            await did.createMethod({
                scope: MethodScope.VerificationMethod(),
                content: MethodContent.PrivateEd25519(key.private()),
                fragment: "#vc-signature",
            });
            const revocationBitmap = new RevocationBitmap();
            await did.createService({
                fragment: "#vc-bitmap",
                type: RevocationBitmap.type(),
                endpoint: revocationBitmap.toEndpoint(),
            });

            await did.publish();
        } else {
            await did.fetchDocument();
        }

        account.account = did;
        return account;
    }

    public getDid(): string {
        return this.account.did().toString();
    }
    public getDocument(): Record<string, any> {
        return this.account.document().toJSON();
    }
}

export class IotaCredentialsManager<
    T extends StorageSpec<Record<string, any>, any>
> implements CredentialsManager<T>
{
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

    public isCredentialValid(cred: Record<string, unknown>): Promise<boolean> {
        return isCredentialValid(cred);
    }
    public verify(cred: Record<string, unknown>): Promise<IVerificationResult> {
        return verifyCredential(cred);
    }
    public async create(
        props: CreateCredentialProps
    ): Promise<Record<string, any>> {
        const { id, recipientDid, body, type } = props;

        const key =
            parseBytesToString(this.account.keyPair.private()) +
            parseBytesToString(this.account.keyPair.public());
        const keyUint8Array = parseStringToBytes(key);

        const signer = didJWT.EdDSASigner(keyUint8Array);
        const vcIssuer: Issuer = {
            did: this.account.getDid(),
            signer,
            alg: "EdDSA",
        };
        const types = Array.isArray(type) ? [...type] : [type];

        const credential: JwtCredentialPayload = {
            sub: recipientDid,
            nbf: Math.floor(Date.now() / 1000),
            id,
            vc: {
                "@context": ["https://www.w3.org/2018/credentials/v1"],
                type: ["VerifiableCredential", ...types],
                id,
                credentialSubject: {
                    ...body,
                },
            },
        };
        const jwt = await createVerifiableCredentialJwt(credential, vcIssuer);

        return { cred: jwt };
    }
    public async revoke(keyIndex: number): Promise<void> {
        await this.account.account.revokeCredentials("#vc-bitmap", keyIndex);
        await this.account.account.publish();
    }
}

/**
 * Validate a credential
 *
 * @param {Credential} signedVc - signed VC that needs to be validated
 * @param {ResolvedDocument} issuerIdentity - account it was signed with
 * @returns {Promise<boolean>}
 */

export async function isCredentialValid(
    cred: Record<string, unknown>
): Promise<boolean> {
    const resolver = await Resolver.builder()
        .clientConfig(clientConfig)
        .build();
    const signedVc = Credential.fromJSON(cred);
    const issuerIdentity = await resolver.resolve(
        DID.parse(signedVc.issuer().toString())
    );

    try {
        CredentialValidator.validate(
            signedVc,
            issuerIdentity,
            CredentialValidationOptions.default(),
            FailFast.AllErrors
        );
    } catch (error) {
        return false;
    }
    return true;
}

/**
 * DVID v0.2.0
 * Domain Verifiable Identity is a module that allows you to verify the source of
 * origin for a verifiable credential, here are the steps to validate with DVID v0.2.0
 *
 * - Parse the Document and look for the domain of origin
 * - Lookup TXT records for the domain of origin
 * - Resolve DID contained in DNS record and validate the credential
 *
 * @param {Credential} signedVc
 * @returns {{ vc: boolean, dvid: boolean}}
 */

export async function verifyCredential(
    cred: Record<string, unknown>
): Promise<{ vc: boolean; dvid: boolean }> {
    const signedVc = Credential.fromJSON(cred);
    const resolver = await Resolver.builder()
        .clientConfig(clientConfig)
        .build();
    const domain = signedVc
        .toJSON()
        .id.split(/(https|http):\/\//)[2]
        .split("/")[0];
    const txtRecords = await dnsResolveTxt(domain);
    const didRecord = txtRecords.find((record) =>
        record[0].includes("DVID.did=")
    );
    if (!didRecord) throw new Error("DVID Record not found");
    const didTag = didRecord[0].split("DVID.did=")[1];
    const resolvedDocument = await resolver.resolve(didTag);

    if (!resolvedDocument) {
        return {
            dvid: false,
            vc: await isCredentialValid(signedVc.toJSON()),
        };
    }

    const vcIntegrity = await isCredentialValid(signedVc.toJSON());
    return {
        dvid: true,
        vc: vcIntegrity,
    };
}
