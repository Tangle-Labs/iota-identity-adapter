import {
    ChainState,
    DID,
    Document,
    Ed25519,
    KeyLocation,
    KeyPair,
    KeyType,
    Signature,
    Storage,
    EncryptionAlgorithm,
    CekAlgorithm,
    EncryptedData,
} from "@iota/identity-wasm/node";
import { StorageSpec, IdentityConfig } from "@tanglelabs/ssimon";

export class IotaStorage implements Storage {
    private _chainStates: Map<string, ChainState>;
    private _documents: Map<string, Document>;
    private _vaults: Map<string, Map<string, KeyPair>>;
    private _storage: StorageSpec<IdentityConfig, IdentityConfig>;

    constructor(storage: StorageSpec<any, any>) {
        this._storage = storage;
        this._chainStates = new Map();
        this._documents = new Map();

        this._vaults = new Map();
        this.setup();
    }

    async setup() {
        const configs = await this._storage.findMany({});
        for (const config of configs) {
            if (!config.document && !config.did) continue;
            const { vault, chainState } = config.extras;

            this._chainStates.set(
                config.did as string,
                ChainState.fromJSON(chainState)
            );
            this._documents.set(
                config.did as string,
                Document.fromJSON(config.document)
            );
            const keyMap: Map<string, KeyPair> = new Map(
                JSON.parse(vault).map((k: any) => [
                    k[0],
                    KeyPair.fromJSON(k[1]),
                ])
            );
            this._vaults.set(config.did as string, keyMap);
        }
    }

    public async didCreate(
        network: string,
        fragment: string,
        privateKey?: Uint8Array
    ): Promise<[DID, KeyLocation]> {
        // Extract a `KeyPair` from the passed private key or generate a new one.
        // For `did_create` we can assume the `KeyType` to be `Ed25519` because
        // that is the only currently available signature type.
        let keyPair;
        if (privateKey) {
            keyPair = KeyPair.tryFromPrivateKeyBytes(
                KeyType.Ed25519,
                privateKey
            );
        } else {
            keyPair = new KeyPair(KeyType.Ed25519);
        }

        // We create the location at which the key pair will be stored.
        // Most notably, this uses the public key as an input.
        const keyLocation: KeyLocation = new KeyLocation(
            KeyType.Ed25519,
            fragment,
            keyPair.public()
        );

        // Next we use the public key to derive the initial DID.
        const did: DID = new DID(keyPair.public(), network);

        // We use the vaults as the index of DIDs stored in this storage instance.
        // If the DID already exists, we need to return an error. We don't want to overwrite an existing DID.
        if (this._vaults.has(did.toString())) {
            throw new Error("identity already exists");
        }

        const vault = this._vaults.get(did.toString());

        // Get the existing vault and insert the key pair,
        // or insert a new vault with the key pair.
        if (vault) {
            vault.set(keyLocation.canonical(), keyPair);
        } else {
            const newVault = new Map([[keyLocation.canonical(), keyPair]]);
            this._vaults.set(did.toString(), newVault);
        }

        await this.flushChanges();
        return [did, keyLocation];
    }

    public async didPurge(did: DID): Promise<boolean> {
        // This method is supposed to be idempotent,
        // so we only need to do work if the DID still exists.
        // The return value signals whether the DID was actually removed during this operation.
        if (this._vaults.has(did.toString())) {
            this._chainStates.delete(did.toString());
            this._documents.delete(did.toString());
            this._vaults.delete(did.toString());
            await this.flushChanges();
            return true;
        }

        return false;
    }

    public async didExists(did: DID): Promise<boolean> {
        return this._vaults.has(did.toString());
    }

    public async didList(): Promise<Array<DID>> {
        // Get all keys from the vaults and parse them into DIDs.
        return Array.from(this._vaults.keys()).map((did) => DID.parse(did));
    }

    public async keyGenerate(
        did: DID,
        keyType: KeyType,
        fragment: string
    ): Promise<KeyLocation> {
        // Generate a new key pair with the given key type.
        const keyPair: KeyPair = new KeyPair(keyType);
        // Derive the key location from the fragment and public key and set the `KeyType` of the location.
        const keyLocation: KeyLocation = new KeyLocation(
            KeyType.Ed25519,
            fragment,
            keyPair.public()
        );

        const vault = this._vaults.get(did.toString());

        // Get the existing vault and insert the key pair,
        // or insert a new vault with the key pair.
        if (vault) {
            vault.set(keyLocation.canonical(), keyPair);
        } else {
            const newVault = new Map([[keyLocation.canonical(), keyPair]]);
            this._vaults.set(did.toString(), newVault);
        }

        await this.flushChanges();
        // Return the location at which the key was generated.
        return keyLocation;
    }

    public async keyInsert(
        did: DID,
        keyLocation: KeyLocation,
        privateKey: Uint8Array
    ): Promise<void> {
        // Reconstruct the key pair from the given private key with the location's key type.
        const keyPair: KeyPair = KeyPair.tryFromPrivateKeyBytes(
            keyLocation.keyType(),
            privateKey
        );

        // Get the vault for the given DID.
        const vault = this._vaults.get(did.toString());

        // Get the existing vault and insert the key pair,
        // or insert a new vault with the key pair.
        if (vault) {
            vault.set(keyLocation.canonical(), keyPair);
        } else {
            const newVault = new Map([[keyLocation.canonical(), keyPair]]);
            this._vaults.set(did.toString(), newVault);
        }

        await this.flushChanges();
    }

    public async keyExists(
        did: DID,
        keyLocation: KeyLocation
    ): Promise<boolean> {
        // Get the vault for the given DID.
        const vault = this._vaults.get(did.toString());

        // Within the DID vault, check for existence of the given location.
        if (vault) {
            return vault.has(keyLocation.canonical());
        } else {
            return false;
        }
    }

    public async keyPublic(
        did: DID,
        keyLocation: KeyLocation
    ): Promise<Uint8Array> {
        // Get the vault for the given DID.
        const vault = this._vaults.get(did.toString());

        // Return the public key or an error if the vault or key does not exist.
        if (vault) {
            const keyPair: KeyPair | undefined = KeyPair.fromJSON(
                vault.get(keyLocation.canonical())
            );
            if (keyPair) {
                const pubKey = keyPair.public();

                return pubKey as unknown as Uint8Array;
            } else {
                throw new Error("Key location not found");
            }
        } else {
            throw new Error("DID not found");
        }
    }

    public async keyDelete(
        did: DID,
        keyLocation: KeyLocation
    ): Promise<boolean> {
        // Get the vault for the given DID.
        const vault = this._vaults.get(did.toString());

        // This method is supposed to be idempotent, so we delete the key
        // if it exists and return whether it was actually deleted during this operation.
        if (vault) {
            await this.flushChanges();
            vault.delete(keyLocation.canonical());
            return true;
        } else {
            return false;
        }
    }

    public async keySign(
        did: DID,
        keyLocation: KeyLocation,
        data: Uint8Array
    ): Promise<Signature> {
        this.flushChanges();
        if (keyLocation.keyType() !== KeyType.Ed25519) {
            throw new Error("Unsupported Method");
        }

        // Get the vault for the given DID.
        const vault = this._vaults.get(did.toString());

        if (vault) {
            const keyPair: KeyPair | undefined = vault.get(
                keyLocation.canonical()
            );

            if (keyPair) {
                // Use the `Ed25519` API to sign the given data with the private key.
                const signature: Uint8Array = Ed25519.sign(
                    data,
                    keyPair.private()
                );
                // Construct a new `Signature` wrapper with the returned signature bytes.
                return new Signature(signature);
            } else {
                throw new Error("Key location not found");
            }
        } else {
            throw new Error("DID not found");
        }
    }

    public async dataEncrypt(
        did: DID,
        plaintext: Uint8Array,
        associatedData: Uint8Array,
        encryptionAlgorithm: EncryptionAlgorithm,
        cekAlgorithm: CekAlgorithm,
        publicKey: Uint8Array
    ): Promise<EncryptedData> {
        throw new Error("not yet implemented");
    }

    public async dataDecrypt(
        did: DID,
        data: EncryptedData,
        encryptionAlgorithm: EncryptionAlgorithm,
        cekAlgorithm: CekAlgorithm,
        privateKey: KeyLocation
    ): Promise<Uint8Array> {
        throw new Error("not yet implemented");
    }

    public async chainStateGet(did: DID): Promise<ChainState | undefined> {
        // Lookup the chain state of the given DID.
        return this._chainStates.get(did.toString());
    }

    public async chainStateSet(
        did: DID,
        chainState: ChainState
    ): Promise<void> {
        // Set the chain state of the given DID.
        this._chainStates.set(did.toString(), chainState);
        await this.flushChanges();
    }

    public async documentGet(did: DID): Promise<Document | undefined> {
        // Lookup the DID document of the given DID.
        return this._documents.get(did.toString());
    }

    public async documentSet(did: DID, document: Document): Promise<void> {
        // Set the DID document of the given DID.
        this._documents.set(did.toString(), document);
        await this.flushChanges();
    }

    public async flushChanges(): Promise<void> {
        const didConfigs = await this._storage.findMany({});
        for (const didConfig of didConfigs) {
            if (!didConfig.did) continue;
            const extras = {
                vault: JSON.stringify(
                    // @ts-ignore
                    Array.from(this._vaults.get(didConfig.did).entries())
                ),

                // @ts-ignore
                chainState: this._chainStates.get(didConfig.did).toJSON(),
            };

            // @ts-ignore
            const document = this._documents.get(didConfig.did).toJSON();
            await this._storage.findOneAndUpdate(
                { did: didConfig.did },
                { extras, document }
            );
        }
    }
}
