import * as ed from "@noble/ed25519";
import Module from "node:module";
const require = Module.createRequire(import.meta.url);
const {
    decodeB64,
    encodeB64,
    Jwk,
    JwkGenOutput,
    JwkStorage,
    EdCurve,
    JwkType,
    JwsAlgorithm,
    KeyIdStorage,
    MethodDigest,
} = require("@iota/identity-wasm/node");
import { StorageSpec } from "@tanglelabs/ssimon";
import { nanoid } from "nanoid";

type Ed25519PrivateKey = Uint8Array;
type Ed25519PublicKey = Uint8Array;

function sleep(ms: number) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
export class IotaJwkStore implements JwkStorage {
    /** The map from key identifiers to Jwks. */
    private _keys: Map<string, Jwk>;

    private constructor(
        private _storage: StorageSpec<any, any>,
        private _alias: string
    ) {}

    public static async build(storage: StorageSpec<any, any>, alias: string) {
        const jwkStore = new IotaJwkStore(storage, alias);
        const keyMapExists = await jwkStore._storage.findOne({
            alias: jwkStore._alias,
        });
        if (
            !keyMapExists ||
            !(keyMapExists.extras && keyMapExists.extras.keysMap)
        ) {
            jwkStore._keys = new Map();
        } else {
            jwkStore._keys = jwkStore.deserializeKeyMap(
                keyMapExists.extras.keysMap
            );
        }
        return jwkStore;
    }

    public static ed25519KeyType(): string {
        return "Ed25519";
    }

    public async generate(
        keyType: string,
        algorithm: JwsAlgorithm
    ): Promise<JwkGenOutput> {
        if (keyType !== IotaJwkStore.ed25519KeyType()) {
            throw new Error(`unsupported key type ${keyType}`);
        }

        if (algorithm !== JwsAlgorithm.EdDSA) {
            throw new Error(`unsupported algorithm`);
        }

        const keyId = randomKeyId();
        const privKey: Ed25519PrivateKey = ed.utils.randomPrivateKey();

        const jwk = await encodeJwk(privKey, algorithm);

        this._keys.set(keyId, jwk);

        const publicJWK = jwk.toPublic();
        if (!publicJWK) {
            throw new Error(`JWK is not a public key`);
        }

        await this.flushChanges();

        return new JwkGenOutput(keyId, publicJWK);
    }

    public async sign(
        keyId: string,
        data: Uint8Array,
        publicKey: Jwk
    ): Promise<Uint8Array> {
        if (publicKey.alg() !== JwsAlgorithm.EdDSA) {
            throw new Error("unsupported JWS algorithm");
        } else {
            if (publicKey.paramsOkp()?.crv !== (EdCurve.Ed25519 as string)) {
                throw new Error("unsupported Okp parameter");
            }
        }

        const jwk = this._keys.get(keyId);

        if (jwk) {
            const [privateKey, _] = decodeJwk(jwk);
            const signature = await ed.signAsync(data, privateKey);
            return signature;
        } else {
            throw new Error(`key with id ${keyId} not found`);
        }
    }

    public async insert(jwk: Jwk): Promise<string> {
        const keyId = randomKeyId();

        if (!jwk.isPrivate) {
            throw new Error(
                "expected a JWK with all private key components set"
            );
        }

        if (!jwk.alg()) {
            throw new Error("expected a Jwk with an `alg` parameter");
        }

        this._keys.set(keyId, jwk);
        await this.flushChanges();

        return keyId;
    }

    public async delete(keyId: string): Promise<void> {
        this._keys.delete(keyId);
        await this.flushChanges();
    }

    public async exists(keyId: string): Promise<boolean> {
        return this._keys.has(keyId);
    }

    public count(): number {
        return this._keys.size;
    }

    private serializeKeyMap() {
        const serializedArray = Array.from(this._keys.entries()).map((e) => [
            e[0],
            JSON.stringify(e[1].toJSON()),
        ]);
        return JSON.stringify(serializedArray);
    }

    private deserializeKeyMap(serialized: string) {
        const serializedArray = JSON.parse(serialized);
        const deserialized = serializedArray.map((e: any) => [
            e[0],
            Jwk.fromJSON(JSON.parse(e[1])),
        ]);

        return new Map(deserialized as any) as Map<string, Jwk>;
    }

    private async flushChanges() {
        const { extras } = await this._storage.findOne({ alias: this._alias });
        await this._storage.findOneAndUpdate(
            { alias: this._alias },
            { extras: { ...extras, keysMap: this.serializeKeyMap() } }
        );
    }
}

// Encodes a Ed25519 keypair into a Jwk.
async function encodeJwk(
    privateKey: Ed25519PrivateKey,
    alg: JwsAlgorithm
): Promise<Jwk> {
    const publicKey = await ed.getPublicKeyAsync(privateKey);
    let x = encodeB64(publicKey);
    let d = encodeB64(privateKey);

    return new Jwk({
        kty: JwkType.Okp,
        crv: "Ed25519",
        d,
        x,
        alg,
    });
}

function decodeJwk(jwk: Jwk): [Ed25519PrivateKey, Ed25519PublicKey] {
    if (jwk.alg() !== JwsAlgorithm.EdDSA) {
        throw new Error("unsupported `alg`");
    }

    const paramsOkp = jwk.paramsOkp();
    if (paramsOkp) {
        const d = paramsOkp.d;

        if (d) {
            let textEncoder = new TextEncoder();
            const privateKey = decodeB64(textEncoder.encode(d));
            const publicKey = decodeB64(textEncoder.encode(paramsOkp.x));
            return [privateKey, publicKey];
        } else {
            throw new Error("missing private key component");
        }
    } else {
        throw new Error("expected Okp params");
    }
}

function randomKeyId(): string {
    return nanoid();
}

export class IotaKidStore implements KeyIdStorage {
    private _keyIds: Map<string, string>;
    private _built: boolean = false;

    private constructor(
        private _storage: StorageSpec<any, any>,
        private _alias: string
    ) {}

    private serializeMap() {
        return JSON.stringify(Array.from(this._keyIds.entries()));
    }

    private deserializeMap(serialized: string) {
        return new Map(JSON.parse(serialized));
    }

    public static async build(storage: StorageSpec<any, any>, alias: string) {
        const kidStore = new IotaKidStore(storage, alias);

        const kidsMapExists = await kidStore._storage.findOne({
            alias: kidStore._alias,
        });
        if (!kidsMapExists || !kidsMapExists.extras?.kidsMap) {
            kidStore._keyIds = new Map();
        } else {
            kidStore._keyIds = kidStore.deserializeMap(
                kidsMapExists.extras.kidsMap
            ) as Map<string, string>;
        }
        return kidStore;
    }

    public async insertKeyId(
        methodDigest: MethodDigest,
        keyId: string
    ): Promise<void> {
        let methodDigestAsString: string = methodDigestToString(methodDigest);
        let value = this._keyIds.get(methodDigestAsString);
        if (value !== undefined) {
            throw new Error("KeyId already exists");
        }
        this._keyIds.set(methodDigestAsString, keyId);
        await this.flushChanges();
    }

    public async getKeyId(methodDigest: MethodDigest): Promise<string> {
        let methodDigestAsString: string = methodDigestToString(methodDigest);
        let value = this._keyIds.get(methodDigestAsString);
        if (value == undefined) {
            throw new Error("KeyId not found");
        }
        return value;
    }

    public async deleteKeyId(methodDigest: MethodDigest): Promise<void> {
        let methodDigestAsString: string = methodDigestToString(methodDigest);
        let success = this._keyIds.delete(methodDigestAsString);
        await this.flushChanges();
        if (success) {
            return;
        } else {
            throw new Error("KeyId not found!");
        }
    }

    public count(): number {
        return this._keyIds.size;
    }

    private async flushChanges() {
        const { extras } = await this._storage.findOne({ alias: this._alias });
        await this._storage.findOneAndUpdate(
            { alias: this._alias },
            { extras: { ...extras, kidsMap: this.serializeMap() } }
        );
    }
}

/**
 * Converts a `MethodDigest` to a base64 encoded string.
 */
function methodDigestToString(methodDigest: MethodDigest): string {
    let arrayBuffer = methodDigest.pack().buffer;
    let buffer = Buffer.from(arrayBuffer);
    return buffer.toString("base64");
}
