import * as ed from "@noble/ed25519";
import {
    decodeB64,
    encodeB64,
    Jwk,
    JwkGenOutput,
    JwkStorage,
    EdCurve,
    JwkType,
    JwsAlgorithm,
} from "@iota/identity-wasm/node";
import { StorageSpec } from "@tanglelabs/ssimon";

type Ed25519PrivateKey = Uint8Array;
type Ed25519PublicKey = Uint8Array;

export class IotaJwkStore implements JwkStorage {
    /** The map from key identifiers to Jwks. */
    private _keys: Map<string, Jwk>;
    private _built: boolean = false;

    /** Creates a new, empty `MemStore` instance. */
    constructor(
        private _storage: StorageSpec<any, any>,
        private _alias: string
    ) {
        this.build();
    }

    private async build() {
        const keyMapExists = await this._storage.findOne({
            alias: this._alias,
        });
        console.log("Map Exists", keyMapExists);
        if (
            !keyMapExists ||
            !(keyMapExists.extras && keyMapExists.extras.keysMap)
        ) {
            this._keys = new Map();
        } else {
            this._keys = this.deserializeKeyMap(keyMapExists.extras.keysMap);
        }
        this._built = true;
    }

    sleep(ms: number) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }

    public static ed25519KeyType(): string {
        return "Ed25519";
    }

    public async generate(
        keyType: string,
        algorithm: JwsAlgorithm
    ): Promise<JwkGenOutput> {
        console.log(this._built);
        if (!this._built) {
            await this.sleep(1000);
            return this.generate(keyType, algorithm);
        }

        if (keyType !== IotaJwkStore.ed25519KeyType()) {
            throw new Error(`unsupported key type ${keyType}`);
        }

        if (algorithm !== JwsAlgorithm.EdDSA) {
            throw new Error(`unsupported algorithm`);
        }

        const keyId = randomKeyId();
        const privKey: Ed25519PrivateKey = ed.utils.randomPrivateKey();

        console.log("failing after this");

        const jwk = await encodeJwk(privKey, algorithm);

        console.log("failing before this");

        this._keys.set(keyId, jwk);

        console.log("what?", this._keys);

        const publicJWK = jwk.toPublic();
        if (!publicJWK) {
            throw new Error(`JWK is not a public key`);
        }

        console.log("here?");

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
            return ed.sign(data, privateKey);
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
        await this._storage.findOneAndUpdate(
            { alias: this._alias },
            { extras: { keysMap: this.serializeKeyMap() } }
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

// Returns a random number between `min` and `max` (inclusive).
// SAFETY NOTE: This is not cryptographically secure randomness and thus not suitable for production use.
// It suffices for our testing implementation however and avoids an external dependency.
function getRandomNumber(min: number, max: number): number {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Returns a random key id.
function randomKeyId(): string {
    const randomness = new Uint8Array(20);
    for (let index = 0; index < randomness.length; index++) {
        randomness[index] = getRandomNumber(0, 255);
    }

    return encodeB64(randomness);
}
