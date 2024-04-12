import { nanoid } from "nanoid";

export class InsufficientBalanceError extends Error {
    address: string;
    message: string;
    amount: number;
    seed: string;
    did: string;

    constructor(address: string, amount: number, seed: string) {
        super("InsufficientFundsError");
        this.name = "InsufficientFundsError";
        this.address = address;
        this.message = "Add more funds to the address";
        this.amount = amount;
        this.seed = seed;
        this.did = "did:iota:" + "TEMP" + nanoid();
    }
}
