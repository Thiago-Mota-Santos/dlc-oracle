import { DlcOracle } from 'dlc-oracle-nodejs';
import { randomBytes } from 'crypto';
import * as readline from 'readline';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'node:url';

(async () => {
    async function main(): Promise<void> {
        let privateKey: Buffer;
        const __filename = fileURLToPath(import.meta.url);
        const __dirname = path.dirname(__filename);
        const keyFilePath: string = path.join(__dirname, "privkey.hex");
        if (fs.existsSync(keyFilePath)) {
            privateKey = fs.readFileSync(keyFilePath);
        } else {
            privateKey = randomBytes(32);
            fs.writeFileSync(keyFilePath, privateKey);
        }

        const publicKey: Buffer = DlcOracle.publicKeyFromPrivateKey(privateKey);

        console.log("Oracle Public Key: ", publicKey.toString('hex'));

        await doSignLoop(privateKey, publicKey);
    }

    async function doSignLoop(privateKey: Buffer, publicKey: Buffer): Promise<void> {
        let privPoint: Buffer = DlcOracle.generateOneTimeSigningKey();
        let rPoint: Buffer = DlcOracle.publicKeyFromPrivateKey(privPoint);
        console.log("R-Point for next publication: ", rPoint.toString('hex'));

        const rl = readline.createInterface({
            input: process.stdin,
            output: process.stdout
        });

        rl.question('Enter number to publish (-1 to exit): ', async (answer: string) => {
            const i: number = parseInt(answer);
            rl.close();
            if (i !== -1) {
                const message: Buffer = DlcOracle.generateNumericMessage(i);
                const sig: Buffer = DlcOracle.computeSignature(privateKey, privPoint, message);
                console.log("Signature: ", sig.toString('hex'));

                const sgFromSig: Buffer = DlcOracle.publicKeyFromPrivateKey(sig);
                console.log("Compute sG from Signature:", sgFromSig.toString('hex'));

                const sgFromPubkeys: Buffer = DlcOracle.computeSignaturePubKey(publicKey, rPoint, message);
                console.log("Compute sG from pub keys and message:", sgFromPubkeys.toString('hex'));

                await doSignLoop(privateKey, publicKey);
            }
        });
    }

    await main();
})();
