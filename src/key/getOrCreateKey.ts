import { DlcOracle } from 'dlc-oracle-nodejs';
import * as fs from 'fs';
import * as assert from 'assert';
import * as path from 'path';

(async () => {
        let privateKey: Buffer;
        const keyFile: string = path.join(__dirname, "testdata", "privkey.hex");
        privateKey = Buffer.from(fs.readFileSync(keyFile).toString().trim(), 'hex');
        const pubKey: Buffer = DlcOracle.publicKeyFromPrivateKey(privateKey);
        const otsKeysHex: string[] = fs.readFileSync(path.join(__dirname, "testdata", "one-time-signing-keys.hex")).toString().split('\n');
        const messagesHex: string[] = fs.readFileSync(path.join(__dirname, "testdata", "messages.hex")).toString().split('\n');
        const sigsHex: string[] = fs.readFileSync(path.join(__dirname, "testdata", "signatures.hex")).toString().split('\n');
        const sGsFromSigHex: string[] = fs.readFileSync(path.join(__dirname, "testdata", "signature-pubkeys-from-sig.hex")).toString().split('\n');
        const sGsFromMsgHex: string[] = fs.readFileSync(path.join(__dirname, "testdata", "signature-pubkeys-from-message.hex")).toString().split('\n');

        for (let i = 0; i < otsKeysHex.length; i++) {
            if (otsKeysHex[i] === '') break;
            const oneTimeKey: Buffer = Buffer.from(otsKeysHex[i], 'hex');
            const oneTimePubKey: Buffer = DlcOracle.publicKeyFromPrivateKey(oneTimeKey);

            const message: Buffer = Buffer.from(messagesHex[i], 'hex');
            const expectedSig: Buffer = Buffer.from(sigsHex[i], 'hex');
            const expectedsG1: Buffer = Buffer.from(sGsFromSigHex[i], 'hex');
            const expectedsG2: Buffer = Buffer.from(sGsFromMsgHex[i], 'hex');

            assert(Buffer.compare(expectedsG1, expectedsG2) == 0, "sGs are not equal. This is an issue in the Go code that generated the testset.");

            const calculatedSig: Buffer = DlcOracle.computeSignature(privateKey, oneTimeKey, message);

            assert(Buffer.compare(calculatedSig, expectedSig) == 0, "Signature mismatch");

            const calculatedsG1: Buffer = DlcOracle.publicKeyFromPrivateKey(calculatedSig);

            assert(Buffer.compare(calculatedsG1, expectedsG1) == 0, "sG from signature incorrect");

            const calculatedsG2: Buffer = DlcOracle.computeSignaturePubKey(pubKey, oneTimePubKey, message);

            assert(Buffer.compare(calculatedsG2, expectedsG2) == 0, "sG from message");

            if (i % 100 == 0) {
                console.log("Testing signatures: ", i);
            }
        }
})();
