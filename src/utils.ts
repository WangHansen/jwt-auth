import * as crypto from "crypto";
import { Secret } from "jsonwebtoken";
import { JWTKeyPair } from "./server";

export function generateRandomPassphrase(): string {
  return Math.random()
    .toString(16)
    .slice(2);
}

export function generateRandomKeyId(): string {
  return (Math.floor(Math.random() * 99) + 1).toString();
}

export function verifyPubPrivKeyPair(
  privateKey: Secret,
  publicKey: string
): boolean {
  const data = "test data to be encrypted";
  const signer = crypto.createSign("sha256");
  signer.update(data);
  const sign = signer.sign(privateKey, "hex");
  const verifier = crypto.createVerify("sha256");
  verifier.update(data);
  return verifier.verify(publicKey, sign, "hex");
}

export function generateKeyPair(): JWTKeyPair {
  const passphrase = this.generateRandomPassphrase();
  const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: "spki",
      format: "pem"
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase
    }
  });
  return {
    privateKey: {
      key: privateKey,
      passphrase
    },
    publicKey: publicKey
  };
}
