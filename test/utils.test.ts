import * as utils from "../src/utils";

const { publicKey, privateKey } = utils.generateKeyPair();
const {
  publicKey: publicKey1,
  privateKey: privateKey1
} = utils.generateKeyPair();

test("generateRandomPassphrase should generate a key of length 13", () => {
  const rand1 = utils.generateRandomPassphrase();
  const rand2 = utils.generateRandomPassphrase();
  expect(rand1).toMatch(/[a-z0-9]{12,13}/);
  expect(rand2).toMatch(/[a-z0-9]{12,13}/);
  expect(rand1).not.toEqual(rand2);
});

test("generateKeyPair should generate set of public private keys", () => {
  jest.spyOn(utils, "generateRandomPassphrase");
  const { publicKey, privateKey } = utils.generateKeyPair();
  const { key, passphrase } = privateKey as any;
  expect(utils.generateRandomPassphrase).toHaveBeenCalled();
  expect(publicKey.indexOf("-----BEGIN PUBLIC KEY-----")).toBe(0);
  expect(key.indexOf("-----BEGIN ENCRYPTED PRIVATE KEY-----")).toBe(0);
  expect(passphrase).toMatch(/[a-z0-9]{12,13}/);
});

test("verifyPubPrivKeyPair should fail for two not related keys and pass for pair of tests", () => {
  expect(utils.verifyPubPrivKeyPair(privateKey, publicKey1)).toBe(false);
  expect(utils.verifyPubPrivKeyPair(privateKey1, publicKey)).toBe(false);
  expect(utils.verifyPubPrivKeyPair(privateKey, publicKey)).toBe(true);
  expect(utils.verifyPubPrivKeyPair(privateKey1, publicKey1)).toBe(true);
});

test("generateRandomKeyId should return a number between 1 and 99", () => {
  for (let i = 0; i < 4; i++) {
    const number = parseInt(utils.generateRandomKeyId());
    expect(number).toBeLessThanOrEqual(99);
  }
});
