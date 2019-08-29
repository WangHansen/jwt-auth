import * as utils from "../src/utils";

const { publicCert, privateCert } = utils.generateCertPair();
const {
  publicCert: publicCert1,
  privateCert: privateCert1
} = utils.generateCertPair();

test("generateRandomPassphrase should generate a key of length 13", () => {
  const rand1 = utils.generateRandomPassphrase();
  const rand2 = utils.generateRandomPassphrase();
  expect(rand1).toMatch(/[a-z0-9]{13}/);
  expect(rand2).toMatch(/[a-z0-9]{13}/);
  expect(rand1).not.toEqual(rand2);
});

test("generateCertPair should generate set of public private keys", () => {
  const { key, passphrase } = privateCert as any;
  // expect(utils.generateRandomPassphrase).toHaveBeenCalled();
  expect(publicCert.indexOf("-----BEGIN PUBLIC KEY-----")).toBe(0);
  expect(key.indexOf("-----BEGIN ENCRYPTED PRIVATE KEY-----")).toBe(0);
  // expect(passphrase).toBe("113076fa00259");
  expect(passphrase).toMatch(/[a-z0-9]{13}/);
});

test("verifyPubPrivCertPair should fail for two not related keys and pass for pair of tests", () => {
  expect(utils.verifyPubPrivCertPair(privateCert, publicCert1)).toBe(false);
  expect(utils.verifyPubPrivCertPair(privateCert1, publicCert)).toBe(false);
  expect(utils.verifyPubPrivCertPair(privateCert, publicCert)).toBe(true);
  expect(utils.verifyPubPrivCertPair(privateCert1, publicCert1)).toBe(true);
});
