import JWTAuth, { JwtAuthOptions } from "../src";
import FileStorage from "../src/storage";
import { JWKS } from "jose";
import { CronJob } from "cron";
import { JWTRevoked } from "../src/error";
jest.mock("../src/storage");
jest.mock("cron");

describe("JWTAuth Tests: ", () => {
  let storageMock: FileStorage;

  beforeAll(() => {
    storageMock = new FileStorage();
  });

  describe("Constructor tests: ", () => {
    test("should be able to create instance without options", () => {
      const auth = new JWTAuth() as any;
      expect(auth).toBeInstanceOf(JWTAuth);
      expect(auth.keystore).toBeInstanceOf(JWKS.KeyStore);
      expect(auth.keystore.size).toBe(3);
      expect(auth.cronJob).toBeInstanceOf(CronJob);
    });
  });

  describe("configCheck tests:", () => {
    test("should correct options to have minimum 3 keys", () => {
      const opt = { amount: 1 };
      const auth = new JWTAuth(opt);
      const config = (auth as any).config;
      expect(config.amount).toBe(3);
    });

    test("should merge options with default values", () => {
      const opts: JwtAuthOptions = {
        algorithm: "RSA",
        crvOrSize: 2048,
        amount: 4,
        signSkip: 2,
        interval: "* */6 * * * *",
        tokenAge: "15m",
      };
      const auth = new JWTAuth(opts);
      const config = (auth as any).config;
      expect(config.algorithm).toBe(opts.algorithm);
      expect(config.crvOrSize).toBe(opts.crvOrSize);
      expect(config.amount).toBe(opts.amount);
      expect(config.signSkip).toBe(opts.signSkip);
      expect(config.interval).toBe(opts.interval);
      expect(config.tokenAge).toBe(opts.tokenAge);
    });

    test("should throw exception if keys skipped is greater than amount of keys in total", () => {
      expect(() => {
        new JWTAuth({ amount: 3, signSkip: 3 });
      }).toThrow();
      expect(() => {
        new JWTAuth({ amount: 5, signSkip: 5 });
      }).toThrow();
      expect(() => {
        new JWTAuth({ amount: 4, signSkip: 1 });
      }).not.toThrow();
      expect(() => {
        new JWTAuth({ signSkip: 2 });
      }).not.toThrow();
    });
  });

  describe("setStorage test ", () => {
    test("should load from storage and then fill the keystore", async () => {
      const auth: any = new JWTAuth();
      const spyLoad = jest
        .spyOn(auth, "loadFromStorage")
        .mockImplementation(() => Promise.resolve());
      const spyFill = jest
        .spyOn(auth, "fillKeystore")
        .mockImplementation(() => Promise.resolve());
      await auth.setStorage(storageMock);
      expect(spyLoad).toBeCalled();
      expect(spyFill).toBeCalled();
      expect(auth.cronJob).toBeInstanceOf(CronJob);
    });
  });

  describe("private methods tests: ", () => {
    test("fillKeystore should fill the keystore with keys", async () => {
      const auth = new JWTAuth() as any;
      const spy = jest.spyOn(auth, "updateKeyIds");
      auth.fillKeystore();
      expect(auth.keystore.size).toBe(3);
      expect(spy).toBeCalled();
    });
    test("fillKeystore should fill the keystore with keys", async () => {
      const auth = new JWTAuth() as any;
      await auth.setStorage(storageMock);
      const spy = jest.spyOn(auth, "updateKeyIds");
      auth.fillKeystore();
      expect(auth.keystore.size).toBe(3);
      expect(spy).toBeCalled();
    });
    test("generateJTI should generate a unique string", () => {
      const auth = new JWTAuth() as any;
      const callTimes = 10;
      const set = new Set();
      const spy = jest.spyOn(auth, "generateJTI");
      for (let i = 0; i < callTimes; i++) {
        const jti = auth.generateJTI();
        expect(set.has(jti)).toBe(false);
        set.add(jti);
      }
      expect(spy).toBeCalledTimes(callTimes);
    });

    test("loadFromStorage should load keys, clients and revoclist", async () => {
      const auth = new JWTAuth() as any;
      await auth.setStorage(storageMock);
      const spyk = jest
        .spyOn(auth, "loadKeys")
        .mockImplementationOnce(() => Promise.resolve());
      const spyl = jest
        .spyOn(auth, "loadRevocList")
        .mockImplementationOnce(() => Promise.resolve());
      await auth.loadFromStorage();
      expect(spyk).toBeCalled();
      expect(spyl).toBeCalled();
    });

    test("loadFromStorage should return if no storage is set", async () => {
      const auth = new JWTAuth() as any;
      const spyk = jest
        .spyOn(auth, "loadKeys")
        .mockImplementationOnce(() => Promise.resolve());
      const spyl = jest
        .spyOn(auth, "loadRevocList")
        .mockImplementationOnce(() => Promise.resolve());
      await auth.loadFromStorage();
      expect(spyk).not.toBeCalled();
      expect(spyl).not.toBeCalled();
    });

    test("loadKeys should call loadkeys on storage", async () => {
      const auth = new JWTAuth() as any;
      await auth.setStorage(storageMock);
      await auth.loadKeys();
      expect(storageMock.loadKeys).toBeCalled();
    });

    test("loadKeys should throw if no storage is set", async () => {
      const auth = new JWTAuth() as any;
      try {
        await auth.loadKeys();
      } catch (error) {
        expect(error).toBeDefined();
        expect((error as any).message).toBe("No persistent storage provided");
      }
      expect(storageMock.loadKeys).not.toBeCalled();
    });

    test("loadRevocList should call loadRevocList on storage", async () => {
      const auth = new JWTAuth() as any;
      await auth.setStorage(storageMock);
      await auth.loadRevocList();
      expect(storageMock.loadRevocationList).toBeCalled();
    });

    test("loadRevocList should throw if no storage is set", async () => {
      const auth = new JWTAuth() as any;
      try {
        await auth.loadRevocList();
      } catch (error) {
        expect(error).toBeDefined();
        expect((error as any).message).toBe("No persistent storage provided");
      }
      expect(storageMock.loadRevocationList).not.toBeCalled();
    });

    test("saveKeys should call storage save with private keys", async () => {
      const auth = new JWTAuth() as any;
      await auth.setStorage(storageMock);
      await auth.saveKeys();
      expect(storageMock.saveKeys).toBeCalledWith(auth.JWKS(true));
    });

    test("saveKeys should throw if no storage is set", async () => {
      const auth = new JWTAuth() as any;
      try {
        await auth.saveKeys();
      } catch (error) {
        expect(error).toBeDefined();
        expect((error as any).message).toBe("No persistent storage provided");
      }
      expect(storageMock.saveKeys).not.toBeCalled();
    });

    test("saveRevocList should call storage save with revocationList", async () => {
      const auth = new JWTAuth() as any;
      await auth.setStorage(storageMock);
      await auth.saveRevocList();
      expect(storageMock.saveRevocationList).toBeCalledWith(
        auth.revocationList
      );
    });

    test("saveRevocList should throw if no storage is set", async () => {
      const auth = new JWTAuth() as any;
      try {
        await auth.saveRevocList();
      } catch (error) {
        expect(error).toBeDefined();
        expect((error as any).message).toBe("No persistent storage provided");
      }
      expect(storageMock.saveRevocationList).not.toBeCalled();
    });
  });

  describe("getters tests: ", () => {
    test("should return corresponding data, keys and recovList", async () => {
      const auth = new JWTAuth() as any;
      const jwksobj = { keys: [{ kid: "123" }] };
      const revocList = [{ jti: "456" }];
      const keystore = auth.keystore;
      jest.spyOn(keystore, "toJWKS").mockImplementation(() => jwksobj);
      auth.revocationList = revocList;
      const data = auth.data;
      const blist = auth.blacklist;
      const jwks = auth.JWKS();
      expect(data).toStrictEqual({
        keys: jwksobj.keys,
        revocList,
      });
      expect(jwks).toBe(jwksobj);
      expect(blist).toBe(revocList);
    });
  });

  describe("public methods tests: ", () => {
    test("rotate should remove the oldest key and generate a new key and sync", async () => {
      const auth: any = new JWTAuth();
      jest.spyOn(auth, "saveKeys").mockImplementation(() => Promise.resolve());
      const keyIds = auth.keyIds;
      const jwks = auth.JWKS();
      await auth.rotate();
      const newKeyids = auth.keyIds;
      const newJwks = auth.JWKS();
      expect(keyIds).toHaveLength(3);
      expect(jwks.keys).toHaveLength(3);
      expect(newKeyids).toHaveLength(3);
      expect(newJwks.keys).toHaveLength(3);
      for (let i = 1; i < 3; i++) {
        expect(keyIds[i]).toBe(newKeyids[i - 1]);
        expect(jwks.keys[i]).toStrictEqual(newJwks.keys[i - 1]);
      }
    });

    test("revokeKey should remove the key based on id", async () => {
      const auth: any = new JWTAuth();
      const keyIds = auth.keyIds;
      const keyid = keyIds[0];
      await auth.revokeKey(keyid);
      const newKeyids = auth.keyIds;
      expect(newKeyids).not.toContain(keyIds);
    });

    test("revokeKey should call saveKeys if storage is present", async () => {
      const auth: any = new JWTAuth();
      await auth.setStorage(storageMock);
      const spy = jest.spyOn(auth, "saveKeys").mockResolvedValueOnce({});
      const keyIds = auth.keyIds;
      const keyid = keyIds[0];
      await auth.revokeKey(keyid);
      const newKeyids = auth.keyIds;
      expect(newKeyids).not.toContain(keyIds);
      expect(spy).toBeCalled();
    });

    test("reset should remove all old key and generate a new set", async () => {
      const auth: any = new JWTAuth();
      const keyIds = auth.keyIds;
      await auth.reset();
      const newKeyids = auth.keyIds;
      for (const id of keyIds) {
        expect(newKeyids).not.toContain(id);
      }
    });

    test("reset should call saveKeys if storage is present", async () => {
      const auth: any = new JWTAuth();
      await auth.setStorage(storageMock);
      const spy = jest.spyOn(auth, "saveKeys").mockResolvedValueOnce({});
      const keyIds = auth.keyIds;
      await auth.reset();
      const newKeyids = auth.keyIds;
      for (const id of keyIds) {
        expect(newKeyids).not.toContain(id);
      }
      expect(spy).toBeCalled();
    });
  });

  describe("JWT tests: ", () => {
    test("token signed should be verified", async () => {
      const auth: any = new JWTAuth();
      jest.spyOn(auth, "generateJTI");
      const jwt = auth.sign({ username: "test" });
      expect(auth.generateJTI).toBeCalled();
      expect(auth.verify(jwt)).toHaveProperty("username", "test");
    });

    test("token revoked should not be verified", async () => {
      const auth: any = new JWTAuth();
      const spy = jest.spyOn(auth, "saveRevocList");
      const jwt = auth.sign({ username: "test" }, { jti: "123" });
      auth.revoke(jwt);
      expect(spy).not.toHaveBeenCalled();
      expect(auth.revocationList).toHaveLength(1);
      expect(auth.revocationList[0]).toHaveProperty("jti", "123");
      expect(() => auth.verify(jwt)).toThrow(JWTRevoked);
    });

    test("token revoked should be saved if storage is set", async () => {
      const auth: any = new JWTAuth();
      const spy = jest.spyOn(auth, "saveRevocList");
      await auth.setStorage(storageMock);
      const jwt = auth.sign({ username: "test" }, { jti: "234" });
      auth.revoke(jwt);
      expect(spy).toBeCalled();
      expect(auth.revocationList).toHaveLength(1);
      expect(auth.revocationList[0]).toHaveProperty("jti", "234");
      expect(() => auth.verify(jwt)).toThrow(JWTRevoked);
    });

    test("verify function should remove old revoken token id", async () => {
      const auth: any = new JWTAuth();
      const expiredRevoc = {
        jti: "111",
        exp: new Date().getTime() / 1000 - 1,
      };
      const revoked = {
        jti: "222",
        exp: new Date().getTime() / 1000 + 10,
      };
      auth.revocationList.push(expiredRevoc);
      auth.revocationList.push(revoked);
      const jwt = auth.sign({ username: "test" }, { jti: "333" });
      auth.verify(jwt);
      expect(auth.revocationList).toHaveLength(1);
      expect(auth.revocationList[0]).toStrictEqual(revoked);
    });
  });
});
