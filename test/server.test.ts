import JWTAuth, { Options } from "../src";
import FileStorage from "../src/storage";
import { JWKS } from "jose";
import { CronJob } from "cron";
import { RevokedError } from "../src/error";
jest.mock("../src/storage");

describe("JWTAuth Tests: ", () => {
  let storageMock: FileStorage;

  beforeAll(() => {
    storageMock = new FileStorage();
  });

  describe("Constructor tests: ", () => {
    // const server = new JWTAuth();

    test("should be able to create instance without options", () => {
      const auth = new JWTAuth(storageMock);
      expect(auth).toBeInstanceOf(JWTAuth);
    });

    test("should attach the storage instance", () => {
      const auth = new JWTAuth(storageMock) as any;
      expect(auth.storage).toBe(storageMock);
    });

    test("should initalize keystore", () => {
      const auth = new JWTAuth(storageMock) as any;
      expect(auth.keystore).toBeInstanceOf(JWKS.KeyStore);
    });

    describe("configCheck tests:", () => {
      test("should correct options to have minimum 3 keys", () => {
        const opt = { amount: 1 };
        const auth = new JWTAuth(storageMock, opt);
        const config = (auth as any).config;
        expect(config.amount).toBe(3);
      });

      test("should merge options with default values", () => {
        const opts: Options = {
          algorithm: "RSA",
          crvOrSize: 256,
          amount: 4,
          signSkip: 2,
          interval: "* */6 * * * *",
          tokenAge: "15m",
        };
        const auth = new JWTAuth(storageMock, opts);
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
          new JWTAuth(storageMock, { amount: 3, signSkip: 3 });
        }).toThrow();
        expect(() => {
          new JWTAuth(storageMock, { amount: 5, signSkip: 5 });
        }).toThrow();
        expect(() => {
          new JWTAuth(storageMock, { amount: 4, signSkip: 1 });
        }).not.toThrow();
        expect(() => {
          new JWTAuth(storageMock, { signSkip: 2 });
        }).not.toThrow();
      });
    });
  });

  describe("init test ", () => {
    test("should load from storage and then fill the keystore", async () => {
      const auth: any = new JWTAuth(storageMock);
      const spyLoad = jest
        .spyOn(auth, "loadFromStorage")
        .mockImplementation(() => Promise.resolve());
      const spyFill = jest
        .spyOn(auth, "fillKeystore")
        .mockImplementation(() => Promise.resolve());
      await auth.init().then(() => auth.cronJob.stop());
      expect(spyLoad).toBeCalled();
      expect(spyFill).toBeCalled();
      expect(auth.cronJob).toBeInstanceOf(CronJob);
    });
  });

  describe("private methods tests: ", () => {
    test("fillKeystore should fill the keystore with keys", async () => {
      const auth = new JWTAuth(storageMock, { amount: 4 }) as any;
      const spy = jest.spyOn(auth, "updateKeyids");
      const spy2 = jest
        .spyOn(auth, "saveKeys")
        .mockImplementation(() => Promise.resolve());
      expect(auth.keystore.size).toBe(0);
      await auth.fillKeystore();
      expect(auth.keystore.size).toBe(4);
      expect(spy).toBeCalled();
      expect(spy2).toBeCalled();
    });
    test("generateJTI should generate a unique string", () => {
      const auth = new JWTAuth(storageMock) as any;
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
      const auth = new JWTAuth(storageMock) as any;
      const spyk = jest
        .spyOn(auth, "loadKeys")
        .mockImplementationOnce(() => Promise.resolve());
      const spyc = jest
        .spyOn(auth, "loadClients")
        .mockImplementationOnce(() => Promise.resolve());
      const spyl = jest
        .spyOn(auth, "loadRevocList")
        .mockImplementationOnce(() => Promise.resolve());
      await auth.loadFromStorage();
      expect(spyk).toBeCalled();
      expect(spyc).toBeCalled();
      expect(spyl).toBeCalled();
    });

    test("loadKeys should call loadkeys on storage", async () => {
      const auth = new JWTAuth(storageMock) as any;
      await auth.loadKeys();
      expect(storageMock.loadKeys).toBeCalled();
    });

    test("loadClients should call loadClients on storage", async () => {
      const auth = new JWTAuth(storageMock) as any;
      await auth.loadClients();
      expect(storageMock.loadClients).toBeCalled();
    });

    test("loadRevocList should call loadRevocList on storage", async () => {
      const auth = new JWTAuth(storageMock) as any;
      await auth.loadRevocList();
      expect(storageMock.loadRevocationList).toBeCalled();
    });

    test("saveKeys should call storage save with private keys", async () => {
      const auth = new JWTAuth(storageMock) as any;
      await auth.saveKeys();
      expect(storageMock.saveKeys).toBeCalledWith(auth.JWKS(true));
    });

    test("saveClients should call storage save with clients object", async () => {
      const auth = new JWTAuth(storageMock) as any;
      await auth.saveClients();
      expect(storageMock.saveClients).toBeCalledWith(auth.clients);
    });

    test("saveRevocList should call storage save with revocationList", async () => {
      const auth = new JWTAuth(storageMock) as any;
      await auth.saveRevocList();
      expect(storageMock.saveRevocationList).toBeCalledWith(
        auth.revocationList
      );
    });
  });

  describe("getters tests: ", () => {
    test("should return corresponding data, keys and recovList", async () => {
      const auth = new JWTAuth(storageMock) as any;
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
      const auth: any = new JWTAuth(storageMock);
      const spySync = jest
        .spyOn(auth, "sync")
        .mockImplementation(() => Promise.resolve());
      jest.spyOn(auth, "saveKeys").mockImplementation(() => Promise.resolve());
      await auth.init().then(() => auth.cronJob.stop());
      const keyids = auth.keyids;
      const jwks = auth.JWKS();
      await auth.rotate();
      const newKeyids = auth.keyids;
      const newJwks = auth.JWKS();
      expect(keyids).toHaveLength(3);
      expect(jwks.keys).toHaveLength(3);
      expect(newKeyids).toHaveLength(3);
      expect(newJwks.keys).toHaveLength(3);
      expect(spySync).toBeCalled();
      for (let i = 1; i < 3; i++) {
        expect(keyids[i]).toBe(newKeyids[i - 1]);
        expect(jwks.keys[i]).toStrictEqual(newJwks.keys[i - 1]);
      }
    });

    test("revokeKey should remove the key based on id", async () => {
      const auth: any = new JWTAuth(storageMock);
      await auth.init().then(() => auth.cronJob.stop());
      const keyids = auth.keyids;
      const keyid = keyids[0];
      await auth.revokeKey(keyid);
      const newKeyids = auth.keyids;
      expect(newKeyids).not.toContain(keyids);
    });

    test("revokeKey should remove the key based on id", async () => {
      const auth: any = new JWTAuth(storageMock);
      await auth.init().then(() => auth.cronJob.stop());
      const keyids = auth.keyids;
      await auth.reset();
      const newKeyids = auth.keyids;
      for (const id of keyids) {
        expect(newKeyids).not.toContain(id);
      }
    });

    test("registerClient should return data", async () => {
      const auth: any = new JWTAuth(storageMock);
      await auth.init().then(() => auth.cronJob.stop());
      const clientdata = {
        name: "test-svc",
        url: "https://localhost/api",
      };
      const spy = jest
        .spyOn(auth, "saveClients")
        .mockImplementation(() => Promise.resolve());
      const res = await auth.registerClient(clientdata);
      expect(spy).toBeCalled();
      expect(res).toStrictEqual(auth.data);
    });
  });

  describe("JWT tests: ", () => {
    test("token signed should be verified", async () => {
      const auth: any = new JWTAuth(storageMock);
      await auth.init().then(() => auth.cronJob.stop());
      jest.spyOn(auth, "generateJTI");
      const jwt = auth.sign({ username: "test" });
      expect(auth.generateJTI).toBeCalled();
      expect(auth.verify(jwt)).toHaveProperty("username", "test");
    });

    test("token revoked should not be verified", async () => {
      const auth: any = new JWTAuth(storageMock);
      await auth.init().then(() => auth.cronJob.stop());
      const spy = jest.spyOn(auth, "saveRevocList");
      const jwt = auth.sign({ username: "test" }, { jti: "123" });
      auth.revoke(jwt);
      expect(spy).toBeCalled();
      expect(auth.revocationList).toHaveLength(1);
      expect(auth.revocationList[0]).toHaveProperty("jti", "123");
      expect(() => auth.verify(jwt)).toThrow(RevokedError);
    });
  });
});
