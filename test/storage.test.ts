import * as fs from "fs";
import FileStorage from "../src/storage";

describe("FileStorage Tests: ", () => {
  const defaultDiskPath = "./authcerts",
    keysFilename = ".keys.json",
    revocListFilename = ".revocList.json";

  beforeAll(() => {
    if (fs.existsSync(defaultDiskPath)) {
      fs.rmdirSync(defaultDiskPath, { recursive: true });
    }
  });

  afterAll(() => {
    if (fs.existsSync(defaultDiskPath)) {
      fs.rmdirSync(defaultDiskPath, { recursive: true });
    }
  });

  describe("Constructor tests: ", () => {
    test("should create the dir if it doesn't exists", () => {
      expect(fs.existsSync(defaultDiskPath)).toBe(false);
      const storage = new FileStorage() as any;
      expect(fs.existsSync(defaultDiskPath)).toBe(true);
      expect(storage.keysFilepath).toBe(`${defaultDiskPath}/${keysFilename}`);
      expect(storage.revocListFilepath).toBe(
        `${defaultDiskPath}/${revocListFilename}`
      );
    });

    test("should expect config passed in for creating files", () => {
      const customConfig = {
        diskPath: "./authtest",
        keysFilename: "keys.txt",
        revocListFilename: "revocs.txt",
      };
      expect(fs.existsSync(customConfig.diskPath)).toBe(false);
      const storage = new FileStorage(customConfig) as any;
      expect(fs.existsSync(customConfig.diskPath)).toBe(true);
      expect(storage.keysFilepath).toBe(
        `${customConfig.diskPath}/${customConfig.keysFilename}`
      );
      expect(storage.revocListFilepath).toBe(
        `${customConfig.diskPath}/${customConfig.revocListFilename}`
      );
      fs.rmdirSync(customConfig.diskPath, { recursive: true });
    });
  });

  describe("private methods tests: ", () => {
    test("loadFromFile should read file and return its content", async () => {
      const filePath = "./authcerts/test_read.txt";
      const fd = await fs.promises.open(filePath, "w");
      const data = "testdatatestdata";
      await fd.write(data);
      await fd.close();
      const storage = new FileStorage() as any;
      const res = await storage.loadFromFile(filePath);
      expect(res).toEqual(data);
    });

    test("saveToFile should save content into file", async () => {
      const filePath = "./authcerts/test_write.txt";
      const data = "writetestdata";
      const storage = new FileStorage() as any;
      await storage.saveToFile(data, filePath);
      const filehandle = await fs.promises.open(filePath, "r");
      const data_r = await filehandle.readFile({ encoding: "utf8" });
      expect(data_r).toEqual(data);
    });

    test("loadFromFile should read content from saveToFile", async () => {
      const filePath = "./authcerts/test_int.txt";
      const data = "somerandomedata";
      const storage = new FileStorage() as any;
      await storage.saveToFile(data, filePath);
      const read = await storage.loadFromFile(filePath);
      expect(read).toEqual(data);
    });
  });

  describe("public methods tests: ", () => {
    const loadTestCases = ["loadKeys", "loadRevocationList"];
    for (const funcName of loadTestCases) {
      test(`${funcName} should call loadFromFile internally and parse to json`, async () => {
        const storage = new FileStorage() as any;
        const data = { test: Math.random().toString(36) };
        const spy = jest
          .spyOn(storage, "loadFromFile")
          .mockResolvedValue(JSON.stringify(data));
        const read = await storage[funcName]();
        expect(spy).toHaveBeenCalled();
        expect(data).toEqual(read);
      });
    }

    const saveTestCases = [
      {
        func: "saveKeys",
        data: { keys: [{ e: "e", d: "d" }] },
      },
      {
        func: "saveRevocationList",
        data: [{ jti: "somejti", exp: new Date() }],
      },
    ];
    for (const t of saveTestCases) {
      test(`${t.func} should call saveToFile internally and stringify data`, async () => {
        const storage = new FileStorage() as any;
        const spy = jest.spyOn(storage, "saveToFile").mockResolvedValue({});
        await storage[t.func](t.data);
        expect(spy).toHaveBeenCalled();
      });
    }
  });
});
