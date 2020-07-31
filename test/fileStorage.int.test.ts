import * as fs from "fs";
import JWTAuth from "../src";
import FileStorage from "../src/storage";
jest.mock("cron");

describe("JWTAuth FileStorage Integration Tests: ", () => {
  beforeEach(() => {
    if (fs.existsSync("./authcerts")) {
      fs.rmdirSync("./authcerts", { recursive: true });
    }
  });
  test("JWTAuth should generate keys and save to FileStorage", async () => {
    const storage = new FileStorage();
    const jwtauth = new JWTAuth();
    const jwks = jwtauth.JWKS(true);
    await jwtauth.setStorage(storage);
    const keys = await storage.loadKeys();
    expect(keys).toEqual(jwks);
  });

  test("JWTAuth should read keys from FileStorage", async () => {
    const temp = new JWTAuth();
    const jwks = temp.JWKS();
    const storage = new FileStorage();
    await storage.saveKeys(jwks);
    const jwtauth = new JWTAuth();
    await jwtauth.setStorage(storage);
    const keys = jwtauth.JWKS();
    expect(keys).toEqual(jwks);
  });
});
