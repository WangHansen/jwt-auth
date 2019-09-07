import { MicroserviceAuthServer } from "../src/server";
import * as utils from "../src/utils";

// const mock_utils = jest.genMockFromModule("../src/utils.ts") as any;
// mock_utils.generateKeyPair = jest.fn(() => ({
//   privateKey: {
//     key: "privateKey",
//     passphrase: "passphrase123"
//   },
//   publicKey: "publicKey"
// }));

// const { publicKey, privateKey } = utils.generateKeyPair();
// console.log(publicKey, privateKey);

// jest.mock("../src/utils.ts", () => ({
//   generateRandomPassphrase: jest.fn(() => "passphrase123"),
//   generateRandomKeyId: jest.fn(() => "66"),
//   verifyPubPrivKeyPair: jest.fn(() => true),
//   default: jest.fn(() => "mocked fruit"),
//   generateKeyPair: jest.fn(() => ({
//     privateKey: {
//       key: "privateKey",
//       passphrase: "passphrase123"
//     },
//     publicKey: "publicKey"
//   }))
// }));

describe("Server Tests: ", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe("Constructor tests: ", () => {
    let server: MicroserviceAuthServer;
    const { publicKey, privateKey } = utils.generateKeyPair();

    test("Server constructor should generate keys", () => {
      const mock = jest.spyOn(utils, "generateKeyPair");
      server = new MicroserviceAuthServer();
      expect(mock).toBeCalledTimes(2);
      expect(server.keys.size).toBe(1);
      expect(server.revokedList.size).toBe(0);
      mock.mockClear();
    });

    test("setRefreshKeys should override refresh keys", () => {
      const mock = jest.spyOn(utils, "verifyPubPrivKeyPair");
      server.setRefreshKeys(privateKey, publicKey);
      expect(mock).toHaveBeenCalled();
      mock.mockClear();
    });
  });
});
