import { VerifyOptions, verify, decode } from "jsonwebtoken";

export interface ClientOption extends VerifyOptions {
  useridKey: string;
}

export class MicroserviceAuthClient {
  private keys: Map<string, string>;
  private blacklist: Map<string, Date>;
  private options: VerifyOptions = {
    algorithms: ["RS256"]
  };

  constructor(
    opts?: VerifyOptions,
    keys = new Map<string, string>(),
    blacklist = new Map<string, Date>()
  ) {
    this.options = Object.assign(this.options, opts);
    this.keys = keys;
    this.blacklist = blacklist;
  }

  _setOptions(opts: ClientOption) {
    this.options = opts;
  }

  _updateKeys(keys: Map<string, string>) {
    this.keys = keys;
  }

  _updateBlacklist(blacklist: Map<string, Date>) {
    this.blacklist = blacklist;
  }

  private getKey(keyid?: string): string | undefined {
    const temp = [...this.keys.keys()];
    const kid = keyid || temp[this.keys.size - 1];
    return this.keys.get(kid);
  }

  verify(token: string, opts?: VerifyOptions) {
    opts = Object.assign(this.options, {} || opts);
    const { header } = decode(token, { complete: true }) as any;
    const publicKey = this.getKey(header.kid);
    if (!publicKey) {
      const err = new Error("Key doesn't exists or expired");
      throw err;
    }
    return verify(token, publicKey, opts);
  }
}
