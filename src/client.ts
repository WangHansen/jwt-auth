import { VerifyOptions, verify, decode } from "jsonwebtoken";

export interface ClientOption extends VerifyOptions {
  useridKey: string;
}

export class MicroserviceAuthClient {
  private certs: Map<string, string>;
  private blacklist: Map<string, Date>;
  private options: VerifyOptions = {
    algorithms: ["RS256"]
  };

  constructor(
    opts?: VerifyOptions,
    certs = new Map<string, string>(),
    blacklist = new Map<string, Date>()
  ) {
    this.options = Object.assign(this.options, opts);
    this.certs = certs;
    this.blacklist = blacklist;
  }

  _setOptions(opts: ClientOption) {
    this.options = opts;
  }

  _updateCerts(certs: Map<string, string>) {
    this.certs = certs;
  }

  _updateBlacklist(blacklist: Map<string, Date>) {
    this.blacklist = blacklist;
  }

  private getCert(keyid?: string): string | undefined {
    const temp = [...this.certs.keys()];
    const kid = keyid || temp[this.certs.size - 1];
    return this.certs.get(kid);
  }

  verify(token: string, opts?: VerifyOptions) {
    opts = Object.assign(this.options, {} || opts);
    const { header } = decode(token, { complete: true }) as any;
    const publicCert = this.getCert(header.kid);
    if (!publicCert) {
      const err = new Error("Cert doesn't exists or expired");
      throw err;
    }
    return verify(token, publicCert, opts);
  }
}
