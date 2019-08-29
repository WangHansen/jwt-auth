import {
  SignOptions,
  VerifyOptions,
  Secret,
  sign,
  verify,
  decode
} from "jsonwebtoken";
import * as utils from "./utils";
import * as moment from "moment";
import { MicroserviceAuthClient } from "./client";

export enum TokenType {
  Access = "access",
  Refresh = "refresh",
  Other = "other"
}

interface JWTKeyPairOptional {
  publicCert?: string;
  privateCert?: Secret;
  kid: string;
}

export interface JWTKeyPair {
  readonly publicCert: string;
  readonly privateCert: Secret;
}

export interface JWTPayload {
  email: string;
  [propName: string]: any;
}

interface TokenComOptions {
  audience?: string; // options for access and refresh token
  subject?: string; // options for access and refresh token
  issuer?: string; // options for access and refresh token
  jwtid?: string; // options for access and refresh token
}

export interface JWTOptions {
  algorithm?: string; // algorithm, default 'RS256'
  certNum?: number; // number of certs kept in rotation
  accessTokenAge?: string; // access token expire time in zeit/ms, default '10m'
  refreshTokenAge?: string; // refresh token expire time in zeit/ms, default '7d'
  useridKey?: string; // the key to look for from payload to identify user, default "email"
}

interface IJWTOptions {
  algorithm: string;
  certNum: number;
  accessTokenAge: string;
  refreshTokenAge?: string;
  useridKey: string;
}

export class MicroserviceAuthServer {
  private refreshCerts: JWTKeyPair;
  private privateCerts: Map<string, Secret>;
  private publicCerts: Map<string, string>;
  private clients?: Array<MicroserviceAuthClient> = [];
  private blacklist: Map<string, Date>; // userid: email to timestamp
  private options: IJWTOptions & TokenComOptions = {
    certNum: 3,
    algorithm: "RS256",
    accessTokenAge: "10m",
    refreshTokenAge: "7d",
    useridKey: "email"
  };

  constructor(
    options?: JWTOptions & TokenComOptions,
    privateCerts?: Map<string, Secret>,
    publicCerts?: Map<string, string>,
    blacklist = new Map<string, Date>()
  ) {
    options = options || {};
    // update options
    this.options = Object.assign(this.options, options);
    if (this.options.certNum < 3) {
      throw new Error("Minimum number of certs in list must be 3");
    }

    // generate refresh certs
    this.refreshCerts = utils.generateCertPair();
    // generate access certs
    const { publicCert, privateCert } = utils.generateCertPair();
    this.publicCerts = new Map([["1", publicCert]]);
    this.privateCerts = new Map([["1", privateCert]]);
    // if certs passed in are valid, replace the generated cert
    if (
      privateCerts &&
      publicCerts &&
      this.validateCerts(privateCerts, publicCerts)
    ) {
      this.privateCerts = privateCerts!;
      this.publicCerts = publicCerts!;
    }
    // initialize blacklist
    this.blacklist = blacklist;
  }

  private validateCerts(
    privCerts?: Map<string, Secret>,
    pubCerts?: Map<string, string>
  ): boolean {
    if (!privCerts && !pubCerts) {
      return false;
    }
    if (!privCerts || !pubCerts) {
      throw new Error("Private or public certs don't exist");
    }
    if (privCerts.size !== pubCerts.size) {
      throw new Error("Number of private/pub certs don't match ");
    }
    for (let kid of privCerts.keys()) {
      if (!pubCerts.get(kid)) {
        throw new Error(
          `No corresponding public cert for private cert with kid ${kid}`
        );
      }
    }
    return pubCerts.size > 0;
  }

  /**
   * getCert will return private/public key pair, either the
   * latest key pair, or the key pair based on kid, to be
   * used either in sign or verify
   *
   * @param  {string} keyid? kid value
   * @returns IJWTKeyPair
   */
  private getCerts(keyid?: string): JWTKeyPairOptional {
    const temp = [...this.publicCerts.keys()];
    const kid = keyid || temp[this.publicCerts.size - 1];
    const privateCert = this.privateCerts.get(kid);
    const publicCert = this.publicCerts.get(kid);
    return {
      kid,
      privateCert,
      publicCert
    };
  }

  private tokenOpts(type: TokenType, sign = true): object {
    const temp: any = {};
    if (this.options.audience) temp["audience"] = this.options.audience;
    if (this.options.subject) temp["subject"] = this.options.subject;
    if (this.options.jwtid) temp["jwtid"] = this.options.jwtid;
    if (this.options.issuer) temp["issuer"] = this.options.issuer;
    if (sign) {
      temp.algorithm = this.options.algorithm;
    } else {
      temp.algorithms = [this.options.algorithm];
    }
    if (type === TokenType.Access) {
      return Object.assign(temp, { expiresIn: this.options.accessTokenAge });
    }
    if (type === TokenType.Refresh) {
      return Object.assign(temp, { expiresIn: this.options.refreshTokenAge });
    }
    return temp;
  }

  registerClient(client: MicroserviceAuthClient) {
    if (!this.clients) this.clients = [];
    this.clients.push(client);
    client._setOptions(
      Object.assign(this.tokenOpts(TokenType.Access, false), {
        useridKey: this.options.useridKey
      })
    );
    client._updateCerts(this.publicCerts);
    client._updateBlacklist(this.blacklist);
  }

  /**
   * setRefreshCerts set the private and public cert used to sign
   * and verify refresh token. It is strongly not advised to pass
   * the refresh certs in unless you are rotating it. By default
   * refresh certs don't get rotated, they are generated when the
   * server starts and never accessed outside, so they are relatively
   * safe. Another reason is that refresh token are not refreshed,
   * they are only verified. When user's refresh token expired, they
   * are asked to login with credentials again.
   *
   * @param  {Secret} privateCert
   * @param  {string} publicCert
   */
  setRefreshCerts(privateCert: Secret, publicCert: string) {
    if (!utils.verifyPubPrivCertPair(privateCert, publicCert)) {
      throw new Error("Public/private certs don't match");
    }
    this.refreshCerts = { publicCert, privateCert };
  }

  /**
   * rotateCerts generates a new pair of public/private certs and
   * insert them in the list of certs. When the certs in the list
   * exceeds the certNum specified, the oldest certs get deleted
   * @returns {Map<string, string>} - the public keys
   */
  rotateCerts(): Map<string, string> {
    let keyid: string;
    do {
      keyid = utils.generateRandomKeyId();
    } while (this.publicCerts.has(keyid));

    const { publicCert, privateCert } = utils.generateCertPair();

    this.publicCerts.set(keyid, publicCert);
    this.privateCerts.set(keyid, privateCert);

    // delete the first key
    if (this.publicCerts.size > this.options.certNum) {
      const temp = [...this.publicCerts.keys()];
      const key = temp[0];
      this.publicCerts.delete(key);
      this.privateCerts.delete(key);
    }

    this.syncCerts();
    return this.publicCerts;
  }

  generateToken(
    type: TokenType,
    payload: JWTPayload,
    opts?: SignOptions
  ): string {
    opts = opts || {};
    // use the pre set algorithm
    delete opts.algorithm;
    // access token use pre set expire time
    if (type === TokenType.Access) {
      delete opts.expiresIn;
    }
    opts = Object.assign(this.tokenOpts(type), opts);
    let { privateCert, kid } = this.getCerts(opts.keyid);
    opts.keyid = kid;
    if (type === TokenType.Refresh) {
      privateCert = this.refreshCerts.privateCert;
    }
    if (!privateCert) {
      throw new Error("Cannot sign without a cert");
    }
    return sign(payload, privateCert, opts);
  }

  verifyToken(type: TokenType, token: string, opts?: VerifyOptions) {
    opts = opts || {};
    // use the pre set algorithm
    delete opts.algorithms;
    opts = Object.assign(this.tokenOpts(type, false), opts);
    const { header } = decode(token, { complete: true }) as any;
    let { publicCert } = this.getCerts(header.kid);
    if (type === TokenType.Refresh) {
      publicCert = this.refreshCerts.publicCert;
    }
    if (!publicCert) {
      const err = new Error("Cert doesn't exists or expired");
      err.name = "CertNotExistsError";
      throw err;
    }
    return verify(token, publicCert, opts);
  }

  revoke(
    refreshToken: string,
    verify = false,
    verifyOpts?: VerifyOptions
  ): Map<string, Date> {
    verifyOpts = { complete: false } || verifyOpts;
    const payload = verify
      ? this.verifyToken(TokenType.Refresh, refreshToken, verifyOpts)
      : decode(refreshToken);
    if (!payload) {
      throw new Error("No payload is found in JWT");
    }
    const userid = (payload as JWTPayload)[this.options.useridKey];
    if (userid) {
      throw new Error("No user email found in payload from JWT");
    }
    const notValidBefore = moment().add(this.options.accessTokenAge);
    this.blacklist.set(userid, notValidBefore.toDate());

    this.syncBlacklist();
    return this.blacklist;
  }

  private syncBlacklist() {
    if (this.clients && this.clients.length > 0) {
      this.clients.forEach(c => c._updateBlacklist(this.blacklist));
    }
  }

  private syncCerts() {
    if (this.clients && this.clients.length > 0) {
      this.clients.forEach(c => c._updateBlacklist(this.blacklist));
    }
  }

  get certs() {
    return this.publicCerts;
  }

  get revokedList() {
    return this.blacklist;
  }
}
