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
  publicKey?: string;
  privateKey?: Secret;
  kid: string;
}

export interface JWTKeyPair {
  readonly publicKey: string;
  readonly privateKey: Secret;
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
  keyAmount?: number; // number of keys kept in rotation
  accessTokenAge?: string; // access token expire time in zeit/ms, default '10m'
  refreshTokenAge?: string; // refresh token expire time in zeit/ms, default '7d'
  useridKey?: string; // the key to look for from payload to identify user, default "email"
}

interface IJWTOptions {
  algorithm: string;
  keyAmount: number;
  accessTokenAge: string;
  refreshTokenAge?: string;
  useridKey: string;
}

export class MicroserviceAuthServer {
  private refreshKeys: JWTKeyPair;
  private privateKeys: Map<string, Secret>;
  private publicKeys: Map<string, string>;
  private clients?: Array<MicroserviceAuthClient> = [];
  private blacklist: Map<string, Date>; // userid: email to timestamp
  private options: IJWTOptions & TokenComOptions = {
    keyAmount: 3,
    algorithm: "RS256",
    accessTokenAge: "10m",
    refreshTokenAge: "7d",
    useridKey: "email"
  };

  constructor(
    options?: JWTOptions & TokenComOptions,
    privateKeys?: Map<string, Secret>,
    publicKeys?: Map<string, string>,
    blacklist = new Map<string, Date>()
  ) {
    options = options || {};
    // update options
    this.options = Object.assign(this.options, options);
    if (this.options.keyAmount < 3) {
      throw new Error("Minimum number of keys in list must be 3");
    }

    // generate refresh keys
    this.refreshKeys = utils.generateKeyPair();
    // generate access keys
    const { publicKey, privateKey } = utils.generateKeyPair();
    this.publicKeys = new Map([["1", publicKey]]);
    this.privateKeys = new Map([["1", privateKey]]);
    // if keys passed in are valid, replace the generated key
    if (
      privateKeys &&
      publicKeys &&
      this.validateKeys(privateKeys, publicKeys)
    ) {
      this.privateKeys = privateKeys!;
      this.publicKeys = publicKeys!;
    }
    // initialize blacklist
    this.blacklist = blacklist;
  }

  private validateKeys(
    privKeys?: Map<string, Secret>,
    pubKeys?: Map<string, string>
  ): boolean {
    if (!privKeys && !pubKeys) {
      return false;
    }
    if (!privKeys || !pubKeys) {
      throw new Error("Private or public keys don't exist");
    }
    if (privKeys.size !== pubKeys.size) {
      throw new Error("Number of private/pub keys don't match ");
    }
    for (let kid of privKeys.keys()) {
      if (!pubKeys.get(kid)) {
        throw new Error(
          `No corresponding public key for private key with kid ${kid}`
        );
      }
    }
    return pubKeys.size > 0;
  }

  /**
   * getKey will return private/public key pair, either the
   * latest key pair, or the key pair based on kid, to be
   * used either in sign or verify
   *
   * @param  {string} keyid? kid value
   * @returns IJWTKeyPair
   */
  private getKeys(keyid?: string): JWTKeyPairOptional {
    const temp = [...this.publicKeys.keys()];
    const kid = keyid || temp[this.publicKeys.size - 1];
    const privateKey = this.privateKeys.get(kid);
    const publicKey = this.publicKeys.get(kid);
    return {
      kid,
      privateKey,
      publicKey
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
    client._updateKeys(this.publicKeys);
    client._updateBlacklist(this.blacklist);
  }

  /**
   * setRefreshKeys set the private and public key used to sign
   * and verify refresh token. It is strongly not advised to pass
   * the refresh keys in unless you are rotating it. By default
   * refresh keys don't get rotated, they are generated when the
   * server starts and never accessed outside, so they are relatively
   * safe. Another reason is that refresh token are not refreshed,
   * they are only verified. When user's refresh token expired, they
   * are asked to login with credentials again.
   *
   * @param  {Secret} privateKey
   * @param  {string} publicKey
   */
  setRefreshKeys(privateKey: Secret, publicKey: string) {
    if (!utils.verifyPubPrivKeyPair(privateKey, publicKey)) {
      throw new Error("Public/private keys don't match");
    }
    this.refreshKeys = { publicKey, privateKey };
  }

  /**
   * rotateKeys generates a new pair of public/private keys and
   * insert them in the list of keys. When the keys in the list
   * exceeds the keyAmount specified, the oldest keys get deleted
   * @returns {Map<string, string>} - the public keys
   */
  rotateKeys(): Map<string, string> {
    let keyid: string;
    do {
      keyid = utils.generateRandomKeyId();
    } while (this.publicKeys.has(keyid));

    const { publicKey, privateKey } = utils.generateKeyPair();

    this.publicKeys.set(keyid, publicKey);
    this.privateKeys.set(keyid, privateKey);

    // delete the first key
    if (this.publicKeys.size > this.options.keyAmount) {
      const temp = [...this.publicKeys.keys()];
      const key = temp[0];
      this.publicKeys.delete(key);
      this.privateKeys.delete(key);
    }

    this.syncKeys();
    return this.publicKeys;
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
    let { privateKey, kid } = this.getKeys(opts.keyid);
    opts.keyid = kid;
    if (type === TokenType.Refresh) {
      privateKey = this.refreshKeys.privateKey;
    }
    if (!privateKey) {
      throw new Error("Cannot sign without a key");
    }
    return sign(payload, privateKey, opts);
  }

  verifyToken(type: TokenType, token: string, opts?: VerifyOptions) {
    opts = opts || {};
    // use the pre set algorithm
    delete opts.algorithms;
    opts = Object.assign(this.tokenOpts(type, false), opts);
    const { header } = decode(token, { complete: true }) as any;
    let { publicKey } = this.getKeys(header.kid);
    if (type === TokenType.Refresh) {
      publicKey = this.refreshKeys.publicKey;
    }
    if (!publicKey) {
      const err = new Error("Key doesn't exists or expired");
      err.name = "KeyNotExistsError";
      throw err;
    }
    return verify(token, publicKey, opts);
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

  private syncKeys() {
    if (this.clients && this.clients.length > 0) {
      this.clients.forEach(c => c._updateKeys(this.publicKeys));
    }
  }

  get keys() {
    return this.publicKeys;
  }

  get revokedList() {
    return this.blacklist;
  }
}
