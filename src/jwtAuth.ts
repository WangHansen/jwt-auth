import {
  JWKS,
  JWT,
  JSONWebKeySet,
  Curves,
  keyType,
  BasicParameters,
} from "jose";
import got from "got";
import { Request, Response, NextFunction } from "express";
import * as crypto from "crypto";
import { Storage } from "./storage/interface";
import { JWTRevoked, SyncError } from "./error";
import { CronJob } from "cron";
import { RevocationListItem } from "./index";

export interface JwtAuthOptions {
  algorithm?: keyType; // default "EC"
  crvOrSize?: Curves | number; // key size (in bits) or named curve ('crv') for "EC"
  amount?: number; // number of keys kept in rotation
  interval?: string; // cron expression for how often to generate a new key
  signSkip?: number; // number of keys skipped in signing, default 1
  tokenAge?: string; // token expire time in zeit/ms, default '10m' for access token
}

interface ClientData {
  name: string;
  url: string;
}

interface JWTAuthData<T> extends JSONWebKeySet {
  revocList: T[];
}

// format is serviceName: url
export interface JWTAuthClientData {
  [name: string]: string;
}

const KEYGENOPT: BasicParameters = { use: "sig" };

export default class JWTAuth<T extends RevocationListItem> {
  private storage: Storage<T> | null = null;
  private keystore: JWKS.KeyStore;
  private keyids: string[] = [];
  private clients: JWTAuthClientData = {};
  private revocationList: T[] = [];
  private cronJob: CronJob | null;
  private config: Required<JwtAuthOptions> = {
    algorithm: "EC",
    crvOrSize: "P-256",
    amount: 3,
    signSkip: 1,
    interval: "00 00 */4 * * *",
    tokenAge: "10m",
  };
  // eslint-disable-next-line @typescript-eslint/explicit-function-return-type
  revokeCallback = ({ payload: { jti, exp } }): T => ({ jti, exp } as T);

  constructor(config?: JwtAuthOptions) {
    this.config = this.configCheck(config);
    const { interval } = this.config;
    this.keystore = new JWKS.KeyStore();
    this.fillKeystore();
    this.cronJob = new CronJob(
      interval,
      function () {
        this.rotate();
      },
      null,
      true,
      undefined,
      this
    );
  }

  /**
   * validate the options passed to constructor
   * @param  {JwtAuthOptions} [config] - configuration
   * @returns {JwtAuthOptions} - merged configuration
   */
  private configCheck(config?: JwtAuthOptions): Required<JwtAuthOptions> {
    if (!config) return this.config;
    const { amount, signSkip } = config;
    if (amount && amount < 3) {
      config.amount = 3; // minimum key number is 3
    }
    if (signSkip && signSkip >= (config.amount || this.config.amount)) {
      throw new Error(
        "Number of keys skipped for signing must be small than total number of keys"
      );
    }
    // TODO: add more config checks
    return Object.assign(this.config, config);
  }

  /**
   * Read the key files from storage to replace the generated keys
   * currently in keystore and generate keys if not enough key is
   * found. Also restart the cron job to rotate keys
   */
  public async setStorage(storage: Storage<T>): Promise<void> {
    const { interval } = this.config;
    this.storage = storage;
    // load keys, clients and revoclist if they exists
    await this.loadFromStorage();
    this.fillKeystore();
    await this.saveKeys();
    this.cronJob = new CronJob(
      interval,
      function () {
        this.rotate();
      },
      null,
      true,
      undefined,
      this
    );
  }

  // if there is not enough keys, generate more, also update keyid list
  private fillKeystore(): void {
    const { amount, algorithm, crvOrSize } = this.config;
    while (this.keystore.size < amount) {
      this.keystore.generateSync(algorithm, crvOrSize, KEYGENOPT);
    }
    this.updateKeyids();
  }

  /**
   * Callback is invoked when sync with a client errors
   * @callback syncFailedCallback
   * @param {string} name - name of the client
   * @param {string} error - error rejected
   */
  /**
   * Sync the keys with all clients
   * @param {object} data - the data to be synced
   * @param {syncFailedCallback} cb - called when sync failed with a client
   */
  private async syncWithClients(
    data: JWTAuthData<T>,
    cb: (name: string, err: Error) => void
  ): Promise<void> {
    const allPromise: Promise<unknown>[] = [];
    Object.entries(this.clients).forEach(([name, url]) => {
      allPromise.push(
        got.post(url, { json: data }).catch((err) => cb(name, err))
      );
    });
    await Promise.all(allPromise);
  }

  private generateJTI(): string {
    const hash = crypto.createHash("sha256");
    const rand =
      new Date().getTime().toString(36) + Math.random().toString(36).slice(2);
    return hash.update(rand).digest("base64");
  }

  private updateKeyids(): void {
    this.keyids = this.keystore.all().map((key) => key.kid);
  }

  private async loadFromStorage(): Promise<void> {
    if (!this.storage) return;
    await Promise.all([
      this.loadKeys(),
      this.loadClients(),
      this.loadRevocList(),
    ]);
  }

  private async loadKeys(): Promise<void> {
    let JWKSet: JSONWebKeySet | undefined;
    if (!this.storage) {
      throw new Error("No persistent storage provided");
    }
    try {
      JWKSet = await this.storage.loadKeys();
    } catch (error) {
      throw new Error("storage.loadKeys function should not throw exception");
    }
    if (JWKSet?.keys) {
      this.keystore = JWKS.asKeyStore(JWKSet);
    }
  }

  private async loadClients(): Promise<void> {
    if (!this.storage) {
      throw new Error("No persistent storage provided");
    }
    try {
      this.clients = (await this.storage.loadClients()) || {};
    } catch (error) {
      throw new Error(
        "storage.loadClients function should not throw exception"
      );
    }
  }

  private async loadRevocList(): Promise<void> {
    if (!this.storage) {
      throw new Error("No persistent storage provided");
    }
    try {
      this.revocationList = (await this.storage.loadRevocationList()) || [];
    } catch (error) {
      throw new Error(
        "storage.loadRevocationList function should not throw exception"
      );
    }
  }

  private async saveKeys(): Promise<void> {
    if (!this.storage) {
      throw new Error("No persistent storage provided");
    }
    try {
      await this.storage.saveKeys(this.JWKS(true));
    } catch (error) {
      "storage.saveKeys function should not throw exception";
    }
  }

  private async saveClients(): Promise<void> {
    if (!this.storage) {
      throw new Error("No persistent storage provided");
    }
    try {
      await this.storage.saveClients(this.clients);
    } catch (error) {
      "storage.saveClients function should not throw exception";
    }
  }

  private async saveRevocList(): Promise<void> {
    if (!this.storage) {
      throw new Error("No persistent storage provided");
    }
    try {
      await this.storage.saveRevocationList(this.revocationList);
    } catch (error) {
      "storage.saveRevocationList function should not throw exception";
    }
  }

  //-----------------------//
  //       getters         //
  //-----------------------//

  get data(): JWTAuthData<T> {
    return {
      keys: this.JWKS().keys,
      revocList: this.revocationList,
    };
  }

  get blacklist(): T[] {
    return this.revocationList;
  }

  //-----------------------//
  //        public         //
  //-----------------------//

  JWKS(isPrivate = false): JSONWebKeySet {
    return this.keystore.toJWKS(isPrivate);
  }

  /**
   * Remove the oldest key and replace it with a new key
   */
  async rotate(): Promise<void> {
    const { amount, algorithm, crvOrSize } = this.config;
    await this.keystore.generate(algorithm, crvOrSize, KEYGENOPT);
    this.updateKeyids();
    let amountToRemove = this.keystore.size - amount;
    while (amountToRemove > 0) {
      const keyToRemove = this.keystore.get({
        kid: this.keyids[0],
      });
      this.keystore.remove(keyToRemove);
      this.updateKeyids();
      amountToRemove--;
    }
    if (this.storage) {
      await this.saveKeys();
    }
    await this.sync((name: string, err: Error) => {
      throw new SyncError(`Failed to sync with ${name}, ${err.message}`);
    });
  }

  /**
   * Revoke one key for verifying and signing
   * Note: this may cause all the JWT signed with this kid
   * to be revoked
   * @param {string} kid - id of the key to be removed
   */
  async revokeKey(kid: string): Promise<void> {
    const keyToRemove = this.keystore.get({ kid });
    this.keystore.remove(keyToRemove);
    this.fillKeystore();
    if (this.storage) {
      await this.saveKeys();
    }
  }

  /**
   * Revoke all keys in the keystore
   * Note: this will cause all JWTs signed to be invalid
   */
  async reset(): Promise<void> {
    this.keystore = new JWKS.KeyStore();
    this.fillKeystore();
    if (this.storage) {
      await this.saveKeys();
    }
  }

  /**
   * Register a client
   * @param {ClientData} data - data passed from client
   * @throws throws an error if one of name, url and path is missing
   */
  async registerClient(data: ClientData): Promise<JWTAuthData<T>> {
    const { name, url } = data;
    if (!name || !url) {
      throw new Error("Client data not complete, missing name or url or path");
    }
    this.clients[name] = url;
    if (this.storage) {
      await this.saveClients();
    }
    return this.data;
  }

  /**
   * Function used for connect like server such as express
   * @example
   * app.post('/client/register', server.register)
   */
  register = async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    try {
      const data = await this.registerClient(req.body);
      res.json({ message: "Registeration success", data });
    } catch (error) {
      next(error);
    }
  };

  /**
   * Sync data with all the registered clients
   * @param {Function} cb - callback to handle error
   */
  async sync(cb: (name: string, err: Error) => void): Promise<void> {
    await this.syncWithClients(this.data, cb);
  }

  /**
   * Create a JWT token with custom payload and options
   * @param {object} payload - payload of jwt
   * @param {JWK.SignOptions} [options]
   * @returns {string} token
   */
  sign(payload: Record<string, unknown>, options?: JWT.SignOptions): string {
    options = options || {};
    const keyIndex = Math.floor(
      Math.random() * (this.keystore.size - this.config.signSkip) +
        this.config.signSkip
    );
    const key = this.keystore.get({
      kid: this.keyids[keyIndex],
    });
    if (!options.expiresIn) {
      options.expiresIn = this.config.tokenAge;
    }
    if (!options.jti) {
      options.jti = this.generateJTI();
    }
    return JWT.sign(payload, key, options);
  }

  /**
   * Verify a JWT token with current keystore
   * @param {string} jwt
   * @param {JWT.VerifyOptions} options
   */
  verify(
    jwt: string,
    options?: JWT.SignOptions
  ): Record<string, unknown> | never {
    options = options || {};
    let revoked = false;
    const payload = JWT.verify(jwt, this.keystore, options) as Record<
      string,
      unknown
    >;
    const newRevokedList: T[] = [];
    for (const item of this.revocationList) {
      const { jti, exp } = item as RevocationListItem;
      if (new Date() > new Date(exp * 1000)) {
        continue;
      } else if (payload.jti === jti) {
        revoked = true;
      } else {
        newRevokedList.push(item);
      }
    }
    if (revoked) {
      throw new JWTRevoked();
    }
    this.revocationList = newRevokedList;
    return payload;
  }

  /**
   * Callback is used to trasform payload into a format which
   * is saved in the revocation list, default format is:
   * { id: <some jti>, exp: <date> }
   * @description
   * By default, jti is used to identify which token in revoked.
   * Default callback returns an object containing both expire
   * time and jti, which then is saved into the revocation list.
   * So the list looks like: [{ id: <some jti>, exp: <date> }]
   * The exp is used by to remove it from the list once the time
   * has passed its exp time.
   *
   * @callback revocListHandler
   * @param {JWT.completeResult} jwt - jwt object containing header, payload, signature
   * @returns {any} object that will be pushed into the list
   */
  /**
   * Revoke access to a specific token
   * @param {string} jwtToken
   * @param {revocListHandler} callback
   */
  async revoke(
    jwtToken: string,
    revocListHandler = ({ payload }) =>
      ({
        jti: payload.jti,
        exp: payload.exp,
      } as T)
  ): Promise<void> {
    const jwtObj = JWT.decode(jwtToken, { complete: true });
    this.revocationList.push(revocListHandler(jwtObj));
    if (this.storage) {
      await this.saveRevocList();
    }
  }
}
