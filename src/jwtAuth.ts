import {
  JWKS,
  JWT,
  JSONWebKeySet,
  Curves,
  keyType,
  BasicParameters,
} from "jose";
import debug from "debug";
import * as crypto from "crypto";
import { Storage } from "./storage/interface";
import { JWTRevoked } from "./error";
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

interface JWTAuthData<T> extends JSONWebKeySet {
  revocList: T[];
}

const KEYGENOPT: BasicParameters = { use: "sig" };

export default class JWTAuth<T extends RevocationListItem> {
  private storage: Storage<T> | null = null;
  private keystore: JWKS.KeyStore;
  private keyIds: string[] = [];
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
      async function () {
        await this.rotate();
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
    this.updateKeyIds();
  }

  private generateJTI(): string {
    const hash = crypto.createHash("sha256");
    const rand =
      new Date().getTime().toString(36) + Math.random().toString(36).slice(2);
    return hash.update(rand).digest("base64");
  }

  private updateKeyIds(): void {
    this.keyIds = this.keystore.all().map((key) => key.kid);
    debug("All keys in store: ", this.keyIds);
  }

  private async loadFromStorage(): Promise<void> {
    if (!this.storage) return;
    await Promise.all([this.loadKeys(), this.loadRevocList()]);
  }

  private async loadKeys(): Promise<void> {
    if (!this.storage) {
      throw new Error("No persistent storage provided");
    }
    debug("loading keys from storage");
    const JWKSet = await this.storage.loadKeys();
    if (JWKSet?.keys) {
      this.keystore = JWKS.asKeyStore(JWKSet);
    }
  }

  private async loadRevocList(): Promise<void> {
    if (!this.storage) {
      throw new Error("No persistent storage provided");
    }
    debug("loading revocation list from storage");
    this.revocationList = (await this.storage.loadRevocationList()) || [];
  }

  private async saveKeys(): Promise<void> {
    if (!this.storage) {
      throw new Error("No persistent storage provided");
    }
    debug("saving revocation list to storage");
    await this.storage.saveKeys(this.JWKS(true));
  }

  private async saveRevocList(): Promise<void> {
    if (!this.storage) {
      throw new Error("No persistent storage provided");
    }
    debug("saving revocation list to storage");
    await this.storage.saveRevocationList(this.revocationList);
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
    debug("rotating keys");
    const { amount, algorithm, crvOrSize } = this.config;
    await this.keystore.generate(algorithm, crvOrSize, KEYGENOPT);
    this.updateKeyIds();
    let amountToRemove = this.keystore.size - amount;
    while (amountToRemove > 0) {
      const keyToRemove = this.keystore.get({
        kid: this.keyIds[0],
      });
      debug(`old key ${keyToRemove.kid} removed`);
      this.keystore.remove(keyToRemove);
      this.updateKeyIds();
      amountToRemove--;
    }
    if (this.storage) {
      await this.saveKeys();
    }
  }

  /**
   * Revoke one key for verifying and signing
   * Note: this may cause all the JWT signed with this kid
   * to be revoked
   * @param {string} kid - id of the key to be removed
   */
  async revokeKey(kid: string): Promise<void> {
    const keyToRemove = this.keystore.get({ kid });
    debug(`key ${kid} revoked`);
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
    debug("remove all existing keys and generating new ones");
    this.keystore = new JWKS.KeyStore();
    this.fillKeystore();
    if (this.storage) {
      await this.saveKeys();
    }
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
      kid: this.keyIds[keyIndex],
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
