import * as fs from "fs";
import debug from "debug";
import { JSONWebKeySet } from "jose";
import { Storage } from "./interface";

export interface RevocationListItem {
  jti: string;
  exp: number;
}

export interface FileStorageConfig {
  diskPath: string;
  keysFilename: string;
  revocListFilename: string;
}

export default class FileStorage extends Storage<RevocationListItem> {
  private config = {
    diskPath: "./authcerts",
    keysFilename: ".keys.json",
    revocListFilename: ".revocList.json",
  };
  private keysFilepath: string;
  private revocListFilepath: string;

  private logger = debug("jwt-auth:filestore");

  constructor(config?: FileStorageConfig) {
    super();
    this.config = Object.assign(this.config, config || {});
    const { diskPath, keysFilename, revocListFilename } = this.config;
    if (!fs.existsSync(diskPath)) {
      fs.mkdirSync(diskPath);
    }
    this.keysFilepath = `${diskPath}/${keysFilename}`;
    this.revocListFilepath = `${diskPath}/${revocListFilename}`;
  }

  /**
   * Load data from a file
   *
   * @param {string} filepath
   * @returns {Promise<string>} data
   */
  private async loadFromFile(filepath: string): Promise<string> | never {
    this.logger(`loading from file ${filepath}`);
    let filehandle: fs.promises.FileHandle | undefined,
      data = "";

    try {
      filehandle = await fs.promises.open(filepath, "r");
      data = await filehandle.readFile({ encoding: "utf8" });
    } catch (e) {
      // file doesn't exists
      this.logger("file doesn't exists");
    } finally {
      if (filehandle != undefined) await filehandle.close();
    }

    return data;
  }

  /**
   * Save data to a file
   *
   * @param data - string to be written to a file
   * @param filepath
   */
  private async saveToFile(data: string, filepath: string): Promise<void> {
    this.logger(`saving to file ${filepath}`);
    const fd = await fs.promises.open(filepath, "w");
    await fd.write(data);
    await fd.close();
  }

  async loadKeys(): Promise<JSONWebKeySet> {
    const str = await this.loadFromFile(this.keysFilepath);
    return str ? JSON.parse(str) : undefined;
  }

  async saveKeys(keys: JSONWebKeySet): Promise<void> {
    await this.saveToFile(JSON.stringify(keys), this.keysFilepath);
  }

  async loadRevocationList(): Promise<RevocationListItem[]> {
    const str = await this.loadFromFile(this.revocListFilepath);
    return str ? JSON.parse(str) : undefined;
  }

  async saveRevocationList(list: RevocationListItem[]): Promise<void> {
    await this.saveToFile(JSON.stringify(list), this.revocListFilepath);
  }
}
