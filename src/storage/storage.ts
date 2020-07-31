import * as fs from "fs";
import { JSONWebKeySet } from "jose";
import { JWTAuthClientData } from "..";
import { Storage } from "./interface";

export interface RevocationListItem {
  jti: string;
  exp: number;
}

export interface FileStorageConfig {
  diskPath: string;
  keysFilename: string;
  clientsFilename: string;
  revocListFilename: string;
}

export default class FileStorage extends Storage<RevocationListItem> {
  private config = {
    diskPath: "./authcerts",
    keysFilename: ".keys.json",
    clientsFilename: ".clients.json",
    revocListFilename: ".revocList.json",
  };
  private keysFilepath: string;
  private clientsFilepath: string;
  private revocListFilepath: string;

  constructor(config?: FileStorageConfig) {
    super();
    this.config = Object.assign(this.config, config || {});
    const {
      diskPath,
      keysFilename,
      clientsFilename,
      revocListFilename,
    } = this.config;
    if (!fs.existsSync(diskPath)) {
      fs.mkdirSync(diskPath);
    }
    this.keysFilepath = `${diskPath}/${keysFilename}`;
    this.clientsFilepath = `${diskPath}/${clientsFilename}`;
    this.revocListFilepath = `${diskPath}/${revocListFilename}`;
  }

  /**
   * Load data from a file
   *
   * @param {string} filepath
   * @returns {Promise<string>} data
   */
  private async loadFromFile(filepath: string): Promise<string> | never {
    let filehandle: fs.promises.FileHandle | undefined,
      data = "";

    try {
      filehandle = await fs.promises.open(filepath, "r");
      data = await filehandle.readFile({ encoding: "utf8" });
    } catch (e) {
      // file doesn't exists
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

  async loadClients(): Promise<JWTAuthClientData> {
    const str = await this.loadFromFile(this.clientsFilepath);
    return str ? JSON.parse(str) : undefined;
  }

  async saveClients(clients: JWTAuthClientData): Promise<void> {
    await this.saveToFile(JSON.stringify(clients), this.clientsFilepath);
  }

  async loadRevocationList(): Promise<RevocationListItem[]> {
    const str = await this.loadFromFile(this.revocListFilepath);
    return str ? JSON.parse(str) : undefined;
  }

  async saveRevocationList(list: RevocationListItem[]): Promise<void> {
    await this.saveToFile(JSON.stringify(list), this.revocListFilepath);
  }
}
