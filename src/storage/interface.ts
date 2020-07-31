import { JSONWebKeySet } from "jose";
import { RevocationListItem, JWTAuthClientData } from "../index";

export abstract class Storage<T extends RevocationListItem> {
  abstract loadKeys(): Promise<JSONWebKeySet | undefined>;
  abstract saveKeys(keys: JSONWebKeySet): Promise<void>;
  loadClients(): Promise<JWTAuthClientData | undefined> {
    return new Promise((resolve) => resolve({}));
  }
  saveClients(clients: JWTAuthClientData): Promise<void> {
    return new Promise((resolve) => resolve());
  }
  abstract loadRevocationList(): Promise<Array<T> | undefined>;
  abstract saveRevocationList(list: Array<T>): Promise<void>;
}
