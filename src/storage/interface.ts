import { JSONWebKeySet } from "jose";
import { RevocationListItem } from "../index";

export abstract class Storage<T extends RevocationListItem> {
  abstract loadKeys(): Promise<JSONWebKeySet | undefined>;
  abstract saveKeys(keys: JSONWebKeySet): Promise<void>;
  abstract loadRevocationList(): Promise<Array<T> | undefined>;
  abstract saveRevocationList(list: Array<T>): Promise<void>;
}
