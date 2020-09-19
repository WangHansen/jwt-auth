import FileStorage from "./storage";
import JWTAuth from "./jwtAuth";
import { Storage } from "./storage/interface";

export * from "./jwtAuth";
export { FileStorage, Storage };
export default JWTAuth;

// item save in revocation list
export interface RevocationListItem {
  jti: string;
  exp: number; // exp time in millsecs
}
