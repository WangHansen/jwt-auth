import FileStorage from "./storage";
import JWTAuth from "./jwtAuth";

export * from "./jwtAuth";
export { FileStorage };
export default JWTAuth;

// item save in revocation list
export interface RevocationListItem {
  jti: string;
  exp: number; // exp time in millsecs
}
