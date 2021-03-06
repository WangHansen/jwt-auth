export class JWTRevoked extends Error {
  code: string;
  constructor(message?: string) {
    super(message);
    this.message = message ?? "token has been revoked";
    this.name = this.constructor.name;
    this.code = "ERR_JWT_REVOKED";
    Error.captureStackTrace(this, this.constructor);
  }
}
