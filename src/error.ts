export class JWTRevoked extends Error {
  code: string;
  constructor(message?: string) {
    super(message);
    if (message === undefined) {
      this.message = "token has been revoked";
    }
    this.name = this.constructor.name;
    this.code = "ERR_JWT_REVOKED";
    Error.captureStackTrace(this, this.constructor);
  }
}

export class SyncError extends Error {
  code: string;
  constructor(message?: string) {
    super(message);
    if (message === undefined) {
      this.message = "failed to sync with client";
    }
    this.name = this.constructor.name;
    this.code = "ERR_SYNC_FAILURE";
    Error.captureStackTrace(this, this.constructor);
  }
}
