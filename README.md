[![Build Status](https://travis-ci.org/WangHansen/jwt-auth.svg?branch=master)](https://travis-ci.org/WangHansen/jwt-auth)
[![codecov](https://codecov.io/gh/WangHansen/jwt-auth/branch/master/graph/badge.svg)](https://codecov.io/gh/WangHansen/jwt-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FWangHansen%2Fjwt-auth.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FWangHansen%2Fjwt-auth?ref=badge_shield)

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <!-- <a href="https://github.com/WangHansen/jwt-auth">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a> -->

  <h3 align="center">JWT Auth</h3>

  <p align="center">
    A light weight authentication library that supports key rotation and revokation list.
  </p>
</p>

<!-- TABLE OF CONTENTS -->

## Table of Contents

- [Another auth library?](#about-the-project)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [API](#api)
- [Persistent Storage](#persistent-storage)
  - [File Storage](#file-storage)
  - [Write your own persistent storage](#write-your-own-persistent-storage)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

<!-- ABOUT THE PROJECT -->

## Another auth library?

There are a lot of authentication libraries out there that deals with JWT, probably the most popular one(the one that I used a lot in my project) is the passport-jwt library used together with passport. However, the library has the few problems:
- Need to be used with passport.js
> This may not be a problem to some people, but I find passport.js a bit difficult to use since it's a black box model (I don't understand the magic happening behind the scene). 
- Need to talk to DB
> The [official example](http://www.passportjs.org/packages/passport-jwt/#configure-strategy) in documentation contains a query to db in order to authenticate the user, which I believe is against the natural, being stateless, of JWT.
- Doesn't handle <b>key rotation</b>
- Doesn't handle <b>key revocation</b>

In order to address these problems, I decided to make this open source library.

<!-- GETTING STARTED -->

## Getting Started

### Prerequisites

I have this tested from Node version 12 and above, make sure you have the right version

### Installation

Install with npm

```JS
npm install --save @hansenw/jwt-auth
```

<!-- USAGE EXAMPLES -->

## Usage

### Simple Usage
```javascript
// authService.js
import JWTAuth from "@hansenw/jwt-auth";

const JWT = new JWTAuth();
export default JWT;

// to use in other files
import jwt from "./authService";

// to generate a jwt token
const token = jwt.sign({ /* some payload */ });

// to verify
try {
  const payload = jwt.verify(token);
  // ...
} catch (e) {
  // cannot be verified
}

// to revoke
await jwt.revoke(token);
jwt.verify(token); // this will throw JWTRevoked
```

### With Express
```javascript
import * as express from "express";
import JWTAuth from "@hansenw/jwt-auth";

const app = express();
const jwt = new JWTAuth();

app.post("/login", async (req, res, next) => {
  const { username, password } = req.body;

  // Your own logic .. to verify credentials
  const match = authenticate(username, password);

  if (match) {
    const jwtpayload = { username };
    const token = jwt.sign(payload);
    res.set({
        "Access-Control-Expose-Headers": "Authorization",
        Authorization: "Bearer " + token,
      })
      .json({
        message: "Login success",
      });
  } else {
    // handle failure logic
  }
})

// middleware for protecting api
function authGuard(req, res, next) {
  // getting token from header
  const header = req.headers["authorization"];
  const token = header ? header.split(" ")[1] : "";
  if (!token) {
    return next(new Error("No auth token"));
  }
  // verify token validity
  try {
    const payload = jwt.verify(token);
    // if token is valid, attach the payload to req object
    req.payload = payload;
  } catch (e) {
    // token invalid, can be handled differently based on the error
  }
}

app.post("/protected", authGuard, async (req, res, next) => { 
  // get JWT payload
  const payload = req.payload;

  // if user info is ever needed
  const user = await db.collection("user").find({ username: payload.username });

  res.json({ message: "Authorized user only" })
})

// start the express app
app.listen(3000)
```

### Advanced Usage with TS
> Customze what to store in the revocation list, be default revocation list contain items on type { jti: string, exp: number }

```typescript
import JWTAuth, { RevocationListItem } from "@hansenw/jwt-auth";

interface RevocListItem extends RevocationListItem {
  ip: string;
}

const jwt = new JWTAuth<RevocListItem>();

const token = jwt.sign({ /* some payload */ });

// to verify
try {
  const payload = jwt.verify(token);
  // ...
} catch (e) {
  // cannot be verified
}

// to revoke
await jwt.revoke(token, (payload) => ({
  jti: payload.jti,
  exp: payload.exp,
  ip: req.ip,
}));
jwt.verify(token); // this will throw JWTRevoked
```

### Microservice

If you want to build your own auth server or auth service within the microservices, check out this [jwt-jwks-client](https://github.com/WangHansen/jwt-jwks-client) library I made that can be used together with this one.

#### server.ts
```typescript
import * as express from "express";
import JWTAuth from "@hansenw/jwt-auth";

const app = express()
const authService = new JwtAuth();

app.post("/login", (req: Request, res: Response) => {
  // Replace with your own matching logic
  if (req.body.username === "admin" && req.body.password === "password") {
    const token = authService.sign({ userId: "admin" });
    return (
      res
        .set("authorization", token)
        .send("Authorized")
    );
  }
  res.status(401).send("Not authorized");
});

// Expose jwks through an API
app.get("/jwks", (req: Request, res: Response) => {
  res.json(authService.JWKS(true));
});
```

#### Client
```ts
import * as express from "express";
import JwksClient from "jwt-jwks-client";

const authClient = new JwksClient({
  jwksUri: "http://localhost:3000/jwks",
  secure: false,
});

app.get("/secret", async (req: Request, res: Response) => {
  const token = req.headers.authorization;
  if (token) {
    // Verify the token here
    await authClient.verify(token);
    return res.send("This is a secret page");
  }
  return res.send(`You are not authorized to see the secret page`);
});
```
See complete example [here](https://github.com/WangHansen/jwt-jwks-client/tree/master/example)

## API

### Constructor
__Class: JWTAuth__
```javascript
const jwt = new JWTAuth(options: JwtAuthOptions);
```
`JwtAuthOptions`:
- `algorithm?`: can be ['RSA' | 'EC' | 'OKP' | 'oct'], __Default__: "EC"
- `crvOrSize?`: `<Curves | number>` key size (in bits) or named curve ('crv') for "EC", __Default__: 2048 for RSA, 'P-256' for EC, 'Ed25519' for OKP and 256 for oct.
- `amount?`: `<number>` number of keys kept in rotation, __Default__: 3
- `interval?`: `<string>` [cron](https://github.com/kelektiv/node-cron#cron-ranges) expression for how often to generate a new key, __Default__: "00 00 */4 * * *": every 4 hour, generate a new token
  > Make sure the token expire time is less than the interval that a new token is generated
- `signSkip?`: `<number>` number of keys skipped when generating a new token, __Default__: 1
  > By default, there are 3 keys stored, and by setting this to 1, every time a new token is signed, only the last 2 keys will be used since the first key will be removed after the rotation.
- `tokenAge?`: `<string>` token expire time in zeit/ms, __Default__ '10m'

### Methods
#### `jwt.sign(payload: object, options?: JWT.SignOptions)`
Generate a new jwt token
```javascript
const token = jwt.sign(payload, options?);
```
- `payload`: `<object>`
- `options`: `<object>` see [jose](https://github.com/panva/jose/blob/HEAD/docs/README.md#jwtsignpayload-key-options)
  - `algorithm`: `<string>` The algorithm to use
  - `audience`: `<string>` &vert; `string[]` JWT Audience, "aud" claim value, if provided it will replace "aud" found in the payload
  - `expiresIn`: `<string>` JWT Expiration Time, "exp" claim value, specified as string which is added to the current unix epoch timestamp e.g. `24 hours`, `20 m`, `60s`, etc., if provided it will replace Expiration Time found in the payload
  - `header`: `<Object>` JWT Header object
  - `iat`: `<Boolean>` When true it pushes the "iat" to the JWT Header. **Default:** 'true'
  - `issuer`: `<string>` JWT Issuer, "iss" claim value, if provided it will replace "iss" found in the payload
  - `jti`: `<string>` JWT ID, "jti" claim value, if provided it will replace "jti" found in the payload
  - `kid`: `<Boolean>` When true it pushes the key's "kid" to the JWT Header. **Default:** 'true' for asymmetric keys, 'false' for symmetric keys.
  - `notBefore`: `<string>` JWT Not Before, "nbf" claim value, specified as string which is added to the current unix epoch timestamp e.g. `24 hours`, `20 m`, `60s`, etc., if provided it will replace Not Before found in the payload
  - `now`: `<Date>` Date object to be used instead of the current unix epoch timestamp. **Default:** 'new Date()'
  - `subject`: `<string>` JWT subject, "sub" claim value, if provided it will replace "sub" found in the payload

---

#### `jwt.verify(token: string, options?: JWT.SignOptions) throws`
Verify the validity of a JWT token
```javascript
try {
  const payload = jwt.verify(token, options?);
} catch (error) {
  // possible error: JWTClaimInvalid, JWTExpired, JWTMalformed, JWTRevoked
}
```
- `payload`: `<object>`
- `options`: `<object>` see [jose](https://github.com/panva/jose/blob/HEAD/docs/README.md#jwtverifytoken-keyorstore-options)
  - `algorithms`: `string[]` Array of expected signing algorithms. JWT signed with an algorithm not found in this option will be rejected. **Default:** accepts all algorithms available on the passed key (or keys in the keystore)
  - `audience`: `<string>` &vert; `string[]` Expected audience value(s). When string an exact match must be found in the payload, when array at least one must be matched.
  - `typ`: `<string>` Expected JWT "typ" Header Parameter value. An exact match must be found in the JWT header. **Default:** 'undefined' unless a `profile` with a specific value is used, in which case this option will be ignored.
  - `clockTolerance`: `<string>` Clock Tolerance for comparing timestamps, provided as timespan string e.g. `120s`, `2 minutes`, etc. **Default:** no clock tolerance
  - `complete`: `<Boolean>` When false only the parsed payload is returned, otherwise an object with a parsed header, payload, the key that verified and the base64url encoded signature will be returned **Default:** 'false'
  - `crit`: `string[]` Array of Critical Header Parameter names to recognize. **Default:** '[]'
  - `ignoreExp`: `<Boolean>` When true will not be validating the "exp" claim value to be in the future from now. **Default:** 'false'
  - `ignoreIat`: `<Boolean>` When true will not be validating the "iat" claim value to be in the past from now if expiration is not present. **Default:** 'false'
  - `ignoreNbf`: `<Boolean>` When true will not be validating the "nbf" claim value to be in the past from now. **Default:** 'false'
  - `issuer`: `<string>` Expected issuer value. An exact match must be found in the payload.
  - `jti`: `<string>` Expected jti value. An exact match must be found in the payload.
  - `maxTokenAge`: `<string>` When provided the payload is checked to have the "iat" claim and its value is validated not to be older than the provided timespan string e.g. `30m`, `24 hours`. Do not confuse with maxAuthAge option.
  - `now`: `<Date>` Date object to be used instead of the current unix epoch timestamp. **Default:** 'new Date()'
  - `subject`: `<string>` Expected subject value. An exact match must be found in the payload.

---

#### `jwt.revoke(token: string, revocListHandler?: Function) throws`
Revoke an already issued JWT token
```javascript
try {
  await jwt.revoke(token)
} catch (error) {
  // failed to revoke a token
}
```
- `token`: `<string>` JWT token
- `revocListHandler`: `<function>` a function that takes `payload` as the parameter and return a object to be saved in the revocation list. __Default__: (payload) => ({ jti: payload.jti, exp: payload.exp }) 
  > The item returned must at least have fields `jti` and `exp`, JWTAuth internally use `jti` to determine if a token is revoked and use `exp` to clear the expired token.

---

#### `jwt.JWKS(isPrivate: boolean)`
Return all keys in the format of [JWKS](https://tools.ietf.org/html/rfc7517)
```javascript
const jwks = jwt.JWKS();
```
- `isPrivate`: `<boolean>` whether to return the private key part

---

#### `jwt.rotate()`
Rotate the key sets by removing the oldest key and generating a new key
```javascript
await jwt.rotate();
```

---

#### `jwt.revokeKey(kid: string)`
Manually remove a key from key set, __Note__: this may cause all the JWT signed with this kid invalid
```javascript
await jwt.revokeKey(kid);
```
- `kid`: `<string>` the id of the key to be removed

---

#### `jwt.reset()`
Remove all current keys and generate a new set, __Note__: !!this will cause all the JWT signed previously invalid
```javascript
await jwt.reset();
```

## Persistent Storage

It is important to save the generated keys to a persistent storage, so that application crashes and restart would not result in all authenticated users log out

### File Storage

By default, this library comes with one storage plugin--local file storage, this storage tries to store all the data in a folder on local disk.
> Since the keys are very sensitive and secretive data, I don't think it is safe to send them on to the internet, thus I only provide the file storage so that it can be securely stored. If you want to store it with databases, please see [write your own persisten plugin](write-your-own-persistent-storage)

```javascript
import JwtAuth, { FileStorage } from "@hansenw/jwt-auth";

const jwtAuth = new JwtAuth();

const fileStore = new FileStorage();

// this is async beacuse it will try to load keys from storage
await jwtAuth.setStorage(fileStore);

// after the storage is set, every time key rotation happens
// keys will be automatically saved to file storage
await jwtAuth.rotate();
```

#### API

##### Constructor
__Class: FileStorage__
```javascript
const jwt = new FileStorage(options: FileStorageConfig);
```
`FileStorageConfig`:
- `diskPath?`: `<string>` path to where to store the files, __Default__: "./authcerts"
- `keysFilename?`: `<string>` name of the file for storing all JWKs, __Default__: ".keys.json"
- `clientsFilename?`: `<number>` name of the file for storing all clients data **[This is currently useless, will be used later on when implementing a client library that can be used]**, __Default__: ".clients.json"
- `revocListFilename?`: `<string>` name of the file for storing all revoked JWTs, __Default__: ".revocList.json"

### Write your own persistent storage

Make sure you extend the Storage abstract provided by the library

```typescript
abstract class Storage<T extends RevocationListItem> {
  abstract loadKeys(): Promise<JSONWebKeySet | undefined>;
  abstract saveKeys(keys: JSONWebKeySet): Promise<void>;
  abstract loadRevocationList(): Promise<Array<T> | undefined>;
  abstract saveRevocationList(list: Array<T>): Promise<void>;
}
```

All you need is to provide 4 methods for storing and retriving data from the persistent storage

#### Methods

All methods on Storage will be called automatically with the auth library so you do't need to worry about calling them

Here is the list of actions that happens with auth library assuming the storage is used:

Auth library method | Storage method 
--------------------|---------------
rotate | saveKeys
revokeKey | saveKeys
reset | saveKeys
revoke | saveRevocList


<!-- ROADMAP -->

## Roadmap

- [x] implement a persistent storage
- [x] document persistent storage
- [x] implement a client library for distributed system/microservices

<!-- CONTRIBUTING -->

## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->

## License

Distributed under the MIT License. See `LICENSE` for more information.


[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FWangHansen%2Fjwt-auth.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FWangHansen%2Fjwt-auth?ref=badge_large)