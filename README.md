[![Build Status](https://travis-ci.org/WangHansen/jwt-auth.svg?branch=master)](https://travis-ci.org/WangHansen/jwt-auth)
[![codecov](https://codecov.io/gh/WangHansen/jwt-auth/branch/master/graph/badge.svg)](https://codecov.io/gh/WangHansen/jwt-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <!-- <a href="https://github.com/WangHansen/jwt-auth">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a> -->

  <h3 align="center">JWT Auth</h3>

  <p align="center">
    A light weight authentication library that supports key rotation and revokation list.
    <br />
    <!-- <a href="https://github.com/WangHansen/jwt-auth"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/WangHansen/jwt-auth">View Demo</a>
    ·
    <a href="https://github.com/WangHansen/jwt-auth/issues">Report Bug</a>
    ·
    <a href="https://github.com/WangHansen/jwt-auth/issues">Request Feature</a> -->
  </p>
</p>

<!-- TABLE OF CONTENTS -->

## Table of Contents

- [About the Project](#about-the-project)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [API](#api)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

<!-- ABOUT THE PROJECT -->

## About The Project

There are a lot of authentication libraries out there that deals with JWT, probably the most popular one(the one that I used a lot in my project) is the passport-jwt library used together with passport. However, the library has the few problems:
- Need to be used with passport.js
> this may not be a problem to some people, but I find passport.js a little bit difficult to use since it is quite a black box model. Also, the [official example](http://www.passportjs.org/packages/passport-jwt/#configure-strategy) in documentation contains a query to db in order to authenticate the user, which I believe is against the natural of JWT (stateless).
- Doesn't handle key rotation
- Doesn't handle key revokation

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
import JWTAuth from "@hansenw/jwt-auth";
import { Router } from "express";

const router = Router();
const jwt = new JWTAuth();

router.post("/login", async (req, res, next) => {
  const { username, password } = req.body;

  // to verify credentials
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
function authVerify(req, res, next) {
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

router.post("/protected", authVerify, async (req, res, next) => { 
  res.json({ message: "jwt valid" })
})
```

### Advanced Usage with TS
> Customze what to store in the revocation list, be default revocation list contain items on type { jti: string, exp: number }

```javascript
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

## API

### Constructor
__Class: JWTAuth__
```javascript
const jwt = new JWTAuth(options: JwtAuthOptions);
```
`options`:
- `algorithm?`: can be ['RSA' | 'EC' | 'OKP' | 'oct'], __Default__: "EC"
- `crvOrSize?`: `<Curves | number>`: key size (in bits) or named curve ('crv') for "EC", __Default__: 2048 for RSA, 'P-256' for EC, 'Ed25519' for OKP and 256 for oct.
- `amount?`: `<number>` number of keys kept in rotation, __Default__: 3
- `interval?`: `<string>` cron expression for how often to generate a new key, __Default__: "* */4 * * * *": every 4 hour, generate a new token
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
  - `nonce`: `<string>` ID Token Nonce, "nonce" claim value, if provided it will replace "nonce" found in the payload. See [OpenID Connect Core 1.0][connect-core] for details.
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
  - `profile`: `<string>` To validate a JWT according to a specific profile, e.g. as an ID Token. Supported values are 'id_token', 'at+JWT' (draft), and 'logout_token' (draft). **Default:** 'undefined' (generic JWT). Combine this option with the other ones like `maxAuthAge` and `nonce` or `subject` depending on the use-case. Draft profiles are updated as minor versions of the library, therefore, since they may have breaking changes use the `~` semver operator when using these and
    pay close attention to changelog and the drafts themselves.
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
  - `maxAuthAge`: `<string>` When provided the payload is checked to have the "auth_time" claim and its value is validated, provided as timespan string e.g. `30m`, `24 hours`. See [OpenID Connect Core 1.0][connect-core] for details. Do not confuse with maxTokenAge option.
  - `maxTokenAge`: `<string>` When provided the payload is checked to have the "iat" claim and its value is validated not to be older than the provided timespan string e.g. `30m`, `24 hours`. Do not confuse with maxAuthAge option.
  - `nonce`: `<string>` Expected nonce value. An exact match must be found in the payload. See [OpenID Connect Core 1.0][connect-core] for details.
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
  > the item returned must at least have two field `jti` and `exp`, JWTAuth internally use `jti` to determine if a token is revoked and use `exp` to clear the list

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

<!-- ROADMAP -->

## Roadmap

- [x] implement a persistent storage
- [ ] document persistent storage
- [ ] implement a client library for distributed system/micro services

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
