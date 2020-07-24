[![Build Status](https://travis-ci.org/WangHansen/jwt-auth.svg?branch=master)](https://travis-ci.org/WangHansen/jwt-auth)
[![codecov](https://codecov.io/gh/WangHansen/jwt-auth/branch/master/graph/badge.svg)](https://codecov.io/gh/WangHansen/jwt-auth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<!-- PROJECT LOGO -->
<br />
<p align="center">
  <a href="https://github.com/WangHansen/jwt-auth">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

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
- [Roadmap](#roadmap)
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

Use this space to show useful examples of how a project can be used. Additional screenshots, code examples and demos work well in this space. You may also link to more resources.

_For more examples, please refer to the [Documentation](https://example.com)_

<!-- ROADMAP -->

## Roadmap

See the [open issues](https://github.com/othneildrew/Best-README-Template/issues) for a list of proposed features (and known issues).

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

<!-- CONTACT -->

## Contact

Your Name - [@your_twitter](https://twitter.com/your_username) - email@example.com

Project Link: [https://github.com/your_username/repo_name](https://github.com/your_username/repo_name)
