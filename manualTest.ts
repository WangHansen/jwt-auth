import { MicroserviceAuthServer, TokenType } from "./src/server";
import { MicroserviceAuthClient } from "./src/client";
import * as jwt from "jsonwebtoken";
import * as utils from "./src/utils";

const { publicCert, privateCert } = utils.generateCertPair();
console.log(publicCert);
console.log(privateCert);
console.log(utils.verifyPubPrivCertPair(privateCert, publicCert));

// const server = new MicroserviceAuthServer();
// const client = new MicroserviceAuthClient();

// server.registerClient(client);

// const access_token_1 = server.generateToken(TokenType.Access, {
//   email: "test email"
// });
// const refresh_token = server.generateToken(TokenType.Refresh, {
//   email: "test email"
// });
// const access_payload_1 = client.verify(access_token_1);
// const refresh_payload = server.verifyToken(TokenType.Refresh, refresh_token);

// server.rotateCerts();
// const access_token_2 = server.generateToken(TokenType.Access, {
//   email: "test email"
// });
// server.rotateCerts();
// server.rotateCerts();

// console.log(access_payload_1);

// try {
//   client.verify(access_token_1);
// } catch (error) {
//   console.log(error);
// }
// try {
//   const { header } = jwt.decode(access_token_2, { complete: true }) as any;
//   console.log(header);
//   const access_payload_2 = client.verify(access_token_2);
//   console.log(access_payload_2);
// } catch (error) {
//   console.log(error);
// }
// // console.log("certs: ");
// // console.log(server.certs);
// console.log(refresh_payload);
