import express from 'express';
import { auth } from 'express-oauth2-jwt-bearer';
import { Principal } from '@dfinity/principal';
import { Ed25519PublicKey } from '@dfinity/identity';

type ApiResponse = {
  principal: string;
  user_id: string;
}

const principalFromNonce = (nonce: string) => {
  const publicKey = Ed25519PublicKey.fromDer(Buffer.from(nonce, 'hex').buffer as ArrayBuffer);
  return Principal.selfAuthenticating(new Uint8Array(publicKey.toDer()));
}

const checkJwt = auth({
  audience: process.env.APP_BACKEND_AUDIENCE,
  issuerBaseURL: process.env.APP_BACKEND_ISSUER_BASE_URL,
  tokenSigningAlg: 'RS256',
  validators: {
    nonce: (_roles, claims, _header) => {
      if (!claims.nonce) {
        return false;
      }

      // check if nonce is a valid principal
      try {
        principalFromNonce(claims.nonce as string);
        console.log('nonce claim is a valid principal');
        return true;
      } catch (e) {
        return false;
      }
    }
  },
});

const app = express();
const port = 3000;

app.get('/authenticated', checkJwt, function (req, res) {
  const auth = req.auth;

  if (!auth) {
    console.log('Unauthenticated request received!');
    res.status(401).end();
    return;
  }

  const principal = principalFromNonce(auth.payload.nonce as string);

  const response = {
    principal: principal.toText(),
    user_id: auth.payload.sub!,
  } satisfies ApiResponse;

  console.log('Authenticated request received!', response);

  res.status(200).json(response);
});

app.listen(port, () => {
  console.log(`Listening on port ${port}...`);
});
