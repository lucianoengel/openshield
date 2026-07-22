# Tasks — ZT-2 wire OIDC
- [x] AccessProxy.SetOIDCVerifier + resolveIdentity (token when configured, else cert); bearerToken parse.
- [x] identity.LoadOIDCKeys (dir of <kid>.pem).
- [x] Gateway wires OPENSHIELD_OIDC_ISSUER/AUDIENCE/ROLE_CLAIM/KEYS_DIR; fail-fast on misconfig.
- [x] Test: valid token authorizes + reaches upstream; no token 401; tampered 403; upstream not reached.
- [x] Test: LoadOIDCKeys valid/non-PEM/empty.
- [x] Mutation: accept unverified token -> tampered token succeeds.
- [x] make all clean; docs D163; sync; archive; commit; push; memory.
