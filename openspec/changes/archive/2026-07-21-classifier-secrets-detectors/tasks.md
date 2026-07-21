# Tasks — secrets/credentials detectors (D96)

## 1. Detectors

- [x] 1.1 Proto: DETECTOR_TYPE_PRIVATE_KEY/AWS_ACCESS_KEY/JWT/API_TOKEN; regenerate.
- [x] 1.2 `internal/classify/secrets.go`: privateKey (PEM, not public), awsAccessKey (prefix+base32), jwt (base64url header → JOSE, no JSON dep), apiToken (vendor prefixes + length floor); registered in New().

## 2. Proof (guards mutation-tested)

- [x] 2.1 **Test**: each detector fires on a real secret at high confidence; benign look-alikes (public key, SSH public line, non-JOSE token, wrong-charset AKIA word, truncated sk-) read clean; the JWT validator decodes the header.

## 3. Docs, ship

- [x] 3.1 `docs/decisions.md` D96.
- [x] 3.2 validate --strict; make all + -race; doccheck; archive; commit + push.

## Verification performed

| mutation | caught by |
|---|---|
| validJWT skips the JOSE-header check | non-JOSE three-part token misdetected as JWT |
| private-key regex also matches PUBLIC keys | a PUBLIC KEY block tripped the private-key detector |
| AWS key charset relaxed to [A-Z0-9] | an AKIA-shaped look-alike with a wrong-charset body tripped the detector |
