# Tasks

- [x] 1. `internal/config`: declare the client's settings (broker URL, device cert + key, CA bundle,
      loopback listen address with a default), typed so a bad value is refused at startup.
- [x] 2. `cmd/openshield-ztna-client`: read configuration, build TLS material, call ListenAndServe.
      Every configuration problem fatal; no decision re-implemented from the library.
- [x] 3. Startup line states the bypass limit, the HTTP(S)-only limit, and that it is not an enrolment
      tool.
- [x] 4. Add it to the build (Makefile / cross-compile list) and to the README's component table.
- [x] 5. Integration scenario: the binary brokers an authorized request to a real access proxy, and
      refuses without a device identity.
- [x] 6. Mutation-verify: drop the device certificate from the TLS config → the broker refuses the
      request, proving the client's identity is what authorized it.
- [x] 7. Remove the README's "built and not yet shipped as a binary" line; targeted tests green;
      decision record; spec sync on archive.
