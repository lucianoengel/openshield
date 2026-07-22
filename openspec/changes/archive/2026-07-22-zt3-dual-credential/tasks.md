# Tasks — ZT-3 dual credential
- [x] Resolve device identity from the client cert always; refuse an unenrolled device.
- [x] resolveUser(deviceID): OIDC token when configured, else the device cert.
- [x] Look up device posture by deviceID.Subject (not the user); risk stays by userID.Subject.
- [x] Test: valid user + no device posture -> denied; user-keyed posture -> denied; device posture -> allowed.
- [x] Mutation: posture keyed by user -> user-keyed posture wrongly admits.
- [x] make all clean; docs D164; sync; archive; commit; push; memory.
