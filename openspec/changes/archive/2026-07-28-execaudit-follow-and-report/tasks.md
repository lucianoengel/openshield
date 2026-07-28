# Tasks

- [x] 1. `internal/connectors/execaudit`: a `Follow` reader — wraps a `*os.File`, waits on EOF instead
      of returning it, resumes from 0 on truncation, reopens when the path names a new inode, and
      returns EOF only when its context is done.
- [x] 2. `cmd/openshield-engine`: use it when the source is a regular file; leave a fifo/socket as-is.
- [x] 3. `cmd/openshield-engine`: report at WARN when the source ends while the engine still runs, and
      state the mode (following / read-once) on the startup line.
- [x] 4. Unit tests for the follower: appended bytes are returned; truncation resumes; a replaced file
      is reopened; context cancellation ends it.
- [x] 5. Integration scenario: engine starts, THEN an exec record is appended, and it produces an audit
      entry. Records must be written after startup — writing them before would pass against the old
      behaviour.
- [x] 6. Mutation-verify: drop the follower → the appended record never arrives.
- [x] 7. Targeted tests green; decision record; spec sync on archive.
