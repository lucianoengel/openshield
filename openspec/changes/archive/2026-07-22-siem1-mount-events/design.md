# Design — mount /events

## The bug class: two muxes, one registration missed

Routes are declared twice — once on the OperatorReadHandler's inner ServeMux (which dispatches
within the operator surface) and once on the server's TLS mux (which gates by cert role and
forwards to the handler). `/events` was added to the first but not the second, so the gate never
forwarded to it and it 404'd. The unit tests called the methods directly, so nothing exercised the
served path.

## The fix and the guard

The one-line mount closes the immediate hole. The durable fix is the test: it drives the REAL
served TLS mux (`ServeHTTPTLS → serve()`) with a CA-issued operator cert and asserts every
operator-read route returns non-404, plus the role gate still refuses an agent cert on the newly
mounted route. Reverting the mount fails it (verified). This catches any future route that is
registered but not served — the class, not just this instance.
