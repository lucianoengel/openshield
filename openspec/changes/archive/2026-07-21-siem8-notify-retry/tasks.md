# Tasks — SIEM-8 notify retry

- [x] `Retrying` decorator: bounded exponential backoff, ctx-aware, injectable sleep seam.
- [x] `Permanent`/`isPermanent` + `Webhook` classifies 4xx (except 429)/marshal/bad-URL as permanent.
- [x] Wrap the server webhook in `Retrying` (OPENSHIELD_ALERT_RETRIES); `envInt` helper.
- [x] Tests: succeed-after-transient, exhaust-budget, skip-permanent, honor-cancellation; webhook classification end-to-end.
- [x] Mutations: retry loop bounded to 1; permanent short-circuit removed; backoff ignores cancellation.
- [x] `make all` clean.
- [x] docs/decisions.md D136; sync spec; archive; commit; push; memory.
