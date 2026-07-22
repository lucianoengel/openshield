# Tasks — NIPS-7 listener rate limit
- [x] internal/connectors/limiter: token bucket (burst + sustained rate), injectable clock.
- [x] DNS listener: global rate limit before parse+sink; RateLimited counter; default on, tunable.
- [x] Limiter test: burst then block; refill over injected time.
- [x] DNS test: burst-1 zero-refill floods 20 -> 1 delivered, rest rate-limited.
- [x] Mutation: remove the rate check -> all 20 delivered.
- [x] make all clean; docs D160; sync; archive; commit; push; memory.
