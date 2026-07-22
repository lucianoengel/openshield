## Context

The system already counts dropped/rejected/gapped telemetry (the honesty counters). PLAT-4
surfaces them so they can be alerted on.

## Goals / Non-Goals

**Goals:** a Prometheus-scrapeable /metrics of the existing counters, dependency-free.

**Non-Goals:** OTel; gateway/engine metrics; histograms; endpoint auth.

## Decisions

**Dependency-free text exposition.** The Prometheus text format is trivial to emit by hand, so
no client library is added — no supply-chain surface for an observability endpoint. Each
counter gets its HELP/TYPE/value lines.

**Separate, unauthenticated address.** Metrics are scraped by Prometheus without client certs,
so `/metrics` is served on its own address (OPENSHIELD_METRICS_ADDR), off by default, to be
placed on an internal/firewalled network. The values are counts only — no subject, no content
— so the endpoint leaks nothing (D10/D29).

## Risks / Trade-offs

- **Unauthenticated** — acceptable for counts on an internal address; if exposed, an attacker
  learns drop/gap rates (operational, not sensitive). Auth is a follow-up if needed.
- **Only the control-plane counters** — the gateway/engine expose their own later via the same
  pattern.
