# AGENTS.md

A contributor-facing guide to this repository. Points both human and AI
coding agents at the conventions, build system, and structure used here.

## Project overview

`nostr` is a [Nostr](https://nostr.com) protocol library for Zig: keys and
encoding, event construction and signing, relay transport, encrypted
messaging, and a local-first event store. It has no runtime dependency on
any specific application — it is consumed as a library by other repos in
the `zig-nostr` org (a signer, a DM client, a read-only client).

## Repository layout

```
src/
  root.zig     — public module entry point (@import("nostr"))
build.zig      — build graph: module + test step
build.zig.zon  — package manifest, dependencies
.zigversion    — pinned Zig compiler version
```

As modules are added (keys, encoding, events, transport, store, crypto),
each gets its own file under `src/` and is re-exported from `root.zig`.
Only declarations re-exported from `root.zig` are part of the public API.

## Build commands

```sh
zig build         # build the library module
zig build test    # run the unit test suite
zig fmt --check .  # verify formatting (CI enforces this)
```

Use the Zig version pinned in `.zigversion`. CI runs on Linux and macOS.

## Dependency graph

No external dependencies yet. Planned, added as each milestone needs them:

- `bitcoin-core/secp256k1` (binding) — BIP-340 Schnorr signing/verification.
- `karlseguin/websocket.zig` — relay transport.
- `allyourcodebase/lmdb` — local event store backing.

Dependencies are pinned in `build.zig.zon`; never vendor or hand-roll crypto
primitives that have an audited upstream implementation.

## Commit and PR conventions

- [Conventional Commits](https://www.conventionalcommits.org/):
  `feat: …`, `fix: …`, `docs: …`, `chore: …`, `test: …`, `refactor: …`.
- One concern per PR: code, tests, and docs for that concern land together.
- Every PR links a tracking issue (`Closes #N`) and has a passing CI run
  (`zig build`, `zig build test`, `zig fmt --check .`) before merge.
- Never push directly to `main`; all changes land via reviewed PRs from
  short-lived branches.
- Update `CHANGELOG.md` (Unreleased section) and `CURRENT_STATE.md` inside
  the same PR that introduces the change — not as a follow-up.

## Code style

- `zig fmt` is the formatter; CI fails on unformatted code.
- Prefer explicit error sets over `anyerror`.
- No hand-rolled cryptography for signing/verification — bind to audited
  upstream implementations (see Dependency graph).
- Validate all externally-sourced data (relay messages, parsed events) at
  the boundary; don't assume well-formed input.

## Security

See [`SECURITY.md`](SECURITY.md) for how to report vulnerabilities.
Cryptographic correctness is the highest-priority quality bar in this repo:
signing/verification must pass the official BIP-340 test vectors, and NIP-44
must pass its official test vectors, before either ships.

## Orientation

- [`CURRENT_STATE.md`](CURRENT_STATE.md) — what's built, in progress, and
  next, updated on every merge.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — full contribution workflow.
- [GitHub milestones](https://github.com/zig-nostr/nostr/milestones) and the
  [org project board](https://github.com/orgs/zig-nostr/projects) — the
  full roadmap.
