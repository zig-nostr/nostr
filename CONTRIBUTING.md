# Contributing

Thanks for your interest in `zig-nostr/nostr`. This document covers the
workflow used for all changes to this repository.

## Prerequisites

- Zig, pinned version in [`.zigversion`](.zigversion) (install via your
  package manager or [ziglang.org/download](https://ziglang.org/download/)).
- `git`.

## Workflow

1. **Open or claim an issue** describing the change, with acceptance
   criteria. Every PR links back to an issue — even small fixes.
2. **Branch from `main`**, named after the change
   (`feat/nip19-encoding`, `fix/event-id-hash`, `chore/ci-macos`).
3. **Implement** the change with tests. Update `CHANGELOG.md` (Unreleased
   section) and `CURRENT_STATE.md` in the same branch.
4. **Verify locally** before opening a PR:
   ```sh
   zig build
   zig build test
   zig fmt --check .
   ```
5. **Open a PR** against `main`, filled out per the PR template, linking
   the issue (`Closes #N`). CI must be green.
6. **Review and merge.** PRs are squash-merged after review; the branch is
   deleted on merge.

## Commit style

[Conventional Commits](https://www.conventionalcommits.org/):
`feat: add NIP-19 bech32 encoding`, `fix: correct event id hash`,
`docs: update AGENTS.md`, `chore: pin CI Zig version`.

## Releases

Milestones map to tagged releases (`v0.1.0`, `v0.2.0`, …). Tags are cut from
`main` once a milestone's acceptance criteria are met, with real release
notes and a `CHANGELOG.md` entry moved out of `Unreleased`.

## AI-assisted development

Contributors may use AI-assisted development tools, but all contributions
are held to the same bar regardless of how they were produced: reviewed,
tested, documented, and scoped like any other engineering work. AI-generated
code must pass CI, include tests, and be understandable by a human reviewer.

Contributors using AI agents can point them at [`AGENTS.md`](AGENTS.md) for
a structured overview of this repository, and [`CURRENT_STATE.md`](CURRENT_STATE.md)
for what's built so far and what's next.

## Security

Do not open public issues for security vulnerabilities — see
[`SECURITY.md`](SECURITY.md).
