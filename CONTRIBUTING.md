# Contributing to LoopLedger

Thank you for helping. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) first.

## Licenses by path

Each path has one license (decision LL-002). By contributing you agree your contribution is under the license of the
path it lands in.

| Path | License |
|---|---|
| `packages/spec`, `packages/vocab` (the passport spec and the vocabularies) | Community Specification License 1.0 |
| `packages/corpus/data` (the jurisdiction corpus) | CDLA-Permissive-2.0 |
| Everything else (the ledger, router, adapters, UI, resolver, tooling) | Apache-2.0, see [LICENSE](LICENSE) |

The license texts are in [LICENSE](LICENSE) and [LICENSES/](LICENSES). Apache-2.0 doesn't license the "LoopLedger"
name or marks.

## Public paths

Development is private. Each merge to `main` adds one commit to github.com/loopledger/loopledger with only these paths
(the allowlist is `mirror.paths`; the mirror carries no private history):

- `packages/spec`, `packages/vocab`, `packages/ports`, `packages/ledger`, `packages/corpus`, `packages/drill`,
  `packages/adapters/*`, `packages/router` and `packages/ui`
- `LICENSE`, `LICENSES/`, `SECURITY.md`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `README.md`, `package.json`, `pnpm-lock.yaml`,
  `pnpm-workspace.yaml`, `tsconfig.json`, `vitest.config.ts`, `.nvmrc` and `.gitignore`

Everything else stays private, including `scripts/` and `docs/requirements/`.

The published root `package.json` leaves out the private `@lemur-labs/kit` dependency and the scripts that run files
under the private `scripts/`, and its `pnpm-lock.yaml` is regenerated to match, so `pnpm install` works in the public
tree.

## Contributing from outside

The public repository is a one-way mirror. A pull request opened there can't be merged, and the next publish leaves it
behind. So:

- Open an [issue](https://github.com/loopledger/loopledger/issues) for a finding, a question or a proposed change. A
  change to the spec or a vocabulary starts as an issue titled `RFC: <change>`.
- If you have a patch, link the branch in your fork from the issue. A maintainer ports it and credits you with a
  `Co-authored-by` trailer.
- Sign off every commit (`git commit -s`). Your sign-off certifies the
  [Developer Certificate of Origin](https://developercertificate.org/): that you may contribute the change under the
  license of the path it lands in.
- Report security issues privately, as [SECURITY.md](SECURITY.md) says, never in a public issue.

## What each kind of contribution needs

- **Spec and vocabularies.** The passport schema, the vocabularies (joint type, material, cause), and the revision and
  feature performance records are spec. Every design tool and every pooled benchmark depends on their meaning holding
  still, so they change only through the RFC process: two maintainers approve, and changes ship in versioned releases.
  Every crossover term is governed the same way.
- **Corpus entries.** Each entry carries `extracted-by` and `verified-by`. Verification needs an identified reviewer who
  accepts responsibility for the entry. An unverified entry is advisory only: it never activates in a router.
- **Adapters.** An adapter ships with conformance tests against the event envelope, and is accepted when its events
  round-trip the validation suite. A feedback adapter is accepted when its output recomputes from the cited ledger
  checkpoint.
- **No outside material.** Don't import proprietary catalogs, branded assets or confidential operator data.
- **Data grants.** Catalog and performance data are governed by data grants, not contributions: a manufacturer or
  financier sees a tenant's record only under a grant both sides signed.

## How a change lands (maintainers)

- Every change is a pull request, and the merger squash-merges it.
- Commits use Conventional Commit subjects and end with a `Refs: Lemur-Labs/loopledger#N` (or `Closes`) trailer.
- Never put a secret in a file, a log or a commit.
- Every behaviour change has a requirement in `docs/requirements/` and a test that names its id.
- Run these before opening a pull request:

```sh
pnpm typecheck
pnpm test
pnpm exec kit workflows
pnpm trace
```
