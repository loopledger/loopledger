# Governance

## Roles

- **Maintainers** approve and merge changes and run releases. Current maintainers: the project owner ([@thelemurcodes](https://github.com/thelemurcodes)).
- **Contributors** are anyone who files an issue, an RFC, a review or a patch.

## Decisions

- **Spec and vocabularies** (`packages/spec`, `packages/vocab`) change only through an RFC: an issue titled `RFC: <change>`, open for public comment for at least 14 days, then approved by two maintainers and shipped in a versioned release. Until there is a second maintainer, the owner approves after the comment period and records the decision on the issue.
- **Corpus entries** carry `extracted_by` and `verified_by`. An entry without an identified verifier is advisory only and never activates in a router.
- **Code** changes are pull requests approved by a maintainer.
- **Neutrality:** no operator, including any future anchor tenant, gets governance rights in proportion to its size. Readiness gates, certification criteria and corpus verification standards change only through the RFC process.

## Data

Catalog and performance data are governed by data grants, not contributions: a manufacturer or financier sees a tenant's record only under a grant both sides signed.

## Continuity

Passports must keep resolving after the project does. The loopledger.org domain and the published schema and vocabulary IRIs are held for that purpose. When the project joins a host (the Joint Development Foundation track is the intended one), the host holds them in trust, with a documented handover if the project dissolves.

## Changing this document

Through an RFC, as for the spec.
