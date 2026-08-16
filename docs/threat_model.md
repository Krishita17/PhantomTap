# PhantomTap threat model & responsible-use policy

PhantomTap is a **defensive access-control auditing tool**. Its deliverable is a
scored, explainable security assessment that a physical-security assessor or a
building owner would use to *find and fix* weak badge systems. It is not a
device for gaining unauthorized entry. This document is deliberately part of the
repository, not an afterthought.

## Intended use

- Authorized physical-security assessment and academic research.
- Producing an audit report that ranks how weak a deployment is, and why, with
  concrete remediation.

## Auditor capability (in scope)

An operator of PhantomTap may:

- Read credentials they are **authorized** to test.
- Query readers they **own** or are **contracted to assess**.
- Model and characterize *their own* or *synthetic* credential populations to
  measure and demonstrate weakness.

## Explicit scope limits (out of scope)

- **All experiments in this repository use synthetic credential populations or
  the author's own cards/readers.** The synthetic generator is the primary
  workbench; the hardware path targets only the author's own equipment.
- The repository ships **no real facility credentials, no site-specific keys,
  and no "clone a stranger's badge" workflow.**
- The candidate generator is demonstrated against a **simulated reader**. It is
  not tuned to defeat any specific commercial product.
- Only **public, well-documented** reference material is included (published
  Wiegand format layouts; publicly known default keys used for *detection*).

## What is deliberately *not* built

- No turnkey cloning/relay attack against third-party systems.
- No collection or storage of real personal credential data.
- No evasion tooling aimed at defeating a named commercial reader.

## Data handling

- Commit only synthetic samples and de-identified reads of the author's own
  test cards.
- Never commit real credentials tied to any real facility or person.
- Treat any captured RF data as sensitive; keep it local.

## Legal & ethical notice

Testing any access-control system you do not own requires **prior written
authorization** from the system owner. Unauthorized reading, cloning, or
replaying of access credentials may be illegal in your jurisdiction. This tool
is for defenders, assessors, and researchers operating within a lawful,
authorized scope. The author and contributors accept no liability for misuse.

## Reporting

If you find a security issue in PhantomTap itself, open an issue describing the
problem (without including any real credential data).
