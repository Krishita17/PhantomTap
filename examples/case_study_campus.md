# PhantomTap Fleet Audit — Acme HQ campus

**Fleet risk (weakest-link):** **69/100** → **HIGH**  
**Facilities:** 4 · **Total credentials:** 480 · **Weakest facility code:** 42  

> A fleet is only as strong as its weakest building: the composite weights the worst facility at 70%.

## Per-facility risk

| Facility code | Deployment | Risk | Band | Top finding |
|--------------:|------------|-----:|------|-------------|
| 42 | `lobby (fc42)` | 75 | CRITICAL | Credential guessing-resistance: 0.0 bits (TRIVIAL) |
| 205 | `west-wing (fc205)` | 62 | HIGH | Credential guessing-resistance: 0.0 bits (TRIVIAL) |
| 118 | `east-wing (fc118)` | 56 | HIGH | Sector key hygiene |
| 250 | `datacenter (fc250)` | 22 | LOW | Attempts-to-characterize |

## Highest-risk facility in detail

# PhantomTap Access-Control Audit Report

**Deployment:** `lobby (fc42)`  
**Composite risk score:** **75/100** → **CRITICAL**  

> Higher score = weaker / more easily audited deployment. This assessment was produced against a synthetic or author-owned system for defensive evaluation only.

## Findings (most severe first)

| # | Severity | Factor | Finding |
|---|----------|--------|---------|
| 1 | 🟥 CRITICAL | `guessability` | Credential guessing-resistance: 0.0 bits (TRIVIAL) |
| 2 | 🟥 CRITICAL | `clonability` | Card family: UID-only (no authentication) |
| 3 | 🟥 CRITICAL | `numbering` | Numbering scheme: sequential |
| 4 | 🟧 HIGH | `format` | Credential format: H10301-26 (26-bit) |
| 5 | 🟧 HIGH | `characterization` | Attempts-to-characterize |
| 6 | ⬜ INFO | `keys` | Sector keys: not applicable |

### 1. Credential guessing-resistance: 0.0 bits (TRIVIAL)  🟥 CRITICAL

- **Factor:** `guessability` (sub-score 100/100)
- **Detail:** A blind adversary faces ~17.1 bits of guessing to forge a valid credential; one that reasons about structure (locked facility code + bounded 120-wide range at 100.0% density) faces only ~0.0 bits. This deployment therefore **leaks ~17.1 bits** of credential security to a structure-aware attacker.
- **Remediation:** Widen the effective key space that survives inference: randomise card numbers across the full field and authenticate the credential so a guessed number alone is worthless.

### 2. Card family: UID-only (no authentication)  🟥 CRITICAL

- **Factor:** `clonability` (sub-score 95/100)
- **Detail:** Credentials are UID-only low-frequency prox / read-only cards. They carry no secret and can be cloned to a blank in seconds by any reader.
- **Remediation:** Replace UID-only prox with a challenge-response smart credential; never authorise access on UID alone.

### 3. Numbering scheme: sequential  🟥 CRITICAL

- **Factor:** `numbering` (sub-score 92/100)
- **Detail:** Card numbers are issued strictly sequentially. Knowing one valid card lets an assessor predict every neighbour with near certainty.
- **Remediation:** Issue card numbers from a cryptographically random, non-guessable pool and decouple them from any physical/temporal issuance order.

### 4. Credential format: H10301-26 (26-bit)  🟧 HIGH

- **Factor:** `format` (sub-score 100/100)
- **Detail:** HID 26-bit, the ubiquitous legacy format. Tiny 8-bit facility code space (0-255) makes facility collisions and guessing trivial. The card-number field is 16 bits (max 65,535), and the facility-code field is 8 bits (max 255).
- **Remediation:** Migrate to a high-bit-count, cryptographically authenticated credential (e.g. Seos / DESFire EV2/EV3, iCLASS SE) rather than a static Wiegand format that can be read and replayed.

### 5. Attempts-to-characterize  🟧 HIGH

- **Factor:** `characterization` (sub-score 100/100)
- **Detail:** Guided search characterised 90% of the issued population in 101 reader queries versus ~2,792,790 for brute force (~27,651x fewer attempts). Low attempts-to-characterize is itself a weakness signal.
- **Remediation:** Randomised numbering and authenticated credentials both raise the query cost of mapping the population.

### 6. Sector keys: not applicable  ⬜ INFO

- **Factor:** `keys` (sub-score 0/100)
- **Detail:** UID-only credentials have no sector key material.
- **Remediation:** n/a

## Efficiency evidence

| Strategy | Reader queries to characterize 90% |
|----------|-----------------------------------:|
| Brute force | 2,792,790 |
| Static dictionary | 892,246 |
| **PhantomTap (ML-guided)** | **101** |

PhantomTap characterized the population with roughly **27,651× fewer** reader interactions than blind brute force.

### Bayesian population sizing

Active-learning boundary search estimated **~130 issued credentials** (true: 120, error 8%) in just **206 reader queries** — recovering the population size in O(log N) rather than scanning O(N). A low error here is itself a weakness: the population is compact and predictable.

### Information-theoretic guessing-resistance

A blind adversary faces **~17.1 bits** of guessing to forge a valid credential; a structure-aware one faces only **~0.0 bits** (TRIVIAL). The deployment **leaks ~17.1 bits** of credential security to anyone who reasons about its structure instead of brute-forcing.

---
*Generated by PhantomTap. Authorized, defensive use only.*