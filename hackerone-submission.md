# HackerOne submission — body fields

Paste each field below into the corresponding form section. Title and weakness/severity
first, then the long-form fields.

---

## Title

`Challenge-response artifacts (hsw, motionData, challenge key) are not bound to the
requesting client, enabling automated bypass by token replay across TLS identities`

Short alternative if the title field is character-limited:

`hsw/motionData artifacts are replayable across clients and connections — automated
challenge bypass`

---

## Weakness

**Primary:** `CWE-294` — Authentication Bypass by Capture-replay
**Secondary:** `CWE-345` — Insufficient Verification of Data Authenticity

Rationale: the human-verification result is derived from artifacts that are produced
client-side, transmitted as plain fields, and accepted without any binding to the
connection, TLS fingerprint, or device that produced them. A captured or re-computed
artifact can be presented by a different client and is accepted.

---

## Severity

**Suggested: High — CVSS 3.1 7.5**

`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N`

| Component | Assessment |
|---|---|
| Attack Vector | Network — the entire flow is HTTP(S) |
| Attack Complexity | Low — no race, no special conditions; artifacts are deterministic given inputs |
| Privileges Required | None — no account needed to request a challenge |
| User Interaction | None — the "human" step is performed offline, out of band |
| Scope | Unchanged |
| Confidentiality | None |
| Integrity | High — the integrity of the "human present" assertion is what fails |
| Availability | None |

Rationale for High rather than Critical: the vulnerability does not disclose data or
enable code execution, and exploitation at meaningful scale requires the attacker to have
built a challenge-trained model first (a cost, not a barrier). Rationale for High rather
than Medium: on a high-value deployment the consequence is automated account creation at
scale, and the cost of entry is a Python client plus a consumer GPU.

Severity is offered as an assessment, not a demand; the triage team's rating governs.

---

## Description

The hCaptcha challenge flow is built from four client-side artifacts:

1. `hsw` — the device-integrity value computed from the `req` JWT;
2. `motionData` — the pointer/telemetry blob;
3. `c` — the site-configuration blob, echoed verbatim from `checksiteconfig`;
4. `key` — the per-challenge identifier returned with the `tasklist`.

Each is verified in isolation. None is cryptographically bound to the connection that
produced it, the TLS/JA4 fingerprint of the client, or a device-held key. They are
therefore independent assertions, and each can be satisfied from a context that is not the
client making the eventual request.

The practical consequence is that the entire flow can be driven by a non-browser HTTP
client:

- `hsw` is a deterministic JavaScript computation. It can be produced once per `req` inside
  a controlled headless browser and then submitted from an unrelated process, on an
  unrelated host, over an unrelated TLS stack.
- `motionData` is plain JSON assembled by JavaScript the caller controls. A recorded human
  trace with programmatic jitter is accepted as "human interaction".
- The challenge taxonomy is stable and the images are fetchable, so a labelled corpus can
  be accumulated by having a human answer a few hundred challenges per class, and a
  supervised model trained on it answers that class thereafter. The class then stops being
  a challenge.
- Because `c` and `key` are not bound to a session identity, a challenge fetched under one
  egress IP can be answered and submitted under another, which neutralises per-IP issuance
  limits.

We are not reporting that the visual puzzles are weak. We are reporting that the *evidence
of humanness* is not bound to the entity presenting it, which makes puzzle strength a
secondary question.

Cost to the attacker: a Python HTTP client with a Chrome-like TLS fingerprint, a proxy
pool, and a consumer GPU. This is commodity tooling, not a browser exploit.

---

## Steps to reproduce

Structural reproduction only. We have not run this against production and have created no
accounts. Field-level detail (exact header order, accepted `motionData` schema, timing
tolerances) is available to the hCaptcha team on request under the same embargo.

1. **Issue a site config.** POST `https://api2.hcaptcha.com/checksiteconfig` with
   `v`, `sitekey`, `host`, `sc=1`, `swa=1`, `spst=1`. Note the returned `c.req` (a signed
   JWT) and `c`.

2. **Compute `hsw` out of band.** Take `req`, compute the `hsw` value in a headless
   Chromium instance that is *not* the client that will submit. Record the resulting
   string.

3. **Fetch a challenge from a different network identity.** From a second process on a
   different egress IP, POST `https://api.hcaptcha.com/getcaptcha/{sitekey}` with
   `v`, `sitekey`, `host`, `hl`, `motionData` (synthesised), `n` (the value from step 2),
   and `c` from step 1. Observe a `tasklist` and `key` are returned to this second
   identity.

4. **Observe acceptance of the transplanted artifact.** The token from step 2 was minted
   by a client with one TLS fingerprint and presented by a client with a different one.
   No challenge re-issuance or rejection is triggered by the mismatch.

5. **Submit from a third identity.** POST
   `https://api.hcaptcha.com/checkcaptcha/{sitekey}/{key}` with the same `n` value
   (re-presented), a second `motionData` blob, and an `answers` map. Observe that the
   request is processed and a `pass` / `generated_pass_UUID` can be returned without the
   submitting client ever having produced a browser-executed attestation of its own.

The reproduction demonstrates the missing binding, not the puzzle-solving capability. Step
3's `motionData` and step 5's `answers` may be arbitrary values — the point under test is
that steps 2, 3, and 5 succeed from three different contexts.

---

## Impact

An attacker with the above toolchain can obtain valid hCaptcha pass tokens without
presenting a browser or a human, at a rate limited only by their infrastructure. On a
high-value deployment this enables:

- **Automated account creation** at scale, with the captcha no longer a meaningful gate;
- **Pass-token harvesting and resale**, defeating the assumption that a token implies a
  human;
- **Credential-stuffing and spam automation** against protected endpoints, since the
  anti-automation control can be satisfied programmatically;
- **Undermining per-IP mitigations**, because challenge issuance and submission can be
  performed under different network identities.

The blast radius is largest for integrators who rely on hCaptcha as their primary
anti-automation control, which is the common case for the deployment where this was
observed.

---

## Supporting material

Attached:

1. `hcaptcha-automation-bypass-disclosure.md` — full report: six findings
   (`hsw` portability, `motionData` forgery, harvestable challenge taxonomy, unbound
   `c`/`key`, absent device-level budgets, unvalidated TLS/UA mismatch), each with
   mechanism, impact, remediation, and a prioritised roadmap (Section 7), plus detection
   guidance applicable to existing traffic (Section 8).

2. Sanitized flow diagram — Appendix A of the attached report.

Deliberately **not** attached, and available on request under embargo: the `hsw` algorithm,
the accepted `motionData` schema, model weights, and harvest scripts. We consider those
unnecessary for remediation and would prefer they not circulate.

---

## Remediation

The root cause is that the artifacts are verified in isolation. The fix is to bind them
into a single per-round proof:

```
round_id    ← issued server-side at checksiteconfig
attestation ← { hsw, motion_hash, key_possession, tls_fingerprint }
              signed once, in the client, over round_id
submission  ← { answers, attestation, round_id }  (same connection)
```

Any party able to produce all of these is, by construction, the client the round was issued
to.

Prioritised:

| Priority | Change | Closes |
|---|---|---|
| P0 | Single-use, connection-bound `hsw`; reject TLS/UA mismatch at issuance | token replay, transport spoofing |
| P0 | Bind `c` and `key` to a server session record; expire `key` on first submit | cross-session mixing |
| P1 | Per-session class caps and diversity quotas | offline model training |
| P1 | Session-to-IP stability; per-device issuance budgets | proxy rotation |
| P2 | Signed hash chain over raw widget events; server-side timing model | `motionData` forgery |
| P2 | Per-session image perturbation and watermarking | corpus harvesting, retroactive attribution |
| P3 | Device-bound attestation (Private Access Tokens / Web Bot Auth) | whole class, for high-value integrators |

Details, rationale, and the inference caveats for each are in the attached report.

---

## Disclosure and notes for triage

- This is a **coordinated disclosure**. 90-day embargo from acknowledgement, extendable if
  fixes are in progress. No public write-up of reproduction detail; any publication will
  cover the design issue and remediation only.
- Findings dependent on server-side behaviour we cannot observe are marked *inferred* in
  the attachment. We would like the team to confirm or refute those internally rather than
  treat them as proven.
- We have not run the described attack against production and have not created accounts.
- We are happy to take a call and to share field-level detail privately.
- If this belongs with a different team or a different program, a redirect would be
  appreciated rather than a closure.
