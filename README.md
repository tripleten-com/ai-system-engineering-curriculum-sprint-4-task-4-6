# Coldline Task 4.6 — Governance decision and held-out check

This repository starts from the Task 5 checkpoint: the settled token verification and access
rule from Task 2, the settled output guardrail and audit events from Task 3, the settled PII
redaction from Task 4, and the settled secret read and security gate from Task 5. The controls
are in place; what is missing is an account of what they cover. Someone on the team asked an AI
assistant to summarize Coldline's security and governance position, and the result in
`docs/governance/ai-governance-analysis.md` reads confidently: it claims protections no test
shows, links controls to governance concerns they do not address, and leaves out risks the
threat model names. This Task adds the governance material around it: a risk register with the
five selected risks and empty fields, the roles that can own a risk, the governance concerns the
Project maps to, the decision policy, and a decision-record template. A development attack
scenario sends one combined attack through the same request, token, audit and evidence
interfaces the held-out check uses. You run it, correct the analysis, complete the register, map
one control to one concern, issue one technical decision, and pass the held-out check.

[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/tripleten-com/ai-system-engineering-curriculum-sprint-4-task-4-6/tree/main)

## Start the system

Prerequisites are Python 3.12 and Docker with Compose v2. The supplied bootstrap supports macOS
arm64/x86-64, Windows x86-64, and Linux x86-64/aarch64, and installs pinned uv 0.11.8 under
`.tools/bin`. If your computer cannot run the stack locally, use the Codespaces button above.

On macOS and most Linux distributions the interpreter is `python3`; substitute it wherever these
commands say `python`.

```shell
python infra/scripts/bootstrap.py
./.tools/bin/uv sync --frozen
./.tools/bin/uv run --frozen poe preflight
./.tools/bin/uv run --frozen poe start
./.tools/bin/uv run --frozen poe ready
./.tools/bin/uv run --frozen poe ingest
```

PowerShell and POSIX wrappers are available under `infra/scripts/`. After uv is on `PATH`, the
shorter `uv run --frozen poe <task>` form works; in PowerShell on Windows the pinned binary is
`.tools/bin/uv.exe`.

| Service | Local URL | Purpose |
|---|---|---|
| API | `http://localhost:8000` | Submit readings, poll exception summaries, search procedures |
| Token issuer: discovery document | `http://localhost:8180/.well-known/openid-configuration` | The development issuer's OIDC discovery document: its `issuer` and `jwks_uri` |
| Token issuer: key set | `http://localhost:8180/.well-known/jwks.json` | The published key set (JWKS) the settled `config/auth.yaml` names |
| Jaeger | `http://localhost:16686` | Open traces; the trace ids the audit records carry are these |
| Grafana | `http://localhost:3000` | Use the focused diagnostics dashboard |
| Prometheus | `http://localhost:9090` | Query bounded metrics and inspect the deployed alert rule |
| Alertmanager | `http://localhost:9093` | Inspect firing and resolved alerts |
| LocalStack S3/SQS/Secrets Manager | `http://localhost:4566` | The emulated object-storage, queue and secret-store endpoint |

Each of these ports can be overridden by setting the matching `COLDLINE_API_HOST_PORT`,
`COLDLINE_ISSUER_HOST_PORT`, `COLDLINE_JAEGER_HOST_PORT`, `COLDLINE_GRAFANA_HOST_PORT`,
`COLDLINE_PROMETHEUS_HOST_PORT`, `COLDLINE_ALERTMANAGER_HOST_PORT`, or
`COLDLINE_LOCALSTACK_HOST_PORT` environment variable in your shell environment or a local
`.env` file (copy `.env.example`) if a default collides with something already running on your
machine. Keep the override in place for every `poe` command. If you remap the issuer port,
keep `config/auth.yaml` unchanged: it is supplied in this Task and names the default port.
Host-side tools (`poe attack-dev`, the in-process test harness and `poe token-check`) resolve
the API's and the issuer's origins from `COLDLINE_API_HOST_PORT` and `COLDLINE_ISSUER_HOST_PORT`
(the environment, then `.env`, then the default), the secret tools resolve LocalStack's host
port from `COLDLINE_LOCALSTACK_HOST_PORT` the same way, and the API and the worker use the
Compose-network origins.

This Task runs as its own Compose project, `coldline-task-4-6`. If an earlier Task's stack is
still running, run `poe stop` in that Task's repository first; otherwise `poe start` here fails
because the published ports are already taken.

PostgreSQL, Redis, worker metrics, and OTLP remain inside the Compose network. Codespaces uses the
same `compose.yaml` and keeps every forwarded port private. Redis keeps running only for an
earlier checkpoint's own contract test; no composition root reads it anymore.

### What a run leaves behind

`poe attack-dev` writes `evidence/attack-dev.json`; the directory is Git-ignored and the file is
overwritten on every run, with a fresh exception each time. The register cites stages by name
(`attack-dev:redactor`), not exception ids, so a later run changes nothing you cited. The worker
container keeps the request records and the authentication record `poe pii-scan` and
`poe provider-auth-check` read; `poe reset` and `poe start` give a fresh stack and a secret
store that holds the first version again.

## Command path

For this Task, run the supplied commands in this order:

```text
poe start
poe ingest
poe attack-dev                           # Step 1
poe audit-trail <exception_id>           # the id attack-dev printed; confirm the event ids
poe answers                              # Steps 2 to 4, as you fill the sheet
poe held-out-dry-run                     # Step 4
poe verify
```

The exact public command is `./.tools/bin/uv run --frozen poe verify`, run from the repository
root. Where a Task page shortens a command to `poe <task>`, that is the form it means.

| Command | Use |
|---|---|
| `poe attack-dev` | Send the supplied development attack (`tests/fixtures/attacks/development.json`) through the running stack: one reading whose handling note carries personal details and whose answer the emulator manipulates, one summary read with an unauthorized token, one read as the dispatcher. Writes `evidence/attack-dev.json` with four stages (`token_check`, `output_schema`, `redactor`, `audit_trail`), each with what was sent, what the control did, an outcome (`held`, `limited`, `failed`), the exception id and, where the stage produced audit events, their ids; prints the stage summary. Needs the running stack; exit 2 means the run could not be made |
| `poe audit-trail <exception_id>` | Print one exception's audit records in order; the `#` column is the event id the evidence file names |
| `poe held-out-dry-run` | Exercise the held-out procedure's mechanism against a fake, non-secret scenario with every interface of the stack replaced by an in-memory stand-in, with no Docker: it reaches every interface and tells a pass, a failed grade and an unusable run apart. It is not the protected held-out check |
| `poe governance-contract` | The assessed rows: the four stages in the evidence file, every claim classified, the corrections and their citations, each register entry's control, test, evidence, owner and residual, the mapping and its note, the decision record's sections, the accepted risk, the wording scan and the sheet's format. Static; needs the evidence file from `poe attack-dev` |
| `poe answers` | The answer sheet's format only: a non-empty claim-review map keyed by claim ids with the four allowed values, a mapping with one control id and one concern id, a decision from the three allowed values, a register id as the accepted risk, and the sheet not a copy of `submission-sample.yaml` |
| `poe submission` | The same check plus the permitted-files boundary: the diff from your merge base touches only the four student files |
| `poe integrity-record`, `poe integrity-check` | The first and last steps of `poe verify`: hash your four files and the checks' own files into a snapshot outside the repository, then compare the tree with it, so a file that changed while the run was in progress is named |
| `poe verify` | The public student verification path: it starts the stack, runs the development attack and the held-out dry run, and runs this Task's assessed rows, the answer format and the boundary |
| `poe scenario [--response <name>] [--note <id>]`, `poe pii-scan <exception_id>`, `poe redaction-report`, `poe model-request <exception_id>` | Task 4's tools, kept for diagnosis: one reading through the stack with a supplied response and note; the four locations searched for a run's marked values; every supplied note's redacted form; the recorded request text |
| `poe token-check <fixture>`, `poe auth-checks`, `poe auth-config` | Task 2's diagnosis tools over the settled `config/auth.yaml` and the access rule, kept |
| `poe secret-status`, `poe secret-replace`, `poe provider-auth-check`, `poe secret-check-old` | Task 5's secret tools, kept; none prints a value. They are the evidence of the secret control, which the combined attack does not exercise |
| `poe security-setup`, `poe security-scan`, `poe seed-secret`, `poe seed-vulnerable` | Task 5's gate tools, kept as supplied; the `security-gate` job still runs `poe security-scan` on every pull request with the settled thresholds and suppression |
| `poe student-tests` | Run the supplied tests under `tests/student/`: the carried Task 4.4 redaction tests, the carried Task 4.3 guardrail and audit tests, and the Task 4.2 access-test file as the Project 4 checkpoints carry it. None is yours in this Task; your register may cite them by path and name |
| `poe queue-contract`, `poe slo-contract`, `poe gate-contract`, `poe runbook-contract`, `poe smoke`, `poe e2e` | Project 3's checks and the inherited platform checks, runnable as supplied; not part of this Task's `poe verify` |
| `poe contract` | Check interfaces, boundaries, submissions, and repository structure |
| `poe migrate`, `poe migrate-down`, `poe migrate-current` | Step the schema by hand; the initializer brings it to head on every start |
| `poe restart` | Restart the existing API and worker containers **without rebuilding** |
| `poe stop` | Remove containers and the network, keeping named volumes |
| `poe reset` | Remove containers, the network, and local named volumes |

`poe verify` records an integrity snapshot of your four files and the checks' own files, runs
the unit tests, starts the stack, ingests the supplied corpus, runs `poe attack-dev` (which
writes the evidence file), runs `poe held-out-dry-run`, then this Task's assessed rows, the
answer-sheet format check, the permitted-files boundary, and finally the integrity check against
the snapshot. The assessed step requires every one of its registered rows to have executed and
passed. The hosted public check runs the same command; the protected answer check and the
held-out check run on the platform after you submit.

## Folder map

```text
repository root/
├── .gitleaks.toml       The settled secret-scanner configuration from Task 5
├── .semgrepignore       The paths Semgrep leaves out
├── config/              Retrieval configuration, settled since Sprint 2, and the settled auth.yaml
├── docs/                Student guidance, public contracts, fidelity notes, the security and governance material
│   ├── contracts/       Machine-readable public contracts, including this Task's answer schema
│   ├── fidelity/        Local-runtime boundary notes for each active adapter
│   ├── governance/      The AI-generated analysis, the owners, the concerns, the decision policy (supplied); the risk register and the decision record (yours)
│   ├── security/        The supplied workflow, threat catalog, control matrix, access policy, output policy, audit events, redactor, and gate policy
│   ├── architecture/    Supplied vector engine technical profiles, in prose
│   ├── retrieval/       Supplied retrieval pipeline reference
│   └── student/         This Task's contract, the settled threat model, the supplied Project 3 runbook, and your corrections
├── evidence/            Git-ignored: the evidence file `poe attack-dev` writes
├── infra/               Local setup and runtime configuration
│   ├── containers/      The API and worker Dockerfiles, with the build identity arguments
│   ├── issuer/          The development token issuer: its server script and the published key set
│   ├── observability/   Prometheus, Alertmanager, and Grafana configuration
│   ├── release/         The supplied release manifest, unchanged
│   ├── corpus/          Supplied synthetic corpus (one procedure carries the planted instruction), query set, and investigation
│   ├── judge/           Supplied cached judge evidence and its provenance record
│   ├── profiles/        Supplied engine and emulator profiles, and their provenance record
│   └── postgres/        Database initialization and the migration baseline stamp
├── loadtest/            Supplied traffic profile and provider-latency harness
├── migrations/          Alembic environment, revision template, and revisions
├── reports/             Git-ignored: the scan report and the bill of materials `poe security-scan` writes
├── schemas/             The supplied output schema the guardrail enforces
├── security/            The settled gate thresholds, the scanner pins, the supplied Semgrep rules
├── src/
│   ├── api/             HTTP application code, the retrieval and document paths, composition, the initializer, the audit-trail command
│   │   └── security/    The settled TokenVerifier and require_access rule
│   ├── worker/          Background application code, the settled settings module, the procedure lookup, the guardrail, the redaction calls
│   ├── common/          The supplied audit sink and the supplied redactor both services use
│   ├── domain/          Shared domain code, contracts, the failure taxonomy, service and repository contracts
│   ├── ports/           Application interfaces
│   └── adapters/        Technology-specific implementations, including the secret-store adapter, the model emulator with its key check, the audit store, the SQS adapter
└── tests/
    ├── unit/            Isolated behavior checks, including the attack procedure's, the governance readers' and the integrity snapshot's
    ├── benchmark/       Supplied evaluation harness, metrics, and adoption policy
    ├── contract/        Interface, retrieval, and repository checks, this Task's assessed rows, the held-out procedure and its dry run
    ├── diagnostics/     Supplied stage inspector
    ├── doubles/         Supplied deterministic test doubles
    ├── failure/         Supplied Project 3 failure-lab and exercise scripts; not this Task's work
    ├── fixtures/        Supplied fixtures: the token fixtures, the credential values, the handling notes under pii/, the development attack under attacks/
    ├── security/        Supplied tooling: the attack procedure, the governance readers, the integrity bookends, the inherited harness, scan, secret and gate tools
    ├── student/         The carried Task 4.4, 4.3 and 4.2 test files; none is yours in this Task
    ├── smoke/           Running-platform checks
    └── e2e/             Supplied workflow tools and checks, including `poe scenario`
```

## Overview

Use the Task 6 lesson (Task 4.6 in this repository) to decide what to do. This README covers
local setup and repository orientation.

1. `README.md` — local setup, commands, and permitted changes.
2. [`docs/student/task-4-6-contract.md`](docs/student/task-4-6-contract.md) — what this Task
   assesses and who assesses it, the Check-list rows and the checks that read them, the citation
   forms, the wording rule, and the permitted paths.
3. [`docs/governance/ai-governance-analysis.md`](docs/governance/ai-governance-analysis.md) — the
   AI-generated analysis with its numbered claims; supplied as received, wrong in places.
4. [`docs/governance/concerns.md`](docs/governance/concerns.md),
   [`docs/governance/owners.md`](docs/governance/owners.md) and
   [`docs/governance/decision-policy.md`](docs/governance/decision-policy.md) — the concerns a
   mapping refers to, the roles that can own a risk, and the rules the decision follows.
5. [`docs/security/control-matrix.md`](docs/security/control-matrix.md) — the controls and the
   limit each one states; the register names controls by its ids.
6. [`docs/student/threat-model.md`](docs/student/threat-model.md) — the settled Task 1 threat
   model; the five register entries are its ranked threats, and its last section names risks the
   analysis may leave out.
7. `tests/fixtures/attacks/development.json` — the development attack: the token fixture, the
   refused answer and the note, with its marked values. The held-out scenario has the same shape
   and is never in this repository.
8. `tests/contract/held_out_review.py` — the public procedure the protected held-out job runs;
   its input is protected and never committed.

The application source lives in six flat packages:

| Package | Responsibility |
|---|---|
| `api` | HTTP delivery, API use cases, the retrieval workflow, versioned routes, token verification and the access rule, configuration, composition, the initializer, and the audit-trail command |
| `worker` | Background processing, retries, procedure lookup, the output guardrail, the redaction, the record readers, the settled settings module, and composition |
| `common` | The audit sink and the redactor the API and the worker share, and the event names |
| `domain` | Provider-neutral contracts, state rules, identity, embedding, chunking, fusion, access constraints, failure classification, service and repository contracts |
| `ports` | Exactly five visible application interfaces |
| `adapters` | PostgreSQL (exception records and audit records), pgvector retrieval, LocalStack SQS/DLQ, S3-compatible object storage, LocalStack Secrets Manager, the deterministic model emulator with its supplied responses, request log and key check, the resilient model-provider wrapper, logs, traces |

`src/api/bootstrap.py` and `src/worker/bootstrap.py` compose each process from its settings and
adapters. Process settings live in `src/api/config.py` and `src/worker/config.py`; the token
verification settings live in `config/auth.yaml`.

## The five ports

Find the available interfaces in `src/ports/`. A port describes an application capability; an
adapter provides it using a concrete technology.

| Port | General responsibility |
|---|---|
| `ModelProvider` | Call an AI model service; it returns the provider's raw answer text, which the worker redacts and the guardrail checks, and it authenticates the key the client presents |
| `Retriever` | Look up relevant context or documents; the worker calls it too |
| `ObjectStore` | Store large binary objects or files |
| `JobQueue` | Publish and consume background work |
| `SecretProvider` | Read API keys and credentials; the supplied LocalStack Secrets Manager adapter provides it |

## Test levels

| Level | Requires Compose | Main question |
|---|---|---|
| Unit | No | Does one responsibility behave correctly, including failures? |
| Contract | Some | Do interfaces, schemas, paths, and dependency rules stay compatible? |
| Smoke | Yes | Did the complete local platform initialize and become observable? |
| E2E | Yes | Can an external client complete the supplied workflow, in one trace? |
| Student | Issuer | Do the carried Task 4, 3 and 2 tests still hold over the supplied code? |

Contract checks marked `runtime` need the running stack. `poe contract` skips them; `poe
runtime-contract`, `poe queue-contract`, `poe slo-contract`, and `poe gate-contract` run them.
Contract checks marked `assessed` read your four files and the evidence file and are expected to
fail on a fresh checkout; `poe contract` skips them too, and `poe governance-contract` and
`poe verify` run them. The held-out dry run is an ordinary contract check: `poe contract`
includes it.

## Submission checks

Run `poe verify` locally before opening your student pull request. Public GitHub CI repeats
the student checks, running `poe answers` first so a malformed sheet fails fast, and the
`security-gate` job runs `poe security-scan` with the settled thresholds. The protected answer
check compares your claim review, your mapping, your decision and your accepted risk with the
expected values after you submit on the platform; no file in this repository holds those
values. The protected held-out job sends one attack you have not seen through the same
interfaces as the development scenario, against the supplied controls, and reports `success`,
`failure`, or `error` on your pull request's exact commit; it never prints the scenario, and
your documents cannot change its result. Follow the Task lesson's instructor-review and
progression policy.

## Task boundary

Task 4.6 asks you to run `poe attack-dev`, correct the AI-generated analysis in
`docs/student/governance-corrections.md`, complete `docs/governance/risk-register.yaml`, write
`docs/governance/decision-record.md`, record the four answers in `submission.yaml`, run
`poe verify`, open a pull request that changes only those files, and add the stage summary from
`evidence/attack-dev.json` and your decision with its accepted risk to the pull request
description, with each command and when you ran it; after you submit, add the held-out check's
visible result, its timestamp and the assessed commit.

The only student-editable paths are:

- `submission.yaml`
- `docs/student/governance-corrections.md`
- `docs/governance/risk-register.yaml`
- `docs/governance/decision-record.md`

Keep the analysis, the owners list, the concerns, the decision policy, the attack scenario, the
procedure, the code, the configuration, the tests and the workflows exactly as supplied; the
public check compares the diff from your merge base against the four files and reports any
other change as a boundary violation, and the held-out job refuses to grade a submission that
changed the supplied system. If the evidence shows a control is weaker than you thought, that
belongs in the register and the decision, not in a code change.

### Student walkthrough

See **Task 6: Governance decision and held-out check** in your course platform for the full
walkthrough. In outline: start the stack, run `poe attack-dev` and read the evidence stage by
stage, classify every claim and write the corrections, complete the register and map one
control, apply the decision policy and write the decision record, run `poe verify`, open and
merge your pull request, and submit on the platform.

## Operational limits

This local system does not authenticate users against a managed identity provider, terminate
TLS, or manage production secrets. The token issuer is a development service: it publishes one
fixed key set over plain HTTP and issues no tokens; the eight fixtures were signed once and
committed. The Compose PostgreSQL password and the LocalStack access keys are development
values, listed once more in `tests/fixtures/credentials/test-values.yaml` so the audit checks
can search for them. Never place real credentials, personal data, or production records in
this repository. Every handling note in this repository, the development attack's included, is
synthetic. Test with the supplied readings, notes, and scenario only; do not search for,
request, or try to reconstruct the held-out attack.

The development attack is one attack: it shows how four controls handled one unauthorized
caller, one manipulated answer and one note with three kinds of personal detail. A stage that
held shows that control on those inputs, not on inputs nobody sent; a stage that was limited
shows a documented limit of the control, which belongs in the register as residual risk. The
held-out check adds one more attack the student did not rehearse; a pass there does not show
the controls resist attacks nobody tested.

The secret store is LocalStack Secrets Manager: it shows the read path and the version check,
not how AWS Secrets Manager, IAM, or KMS would decide who may read the secret. See
[SecretProvider fidelity](docs/fidelity/SecretProvider.md). The emulator's key check is a
property of this emulator. See [ModelProvider fidelity](docs/fidelity/ModelProvider.md).

The scanners find what their rules and their database cover, at the versions pinned in
`security/scanners.yaml`; an absent finding is not an absent weakness, as
`docs/security/gate-policy.md` states.

Alertmanager here is configured with a "default" receiver that has no notification integration:
alerts are queryable through its own API but never sent anywhere real. Never add a webhook, email,
Slack, or paid integration; Sprints 1-4 are emulator-only and never call a hosted endpoint.

LocalStack's SQS emulation is a local reliability primitive, not a managed-service durability,
IAM, availability, or cost claim. See [JobQueue fidelity](docs/fidelity/JobQueue.md) for the
exact boundary.

Named volumes preserve local PostgreSQL, Redis, Prometheus, Alertmanager, Grafana, and Jaeger state
across `poe stop`; the audit table is in the PostgreSQL volume. LocalStack object, queue and
secret contents are deliberately not persisted; the initializer re-uploads the supplied corpus
artifacts, re-provisions the queue and re-creates the secret's first version on every start. The
worker's request records and its authentication record live inside the worker container and are
gone when it is recreated. The `poe reset` command deletes the named volumes. This topology makes
no backup, replication, high-availability, disaster-recovery, capacity, latency-SLO, or
availability claim beyond what Project 3 settled.

See [TokenIssuer fidelity](docs/fidelity/TokenIssuer.md),
[JobQueue fidelity](docs/fidelity/JobQueue.md),
[ModelProvider fidelity](docs/fidelity/ModelProvider.md),
[SecretProvider fidelity](docs/fidelity/SecretProvider.md),
[ObjectStore fidelity](docs/fidelity/ObjectStore.md), and
[Retriever fidelity](docs/fidelity/Retriever.md) for the active adapter boundaries. The
[local runtime evidence](docs/fidelity/local-runtime.md) records the current measurement and its
qualification limits.
