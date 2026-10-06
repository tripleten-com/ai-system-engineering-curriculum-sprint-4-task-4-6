# Task 4.6 — Governance decision and held-out check contract

Run the supplied development attack, correct the AI-generated governance analysis, complete the
risk register, map one control to one governance concern, issue one technical decision, and pass
the held-out check. You write three documents and the sheet; you change no code, no
configuration, no test and no workflow.

## What is assessed, and by whom

| Assessed | By |
|---|---|
| The pull request changes only `submission.yaml`, `docs/student/governance-corrections.md`, `docs/governance/risk-register.yaml` and `docs/governance/decision-record.md` | Automated, in this repository (`poe submission` inside `poe verify`, and the boundary test under `poe contract`); the protected held-out job applies the same boundary before it grades |
| The register keeps its five supplied entries, in their order, each with its supplied id, threat and title, holds `risks` as its one top-level key, and changes only the six completion fields | Automated, in this repository (`poe verify`): every register row reads the register through the same loader, which refuses a key beside `risks`, an entry removed, added, reordered or renamed, and YAML with duplicate keys, aliases, anchors, merge keys or non-JSON tags |
| Nothing under the four files or the checks' own files changed while `poe verify` ran | Automated: `poe verify` records a hash snapshot as its first step and checks it as its last |
| `evidence/attack-dev.json` records an outcome for the token check, the output schema check, the redactor and the audit trail | Automated (`poe verify`): `poe attack-dev` writes it during the run and the first assessed row reads it |
| Every numbered claim of the analysis has one classification in `answers.claim_review`, from the four allowed values, and no other id does | Automated, in this repository (`poe verify`) |
| The corrections have one entry per claim not classified `supported`, with its three lines, and at least one omitted-risk entry; every entry cites a file, a test, an attack-evidence stage or a pull request that resolves | Automated, in this repository (`poe verify`): the structure and the citations; the content is read at the Task 7 Instructor Review |
| Every register entry names a control id from `docs/security/control-matrix.md`, a test that pytest collects, an evidence record (a stage in `evidence/attack-dev.json`, or a pull request citation in the documented form), an owner role from `docs/governance/owners.md`, and a residual risk that is not "none" | Automated, in this repository (`poe verify`); the register's content is read at the Task 7 Instructor Review |
| `answers.governance_mapping` names a control recorded in the register and a concern id from `docs/governance/concerns.md`, and that entry's `mapping_note` is filled | Automated, in this repository (`poe verify`) |
| `answers.decision` is one of the three values, the decision record's Decision section carries exactly one `Outcome:` line and it agrees, the section carries a rationale beyond that line, and the Evidence and outcome-specific sections are filled with no template marker left; for a conditional go or a no go, every condition or required change is one `### <heading>` entry whose `Applies to` (the rule and what it applied to: `C1:attack-dev:<stage>` or `C2:R-nn` for a condition, `N1`, `N2` or `N3` for a required change), `What must be true`, `Owner` (a role id of `docs/governance/owners.md`) and `Evidence` (a citation that resolves) lines are filled; for a conditional go the labels are exactly the rules that applied, one entry each: one per `limited` stage in `evidence/attack-dev.json` and one per register entry whose evidence is a pull request citation | Automated, in this repository (`poe verify`): the shape, the labels against the evidence and the register, and the citations; whether a condition is sound is read at the Task 7 Instructor Review |
| The corrections and the decision record are read as they render: a section, an entry or a line inside an HTML comment (`<!-- -->`) counts as nothing | Automated, in this repository (`poe verify`): the structural rows parse the visible Markdown; the wording scan reads the raw text, comments included |
| `answers.accepted_risk` names a register entry, and the record's Accepted risk section names the same entry, the owner role the register records for it, why it is acceptable now, and what evidence would change the decision | Automated, in this repository (`poe verify`) |
| None of the four files claims compliance or certification in your own words | Automated, in this repository (`poe verify`): the wording scan below |
| `submission.yaml` is in the published shape and is not a copy of the sample | Automated, in this repository (`poe answers`, repeated by `poe verify`) |
| Your claim review, your mapping, your decision and your accepted risk | Protected automated check, after you submit on the platform; no check in this repository reads the correct values |
| The supplied controls hold against one attack you have not seen | Protected held-out job, after you submit on the platform; it grades the supplied controls, never your documents, and reports `success`, `failure` or `error` without describing the scenario |
| The soundness of your corrections, your residual risks, your mapping note and your conditions; the stage summary, your decision and the held-out result in the pull request description | Your instructor, at the Task 7 Instructor Review; you defend the accepted risk at the Project Defense |

## The supplied material

| Supplied | Where | Note |
|---|---|---|
| The AI-generated analysis | `docs/governance/ai-governance-analysis.md` | Twelve numbered claims (`### CL-nn`), as received. Not student-editable; nothing in it is evidence |
| The risk register | `docs/governance/risk-register.yaml` | Five entries: the settled Task 1 top five, in rank order, with their register ids, threat ids and titles supplied and six fields empty. Yours to complete; the supplied ids, threats and titles stay, in their order |
| The owner roles | `docs/governance/owners.md` | Four role ids and the rule that says which one owns a risk, read from the residual |
| The governance concerns | `docs/governance/concerns.md` | Eight concern ids with their intent, their sources (for educational use) and the criteria a control must meet to serve each. It names no control: which control serves which concern follows from the criteria, the control matrix and the evidence |
| The decision policy | `docs/governance/decision-policy.md` | The stage-outcome vocabulary, the no-go, conditional-go and go rules by id, what a condition must contain (its `Applies to` label among the four lines) and the entry shape it takes, and which residual risks may be accepted |
| The decision record | `docs/governance/decision-record.md` | The template, with its headings, its condition and required-change entry shape (four labelled lines each), and `[fill in: ...]` markers. Yours to write |
| The corrections | `docs/student/governance-corrections.md` | The template, with the two sections and the entry shape. Yours to write |
| The control matrix | `docs/security/control-matrix.md` | The control ids the register names, with the limit each Project control states |
| The development attack | `tests/fixtures/attacks/development.json` | One unauthorized token fixture, one refused answer, one handling note with its marked values. The held-out scenario has the same shape and is never in this repository |
| The attack procedure | `tests/security/attack_scenario.py`, `tests/security/attack_dev.py` | `poe attack-dev`: the four stages, their outcomes and what each records |
| The held-out procedure | `tests/contract/held_out_review.py`, `tests/contract/test_held_out_review_module.py` | The protected job's procedure and `poe held-out-dry-run` |
| The governance readers | `tests/security/governance.py` | What the assessed rows parse: the ids, the register, the corrections, the decision record, the citation forms, the wording scan |
| The assessed-module runner and the integrity snapshot | `tests/security/assessed_run.py`, `tests/security/integrity.py` | `poe governance-contract`, `poe integrity-record`, `poe integrity-check` |
| The carried completions | `src/worker/config.py`, `src/worker/procedures.py`, `security/gate.yaml`, `.gitleaks.toml`, the Task 4.4, 4.3 and 4.2 files | The Task 5 completion and the earlier ones, supplied and settled. Not student-editable |

## The four steps

### Step 1 — Run the development attack and collect the control evidence

Start the stack as `README.md` describes, ingest the corpus, and run `poe attack-dev`. Open
`evidence/attack-dev.json`: four stages, in order, each with `sent`, `result`, `outcome`,
`exception_id` and `audit_event_ids`. Where a stage names audit event ids, run
`poe audit-trail <exception_id>` and confirm those ids appear. Compare each stage's outcome with
what its control is meant to do; `held`, `limited` and `failed` are defined in
`docs/governance/decision-policy.md`. A stage that is `limited` is the evidence the register and
the decision need, not a broken run to fix. Copy the stage summary the command prints for the
pull request.

### Step 2 — Correct the AI-generated analysis

Read the twelve claims. For each one, find the code, test or evidence record that would support
it; `docs/governance/concerns.md` defines the concerns a mapping claim refers to. Classify each
claim in `answers.claim_review` in the order the sheet's comments state, and write one entry in
`docs/student/governance-corrections.md` for each claim that is not `supported`, plus at least
one omitted-risk entry. Run `poe answers`.

### Step 3 — Complete the risk register and map one control

For each register entry record the control id, the test as `<path>::<test name>`, the evidence
record, the owner role id and the residual risk; the supplied id, threat and title of each
entry stay as they are. Choose one control from the register and one concern of
`docs/governance/concerns.md` whose every criterion that control meets, as the control matrix
describes the control and the evidence shows it; record both in `answers.governance_mapping`
and write that entry's `mapping_note`. Run `poe answers`.

### Step 4 — Issue the technical decision and pass the held-out check

Apply `docs/governance/decision-policy.md` to your register and the stage outcomes; record the
outcome in `answers.decision` and write `docs/governance/decision-record.md`: the rationale under
the `Outcome:` line, the evidence, and, for a conditional go or a no go, one `### <heading>`
entry per rule that applied with its `Applies to` (`C1:attack-dev:<stage>` for a `limited`
stage, `C2:R-nn` for an entry whose evidence is an earlier Task's run), `What must be true`,
`Owner` and `Evidence` lines. Choose one residual risk the policy allows you to accept, record it in
`answers.accepted_risk`, and fill the Accepted risk section with the owner your register
records for that entry. Run `poe verify`, which includes `poe held-out-dry-run`. After you
submit, the platform runs the protected answer check and the held-out check.

## Citation forms

The register's `test` field, its `evidence` field, every `Evidence:` line of the corrections and
every `Evidence:` line of a condition or required change in the decision record are read by
machine. The forms:

| Cites | Form | Resolves when |
|---|---|---|
| A test | `<path>::<test name>` (`tests/student/test_audit.py::<name>`; a parametrized test by its function name, a method as `Class::name` or by its bare name) | pytest collects that case from that module |
| A stage of the development attack | `attack-dev:<stage>` with `token_check`, `output_schema`, `redactor` or `audit_trail` | the stage is in `evidence/attack-dev.json` |
| An earlier Task's run | `task-4.<n> pull request <URL of your merged pull request> commit <accepted commit>` | the form matches; your instructor opens it |
| A file (corrections and conditions only) | its repository-relative path (`docs/security/output-policy.md`) | the file exists |

The register's `test` field holds exactly one test citation; its `evidence` field holds exactly
one stage or one pull request citation. An `Evidence:` line in the corrections or in a condition
may hold several citations in prose; at least one must resolve.

## The wording rule

No file you change may claim that Coldline complies with, or is certified under, a regulation. The
scan reads your four files for these words and names, in any letter case: `compliant`,
`complies with`, `in compliance with`, `certified`, `certification`, `EU AI Act`, `HIPAA`,
`GDPR`. It reads what you wrote, not the bytes: the sheet and the register are scanned over their
decoded YAML values and keys and every comment (a comment after a value on the same line
included); the corrections and the decision record as they render, with HTML entities decoded,
Markdown escapes and invisible characters removed, inline markup (emphasis, code spans, links,
tags) removed and the lines of a paragraph read as one text, so an escaped or split spelling, a
word split by emphasis and a phrase split over two lines are read as the word or phrase they
render; an HTML comment is scanned like any other text. Refer to a regulation's intent by its concern id
from `docs/governance/concerns.md`. Where a correction quotes the analysis's own wording, put the
quotation in a blockquote whose first line starts with `> Analysis (CL-nn):` and quote the claim's
text as it stands; the scan treats that blockquote as quoted analysis text only in the
corrections file and only when the quoted text is text the named claim holds. Everything else
is yours.

## Template markers

The three document templates carry `[fill in: ...]` markers. The checks treat a marker left in a
required place as an empty field: in every register field you fill, in every correction line, in
the decision record's Decision and Evidence sections, in the section your outcome requires (its
marker line and, for a conditional go or a no go, every one of the four lines of every entry),
and in the four Accepted risk lines. Sections your outcome does not require may keep their
markers. The two Markdown documents are read as they render: the templates' header comments,
and anything else inside `<!-- -->`, count as nothing, so a required section or entry must
stand outside any comment.

## Commands

```shell
poe attack-dev                     # the development attack; writes evidence/attack-dev.json
poe audit-trail <exception_id>     # the events the evidence file names, in order
poe held-out-dry-run               # the held-out mechanism against a fake scenario, no Docker
poe governance-contract            # the assessed rows, through the assessed-module runner
poe answers                        # the answer sheet's format only
poe submission                     # the format plus the permitted-files boundary
poe integrity-record               # hash the four files and the checks' files; first step of `poe verify`
poe integrity-check                # compare the tree with that snapshot; last step of `poe verify`
poe verify                         # the full public path
```

Start the stack per `README.md` first; `poe verify` starts it again itself and ingests the
supplied corpus. `poe attack-dev` needs the running stack; `poe held-out-dry-run`,
`poe governance-contract` (after `poe attack-dev`), `poe answers` and `poe submission` are
static.

## Check-list rows and the checks that read them

| Check-list row | Check |
|---|---|
| `poe attack-dev` produced `evidence/attack-dev.json` with a result for the token check, the output schema check, the redactor, and the audit trail | `test_the_attack_evidence_has_a_result_for_each_stage` |
| Every claim in the AI-generated analysis has one classification in `answers.claim_review` | `test_every_claim_has_one_classification_from_the_allowed_values` |
| `docs/student/governance-corrections.md` has an entry for every claim that isn't `supported` | `test_the_corrections_have_an_entry_for_every_claim_that_is_not_supported` |
| Each correction cites a file, test, or evidence record | `test_every_correction_cites_a_file_a_test_or_an_evidence_record` |
| The corrections name at least one risk the analysis omits | `test_the_corrections_name_at_least_one_omitted_risk_with_a_citation` |
| Every risk register entry names a control from the control matrix, an existing test, an evidence record, an owner role from `docs/governance/owners.md`, and a residual risk | `test_every_register_entry_names_a_control_from_the_control_matrix`, `test_every_register_entry_cites_a_test_that_exists`, `test_every_register_entry_cites_an_evidence_record_that_exists`, `test_every_register_entry_names_an_owner_role_and_a_residual_risk` |
| `answers.governance_mapping` names one control id from the risk register and one concern id from `docs/governance/concerns.md` | `test_the_governance_mapping_names_a_register_control_and_a_concern_with_a_note` |
| The mapped register entry's `mapping_note` says what the control contributes to the concern and what it doesn't | `test_the_governance_mapping_names_a_register_control_and_a_concern_with_a_note` (the note is filled); its content is your instructor's |
| `answers.decision` is `go`, `conditional_go`, or `no_go` | `test_the_decision_record_has_the_sections_its_outcome_requires`, and `poe answers` |
| `answers.accepted_risk` names one register entry | `test_the_accepted_risk_names_a_register_entry_the_record_explains` |
| Your claim review, governance mapping, decision, and accepted risk pass the protected answer check | The protected check on the platform; no check in this repository reads the correct values |
| `docs/governance/decision-record.md` states the decision, the evidence it rests on, and what the policy requires for that outcome | `test_the_decision_record_has_the_sections_its_outcome_requires` (the rationale and the sections are filled; each condition or required change has its four lines, a label naming the rule it applies to, a role-id owner and a resolving citation; a conditional go's labels are exactly the rules the evidence and the register make apply); their content is your instructor's |
| `docs/governance/decision-record.md` states why the accepted risk is acceptable, who owns it, and what evidence would change the decision | `test_the_accepted_risk_names_a_register_entry_the_record_explains` (the four lines are filled, and the owner is the register's owner for that entry); their content is your instructor's |
| Your corrections, register, decision record, and answers make no claim that Coldline complies with, or is certified under, a regulation; any compliance or certification wording you quote from the analysis is identified and corrected | `test_no_student_file_claims_compliance_or_certification`; whether the quoted claim is corrected is your instructor's |
| `submission.yaml` passes the public answer-format check | `test_submission_answers_use_the_allowed_values`, and `poe answers` |
| Every attack-evidence stage cited in the risk register exists in `evidence/attack-dev.json` | `test_every_register_entry_cites_an_evidence_record_that_exists` |
| The public check, including `poe held-out-dry-run`, passes on the platform for this submission | The hosted `verify` job; `poe verify` is the same command |
| Before you merge, your pull request description has the stage summary from `evidence/attack-dev.json` and your decision with its accepted risk, each with its command and when you ran it | Your instructor, at the Task 7 Instructor Review |
| The held-out check passes on the platform for this submission | The protected held-out job |
| After you submit, your pull request description records the held-out check's result, timestamp, and assessed commit | Your instructor, at the Task 7 Instructor Review |
| The pull request modifies only `submission.yaml`, `docs/student/governance-corrections.md`, `docs/governance/risk-register.yaml`, and `docs/governance/decision-record.md` | `test_submission_change_stays_within_the_permitted_diff` in `tests/contract/test_authoring_contract.py`, and `poe submission` inside `poe verify` |

The rows live in `tests/contract/test_governance_contract.py` (`poe governance-contract`). They
are marked `assessed`: `poe contract` leaves them out, and `poe verify` runs them through
`tests/security/assessed_run.py`, which requires every registered case to have executed and
passed (a skipped or missing case fails the step). A fresh checkout fails most of them, which is
the exercise; the evidence row passes once `poe attack-dev` has run, and the wording row passes
on the untouched templates.

## What the checks verify

| Check | What it looks at |
|---|---|
| `tests/security/attack_scenario.py` | One reading with the scenario's note and response through the open intake, awaited through the database; the summary read with the unauthorized fixture (the access policy's status, a body that is the access rule's refusal and nothing else, no `summary_read` added); one read as the dispatcher; the stored record against the output policy (state, the fixed message, a reason code, no validated field, no answer text in any field); the four locations `poe pii-scan` reads searched for the note's marked values, with the supplied redactor run over the note in-process to tell a documented limit (`limited`) from a value the redactor replaces that reached a location anyway (`failed`); the trail's sequence, fields, trace ids and absence of credentials. Marked values appear as labels; no token or key is written; the exception id the intake returns is accepted only in the shape the API mints (`exc-` and one UUID), and a run that returned anything else is refused before the id is used or written; every other value read from the stack (a state, a reason code, an event name, a field name, a status) is recorded only when it is one of a closed list and as `unrecognized` otherwise, and the trail rules' findings are recorded as counts |
| `tests/security/governance.py` | The claim ids and claim texts from the analysis's `### CL-nn` headings; the control ids from the matrix's rows; the concern ids from the `## GC-nn` headings; the role ids from the owners table; the register as one `risks:` list of nine-key entries read with the restricted YAML loader, with exactly the five supplied entries in order; the corrections' two sections and their `- Label:` lines and the decision record's `##` sections, its one `Outcome:` line and rationale, its condition and required-change entries (their `Applies to` labels matched against the `limited` stages of the evidence file and the register's pull request citations) and the four Accepted risk lines, all read from the visible Markdown with HTML comments removed; the citation forms above, with the cited test modules collected by `pytest --collect-only`; the wording scan over rendered Markdown text, decoded YAML values and keys and every YAML comment |
| `tests/security/assessed_run.py` | The assessed module run under pytest with a junit report, then, outside that process, the report compared with the registered inventory: every registered case must appear once and have passed |
| `tests/security/integrity.py` | SHA-256 digests of the four student files, `docs/governance/`, `docs/security/`, every file under `src/`, `security/`, `tests/contract/`, `tests/security/`, `tests/student/`, `tests/fixtures/`, `schemas/`, plus `.gitleaks.toml`, `.semgrepignore`, the security and held-out workflows, the answer schema, `config/auth.yaml`, `infra/corpus/documents.jsonl`, `pyproject.toml` and `uv.lock`, recorded to a file outside the repository when `poe verify` starts and compared when it ends; the evidence file the run writes is not covered |
| `tests/contract/submission_validation.py` (`poe answers`, `poe submission`) and `test_submission_change_stays_within_the_permitted_diff` | `submission.yaml` is one plain YAML mapping whose `answers` holds a non-empty claim-review map keyed by `CL-nn` ids with the four allowed values, a mapping with a `C-nn` control and a `GC-nn` concern, a decision from the three values and an `R-nn` accepted risk, and is not a copy of `submission-sample.yaml`; the diff from the merge base touches only the four files |
| `tests/contract/held_out_review.py` | The same procedure as `poe attack-dev`, run with a scenario from the environment that carries its own expectation for each of the four stages (a scenario naming fewer is refused before the attack is sent), graded by comparing each stage's outcome and named result fields, printing one token and nothing about the scenario. Public fixtures demonstrate the harness interfaces and make no statement about the protected scenario's inputs |

## Student-editable paths

- `submission.yaml`
- `docs/student/governance-corrections.md`
- `docs/governance/risk-register.yaml` (the six empty fields of each entry; the supplied keys,
  ids, threats and titles stay, in their order, and no entry is added or removed)
- `docs/governance/decision-record.md`

That is the whole list. The analysis, the owners, the concerns, the decision policy, the attack
scenario, the procedure, the application code, the configuration, the tests, `compose.yaml`,
`pyproject.toml` and the workflows stay as supplied. Before you push, run `git status` and
`git diff --stat`: if anything else changed, the public check reports the boundary violation
rather than your work, and the held-out job refuses to grade.
