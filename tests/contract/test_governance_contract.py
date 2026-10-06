"""Coldline.

===================

File:              tests/contract/test_governance_contract.py
Component:         Contract tests — Governance decision and held-out check
Purpose:           One assessed check per public Check-list row: the four attack-evidence stages,
                    every claim classified, the corrections and their citations, the register's
                    controls, tests, evidence, owners and residual risks, the mapping and its
                    note, the decision record's sections, the accepted risk, the wording scan,
                    and the sheet's format.
Interacts With:    submission.yaml, docs/student/governance-corrections.md,
                    docs/governance/risk-register.yaml, docs/governance/decision-record.md,
                    docs/governance/* (supplied), docs/security/control-matrix.md,
                    evidence/attack-dev.json, tests/security/governance.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          Structure checked by machine, content judged at the Task 7 review, citations
                    that resolve
Tools:             Python 3.12, pytest

Assessed: a fresh starter carries a blank sheet, a corrections template, an empty register
and a decision-record template, so most rows fail until the Task's work is done. ``poe
contract`` deselects them; ``poe governance-contract`` and ``poe verify`` run them through
``tests/security/assessed_run.py``, after ``poe attack-dev`` has written the evidence file
and ``poe held-out-dry-run`` has proved the held-out mechanism. Every row is static: it
reads the four student files, the supplied material and the evidence file, and collects the
cited tests with pytest; none starts the stack.

No row knows an answer. Which classification, mapping, decision or accepted risk is right
is the protected answer check's question; whether a correction, a residual risk or a
condition is sound is the instructor's, at the Task 7 Instructor Review. What the rows do
hold the student to is shape: the register keeps its five supplied entries and changes only
the six completion fields; the Decision section carries exactly one ``Outcome:`` line and
a rationale beyond it; a condition or a required change says which policy rule it
applies to, what must be true, who owns it and what evidence would show it, with a
citation that resolves; a conditional go carries exactly one condition per rule that
applied, derived from the evidence file and the register; the accepted risk's owner is the
owner the register records for that entry; the two Markdown documents are read as they
render, HTML comments removed; and the wording scan reads the files as a reader sees them.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

import pytest

from tests.contract.submission_validation import SubmissionError, validate_submission
from tests.security import governance
from tests.security.attack_scenario import STAGES
from tests.security.governance import (
    ACCEPTED_LINES,
    CLAIM_ENTRY_LINES,
    CLAIM_VALUES,
    CONDITION_LINES,
    DECISION_SECTION,
    DECISIONS,
    ENTRY_OUTCOMES,
    EVIDENCE_SECTION,
    OMITTED_ENTRY_LINES,
    REQUIRED_SECTIONS,
    SUPPORTED,
    CorrectionEntry,
    Corrections,
    DecisionRecord,
    GovernanceError,
    RegisterEntry,
)

pytestmark = pytest.mark.assessed
TASK_ROOT = Path(__file__).resolve().parents[2]


def _supplied[T](read: Callable[[], T]) -> T:
    """Read one supplied or student file, or fail the row with the reader's reason."""
    try:
        return read()
    except GovernanceError as exc:
        pytest.fail(str(exc))


def _claim_review(answers: dict[str, Any]) -> dict[str, Any]:
    """Return the sheet's claim-review mapping, empty when it is not a mapping."""
    review = answers.get("claim_review")
    return dict(review) if isinstance(review, dict) else {}


def _entry_findings(entries: Iterable[CorrectionEntry], labels: Iterable[str]) -> list[str]:
    """Return every entry whose labelled line is missing, empty or still a template marker."""
    return [
        f"{entry.entry_id}: `{label}`"
        for entry in entries
        for label in labels
        if governance.is_blank(entry.fields.get(label, ""))
    ]


def _cites(entry: CorrectionEntry, collected: dict[str, set[str]]) -> bool:
    """Return whether an entry's Evidence line holds a citation that resolves."""
    evidence = entry.fields.get("evidence", "")
    return bool(governance.resolved_citations(evidence, TASK_ROOT, collected))


def _record_entries(record: DecisionRecord) -> list[CorrectionEntry]:
    """Return the entries of the two entry-shaped sections, whatever the outcome."""
    return [
        entry
        for outcome in ENTRY_OUTCOMES
        for entry in governance.section_entries(record, REQUIRED_SECTIONS[outcome])
    ]


# --- Fixtures -----------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def register() -> tuple[RegisterEntry, ...]:
    """Return the student's register in the supplied shape."""
    return _supplied(lambda: governance.load_register(TASK_ROOT))


@pytest.fixture(scope="module")
def answers() -> dict[str, Any]:
    """Return the sheet's answers mapping, blank values included."""
    return _supplied(lambda: governance.sheet_answers(TASK_ROOT))


@pytest.fixture(scope="module")
def corrections() -> Corrections:
    """Return the student's corrections, parsed into their entries."""
    path = TASK_ROOT / governance.CORRECTIONS_PATH
    if not path.is_file():
        pytest.fail(f"{governance.CORRECTIONS_PATH.as_posix()} is missing")
    return governance.parse_corrections(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def record() -> DecisionRecord:
    """Return the student's decision record, parsed into its sections, lines and entries."""
    path = TASK_ROOT / governance.DECISION_RECORD_PATH
    if not path.is_file():
        pytest.fail(f"{governance.DECISION_RECORD_PATH.as_posix()} is missing")
    return governance.parse_decision_record(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def evidence() -> dict[str, Any]:
    """Return the evidence document `poe attack-dev` wrote during this run."""
    return _supplied(lambda: governance.load_evidence(TASK_ROOT))


@pytest.fixture(scope="module")
def collected(
    register: tuple[RegisterEntry, ...], corrections: Corrections, record: DecisionRecord
) -> dict[str, set[str]]:
    """Collect, once, every test module the register, the corrections and the record cite."""
    paths: set[str] = set()
    for entry in register:
        citation = governance.parse_test_citation(entry.test)
        if citation is not None:
            paths.add(citation.path)
    cited = (*corrections.claims.values(), *corrections.omitted.values(), *_record_entries(record))
    for item in cited:
        for citation in governance.test_citations_in(item.fields.get("evidence", "")):
            paths.add(citation.path)
    return _supplied(lambda: governance.collected_tests(TASK_ROOT, paths))


# --- Step 1: the development attack evidence ---------------------------------------------------


def test_the_attack_evidence_has_a_result_for_each_stage(evidence: dict[str, Any]) -> None:
    """`evidence/attack-dev.json` records an outcome for each of the four stages.

    The token check, the output schema check, the redactor and the audit trail, each with
    one of the three outcomes, whatever the control did. `poe attack-dev` writes the file;
    `poe verify` runs it before this step.
    """
    stages = governance.evidence_stages(evidence)
    missing = [stage for stage in STAGES if stage not in stages]
    assert not missing, (
        f"evidence/attack-dev.json records no outcome for {', '.join(missing)}; run "
        "`poe attack-dev` against the running stack"
    )
    assert list(evidence.get("stage_order", [])) == list(STAGES), (
        "evidence/attack-dev.json does not list the four stages in the procedure's order"
    )


# --- Step 2: the claim review and the corrections ----------------------------------------------


def test_every_claim_has_one_classification_from_the_allowed_values(
    answers: dict[str, Any],
) -> None:
    """Every numbered claim has one allowed value in `answers.claim_review`; no other id has one."""
    ids = _supplied(lambda: governance.claim_ids(TASK_ROOT))
    review = _claim_review(answers)
    assert review, (
        "answers.claim_review is empty; classify every numbered claim of "
        "docs/governance/ai-governance-analysis.md in the order the sheet's comments state"
    )
    missing = [claim for claim in ids if claim not in review]
    extra = sorted(set(review) - set(ids))
    assert not missing, f"answers.claim_review has no value for {', '.join(missing)}"
    assert not extra, (
        f"answers.claim_review names {', '.join(extra)}, which the analysis does not number"
    )
    wrong = sorted(claim for claim, value in review.items() if value not in CLAIM_VALUES)
    assert not wrong, (
        f"answers.claim_review gives {', '.join(wrong)} a value outside {', '.join(CLAIM_VALUES)}"
    )


def test_the_corrections_have_an_entry_for_every_claim_that_is_not_supported(
    answers: dict[str, Any], corrections: Corrections
) -> None:
    """One `### CL-nn` entry per claim not classified `supported`, each with its three lines.

    An entry for an id the analysis does not number, an entry for a claim the sheet
    classifies `supported`, a repeated entry, and a missing or template-marked line are
    each named. The file is read as it renders: an entry inside an HTML comment is absent.
    """
    ids = set(_supplied(lambda: governance.claim_ids(TASK_ROOT)))
    review = _claim_review(answers)
    entries = corrections.claims
    unknown = sorted(entry for entry in entries if entry not in ids)
    assert not unknown, (
        f"the corrections have an entry for {', '.join(unknown)}, which the analysis does not "
        "number (remove the template's placeholder entry)"
    )
    assert not corrections.duplicates, (
        f"the corrections repeat an entry for {', '.join(corrections.duplicates)}"
    )
    not_supported = sorted(claim for claim in ids if claim in review and review[claim] != SUPPORTED)
    missing = sorted(set(not_supported) - set(entries))
    assert not missing, (
        f"the corrections have no entry for {', '.join(missing)}, which answers.claim_review "
        f"does not classify {SUPPORTED}"
    )
    corrected_supported = sorted(entry for entry in entries if review.get(entry) == SUPPORTED)
    assert not corrected_supported, (
        f"the corrections have an entry for {', '.join(corrected_supported)}, which "
        f"answers.claim_review classifies {SUPPORTED}; a supported claim needs no correction"
    )
    incomplete = _entry_findings(entries.values(), CLAIM_ENTRY_LINES)
    assert not incomplete, (
        "these correction lines are missing, empty or still a template marker: "
        + "; ".join(incomplete)
    )


def test_every_correction_cites_a_file_a_test_or_an_evidence_record(
    corrections: Corrections, collected: dict[str, set[str]]
) -> None:
    """Each claim correction's Evidence line cites something that resolves in this repository.

    A file by its path, a test as `<path>::<name>` that pytest collects, a stage as
    `attack-dev:<stage>`, or an earlier Task's pull request in the documented form.
    """
    uncited = [
        entry_id for entry_id, entry in corrections.claims.items() if not _cites(entry, collected)
    ]
    assert not uncited, (
        f"the corrections for {', '.join(uncited)} cite no file, test, attack-dev stage or "
        "pull request that resolves (the forms are in the file's header comment)"
    )


def test_the_corrections_name_at_least_one_omitted_risk_with_a_citation(
    corrections: Corrections, collected: dict[str, set[str]]
) -> None:
    """At least one `### OR-nn` entry names a risk the analysis omits, with a resolving citation."""
    entries = corrections.omitted
    assert entries, (
        "no `### OR-nn` entry under `## Omitted risks`; name at least one risk the analysis "
        "leaves out entirely"
    )
    incomplete = _entry_findings(entries.values(), OMITTED_ENTRY_LINES)
    assert not incomplete, (
        "these omitted-risk lines are missing, empty or still a template marker: "
        + "; ".join(incomplete)
    )
    cited = [entry_id for entry_id, entry in entries.items() if _cites(entry, collected)]
    assert cited, (
        "no omitted-risk entry cites a file, test, attack-dev stage or pull request that "
        "resolves (docs/student/threat-model.md names the risks the reference model lists)"
    )


# --- Step 3: the risk register and the mapping -------------------------------------------------


def test_every_register_entry_names_a_control_from_the_control_matrix(
    register: tuple[RegisterEntry, ...],
) -> None:
    """Every entry's `control` is an id of docs/security/control-matrix.md."""
    controls = _supplied(lambda: governance.control_ids(TASK_ROOT))
    wrong = [
        f"{entry.id}: {entry.control or '(empty)'}"
        for entry in register
        if entry.control not in controls
    ]
    assert not wrong, (
        "register entries whose control is not an id of docs/security/control-matrix.md: "
        + "; ".join(wrong)
    )


def test_every_register_entry_cites_a_test_that_exists(
    register: tuple[RegisterEntry, ...], collected: dict[str, set[str]]
) -> None:
    """Every entry's `test` is `<path>::<name>`, and pytest collects that case from that module."""
    findings: list[str] = []
    for entry in register:
        citation = governance.parse_test_citation(entry.test)
        if citation is None:
            findings.append(
                f"{entry.id}: `{entry.test or '(empty)'}` is not of the form <path>::<test name>"
            )
        elif not (TASK_ROOT / citation.path).is_file():
            findings.append(f"{entry.id}: {citation.path} does not exist")
        elif not governance.test_exists(citation, collected):
            findings.append(f"{entry.id}: {citation.path} collects no test named {citation.name}")
    assert not findings, "; ".join(findings)


def test_every_register_entry_cites_an_evidence_record_that_exists(
    register: tuple[RegisterEntry, ...], evidence: dict[str, Any]
) -> None:
    """Every entry's `evidence` is a recorded attack-dev stage or a pull request citation."""
    stages = governance.evidence_stages(evidence)
    findings: list[str] = []
    for entry in register:
        kind = governance.evidence_kind(entry.evidence)
        if kind is None:
            findings.append(
                f"{entry.id}: `{entry.evidence or '(empty)'}` is neither attack-dev:<stage> nor a "
                "pull request citation in the documented form"
            )
        elif kind == "stage":
            stage = governance.cited_stage(entry.evidence)
            if stage not in stages:
                findings.append(f"{entry.id}: evidence/attack-dev.json records no stage {stage}")
    assert not findings, "; ".join(findings)


def test_every_register_entry_names_an_owner_role_and_a_residual_risk(
    register: tuple[RegisterEntry, ...],
) -> None:
    """Every entry's `owner` is a role id of docs/governance/owners.md; no residual is "none"."""
    roles = _supplied(lambda: governance.owner_roles(TASK_ROOT))
    findings: list[str] = []
    for entry in register:
        if entry.owner not in roles:
            findings.append(
                f"{entry.id}: owner `{entry.owner or '(empty)'}` is not a role id of "
                "docs/governance/owners.md"
            )
        if governance.is_blank(entry.residual):
            findings.append(
                f'{entry.id}: the residual risk is empty or "none"; every control in this '
                "Project has a stated limit, and the register carries it"
            )
    assert not findings, "; ".join(findings)


def test_the_governance_mapping_names_a_register_control_and_a_concern_with_a_note(
    register: tuple[RegisterEntry, ...], answers: dict[str, Any]
) -> None:
    """The mapping names a register control and a concern, and that entry's note is filled."""
    mapping = answers.get("governance_mapping")
    assert isinstance(mapping, dict), (
        "answers.governance_mapping is not a mapping with `control` and `concern`"
    )
    control = mapping.get("control")
    concern = mapping.get("concern")
    recorded = [entry.control for entry in register if entry.control]
    assert control in recorded, (
        f"answers.governance_mapping.control `{control}` is not a control recorded in a "
        "register entry"
    )
    concerns = _supplied(lambda: governance.concern_ids(TASK_ROOT))
    assert concern in concerns, (
        f"answers.governance_mapping.concern `{concern}` is not a concern id of "
        "docs/governance/concerns.md"
    )
    without = [
        entry.id
        for entry in register
        if entry.control == control and governance.is_blank(entry.mapping_note)
    ]
    assert not without, (
        f"the register entry for {control} ({', '.join(without)}) has an empty mapping_note; "
        f"say what the control contributes to {concern} and what it does not"
    )


# --- Step 4: the decision and the accepted risk ------------------------------------------------


def test_the_decision_record_has_the_sections_its_outcome_requires(
    answers: dict[str, Any],
    record: DecisionRecord,
    register: tuple[RegisterEntry, ...],
    evidence: dict[str, Any],
    collected: dict[str, set[str]],
) -> None:
    """The record's Outcome is `answers.decision`, and what the outcome requires is there.

    The Decision section carries exactly one `Outcome:` line and rationale beyond it
    (a repeated outcome line is neither the outcome nor rationale); the Evidence section
    is filled; and the section the outcome requires is filled. For a conditional go and a
    no go that section holds one `### <heading>` entry per condition or required change,
    each with an `Applies to` label naming the rule it applies to and what to
    (`C1:attack-dev:<stage>` or `C2:R-nn` for a condition; `N1`, `N2` or `N3` for a
    required change), `What must be true`, an `Owner` that is a role id of
    docs/governance/owners.md and an `Evidence` citation that resolves (a test, a stage, a
    file or a pull request). For a conditional go the labels must be exactly the rules that
    applied: one per `limited` stage in evidence/attack-dev.json and one per register entry
    whose evidence is a pull request citation, one entry each. Whether a condition is sound
    is the instructor's question.
    """
    decision = answers.get("decision")
    assert decision in DECISIONS, (
        f"answers.decision `{decision}` is not one of {', '.join(DECISIONS)}"
    )
    assert record.outcome_lines == 1, (
        f"the `## Decision` section carries {record.outcome_lines} `Outcome:` lines; write "
        "exactly one, with the rationale under it"
    )
    assert record.outcome == decision, (
        f"the decision record's `Outcome:` line says `{record.outcome}`; answers.decision says "
        f"`{decision}`"
    )
    for name in (DECISION_SECTION, EVIDENCE_SECTION):
        assert governance.section_is_filled(record, name), (
            f"the section `## {name}` is empty or still holds a template marker (text inside "
            "an HTML comment renders as nothing and counts as nothing)"
        )
    assert not governance.is_blank(record.rationale), (
        "the `## Decision` section holds only its `Outcome:` line; add the rationale: what is "
        "decided and the policy rules (by id) that gave this outcome"
    )
    required = REQUIRED_SECTIONS[str(decision)]
    assert governance.section_is_filled(record, required), (
        f"the section `## {required}` is empty or still holds a template marker; a "
        f"{decision} requires it (docs/governance/decision-policy.md)"
    )
    if decision not in ENTRY_OUTCOMES:
        return
    entries = governance.section_entries(record, required)
    assert entries, (
        f"the section `## {required}` holds no `### <heading>` entry; write one entry per "
        "condition with its `Applies to`, `What must be true`, `Owner` and `Evidence` lines"
    )
    incomplete = _entry_findings(entries, CONDITION_LINES)
    assert not incomplete, (
        f"these lines under `## {required}` are missing, empty or still a template marker: "
        + "; ".join(incomplete)
    )
    applicable = None
    if decision == "conditional_go":
        applicable = governance.required_conditions(governance.evidence_stages(evidence), register)
    mislabelled = governance.condition_findings(entries, applicable, str(decision))
    assert not mislabelled, (
        f"the `Applies to` labels under `## {required}` do not name the rules that applied "
        "(docs/governance/decision-policy.md: one entry per `limited` stage as "
        "`C1:attack-dev:<stage>`, one per entry whose evidence is an earlier Task's run as "
        "`C2:R-nn`): " + "; ".join(mislabelled)
    )
    roles = _supplied(lambda: governance.owner_roles(TASK_ROOT))
    wrong_owner = [
        f"{entry.entry_id}: `{entry.fields['owner'].strip('` ')}`"
        for entry in entries
        if entry.fields["owner"].strip("` ") not in roles
    ]
    assert not wrong_owner, (
        f"these entries under `## {required}` name an Owner that is not a role id of "
        "docs/governance/owners.md: " + "; ".join(wrong_owner)
    )
    uncited = [entry.entry_id for entry in entries if not _cites(entry, collected)]
    assert not uncited, (
        f"these entries under `## {required}` cite no test, attack-dev stage, file or pull "
        "request that resolves on their Evidence line: " + ", ".join(uncited)
    )


def test_the_accepted_risk_names_a_register_entry_the_record_explains(
    register: tuple[RegisterEntry, ...], answers: dict[str, Any], record: DecisionRecord
) -> None:
    """`answers.accepted_risk` is a register id; the Accepted risk section explains it.

    The section's four lines are filled, its Register id is the accepted id, and its
    Owner is the owner role the register records for that entry.
    """
    accepted = answers.get("accepted_risk")
    by_id = {entry.id: entry for entry in register}
    assert accepted in by_id, f"answers.accepted_risk `{accepted}` is not a register id"
    lines = record.accepted
    missing = [name for name in ACCEPTED_LINES if governance.is_blank(lines.get(name, ""))]
    assert not missing, (
        f"the `## Accepted risk` section leaves {', '.join(missing)} empty or as a template marker"
    )
    named = lines["Register id"].strip("` ")
    assert named == accepted, (
        f"the `## Accepted risk` section names {named}; answers.accepted_risk names {accepted}"
    )
    roles = _supplied(lambda: governance.owner_roles(TASK_ROOT))
    owner = lines["Owner"].strip("` ")
    assert owner in roles, (
        f"the accepted risk's Owner `{owner}` is not a role id of docs/governance/owners.md"
    )
    recorded = by_id[str(accepted)].owner
    assert owner == recorded, (
        f"the accepted risk's Owner `{owner}` is not the owner the register records for "
        f"{accepted} (`{recorded}`); the entry's owner carries the accepted risk"
    )


# --- The wording scan and the sheet ------------------------------------------------------------


def test_no_student_file_claims_compliance_or_certification() -> None:
    """None of the four student files claims compliance or certification in the student's words.

    The scan reads the sheet, the corrections, the register and the decision record for the
    words and names listed in `tests/security/governance.py`, as a reader sees them: YAML
    values and keys decoded and every YAML comment read (a trailing comment after a value
    included); Markdown read as it renders, with HTML entities, escapes and invisible
    characters normalized, inline markup (emphasis, code, links, tags) removed, and the
    lines of a paragraph read as one text. One exemption: a blockquote in the corrections
    whose first line starts with `> Analysis (CL-nn):` and whose quoted text is text that
    claim holds in the analysis.
    """
    findings = governance.student_file_wording_findings(TASK_ROOT)
    assert not findings, (
        "a student file claims compliance or certification in its own words: "
        + "; ".join(findings)
        + " (quote the analysis inside a `> Analysis (CL-nn):` blockquote and correct it; name "
        "a regulation's intent by its concern id from docs/governance/concerns.md)"
    )


def test_submission_answers_use_the_allowed_values() -> None:
    """`submission.yaml` carries the four answers in the published shape.

    The public format check: a non-empty claim-review map keyed by claim ids with the four
    allowed values, a mapping with one control id and one concern id, a decision from the
    three allowed values, a register id, and the sheet not a copy of the fictional sample.
    Which values are right is the protected answer check's question.
    """
    try:
        validate_submission(
            TASK_ROOT / "submission.yaml",
            TASK_ROOT / "docs/contracts/submission.schema.json",
            sample_path=TASK_ROOT / "submission-sample.yaml",
            task_root=TASK_ROOT,
        )
    except SubmissionError as exc:
        pytest.fail(str(exc))
