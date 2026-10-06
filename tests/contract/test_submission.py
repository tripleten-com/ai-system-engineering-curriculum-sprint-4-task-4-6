"""Coldline.

===================

File:              tests/contract/test_submission.py
Component:         Contract tests — Test Submission
Purpose:           Tests for the public answer and path checks for this Task's submission.
Interacts With:    Published interfaces and repository boundaries
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          Compatibility, ownership, export safety
Tools:             Python 3.12, pytest
"""

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.contract.submission_validation import (
    ALLOWED_PATHS,
    ANSWER_FIELDS,
    CLAIM_VALUES,
    DECISIONS,
    SubmissionError,
    _load_one_document,
    main,
    validate_changed_paths,
    validate_submission,
)

ROOT = Path(__file__).parents[2]
SCHEMA = ROOT / "docs/contracts/submission.schema.json"
TEMPLATE = ROOT / "tests/fixtures/submission-template.yaml"
PERMITTED = [
    "submission.yaml",
    "docs/student/governance-corrections.md",
    "docs/governance/risk-register.yaml",
    "docs/governance/decision-record.md",
]
# Invented ids for the format tests. None names a claim of the supplied analysis, a control,
# a concern or a register entry, and every allowed claim-review value appears once, so the
# fixtures show the shape and nothing about any answer.
IDS = ("CL-80", "CL-81", "CL-82", "CL-83")


def valid_answers(**overrides: Any) -> dict[str, object]:
    """Return a complete answer sheet in the published shape.

    Fictional format example: these values show the shape and state no result. The claim
    ids are invented and each classification value appears once, in the sheet's order; the
    control, the concern and the register id name nothing in this repository; the decision
    is the first allowed value, and the decision tests below use all three.
    """
    answers: dict[str, Any] = {
        "claim_review": dict(zip(IDS, CLAIM_VALUES, strict=True)),
        "governance_mapping": {"control": "C-80", "concern": "GC-80"},
        "decision": DECISIONS[0],
        "accepted_risk": "R-80",
    }
    answers.update(overrides)
    return {"answers": answers}


def own_answers() -> dict[str, object]:
    """Return a complete sheet that is not the published sample."""
    return valid_answers()


def _task_root(tmp_path: Path, submission_text: str) -> Path:
    """Stage a minimal Task root the public verifier can validate."""
    (tmp_path / "docs/contracts").mkdir(parents=True)
    (tmp_path / "submission.yaml").write_text(submission_text, encoding="utf-8")
    (tmp_path / "submission-sample.yaml").write_text(
        (ROOT / "submission-sample.yaml").read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "docs/contracts/submission.schema.json").write_text(
        SCHEMA.read_text(encoding="utf-8"), encoding="utf-8"
    )
    return tmp_path


def test_a_complete_sheet_is_well_formed(tmp_path: Path) -> None:
    """The public schema accepts a complete sheet without judging its correctness."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers()))

    validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize("decision", DECISIONS)
def test_every_allowed_decision_is_well_formed(tmp_path: Path, decision: str) -> None:
    """Each of the three decisions passes the format check; the schema prefers none of them."""
    root = _task_root(tmp_path, yaml.safe_dump(valid_answers(decision=decision)))

    validate_submission(root / "submission.yaml", SCHEMA)


def test_blank_template_fails_with_field_address(tmp_path: Path) -> None:
    """An untouched answer sheet must identify the first incomplete field."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    with pytest.raises(SubmissionError, match="answers.claim_review is incomplete"):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize(
    "overrides,message",
    [
        ({"claim_review": {"CL-80": "rejected"}}, "claim_review"),
        ({"claim_review": {"CL-80": "Supported"}}, "claim_review"),
        ({"claim_review": {"80": "supported"}}, "claim_review"),
        ({"claim_review": {"CL-8": "supported"}}, "claim_review"),
        ({"claim_review": ["CL-80"]}, "claim_review"),
        ({"governance_mapping": {"control": "80", "concern": "GC-80"}}, "control"),
        ({"governance_mapping": {"control": "C-80", "concern": "gc-80"}}, "concern"),
        ({"governance_mapping": {"control": "C-80"}}, "concern"),
        (
            {"governance_mapping": {"control": "C-80", "concern": "GC-80", "note": "x"}},
            "governance_mapping",
        ),
        ({"decision": "maybe"}, "decision"),
        ({"decision": "Go"}, "decision"),
        ({"accepted_risk": "R-8"}, "accepted_risk"),
        ({"accepted_risk": 80}, "accepted_risk"),
    ],
    ids=[
        "unlisted-claim-value",
        "capitalised-claim-value",
        "claim-key-without-prefix",
        "claim-key-too-short",
        "claim-review-not-a-map",
        "control-without-prefix",
        "concern-lowercase",
        "mapping-missing-concern",
        "mapping-extra-key",
        "unlisted-decision",
        "capitalised-decision",
        "accepted-risk-too-short",
        "accepted-risk-not-a-string",
    ],
)
def test_values_outside_the_published_contract_are_rejected(
    tmp_path: Path, overrides: dict[str, Any], message: str
) -> None:
    """The public schema must name the field it rejected, and reject the right ones."""
    sheet = valid_answers()
    answers = sheet["answers"]
    assert isinstance(answers, dict)
    answers.update(overrides)
    root = _task_root(tmp_path, yaml.safe_dump(sheet))

    with pytest.raises(SubmissionError, match=message):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize("field", ANSWER_FIELDS)
def test_a_missing_or_blank_field_is_named(tmp_path: Path, field: str) -> None:
    """Each of the four answers is required, and a blank one is named as incomplete."""
    answers = dict(valid_answers()["answers"])  # type: ignore[arg-type]
    del answers[field]
    root = _task_root(tmp_path, yaml.safe_dump({"answers": answers}))
    with pytest.raises(SubmissionError, match=field):
        validate_submission(root / "submission.yaml", SCHEMA)

    blank = dict(valid_answers()["answers"])  # type: ignore[arg-type]
    blank[field] = {} if field in ("claim_review", "governance_mapping") else ""
    root = _task_root(tmp_path / "blank", yaml.safe_dump({"answers": blank}))
    with pytest.raises(SubmissionError, match=f"answers.{field} is incomplete"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_a_blank_mapping_field_is_named_by_its_own_address(tmp_path: Path) -> None:
    """A mapping with its keys present and empty names the first empty key."""
    sheet = valid_answers(governance_mapping={"control": "", "concern": "GC-80"})
    root = _task_root(tmp_path, yaml.safe_dump(sheet))

    with pytest.raises(SubmissionError, match="answers.governance_mapping.control is incomplete"):
        validate_submission(root / "submission.yaml", SCHEMA)


@pytest.mark.parametrize(
    "field",
    ["held_out_passed", "instructor_approved", "decision_defended", "notes"],
)
def test_no_self_attestation_or_report_field_is_accepted(tmp_path: Path, field: str) -> None:
    """Reject a self-approval, a pass boolean, or a report field."""
    answers = valid_answers()
    mapping = answers["answers"]
    assert isinstance(mapping, dict)
    mapping[field] = True
    root = _task_root(tmp_path, yaml.safe_dump(answers))

    with pytest.raises(SubmissionError, match="Additional properties"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_missing_answers_mapping_is_rejected(tmp_path: Path) -> None:
    """The answers mapping is required, not merely tolerated."""
    root = _task_root(tmp_path, "task: 4.6\n")

    with pytest.raises(SubmissionError, match="answers must be one mapping"):
        validate_submission(root / "submission.yaml", SCHEMA)


def test_exact_sample_copy_is_rejected(tmp_path: Path) -> None:
    """The published sample must not be accepted as a student submission."""
    root = _task_root(tmp_path, (ROOT / "submission-sample.yaml").read_text(encoding="utf-8"))

    with pytest.raises(SubmissionError, match="fictional sample"):
        validate_submission(
            root / "submission.yaml",
            SCHEMA,
            sample_path=root / "submission-sample.yaml",
        )


def test_public_entrypoint_reports_an_incomplete_answer_sheet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Catch a verifier entrypoint that skips the real submission contract."""
    root = _task_root(tmp_path, TEMPLATE.read_text(encoding="utf-8"))

    assert main(root, changed_paths=[], format_only=True) == 1
    assert "answers.claim_review is incomplete" in capsys.readouterr().err


def test_public_entrypoint_rejects_the_sample_and_accepts_a_complete_sheet(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """`poe answers` applies the sample-copy check; a complete sheet of its own passes."""
    copied = _task_root(tmp_path / "copied", (ROOT / "submission-sample.yaml").read_text("utf-8"))
    assert main(copied, changed_paths=[], format_only=True) == 1
    assert "fictional sample" in capsys.readouterr().err

    own = _task_root(tmp_path / "own", yaml.safe_dump(own_answers()))
    assert main(own, changed_paths=[], format_only=True) == 0
    assert main(own, changed_paths=list(PERMITTED)) == 0


def test_public_entrypoint_reports_a_protected_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A change to a supplied governance file is named, not silently accepted."""
    root = _task_root(tmp_path, yaml.safe_dump(own_answers()))

    assert main(root, changed_paths=["docs/governance/decision-policy.md"]) == 1
    assert "protected path changed: docs/governance/decision-policy.md" in capsys.readouterr().err


def test_only_the_four_student_files_are_permitted() -> None:
    """The four student files pass; every supplied file is a protected path."""
    assert ALLOWED_PATHS == frozenset(PERMITTED)
    validate_changed_paths(list(PERMITTED))

    for protected in (
        "docs/governance/ai-governance-analysis.md",
        "docs/governance/owners.md",
        "docs/governance/concerns.md",
        "docs/governance/decision-policy.md",
        "docs/security/control-matrix.md",
        "docs/student/threat-model.md",
        "tests/fixtures/attacks/development.json",
        "tests/security/attack_scenario.py",
        "tests/contract/held_out_review.py",
        "tests/contract/test_governance_contract.py",
        ".github/workflows/protected-review.yml",
        ".github/workflows/task.yml",
        "src/worker/config.py",
        "src/worker/use_cases.py",
        "security/gate.yaml",
        ".gitleaks.toml",
        "compose.yaml",
        "pyproject.toml",
        "uv.lock",
        "README.md",
        "submission-sample.yaml",
    ):
        with pytest.raises(SubmissionError, match="protected path changed"):
            validate_changed_paths([protected])


@pytest.mark.parametrize(
    "unsafe_text",
    [
        "answers: {value: first, value: second}\n",
        "answers: &answer {value: fictional}\n",
        "answers: *missing\n",
        "answers: {<<: {value: fictional}}\n",
        "answers: {value: 2026-09-04}\n",
        "answers: {value: !custom fictional}\n",
        "answers: {1: fictional}\n",
    ],
    ids=["duplicate-key", "anchor", "alias", "merge-key", "date", "custom-tag", "non-string-key"],
)
def test_non_json_yaml_constructs_are_rejected(tmp_path: Path, unsafe_text: str) -> None:
    """Reject restricted syntax before schema validation can mask a parser defect."""
    submission = tmp_path / "submission.yaml"
    submission.write_text(unsafe_text, encoding="utf-8")

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)


def test_multiple_yaml_documents_are_rejected(tmp_path: Path) -> None:
    """A second document cannot supply or replace the answer mapping."""
    submission = tmp_path / "submission.yaml"
    submission.write_text("answers: {}\n---\nanswers: {}\n", encoding="utf-8")

    with pytest.raises(SubmissionError, match="exactly one YAML mapping"):
        _load_one_document(submission)


def test_a_sheet_that_is_not_utf_8_is_a_submission_error(tmp_path: Path) -> None:
    """A sheet saved in another encoding gets the public error, not a Python traceback."""
    submission = tmp_path / "submission.yaml"
    submission.write_bytes("answers: {decision: go}\n".encode("utf-16"))

    with pytest.raises(SubmissionError, match="restricted YAML"):
        _load_one_document(submission)


def test_the_schema_names_the_allowed_values_and_the_id_forms() -> None:
    """The schema's enums are the sheet's values and its ids have the documented forms."""
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    answers = schema["properties"]["answers"]

    assert tuple(answers["required"]) == ANSWER_FIELDS
    review = answers["properties"]["claim_review"]
    assert tuple(review["additionalProperties"]["enum"]) == CLAIM_VALUES
    assert review["minProperties"] == 1
    assert review["propertyNames"]["pattern"] == schema["$defs"]["claim_id"]["pattern"]
    assert tuple(answers["properties"]["decision"]["enum"]) == DECISIONS
    mapping = answers["properties"]["governance_mapping"]
    assert tuple(mapping["required"]) == ("control", "concern")
    assert mapping["additionalProperties"] is False
    assert schema["$defs"]["claim_id"]["pattern"] == "^CL-[0-9]{2}$"
    assert schema["$defs"]["control_id"]["pattern"] == "^C-[0-9]{2}$"
    assert schema["$defs"]["concern_id"]["pattern"] == "^GC-[0-9]{2}$"
    assert schema["$defs"]["register_id"]["pattern"] == "^R-[0-9]{2}$"


def test_the_template_fixture_is_a_blank_sheet_with_the_four_fields() -> None:
    """The fixture is the blank shape: an empty map, an empty mapping and two empty strings."""
    document = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))

    assert document == {
        "answers": {
            "claim_review": {},
            "governance_mapping": {"control": "", "concern": ""},
            "decision": "",
            "accepted_risk": "",
        }
    }


def test_the_sample_shows_every_claim_value_under_invented_ids() -> None:
    """The sample covers every allowed claim value and names ids nothing in this tree uses."""
    document = yaml.safe_load((ROOT / "submission-sample.yaml").read_text(encoding="utf-8"))
    answers = document["answers"]

    assert tuple(answers["claim_review"].values()) == CLAIM_VALUES
    assert all(key.startswith("CL-9") for key in answers["claim_review"])
    assert answers["governance_mapping"] == {"control": "C-90", "concern": "GC-90"}
    assert answers["decision"] in DECISIONS
    assert answers["accepted_risk"] == "R-90"
