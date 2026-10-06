"""Coldline.

===================

File:              tests/contract/submission_validation.py
Component:         Contract tests — Submission Validation
Purpose:           Validate the Task 4.6 answer sheet (the claim review, the governance mapping,
                    the decision and the accepted risk) and the permitted paths: the sheet and
                    the three governance documents.
Interacts With:    Published interfaces and repository boundaries, tests/security/repository.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          Compatibility, ownership, export safety
Tools:             Python 3.12, pytest

Two entrypoints share this module. ``poe answers`` runs it with ``--format-only`` and
checks the answer sheet alone: one plain YAML mapping whose ``answers`` carries
``claim_review`` (a non-empty map from claim ids of the form ``CL-nn`` to one of
``wrong_mapping``, ``unsupported``, ``overclaim`` or ``supported``), ``governance_mapping``
(a ``control`` of the form ``C-nn`` and a ``concern`` of the form ``GC-nn``), ``decision``
(``go``, ``conditional_go`` or ``no_go``) and ``accepted_risk`` (a register id of the form
``R-nn``), and that the sheet is not a copy of the fictional sample. ``poe submission``
(inside ``poe verify``) runs it in full, which adds the permitted-path boundary: the diff
from the merge base touches only ``submission.yaml``,
``docs/student/governance-corrections.md``, ``docs/governance/risk-register.yaml`` and
``docs/governance/decision-record.md``. Nothing here judges which values are right: that is
the protected answer check's job, after the submission on the platform; whether the ids
name real claims, controls, concerns and register entries is the assessed module's.
"""

import argparse
import json
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from tests.security import repository

# The four files every Task 4.6 pull request may change.
ALLOWED_PATHS = frozenset(
    {
        "submission.yaml",
        "docs/student/governance-corrections.md",
        "docs/governance/risk-register.yaml",
        "docs/governance/decision-record.md",
    }
)
ALLOWED_PREFIXES: tuple[str, ...] = ()
ANSWER_FIELDS = ("claim_review", "governance_mapping", "decision", "accepted_risk")
MAPPING_FIELDS = ("control", "concern")
CLAIM_VALUES = ("wrong_mapping", "unsupported", "overclaim", "supported")
DECISIONS = ("go", "conditional_go", "no_go")
CLAIM_ID = re.compile(r"^CL-\d{2}$")
CONTROL_ID = re.compile(r"^C-\d{2}$")
CONCERN_ID = re.compile(r"^GC-\d{2}$")
REGISTER_ID = re.compile(r"^R-\d{2}$")


_JSON_YAML_TAGS = frozenset(
    {
        "tag:yaml.org,2002:map",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
    }
)


class RestrictedYamlLoader(yaml.SafeLoader):  # type: ignore[misc]
    """Load the Task's small YAML profile without YAML-only conveniences.

    Public, because the governance readers (``tests/security/governance.py``) read the
    student's register and sheet with the same loader: no duplicate keys, no aliases or
    anchors, no merge keys, no non-JSON tags.
    """

    def compose_node(self, parent: object, index: object) -> yaml.Node:
        """Compose one node, refusing an alias or an anchor where it appears."""
        # A prior anchor is already rejected below, but deny aliases directly too.
        if self.check_event(yaml.AliasEvent):
            event = self.get_event()
            raise yaml.composer.ComposerError(
                None,
                None,
                "YAML aliases are not permitted",
                event.start_mark,
            )
        event = self.peek_event()
        if getattr(event, "anchor", None) is not None:
            raise yaml.composer.ComposerError(
                None,
                None,
                "YAML anchors are not permitted",
                event.start_mark,
            )
        return super().compose_node(parent, index)

    def construct_object(self, node: yaml.Node, deep: bool = False) -> object:
        """Construct one value, refusing any tag outside the JSON-compatible set."""
        if node.tag not in _JSON_YAML_TAGS:
            raise yaml.constructor.ConstructorError(
                None,
                None,
                "non-JSON YAML tags are not permitted",
                node.start_mark,
            )
        return super().construct_object(node, deep=deep)

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[str, object]:
        """Construct one mapping with string keys, refusing merge keys and repeated keys."""
        mapping: dict[str, object] = {}
        for key_node, value_node in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "YAML merge keys are not permitted",
                    key_node.start_mark,
                )
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str):
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    "YAML mapping keys must be strings",
                    key_node.start_mark,
                )
            if key in mapping:
                raise yaml.constructor.ConstructorError(
                    None,
                    None,
                    f"duplicate YAML key: {key}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


class SubmissionError(ValueError):
    """Report one actionable public-verification failure."""


def main(
    root: Path | None = None,
    *,
    changed_paths: list[str] | None = None,
    format_only: bool = False,
) -> int:
    """Validate the answer sheet, and unless ``format_only``, the permitted-path boundary.

    The optional arguments keep this entrypoint testable without changing the
    process working directory or creating a temporary Git repository.
    """
    task_root = Path.cwd() if root is None else root
    try:
        validate_submission(
            task_root / "submission.yaml",
            task_root / "docs/contracts/submission.schema.json",
            sample_path=task_root / "submission-sample.yaml",
            task_root=task_root,
        )
        if not format_only:
            changed = _changed_paths(task_root) if changed_paths is None else changed_paths
            validate_changed_paths(changed)
    except (SubmissionError, RuntimeError) as exc:
        print(f"verification failed: {exc}", file=sys.stderr)
        return 1
    if format_only:
        print("Task 4.6 answer format check passed.")
    else:
        print("Task 4.6 answer and permitted-path verification passed.")
    return 0


def _incomplete(answers: dict[str, Any]) -> str | None:
    """Return the address of the first blank answer, or None when none is blank.

    The blank sheet names the field left empty, before the schema reports a pattern: an
    empty string, an empty mapping, a null, or a mapping whose own fields are blank.
    """
    for field in ANSWER_FIELDS:
        if field not in answers:
            continue
        value = answers[field]
        if value is None or (isinstance(value, str) and not value.strip()):
            return f"answers.{field}"
        if isinstance(value, dict) and not value:
            return f"answers.{field}"
        if field == "governance_mapping" and isinstance(value, dict):
            for name in MAPPING_FIELDS:
                inner = value.get(name)
                if name in value and (
                    inner is None or (isinstance(inner, str) and not inner.strip())
                ):
                    return f"answers.{field}.{name}"
    return None


def validate_submission(
    submission_path: Path,
    schema_path: Path,
    *,
    sample_path: Path | None = None,
    task_root: Path | None = None,
) -> None:
    """Validate YAML shape, placeholders, the schema, and sample-copy behavior.

    ``task_root`` names the repository that owns the published contracts. It defaults
    to the answer sheet's own directory, which is correct for a student checkout. A
    curriculum-owned evaluator validating a sheet stored elsewhere passes the trusted
    Task root explicitly.
    """
    submission = _load_one_document(submission_path)
    answers = submission.get("answers") if isinstance(submission, dict) else None
    if not isinstance(answers, dict):
        raise SubmissionError("answers must be one mapping")

    incomplete = _incomplete(answers)
    if incomplete is not None:
        raise SubmissionError(f"{incomplete} is incomplete")

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    errors = sorted(
        Draft202012Validator(schema).iter_errors(submission), key=lambda error: list(error.path)
    )
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.absolute_path) or "submission"
        raise SubmissionError(f"{location}: {error.message}")

    if sample_path is not None and submission == _load_one_document(sample_path):
        raise SubmissionError("submission must not copy the fictional sample answers")


def validate_changed_paths(paths: list[str], permitted: frozenset[str] = ALLOWED_PATHS) -> None:
    """Reject changed paths outside the permitted surfaces."""
    normalized = {PurePosixPath(path.replace("\\", "/")).as_posix() for path in paths}
    protected = sorted(
        path for path in normalized - permitted if not path.startswith(ALLOWED_PREFIXES)
    )
    if protected:
        raise SubmissionError(f"protected path changed: {', '.join(protected)}")


def _changed_paths(root: Path) -> list[str]:
    """Return changes since the commit this checkout branched from."""
    try:
        return repository.changed_paths(root)
    except repository.RepositoryError as exc:
        raise RuntimeError("Git history is unavailable for protected-path validation") from exc


def _load_one_document(path: Path) -> dict[str, Any]:
    """Load exactly one plain JSON-compatible YAML mapping.

    A file that is not UTF-8 is reported the same way as one that is not the
    restricted YAML profile: as a public verification failure, not a traceback.
    """
    try:
        documents = list(
            yaml.load_all(path.read_text(encoding="utf-8"), Loader=RestrictedYamlLoader)
        )
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        raise SubmissionError(f"{path.name} must contain UTF-8 restricted YAML") from exc
    if len(documents) != 1 or not isinstance(documents[0], dict):
        raise SubmissionError(f"{path.name} must contain exactly one YAML mapping")
    return documents[0]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate the Task 4.6 submission.")
    parser.add_argument(
        "--format-only",
        action="store_true",
        help="check the answer sheet's format only (what `poe answers` runs)",
    )
    arguments = parser.parse_args()
    raise SystemExit(main(format_only=arguments.format_only))
