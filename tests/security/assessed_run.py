"""Coldline.

===================

File:              tests/security/assessed_run.py
Component:         Security tooling — Assessed-module runner
Purpose:           Run the assessed contract module under pytest with a junit report and require
                    every registered assessed case to have executed and passed.
Interacts With:    tests/contract/test_governance_contract.py, pyproject.toml
                    (`poe governance-contract`, `poe verify`)
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          Closed inventories, skipped is not passed, trusted comparison outside the
                    process under test
Tools:             Python 3.12, pytest (as a subprocess), junit XML

Task 4.6's student files are documents and a sheet, so the assessed module imports no
student code. The runner is kept all the same, as every assessed module since Task 4.3 has
been run through it: ``poe governance-contract`` does not call pytest directly; this module
does, with a junit report in a temporary directory, and then compares the report against the
registered inventory of the module's cases. Every registered case must appear exactly once
and have ``passed``; a case that is missing, skipped, errored or failed, and a case the
inventory does not know, is named and fails the step, whatever pytest's own exit code was.
pytest's output is passed through, so the student still reads the rows' own messages.

The inventory is static text, keyed by the module's path: the case names as junit reports
them. A unit test keeps the names in step with the module's source.

``python -m tests.security.assessed_run tests/contract/test_governance_contract.py`` is the
command; extra arguments are passed to pytest unchanged (``-k`` is refused, because a
deselection is what this runner exists to catch).
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Sequence
from pathlib import Path

TASK_ROOT = Path(__file__).resolve().parents[2]
PYTEST_TIMEOUT_SECONDS = 3600
GOVERNANCE_MODULE = "tests/contract/test_governance_contract.py"
# Every assessed case the module collects, as junit names it, in the module's order. A
# module not listed here cannot be run through this runner.
REGISTERED_CASES: dict[str, tuple[str, ...]] = {
    GOVERNANCE_MODULE: (
        "test_the_attack_evidence_has_a_result_for_each_stage",
        "test_every_claim_has_one_classification_from_the_allowed_values",
        "test_the_corrections_have_an_entry_for_every_claim_that_is_not_supported",
        "test_every_correction_cites_a_file_a_test_or_an_evidence_record",
        "test_the_corrections_name_at_least_one_omitted_risk_with_a_citation",
        "test_every_register_entry_names_a_control_from_the_control_matrix",
        "test_every_register_entry_cites_a_test_that_exists",
        "test_every_register_entry_cites_an_evidence_record_that_exists",
        "test_every_register_entry_names_an_owner_role_and_a_residual_risk",
        "test_the_governance_mapping_names_a_register_control_and_a_concern_with_a_note",
        "test_the_decision_record_has_the_sections_its_outcome_requires",
        "test_the_accepted_risk_names_a_register_entry_the_record_explains",
        "test_no_student_file_claims_compliance_or_certification",
        "test_submission_answers_use_the_allowed_values",
    ),
}
REFUSED_OPTIONS: frozenset[str] = frozenset({"-k", "--deselect", "-m"})


class AssessedRunError(RuntimeError):
    """Report that the run could not be made or read, as opposed to a verdict about it."""


def outcomes_of(report: Path) -> dict[str, str]:
    """Return each junit case's outcome by its name: passed, failed, error, or skipped.

    A name that appears twice is an error: one outcome per registered case is required.
    """
    if not report.is_file():
        raise AssessedRunError(f"pytest wrote no junit report at {report}")
    outcomes: dict[str, str] = {}
    for case in ET.parse(report).iter("testcase"):
        name = case.attrib.get("name", "")
        if name in outcomes:
            raise AssessedRunError(f"the junit report names {name!r} twice")
        if case.find("error") is not None:
            outcomes[name] = "error"
        elif case.find("failure") is not None:
            outcomes[name] = "failed"
        elif case.find("skipped") is not None:
            outcomes[name] = "skipped"
        else:
            outcomes[name] = "passed"
    return outcomes


def compare(module: str, outcomes: dict[str, str]) -> list[str]:
    """Return why the report is not every registered case of ``module``, each passed."""
    registered = REGISTERED_CASES.get(module)
    if registered is None:
        raise AssessedRunError(
            f"{module} is not a registered assessed module; choose one of "
            f"{', '.join(REGISTERED_CASES)}"
        )
    findings: list[str] = []
    for name in registered:
        outcome = outcomes.get(name)
        if outcome is None:
            findings.append(f"{name} did not run (missing from the report)")
        elif outcome != "passed":
            findings.append(f"{name} {outcome}")
    for name in outcomes:
        if name not in registered:
            findings.append(
                f"{name} is not a registered case of {module}; the inventory in "
                "tests/security/assessed_run.py must list every case"
            )
    return findings


def refused_option(argument: str) -> bool:
    """Return whether a pytest argument would deselect cases (``-k``, ``-m``, ``--deselect``)."""
    return argument in REFUSED_OPTIONS or any(
        argument.startswith(f"{option}=") for option in REFUSED_OPTIONS
    )


def run(module: str, extra: Sequence[str] = (), *, root: Path = TASK_ROOT) -> tuple[int, list[str]]:
    """Run one assessed module under pytest and compare its junit report; return (exit, findings).

    pytest's exit code is returned as it was, so a failing row still exits 1; the
    findings are what the inventory comparison adds. A refused option (``-k``, ``-m``,
    ``--deselect``) is a tooling error: this runner exists to refuse a deselection.
    """
    for argument in extra:
        if refused_option(argument):
            raise AssessedRunError(
                f"{argument} is not permitted here: every assessed case must run"
            )
    with tempfile.TemporaryDirectory(prefix="coldline-assessed-") as temporary:
        report = Path(temporary) / "assessed.xml"
        completed = subprocess.run(
            [sys.executable, "-m", "pytest", module, *extra, f"--junitxml={report}"],
            cwd=root,
            check=False,
            timeout=PYTEST_TIMEOUT_SECONDS,
        )
        if completed.returncode not in {0, 1} and not report.is_file():
            raise AssessedRunError(
                f"pytest exited {completed.returncode} running {module} and wrote no report: "
                "the run did not happen as asked"
            )
        findings = compare(module, outcomes_of(report))
    return completed.returncode, findings


def main(argv: Sequence[str] | None = None) -> int:
    """Run the module named first, pass the rest to pytest, and require every case passed."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0].startswith("-"):
        print("assessed-run: name the assessed module to run first", file=sys.stderr)
        return 2
    module = Path(arguments[0]).as_posix()
    try:
        returncode, findings = run(module, arguments[1:])
    except AssessedRunError as exc:
        print(f"assessed-run: {exc}", file=sys.stderr)
        return 2
    registered = len(REGISTERED_CASES[module])
    if findings:
        print(
            f"assessed-run: {module}: {len(findings)} of {registered} registered cases did not "
            "execute and pass:",
            file=sys.stderr,
        )
        for finding in findings:
            print(f"- {finding}", file=sys.stderr)
        return returncode or 1
    print(f"assessed-run: {module}: all {registered} registered cases executed and passed.")
    return returncode


if __name__ == "__main__":
    raise SystemExit(main())
