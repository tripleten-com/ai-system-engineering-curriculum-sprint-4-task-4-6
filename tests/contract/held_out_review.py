"""Coldline.

===================

File:              tests/contract/held_out_review.py
Component:         Contract — Held-out review
Purpose:           Run one held-out combined attack and grade the supplied controls without
                    exposing the scenario.
Interacts With:    The live API, worker, PostgreSQL and the audit trail (Docker Compose), a
                    runtime-supplied scenario, tests/security/attack_scenario.py,
                    .github/workflows/protected-review.yml
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          Held-out evaluation, protected grading, one procedure for two scenarios
Tools:             Python 3.12, httpx, Docker Compose

Sprint 4's only held-out scenario runs here, in protected CI, after the public checks.
The scenario arrives at runtime through the ``HELD_OUT_SCENARIO`` environment variable and
is never committed: this file holds the *procedure*, which is the same one ``poe
attack-dev`` runs (``tests/security/attack_scenario.py``), and the expectation it grades
against travels inside the scenario.

The attack is one combined attack the student has not seen, with the development
scenario's shape (one unauthorized token fixture, one refused answer, one handling note
with marked personal details), sent through the same request, token, audit and evidence
interfaces. Public fixtures demonstrate the harness interfaces and make no statement about
the protected scenario's inputs. It grades the SUPPLIED controls (the token check and
access rule from Task 2, the output validation and audit sink from Task 3, the redactor
from Task 4), never a student's document: a submission whose controls are intact passes,
whatever its decision says.

Nothing about the scenario is printed. A student reading CI output learns whether the
controls held and nothing about which fixture, which answer or which note was sent. Run it
as a module from the Task root (``python -m tests.contract.held_out_review <api base url>``),
so the ``tests`` package is importable.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import httpx

from tests.security.attack_scenario import (
    STAGES,
    AttackInterfaces,
    LiveInterfaces,
    ScenarioError,
    grade,
    load_scenario_text,
    run_attack,
)

TASK_ROOT = Path(__file__).resolve().parents[2]
PASS = "HELD_OUT_CHECK_PASSED"
FAIL = "HELD_OUT_CHECK_FAILED"
# Printed instead of any exception text. A traceback here could carry the scenario's note,
# a Compose error, or an API response into a log a student can read.
INFRASTRUCTURE = "HELD_OUT_INFRASTRUCTURE_ERROR: contact course support."


def run_held_out_check(
    scenario_json: str,
    api_base_url: str,
    *,
    root: Path = TASK_ROOT,
    interfaces: AttackInterfaces | None = None,
) -> bool:
    """Run the scenario and grade the stages against the expectation it carries.

    Returns True or False for a grade, and raises ``ScenarioError`` when it could not
    grade at all (a malformed scenario, a scenario whose expectations do not cover all
    four stages, a stack that did not answer). Neither carries anything about the
    scenario. ``interfaces`` replaces the running stack in the dry run.

    A held-out scenario must state an expectation for every stage: a scenario that names
    a subset would silently stop assessing the other controls. Partial expectations stay
    available to ``grade`` for the lower-level tests only.
    """
    scenario = load_scenario_text(scenario_json, require_expected=True)
    if scenario.expected is None:  # pragma: no cover - require_expected guarantees it
        raise ScenarioError("invalid attack scenario")
    if set(scenario.expected) != set(STAGES):
        raise ScenarioError("invalid attack scenario")
    if interfaces is not None:
        result = run_attack(scenario, interfaces)
    else:
        with httpx.Client(base_url=api_base_url, timeout=10.0) as client:
            result = run_attack(scenario, LiveInterfaces(client, root))
    return grade(result, scenario.expected) == []


def main(
    scenario_json: str,
    api_base_url: str,
    *,
    root: Path = TASK_ROOT,
    interfaces: AttackInterfaces | None = None,
) -> int:
    """Return 0 for a pass, 1 for a failed grade, and 2 for an unusable run.

    Three exit codes rather than two, so the workflow can report `error` instead of
    `failure` when the fault is on this side. A missing secret, a malformed scenario, or
    a stack that did not start must never look like a wrong answer.
    """
    try:
        passed = run_held_out_check(scenario_json, api_base_url, root=root, interfaces=interfaces)
    except Exception:  # noqa: BLE001 - the text of any error may carry the scenario
        print(INFRASTRUCTURE, file=sys.stderr)
        return 2
    print(PASS if passed else FAIL)
    return 0 if passed else 1


if __name__ == "__main__":
    # The scenario arrives through the environment, never as an argument: a command-line
    # argument is readable from /proc/<pid>/cmdline by any other process for as long as
    # this one lives.
    scenario_env = os.environ.get("HELD_OUT_SCENARIO", "")
    api_base_url_env = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
    sys.exit(main(scenario_env, api_base_url_env))
