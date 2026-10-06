"""Coldline.

===================

File:              tests/contract/test_held_out_review_module.py
Component:         Contract — Held-out review dry run
Purpose:           Confirm the held-out check's mechanism reaches every interface and grades a
                    pass, a failed grade and an unusable run apart, using a fake, non-secret
                    scenario and an in-memory stand-in for the stack.
Interacts With:    tests.contract.held_out_review, tests.security.attack_scenario
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          Held-out evaluation, one procedure for two scenarios
Tools:             Python 3.12, pytest

This is ``poe held-out-dry-run``. It needs no running stack: the six interfaces the
procedure reaches (the intake, the finished record, the summary read, the stored record,
the four evidence locations and the audit trail) are one in-memory stand-in, so the
*mechanism* is provable without the stack and without any scenario the student has not
seen. The real attack runs only in the protected job, against the real stack, with the real
scenario. Public fixtures demonstrate the harness interfaces and make no statement about
the protected scenario's inputs; the fake scenario states an expectation for all four
stages, as the entrypoint requires of every held-out scenario.

The stand-in (``_FakeStack``) derives what its intact controls do from the supplied
contracts, not from constants: the exception id is minted by the API's own rule, the
summary read's status is the access policy's for the fixture presented, and the refused
answer is the one the supplied emulator gives the reading's response selector, judged by
the supplied guardrail, so the reason code it stores is the guardrail's. The stand-in can
be configured for one scenario and then refuses a reading that carries another, so a
caller that lends it a scenario (the authoring qualification) grades that scenario alone.
"""

from __future__ import annotations

import asyncio
import hashlib
import itertools
import json
from collections.abc import Mapping
from typing import Any, Literal

import pytest

from adapters.model.deterministic import REJECTED_RESPONSES, DeterministicModelProvider
from common.redactor import redact
from domain.contracts import ModelRequest, SensorReading
from domain.exceptions import exception_id_for
from tests.contract.held_out_review import (
    FAIL,
    INFRASTRUCTURE,
    PASS,
    main,
    run_held_out_check,
)
from tests.security import pii
from tests.security.attack_dev import SCENARIO_PATH, TASK_ROOT
from tests.security.attack_scenario import (
    AUDIT_TRAIL,
    FAILED,
    HELD,
    LIMITED,
    OUTPUT_SCHEMA,
    REDACTOR,
    REFUSAL_FIELD,
    STAGES,
    TOKEN_CHECK,
    AttackScenario,
    ScenarioError,
    load_scenario_text,
    run_attack,
)
from tests.security.fixtures import EXPECTED_STATUS, FIXTURE_NAMES
from worker.guardrail import REVIEW_MESSAGE, RejectedSummary, validate_summary

UNUSED = "http://unused.invalid"
# A fake scenario, in the open, so the mechanism is testable without the real one. The
# fixture, the answer and the note are invented for this check and grade nothing: the
# protected job supplies the real scenario at runtime.
FAKE_SCENARIO: dict[str, Any] = {
    "scenario_id": "dry-run",
    "token_fixture": "wrong-issuer",
    "response": "manipulated",
    "note": {
        "id": "D-01",
        "text": "Notify Marek Nowak at the gate on 555-0150 before the night run.",
        "pii": [
            {"kind": "name", "value": "Marek Nowak"},
            {"kind": "phone", "value": "555-0150"},
        ],
    },
    "expected": {
        TOKEN_CHECK: {"outcome": HELD, "result": {"status": 401, "refusal_body": True}},
        OUTPUT_SCHEMA: {"outcome": HELD, "result": {"rejection_reason": "unknown_property"}},
        REDACTOR: {"outcome": HELD},
        AUDIT_TRAIL: {"outcome": HELD, "result": {"summary_reads": 1}},
    },
}
# The same attack with a note whose contact name opens a sentence, which the supplied
# redactor does not recognize (docs/security/redactor.md): a documented limit, not a failure.
LIMITED_SCENARIO: dict[str, Any] = {
    **FAKE_SCENARIO,
    "scenario_id": "dry-run-limited",
    "note": {
        "id": "D-02",
        "text": "Marek Nowak has the gate keys; notify the desk on 555-0150.",
        "pii": [
            {"kind": "name", "value": "Marek Nowak"},
            {"kind": "phone", "value": "555-0150"},
        ],
    },
    "expected": {**FAKE_SCENARIO["expected"], REDACTOR: {"outcome": LIMITED}},
}
Behaviour = Literal["correct", "token-accepted", "answer-stored", "note-leaked", "no-trail"]
INTERFACES = ("submit", "wait_finished", "read_summary", "stored_record", "locations", "trail")
VALIDATED = {"handling_class": "thermal_excursion", "next_step": "operational_review"}


def emulated_answer(reading: Mapping[str, Any], exception_id: str, note: str) -> str:
    """Return the raw answer the supplied emulator gives this reading, as the worker receives it.

    The request is the worker's: the reading's identity and temperatures, the note as the
    worker sends it (redacted), no procedure excerpt, and the reading's response selector,
    so a refused selector yields the emulator's own refused answer and the guardrail's
    verdict on it is the real one.
    """
    request = ModelRequest(
        exception_id=exception_id,
        shipment_id=str(reading["shipment_id"]),
        temperature_c=float(reading["temperature_c"]),
        allowed_min_c=float(reading["allowed_min_c"]),
        allowed_max_c=float(reading["allowed_max_c"]),
        handling_note=note,
        emulator_response=reading.get("emulator_response"),
    )
    answer = asyncio.run(DeterministicModelProvider(latency_ms=0).summarize(request))
    return answer.text


class _FakeStack:
    """One in-memory stand-in for the six interfaces, with one deliberate defect per behaviour.

    ``correct`` refuses the unauthorized read with the access policy's status and the
    access rule's refusal body, withholds
    the answer the supplied guardrail refuses with the guardrail's own reason code,
    redacts the note as the supplied redactor does and records the five audit events;
    ``token-accepted`` returns the record to every caller and records a read for it;
    ``answer-stored`` stores the answer as a completed summary; ``note-leaked`` lets the
    raw note reach the worker log and the model request; ``no-trail`` records no audit
    event at all. Given a ``scenario``, the stand-in accepts only a reading that carries
    that scenario's response selector and note.
    """

    def __init__(self, behaviour: Behaviour, scenario: AttackScenario | None = None) -> None:
        self.behaviour = behaviour
        self.scenario = scenario
        self.calls: list[str] = []
        self.records: dict[str, dict[str, Any]] = {}
        self.trails: dict[str, list[dict[str, Any]]] = {}
        self.notes: dict[str, str] = {}
        self.readings: dict[str, dict[str, Any]] = {}
        self.traces: dict[str, str] = {}
        self.tokens = {name: f"fake-token-{name}" for name in FIXTURE_NAMES}
        self._ids = itertools.count(1)

    def _event(self, exception_id: str, event: str, trace_id: str, details: dict[str, Any]) -> None:
        self.trails[exception_id].append(
            {
                "audit_id": next(self._ids),
                "event": event,
                "exception_id": exception_id,
                "trace_id": trace_id,
                "recorded_at": "2026-10-06T00:00:00+00:00",
                "details": details,
            }
        )

    def submit(self, reading: dict[str, Any], trace_id: str) -> str:
        self.calls.append("submit")
        if self.scenario is not None and (
            reading.get("emulator_response") != self.scenario.response
            or reading.get("handling_note") != self.scenario.note.text
        ):
            raise AssertionError("the stand-in is configured for another scenario")
        # The id the API would mint for this reading (`src/domain/exceptions.py`).
        exception_id = exception_id_for(SensorReading.model_validate(reading))
        self.readings[exception_id] = dict(reading)
        self.notes[exception_id] = str(reading["handling_note"])
        self.traces[exception_id] = trace_id
        self.trails[exception_id] = []
        self.records[exception_id] = {"state": "QUEUED", "summary": None}
        return exception_id

    def wait_finished(self, exception_id: str) -> str:
        self.calls.append("wait_finished")
        trace_id = self.traces[exception_id]
        reading = self.readings[exception_id]
        note = redact(self.notes[exception_id])
        # The supplied emulator's answer for this reading's response selector, and the
        # supplied guardrail's verdict on it: what the real worker would store.
        answer = emulated_answer(reading, exception_id, note)
        verdict = validate_summary(answer)
        if self.behaviour == "answer-stored":
            record: dict[str, Any] = {
                "state": "COMPLETED",
                "summary": answer,
                **VALIDATED,
                "rejection_reason": None,
                "failure_reason": None,
            }
            decision = ("output_validated", dict(VALIDATED))
        elif isinstance(verdict, RejectedSummary):
            record = {
                "state": "NEEDS_REVIEW",
                "summary": REVIEW_MESSAGE,
                "handling_class": None,
                "next_step": None,
                "rejection_reason": verdict.code,
                "failure_reason": None,
            }
            decision = ("output_rejected", {"reason_code": verdict.code})
        else:
            record = {
                "state": "COMPLETED",
                "summary": verdict.summary,
                "handling_class": verdict.handling_class,
                "next_step": verdict.next_step,
                "rejection_reason": None,
                "failure_reason": None,
            }
            decision = (
                "output_validated",
                {"handling_class": verdict.handling_class, "next_step": verdict.next_step},
            )
        self.records[exception_id] = record
        if self.behaviour != "no-trail":
            self._event(
                exception_id,
                "processing_requested",
                trace_id,
                {"reading_id": reading["reading_id"], "delivery_count": 1},
            )
            self._event(
                exception_id,
                "model_responded",
                trace_id,
                {
                    "provider": "deterministic-local",
                    "answer_digest": hashlib.sha256(answer.encode("utf-8")).hexdigest(),
                    "answer_length": len(answer),
                },
            )
            self._event(exception_id, decision[0], trace_id, decision[1])
            self._event(
                exception_id,
                "outcome_stored",
                trace_id,
                {"state": record["state"], "summary": record["summary"]},
            )
        return str(record["state"])

    def read_summary(self, exception_id: str, fixture: str, trace_id: str) -> tuple[int, str]:
        self.calls.append(f"read_summary:{fixture}")
        if fixture == "dispatcher-valid" or self.behaviour == "token-accepted":
            if self.behaviour != "no-trail":
                self._event(
                    exception_id,
                    "summary_read",
                    trace_id,
                    {"subject": "user:dispatcher-01", "role": "dispatcher"},
                )
            record = {"exception_id": exception_id, **self.records[exception_id]}
            return 200, json.dumps(record)
        # The access rule's refusal as FastAPI renders it (`src/api/security/access.py`):
        # one `detail` text and nothing else.
        return EXPECTED_STATUS[fixture], json.dumps({REFUSAL_FIELD: "the access rule refused it"})

    def stored_record(self, exception_id: str) -> dict[str, Any] | None:
        self.calls.append("stored_record")
        return dict(self.records[exception_id])

    def locations(self, exception_id: str) -> dict[str, str | None]:
        self.calls.append("locations")
        note = self.notes[exception_id]
        shown = note if self.behaviour == "note-leaked" else redact(note)
        summary = self.records[exception_id]["summary"]
        return {
            "worker logs": f"reading job exception_id={exception_id} handling_note={shown}",
            "model request": f"handling_note: {shown}",
            "audit records": pii.details_text(
                record["details"] for record in self.trails[exception_id]
            ),
            "stored summary": str(summary or ""),
        }

    def trail(self, exception_id: str) -> list[dict[str, Any]]:
        self.calls.append("trail")
        return [dict(record) for record in self.trails[exception_id]]

    def token(self, fixture: str) -> str:
        return self.tokens[fixture]


def _scenario(document: dict[str, Any]) -> str:
    """Return a scenario as the JSON text the environment variable carries."""
    return json.dumps(document)


def test_held_out_check_mechanism_with_a_fake_scenario() -> None:
    """The mechanism must send the attack, reach every interface, and pass intact controls."""
    stack = _FakeStack("correct")

    passed = run_held_out_check(_scenario(FAKE_SCENARIO), UNUSED, interfaces=stack)

    assert passed
    reached = {call.split(":", 1)[0] for call in stack.calls}
    assert set(INTERFACES) <= reached, sorted(reached)
    unauthorized = stack.calls.index("read_summary:wrong-issuer")
    dispatcher = stack.calls.index("read_summary:dispatcher-valid")
    assert unauthorized < dispatcher, "the unauthorized read comes before the dispatcher's"


def test_the_stand_in_derives_its_controls_from_the_supplied_contracts() -> None:
    """The id, the status and the reason code are the API's, the policy's and the guardrail's.

    Nothing of what the intact stand-in records is a constant of this module: the
    exception id is the one `src/domain/exceptions.py` mints for the reading, the refused
    read's status is `EXPECTED_STATUS` for the fixture presented, and the stored reason
    code is the guardrail's verdict on the answer the emulator gives the scenario's
    response selector (`unknown_property` for a manipulated answer, as the development
    scenario's live run records). A stand-in lent a scenario refuses another's reading.
    """
    stack = _FakeStack("correct")
    scenario = load_scenario_text(_scenario(FAKE_SCENARIO), require_expected=True)

    result = run_attack(scenario, stack)

    (exception_id,) = stack.readings
    assert result.exception_id == exception_id
    assert exception_id == exception_id_for(
        SensorReading.model_validate(stack.readings[exception_id])
    )
    assert result.stage(TOKEN_CHECK).result["status"] == EXPECTED_STATUS["wrong-issuer"]
    answer = emulated_answer(stack.readings[exception_id], exception_id, redact(scenario.note.text))
    verdict = validate_summary(answer)
    assert isinstance(verdict, RejectedSummary)
    assert stack.records[exception_id]["rejection_reason"] == verdict.code
    assert result.stage(OUTPUT_SCHEMA).result["rejection_reason"] == verdict.reason_code
    assert verdict.reason_code == "unknown_property"
    # Every refused selector yields the guardrail's code for that answer, not a constant.
    for response in REJECTED_RESPONSES:
        other = {**FAKE_SCENARIO, "response": response, "scenario_id": "dry-run-other"}
        other_scenario = load_scenario_text(_scenario(other), require_expected=True)
        other_stack = _FakeStack("correct", scenario=other_scenario)
        other_result = run_attack(other_scenario, other_stack)
        (other_id,) = other_stack.readings
        other_verdict = validate_summary(
            emulated_answer(
                other_stack.readings[other_id], other_id, redact(other_scenario.note.text)
            )
        )
        assert isinstance(other_verdict, RejectedSummary), response
        assert (
            other_result.stage(OUTPUT_SCHEMA).result["rejection_reason"]
            == other_verdict.reason_code
        )
        assert other_result.stage(OUTPUT_SCHEMA).outcome == HELD, response
        # The configured stand-in grades the scenario it was lent and no other.
        if response != scenario.response:
            with pytest.raises(AssertionError):
                run_attack(scenario, _FakeStack("correct", scenario=other_scenario))


@pytest.mark.parametrize(
    "behaviour,stage",
    [
        ("token-accepted", TOKEN_CHECK),
        ("answer-stored", OUTPUT_SCHEMA),
        ("note-leaked", REDACTOR),
        ("no-trail", AUDIT_TRAIL),
    ],
    ids=["token-accepted", "answer-stored", "note-leaked", "no-trail"],
)
def test_a_control_that_did_not_hold_fails_its_own_stage_and_the_grade(
    behaviour: Behaviour, stage: str
) -> None:
    """Each defect is classified by the stage of the control it defeats, and fails the grade."""
    stack = _FakeStack(behaviour)
    scenario = load_scenario_text(_scenario(FAKE_SCENARIO), require_expected=True)

    result = run_attack(scenario, stack)

    assert result.stage(stage).outcome == FAILED, result.stage(stage).result
    others = [result.stage(name).outcome for name in STAGES if name != stage]
    assert others == [HELD] * 3, "a defect is named by its own stage alone"
    assert run_held_out_check(_scenario(FAKE_SCENARIO), UNUSED, interfaces=stack) is False


def test_a_documented_limit_is_limited_not_failed() -> None:
    """A value the redactor itself leaves in place is `limited`, graded as the scenario expects."""
    stack = _FakeStack("correct")
    scenario = load_scenario_text(_scenario(LIMITED_SCENARIO), require_expected=True)

    result = run_attack(scenario, stack)

    redactor = result.stage(REDACTOR)
    assert redactor.outcome == LIMITED
    by_label = {line["label"]: line for line in redactor.result["values"]}
    assert by_label["D-02 name"]["redactor_replaces_it"] is False
    assert by_label["D-02 name"]["reached"] == ["worker logs", "model request"]
    assert by_label["D-02 phone"]["redactor_replaces_it"] is True
    assert by_label["D-02 phone"]["reached"] == []
    assert run_held_out_check(_scenario(LIMITED_SCENARIO), UNUSED, interfaces=stack)
    held_instead = {**LIMITED_SCENARIO, "expected": FAKE_SCENARIO["expected"]}
    assert run_held_out_check(_scenario(held_instead), UNUSED, interfaces=stack) is False


def test_an_unreachable_stack_is_unusable_not_a_failure() -> None:
    """A stack that did not answer, or a run with no answer to judge, is our fault, not a grade."""
    stack = _FakeStack("correct")

    def refuse(reading: dict[str, Any], trace_id: str) -> str:
        raise ScenarioError("the intake did not answer")

    stack.submit = refuse  # type: ignore[method-assign]
    with pytest.raises(ScenarioError):
        run_held_out_check(_scenario(FAKE_SCENARIO), UNUSED, interfaces=stack)

    failing = _FakeStack("correct")
    original = failing.wait_finished

    def fail_run(exception_id: str) -> str:
        original(exception_id)
        failing.records[exception_id]["state"] = "FAILED"
        return "FAILED"

    failing.wait_finished = fail_run  # type: ignore[method-assign]
    with pytest.raises(ScenarioError):
        run_held_out_check(_scenario(FAKE_SCENARIO), UNUSED, interfaces=failing)


@pytest.mark.parametrize(
    "scenario",
    [
        "",
        "not json",
        "{}",
        json.dumps({key: value for key, value in FAKE_SCENARIO.items() if key != "note"}),
        json.dumps({key: value for key, value in FAKE_SCENARIO.items() if key != "expected"}),
        json.dumps({**FAKE_SCENARIO, "surprise": 1}),
        json.dumps({**FAKE_SCENARIO, "token_fixture": "dispatcher-valid"}),
        json.dumps({**FAKE_SCENARIO, "response": "valid"}),
        json.dumps({**FAKE_SCENARIO, "note": {**FAKE_SCENARIO["note"], "pii": []}}),
        json.dumps(
            {
                **FAKE_SCENARIO,
                "note": {**FAKE_SCENARIO["note"], "pii": [{"kind": "name", "value": "Nobody"}]},
            }
        ),
        json.dumps({**FAKE_SCENARIO, "expected": {"secret_check": {"outcome": HELD}}}),
        json.dumps({**FAKE_SCENARIO, "expected": {TOKEN_CHECK: {"outcome": "passed"}}}),
        json.dumps({**FAKE_SCENARIO, "expected": {REDACTOR: {"outcome": HELD}}}),
    ],
    ids=[
        "empty",
        "not-json",
        "no-keys",
        "missing-note",
        "missing-expected",
        "unexpected-key",
        "accepted-fixture",
        "accepted-response",
        "no-marked-value",
        "value-not-in-text",
        "unknown-stage",
        "unknown-outcome",
        "partial-expected",
    ],
)
def test_an_unusable_scenario_is_refused_before_anything_is_sent(scenario: str) -> None:
    """A missing, malformed or partial scenario is refused, never graded, and touches no interface.

    Partial: an expectation for fewer than the four stages would silently stop assessing
    the other controls, so the entrypoint refuses it before the attack is sent.
    """
    stack = _FakeStack("correct")

    with pytest.raises(ScenarioError):
        run_held_out_check(scenario, UNUSED, interfaces=stack)
    assert stack.calls == []


def test_the_entry_point_separates_a_failed_grade_from_an_unusable_run(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Exit 0, 1, and 2 must mean pass, failed grade, and unusable run.

    The workflow reads these codes to decide between reporting `success`, `failure`, and
    `error` on the pull request. Collapsing the last two would show a student a wrong
    answer where the fault was a missing secret or a stack that did not start.
    """
    assert main(_scenario(FAKE_SCENARIO), UNUSED, interfaces=_FakeStack("correct")) == 0
    assert capsys.readouterr().out.strip() == PASS

    assert main(_scenario(FAKE_SCENARIO), UNUSED, interfaces=_FakeStack("no-trail")) == 1
    assert capsys.readouterr().out.strip() == FAIL

    assert main("", UNUSED, interfaces=_FakeStack("correct")) == 2
    unusable = capsys.readouterr()
    assert INFRASTRUCTURE in unusable.err
    assert PASS not in unusable.out and FAIL not in unusable.out


def test_no_scenario_content_reaches_the_output(capsys: pytest.CaptureFixture[str]) -> None:
    """A student reads this output, so nothing about the scenario may appear in it."""
    stack = _FakeStack("note-leaked")
    main(_scenario(FAKE_SCENARIO), UNUSED, interfaces=stack)
    captured = capsys.readouterr()
    assert captured.out.strip() == FAIL
    assert captured.err == ""
    for secret in (
        "Marek",
        "555-0150",
        "wrong-issuer",
        "manipulated",
        *stack.readings,
        *stack.tokens.values(),
    ):
        assert secret not in captured.out


def test_the_development_scenario_is_usable_only_by_the_development_tool() -> None:
    """The public scenario parses for `poe attack-dev`; without an expectation it grades nothing."""
    text = (TASK_ROOT / SCENARIO_PATH).read_text(encoding="utf-8")
    scenario = load_scenario_text(text, require_expected=False)
    assert scenario.expected is None
    assert scenario.note.marked, "the development note marks no personal value"
    with pytest.raises(ScenarioError):
        load_scenario_text(text, require_expected=True)
