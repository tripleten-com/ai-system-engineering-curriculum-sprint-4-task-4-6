"""Coldline.

===================

File:              tests/unit/security/test_governance.py
Component:         Unit tests — Governance material readers and rules
Purpose:           Prove the readers parse the supplied material's shapes, the register keeps
                    its supplied metadata, the student-file parsers read entries, sections,
                    conditions and citations as documented from the visible Markdown, the
                    conditions' labels are derived and matched as the policy states, and the
                    wording scan reads what a reader sees (every YAML comment and key
                    included, Markdown rendered with its markup removed and its paragraphs
                    joined) and exempts only a marked quotation of the analysis.
Interacts With:    tests/security/governance.py, docs/governance/*, docs/security/control-matrix.md
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          Structure by machine, content by the instructor
Tools:             Python 3.12, pytest

The student files are never read here for their content: the parsers are exercised over
small texts written in these tests under invented ids (CL-9n, OR-9n, TH-9n, R-9n, C-9n), and
the supplied material is read only for its ids, its claim texts and the register's supplied
metadata, which are public and which every valid submission keeps.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tests.security import governance
from tests.security.governance import SUPPLIED_RISKS

TASK_ROOT = Path(__file__).resolve().parents[3]
_CONTROL_ID = re.compile(r"\bC-\d{2}\b")
# Completion values invented for these tests: a control id, a test and an owner role that
# have the documented forms and name nothing of the Task's answers.
_FILLED = {
    "control": "C-90",
    "test": "tests/unit/test_example.py::test_one",
    "evidence": "attack-dev:redactor",
    "owner": "platform-lead",
    "residual": "Something remains.",
    "mapping_note": "",
}


def _register_text(
    risks: tuple[tuple[str, str, str], ...] = SUPPLIED_RISKS, **overrides: dict[str, str]
) -> str:
    """Render a register with the supplied metadata and invented completion values.

    ``overrides`` replaces completion values for one entry by its register id.
    """
    lines = ["risks:"]
    for entry_id, threat, title in risks:
        values = {**_FILLED, **overrides.get(entry_id.replace("-", "_"), {})}
        lines.append(f"  - id: {entry_id}")
        lines.append(f"    threat: {threat}")
        lines.append(f"    title: {title}")
        for name in governance.COMPLETION_FIELDS:
            lines.append(f"    {name}: {values[name]!r}")
    return "\n".join(lines) + "\n"


def _write_register(root: Path, text: str) -> None:
    (root / "docs/governance").mkdir(parents=True, exist_ok=True)
    (root / governance.REGISTER_PATH).write_text(text, encoding="utf-8")


def test_the_supplied_material_parses_to_its_ids() -> None:
    """The analysis numbers claims, the matrix lists controls, the concerns and roles have ids."""
    claims = governance.claim_ids(TASK_ROOT)
    assert claims and all(governance.valid_claim_id(claim) for claim in claims)
    assert len(claims) == len(set(claims))
    controls = governance.control_ids(TASK_ROOT)
    assert controls[:6] == ("C-01", "C-02", "C-03", "C-04", "C-05", "C-06")
    concerns = governance.concern_ids(TASK_ROOT)
    assert concerns and all(concern.startswith("GC-") for concern in concerns)
    roles = governance.owner_roles(TASK_ROOT)
    assert len(roles) >= 3 and all(role == role.lower() for role in roles)


def test_the_analysis_claim_texts_are_read_per_claim() -> None:
    """Each numbered claim's text is read under its id, normalized for the quotation check."""
    texts = governance.claim_texts(TASK_ROOT)
    assert tuple(texts) == governance.claim_ids(TASK_ROOT)
    assert all(text and "  " not in text and "\n" not in text for text in texts.values())


def test_every_concern_states_its_intent_sources_and_criteria_and_names_no_control() -> None:
    """A concern says what a control would have to do to serve it; it enumerates no control.

    The mapping is the student's to derive from the criteria, the control matrix and the
    evidence, so the concerns file lists neither the controls that serve a concern nor the
    ones that do not; it names no control id at all.
    """
    text = (TASK_ROOT / governance.CONCERNS_PATH).read_text(encoding="utf-8")
    assert "Served in this Project by" not in text
    assert "Not served by" not in text
    assert _CONTROL_ID.search(text) is None
    sections = re.split(r"^## (GC-\d{2})\b.*$", text, flags=re.MULTILINE)
    bodies = dict(zip(sections[1::2], sections[2::2], strict=True))
    assert tuple(bodies) == governance.concern_ids(TASK_ROOT)
    for concern, body in bodies.items():
        for label in ("- Intent:", "- Sources:", "- Served when"):
            assert label in body, f"{concern} lacks `{label}`"
        assert len(re.findall(r"^  \d+\. ", body, flags=re.MULTILINE)) >= 2, concern


def test_the_shipped_register_carries_exactly_the_pinned_supplied_entries() -> None:
    """The register's supplied metadata is the pin, entry for entry, in order.

    The pin names the supplied part of a student-editable file, not its starter state: a
    valid submission keeps every id, threat and title, so this holds on the untouched
    template and on every completed register alike.
    """
    entries = governance.load_register(TASK_ROOT)
    assert tuple((entry.id, entry.threat, entry.title) for entry in entries) == SUPPLIED_RISKS
    assert len(SUPPLIED_RISKS) == 5
    assert [risk[0] for risk in SUPPLIED_RISKS] == ["R-01", "R-02", "R-03", "R-04", "R-05"]


def test_a_register_with_the_supplied_entries_loads_and_its_completion_fields_are_read(
    tmp_path: Path,
) -> None:
    """The five supplied entries with filled or empty completion fields load as text values."""
    _write_register(
        tmp_path,
        _register_text(R_02={"control": "", "residual": "", "evidence": ""}),
    )
    entries = governance.load_register(tmp_path)
    assert [entry.id for entry in entries] == [risk[0] for risk in SUPPLIED_RISKS]
    assert entries[0].control == "C-90" and entries[1].control == ""
    assert entries[1].residual == "" and entries[0].residual == "Something remains."
    assert governance.register_fields(entries, "owner") == ["platform-lead"] * 5


_RESIDUAL_LINE = "    residual: 'Something remains.'\n"
_OWNER_LINE = "    owner: 'platform-lead'\n"
_RETITLED = (SUPPLIED_RISKS[2][0], SUPPLIED_RISKS[2][1], "Retitled")


@pytest.mark.parametrize(
    "text,reason",
    [
        (_register_text(SUPPLIED_RISKS[:4]), "exactly the 5 supplied entries"),
        (
            _register_text((*SUPPLIED_RISKS, ("R-06", "TH-99", "An added entry"))),
            "exactly the 5 supplied entries",
        ),
        (
            _register_text((SUPPLIED_RISKS[1], SUPPLIED_RISKS[0], *SUPPLIED_RISKS[2:])),
            "entry 1 must keep the supplied id, threat and title",
        ),
        (
            _register_text((*SUPPLIED_RISKS[:4], ("R-05", "TH-99", SUPPLIED_RISKS[4][2]))),
            "entry 5 must keep the supplied id, threat and title",
        ),
        (
            _register_text((*SUPPLIED_RISKS[:2], _RETITLED, *SUPPLIED_RISKS[3:])),
            "entry 3 must keep the supplied id, threat and title",
        ),
        (_register_text().replace(_RESIDUAL_LINE, "", 1), "exactly the keys"),
        (
            _register_text().replace(_OWNER_LINE, _OWNER_LINE + "    owner: 'privacy-lead'\n", 1),
            "not restricted YAML",
        ),
        (
            _register_text().replace(_RESIDUAL_LINE, "    residual: &r 'Something remains.'\n", 1),
            "not restricted YAML",
        ),
        ("risks: []\n", "non-empty"),
        ("risks:\n  - id: R-01\n    threat: TH-01\n", "exactly the 5 supplied entries"),
        # The regression round 3 named: a key beside `risks` left the five entries intact
        # and, as a key, escaped the value scan; the register holds `risks` alone.
        (_register_text() + '"Coldline is HIPAA compliant": ""\n', "exactly one top-level key"),
        ("notes: []\n" + _register_text(), "exactly one top-level key"),
        ("- id: R-01\n", "exactly one top-level key"),
    ],
    ids=[
        "entry-removed",
        "entry-added",
        "entries-reordered",
        "threat-changed",
        "title-changed",
        "key-missing",
        "duplicate-key",
        "anchor",
        "empty-list",
        "one-partial-entry",
        "key-beside-risks",
        "key-before-risks",
        "not-a-mapping",
    ],
)
def test_a_register_that_changes_the_supplied_part_or_the_shape_is_refused(
    tmp_path: Path, text: str, reason: str
) -> None:
    """Only the six completion fields may change; anything else names the problem."""
    _write_register(tmp_path, text)
    with pytest.raises(governance.GovernanceError, match=re.escape(reason)):
        governance.load_register(tmp_path)


def test_evidence_records_are_recognized_in_their_documented_forms_only() -> None:
    """A stage, a pull request citation, or nothing."""
    assert governance.evidence_kind("attack-dev:redactor") == "stage"
    assert governance.cited_stage(" attack-dev:audit_trail ") == "audit_trail"
    citation = (
        "task-4.5 pull request https://github.com/example/coldline-task-4-5/pull/7 "
        "commit 0123456789abcdef0123456789abcdef01234567"
    )
    assert governance.evidence_kind(citation) == "pull_request"
    for wrong in (
        "",
        "attack-dev:secret_check",
        "attack-dev",
        "https://github.com/example/coldline-task-4-5/pull/7",
        "task-4.5 pull request 7",
        "task-4.9 pull request https://github.com/example/x/pull/7 commit 0123456",
    ):
        assert governance.evidence_kind(wrong) is None, wrong


def test_evidence_stages_are_read_from_the_document() -> None:
    """Only a stage with a known outcome counts."""
    document = {
        "stages": {
            "token_check": {"outcome": "held"},
            "redactor": {"outcome": "limited"},
            "audit_trail": {"outcome": "unknown"},
            "output_schema": {},
        }
    }
    assert governance.evidence_stages(document) == {"token_check": "held", "redactor": "limited"}
    assert governance.evidence_stages({}) == {}


def test_test_citations_are_parsed_and_collected(tmp_path: Path) -> None:
    """A `<path>::<name>` citation resolves only when pytest collects that case from that module."""
    assert governance.parse_test_citation(
        "tests/unit/test_x.py::test_a"
    ) == governance.TestCitation("tests/unit/test_x.py", "test_a")
    assert governance.parse_test_citation("tests/unit/test_x.py") is None
    assert governance.parse_test_citation("src/api/routes.py::get_exception") is None
    found = governance.test_citations_in(
        "see `tests/unit/test_x.py::test_a` and tests/unit/test_y.py::TestCase::test_b."
    )
    assert [citation.name for citation in found] == ["test_a", "TestCase::test_b"]

    (tmp_path / "tests/unit").mkdir(parents=True)
    (tmp_path / "tests/unit/test_probe.py").write_text(
        "import pytest\n\n\ndef test_one():\n    pass\n\n\n"
        "@pytest.mark.parametrize('n', [1, 2])\ndef test_two(n):\n    pass\n\n\n"
        "class TestGroup:\n    def test_three(self):\n        pass\n",
        encoding="utf-8",
    )
    collected = governance.collected_tests(
        tmp_path, ["tests/unit/test_probe.py", "tests/unit/test_absent.py"]
    )
    assert set(collected) == {"tests/unit/test_probe.py"}
    names = collected["tests/unit/test_probe.py"]
    assert {"test_one", "test_two", "test_three", "TestGroup::test_three"} <= names
    for name, exists in (("test_two", True), ("TestGroup::test_three", True), ("test_four", False)):
        citation = governance.TestCitation("tests/unit/test_probe.py", name)
        assert governance.test_exists(citation, collected) is exists
    absent = governance.TestCitation("tests/unit/test_absent.py", "test_one")
    assert governance.test_exists(absent, collected) is False


def test_resolved_citations_name_files_tests_stages_and_pull_requests(tmp_path: Path) -> None:
    """Each documented form resolves; a path that does not exist and a plain word do not."""
    (tmp_path / "docs/security").mkdir(parents=True)
    (tmp_path / "docs/security/output-policy.md").write_text("# policy\n", encoding="utf-8")
    collected = {"tests/unit/test_x.py": {"test_a"}}
    text = (
        "docs/security/output-policy.md, `tests/unit/test_x.py::test_a`, attack-dev:redactor, "
        "task-4.3 pull request https://github.com/example/x/pull/3 commit abcdef1234567, "
        "docs/security/missing.md, tests/unit/test_x.py::test_b and a word"
    )
    found = governance.resolved_citations(text, tmp_path, collected)
    assert found == [
        "docs/security/output-policy.md",
        "tests/unit/test_x.py::test_a",
        "attack-dev:redactor",
        "task-4.3 pull request https://github.com/example/x/pull/3 commit abcdef1234567",
    ]
    assert governance.resolved_citations("nothing cited here", tmp_path, collected) == []


def test_corrections_are_parsed_into_their_two_sections() -> None:
    """Entries under each section, labelled lines, continuation lines, and repeats."""
    text = (
        "# Governance corrections\n\n## Claim corrections\n\n### CL-93\n"
        "- What is wrong: The first line.\n- Corrected statement: A statement that\n  continues.\n"
        "- Evidence: attack-dev:redactor\n\n> Analysis (CL-93): quoted words\n\n"
        "### CL-95\n- What is wrong: x\n- Corrected statement: y\n- Evidence: z\n"
        "### CL-95\n- What is wrong: again\n\n## Omitted risks\n\n### OR-91\n"
        "- Risk: TH-96 is left out.\n- Evidence: docs/student/threat-model.md\n"
    )
    parsed = governance.parse_corrections(text)
    assert set(parsed.claims) == {"CL-93", "CL-95"}
    assert parsed.claims["CL-93"].fields["corrected statement"] == "A statement that continues."
    assert parsed.claims["CL-93"].fields["evidence"].startswith("attack-dev:redactor")
    assert parsed.duplicates == ("CL-95",)
    assert list(parsed.omitted) == ["OR-91"]
    assert parsed.omitted["OR-91"].fields["risk"] == "TH-96 is left out."
    empty = governance.parse_corrections("# Nothing\n\n### CL-91\n- Evidence: x\n")
    assert empty.claims == {} and empty.omitted == {}


def test_section_entries_are_parsed_from_their_headings_and_labelled_lines() -> None:
    """A `### <heading>` entry holds labelled lines; text before the first heading is none."""
    body = (
        "Some words before the first entry.\n\n### Condition 1\n\n"
        "- Applies to: C1:attack-dev:redactor\n"
        "- What must be true: A statement\n  that continues.\n- Owner: platform-lead\n"
        "- Evidence: attack-dev:redactor\n\n### Condition 2\n\n- Applies to: `C2:R-95`\n"
        "- What must be true: Another.\n"
        "- Owner: `privacy-lead`\n- Evidence: docs/security/redactor.md\n"
    )
    entries = governance.parse_entries(body)
    assert [entry.entry_id for entry in entries] == ["Condition 1", "Condition 2"]
    assert entries[0].fields == {
        "applies to": "C1:attack-dev:redactor",
        "what must be true": "A statement that continues.",
        "owner": "platform-lead",
        "evidence": "attack-dev:redactor",
    }
    assert entries[1].fields["owner"] == "`privacy-lead`"
    assert entries[1].fields["applies to"] == "`C2:R-95`"
    assert governance.parse_entries("") == []
    assert governance.parse_entries("- Owner: nobody\n") == []


def _condition(heading: str, label: str) -> governance.CorrectionEntry:
    """Return one complete condition entry with the given `Applies to` label."""
    return governance.CorrectionEntry(
        heading,
        {
            "applies to": label,
            "what must be true": "Something observable.",
            "owner": "platform-lead",
            "evidence": "attack-dev:redactor",
        },
    )


_RULE_REGISTER = (
    governance.RegisterEntry(
        "R-91", "TH-91", "t", "C-90", "", "attack-dev:token_check", "", "", ""
    ),
    governance.RegisterEntry(
        "R-93",
        "TH-93",
        "t",
        "C-91",
        "",
        "task-4.5 pull request https://github.com/example/x/pull/7 commit 0123456789ab",
        "",
        "",
        "",
    ),
    governance.RegisterEntry("R-95", "TH-95", "t", "C-92", "", "", "", "", ""),
)


def test_the_required_conditions_follow_from_the_evidence_and_the_register() -> None:
    """One C1 per `limited` stage in stage order, then one C2 per pull request citation."""
    stages = {"token_check": "held", "redactor": "limited", "audit_trail": "held"}
    assert governance.required_conditions(stages, _RULE_REGISTER) == [
        "C1:attack-dev:redactor",
        "C2:R-93",
    ]
    two_limited = {**stages, "token_check": "limited"}
    assert governance.required_conditions(two_limited, _RULE_REGISTER)[:2] == [
        "C1:attack-dev:token_check",
        "C1:attack-dev:redactor",
    ]
    assert governance.required_conditions({"redactor": "held"}, _RULE_REGISTER[::2]) == []


@pytest.mark.parametrize(
    "text,outcome,expected",
    [
        ("C1:attack-dev:redactor", "conditional_go", "C1:attack-dev:redactor"),
        (" `C2:R-05` ", "conditional_go", "C2:R-05"),
        ("N1:attack-dev:token_check", "no_go", "N1:attack-dev:token_check"),
        ("N3:R-02", "no_go", "N3:R-02"),
        ("N1:attack-dev:redactor", "conditional_go", None),
        ("C1:attack-dev:redactor", "no_go", None),
        ("C1:R-03", "conditional_go", None),
        ("C2:attack-dev:redactor", "conditional_go", None),
        ("C1:attack-dev:secret_check", "conditional_go", None),
        ("C3:R-01", "conditional_go", None),
        ("redactor", "conditional_go", None),
        ("", "conditional_go", None),
        ("C1:attack-dev:redactor", "go", None),
    ],
)
def test_an_applies_to_label_names_a_rule_of_the_outcome_and_what_it_applied_to(
    text: str, outcome: str, expected: str | None
) -> None:
    """A condition applies to C1 (a stage) or C2 (an entry); a required change to N1, N2 or N3."""
    assert governance.applies_to(text, outcome) == expected


def test_a_conditional_go_needs_exactly_one_condition_per_rule_that_applied() -> None:
    """A missing, a doubled, an unrequired and a malformed label are each a finding."""
    required = ["C1:attack-dev:redactor", "C2:R-93"]
    complete = [
        _condition("Condition 1", "C1:attack-dev:redactor"),
        _condition("Condition 2", "C2:R-93"),
    ]
    assert governance.condition_findings(complete, required, "conditional_go") == []
    # The regression round 2 named: deleting either required condition is a finding.
    for kept, missing in ((complete[:1], "C2:R-93"), (complete[1:], "C1:attack-dev:redactor")):
        findings = governance.condition_findings(kept, required, "conditional_go")
        assert findings == [f"no entry applies to {missing}, a rule that applied"]
    doubled = [*complete, _condition("Condition 3", "C2:R-93")]
    assert governance.condition_findings(doubled, required, "conditional_go") == [
        "2 entries apply to C2:R-93 (Condition 2, Condition 3)"
    ]
    extra = [*complete, _condition("Condition 3", "C1:attack-dev:token_check")]
    [finding] = governance.condition_findings(extra, required, "conditional_go")
    assert finding.startswith("Condition 3: applies to C1:attack-dev:token_check, which no rule")
    malformed = [complete[0], _condition("Condition 2", "the secret control")]
    findings = governance.condition_findings(malformed, required, "conditional_go")
    assert findings[0].startswith("Condition 2: `Applies to` is not")
    assert "no entry applies to C2:R-93" in findings[1]
    # A no go checks the shape alone: which no-go rule applied is the instructor's question.
    changes = [_condition("Change 1", "N2:R-91"), _condition("Change 2", "N1:attack-dev:redactor")]
    assert governance.condition_findings(changes, None, "no_go") == []
    assert governance.condition_findings(
        [_condition("Change 1", "C1:attack-dev:redactor")], None, "no_go"
    )
    assert governance.condition_findings([], required, "conditional_go") == [
        "no entry applies to C1:attack-dev:redactor, a rule that applied",
        "no entry applies to C2:R-93, a rule that applied",
    ]


@pytest.mark.parametrize("outcome", governance.DECISIONS)
def test_the_decision_record_is_split_into_sections_lines_and_entries(outcome: str) -> None:
    """The Outcome line, the rationale, each section's body, the entries, the accepted lines."""
    text = (
        f"# Decision record\n\n## Decision\n\nOutcome: {outcome}\n\nThe rationale paragraph.\n\n"
        "## Evidence\n\nR-91 to R-95.\n\n## Conditions (conditional go)\n\n### Condition 1\n\n"
        "- What must be true: One thing.\n- Owner: platform-lead\n"
        "- Evidence: attack-dev:redactor\n\n"
        "## What must change first (no go)\n\n[fill in: left as supplied]\n\n"
        "## Why no residual risk blocks a go (go)\n\n\n## Accepted risk\n\n"
        "Register id: R-94\nOwner: platform-lead\nWhy it is acceptable now: Bounded.\n"
        "What evidence would change the decision: A read nobody made.\n"
    )
    record = governance.parse_decision_record(text)
    assert record.outcome == outcome
    assert record.rationale == "The rationale paragraph."
    assert governance.section_is_filled(record, "Decision")
    assert governance.section_is_filled(record, "Evidence")
    assert governance.section_is_filled(record, "Conditions (conditional go)")
    assert not governance.section_is_filled(record, "What must change first (no go)")
    assert not governance.section_is_filled(record, "Why no residual risk blocks a go (go)")
    assert not governance.section_is_filled(record, "Missing section")
    entries = governance.section_entries(record, "Conditions (conditional go)")
    assert [entry.entry_id for entry in entries] == ["Condition 1"]
    assert entries[0].fields["owner"] == "platform-lead"
    assert governance.section_entries(record, "What must change first (no go)") == []
    assert governance.section_entries(record, "Missing section") == []
    assert record.accepted == {
        "Register id": "R-94",
        "Owner": "platform-lead",
        "Why it is acceptable now": "Bounded.",
        "What evidence would change the decision": "A read nobody made.",
    }


_VISIBLE_CORRECTIONS = (
    "# Governance corrections\n\n## Claim corrections\n\n### CL-93\n"
    "- What is wrong: x.\n- Corrected statement: y.\n- Evidence: attack-dev:redactor\n\n"
    "## Omitted risks\n\n### OR-91\n- Risk: TH-96 is left out.\n"
    "- Evidence: docs/student/threat-model.md\n"
)
_VISIBLE_RECORD = (
    "# Decision record\n\n## Decision\n\nOutcome: conditional_go\n\nThe rationale.\n\n"
    "## Evidence\n\nR-91.\n\n## Conditions (conditional go)\n\n### Condition 1\n\n"
    "- Applies to: C1:attack-dev:redactor\n- What must be true: One thing.\n"
    "- Owner: platform-lead\n- Evidence: attack-dev:redactor\n\n## Accepted risk\n\n"
    "Register id: R-94\nOwner: platform-lead\nWhy it is acceptable now: Bounded.\n"
    "What evidence would change the decision: A read nobody made.\n"
)


def test_the_structural_parsers_read_the_visible_markdown_only() -> None:
    """A document wrapped in an HTML comment renders as nothing and parses to nothing.

    The regression round 2 named: a complete corrections file or decision record inside
    `<!-- -->` passed the structural checks while rendering an empty deliverable. Now the
    parsers remove HTML comments first, so the wrapped corrections have no entries (the
    corrections rows report every claim missing) and the wrapped record has no outcome and
    no filled section (the decision rows fail on the outcome). A comment hiding one entry
    hides that entry alone, and an unterminated comment hides everything after it.
    """
    assert governance.visible_markdown("a <!-- b --> c") == "a  c"
    assert governance.visible_markdown("a <!-- b\nc --> d <!-- e") == "a  d "
    parsed = governance.parse_corrections(_VISIBLE_CORRECTIONS)
    assert set(parsed.claims) == {"CL-93"} and set(parsed.omitted) == {"OR-91"}
    wrapped = governance.parse_corrections(f"<!--\n{_VISIBLE_CORRECTIONS}-->\n")
    assert wrapped.claims == {} and wrapped.omitted == {} and wrapped.duplicates == ()
    partly = governance.parse_corrections(
        _VISIBLE_CORRECTIONS.replace("### CL-93\n", "<!-- ### CL-93\n").replace(
            "attack-dev:redactor\n", "attack-dev:redactor -->\n"
        )
    )
    assert partly.claims == {} and set(partly.omitted) == {"OR-91"}

    record = governance.parse_decision_record(_VISIBLE_RECORD)
    assert record.outcome == "conditional_go"
    assert governance.section_is_filled(record, "Conditions (conditional go)")
    assert [
        entry.entry_id
        for entry in governance.section_entries(record, "Conditions (conditional go)")
    ] == ["Condition 1"]
    hidden = governance.parse_decision_record(f"<!--\n{_VISIBLE_RECORD}-->\n")
    assert hidden.outcome is None and hidden.rationale == "" and hidden.accepted == {}
    assert hidden.sections == {}
    for name in ("Decision", "Evidence", "Conditions (conditional go)"):
        assert not governance.section_is_filled(hidden, name), name
    assert governance.section_entries(hidden, "Conditions (conditional go)") == []
    # The wording scan is separate and still reads the raw text, comment and all.
    commented = "<!-- Coldline is HIPAA compliant. -->\n## Decision\n\nOutcome: go\n"
    assert governance.wording_findings(commented, markdown=True) == [
        "line 1: 'HIPAA'",
        "line 1: 'compliant'",
    ]


def test_a_decision_section_with_only_the_outcome_line_has_no_rationale() -> None:
    """The rationale is the Decision section without its Outcome line; a marker is no outcome."""
    only_outcome = governance.parse_decision_record("## Decision\n\nOutcome: go\n")
    assert only_outcome.outcome == "go" and only_outcome.rationale == ""
    assert only_outcome.outcome_lines == 1
    assert governance.section_is_filled(only_outcome, "Decision")
    marked = governance.parse_decision_record("## Decision\n\nOutcome: [fill in: go]\n")
    assert marked.outcome is None and marked.outcome_lines == 0
    assert governance.has_marker(marked.rationale)


def test_a_repeated_outcome_line_is_neither_the_outcome_nor_the_rationale() -> None:
    """The regression round 3 named: two `Outcome:` lines and no rationale is no record.

    The Decision section must carry exactly one outcome line; a second one, identical or
    not, is counted (`outcome_lines`), leaves `outcome` None, and is left out of the
    rationale, so the section with two outcome lines and nothing else has none.
    """
    doubled = governance.parse_decision_record(
        "## Decision\n\nOutcome: conditional_go\n\nOutcome: conditional_go\n"
    )
    assert doubled.outcome is None and doubled.outcome_lines == 2
    assert doubled.rationale == "" and governance.is_blank(doubled.rationale)
    differing = governance.parse_decision_record(
        "## Decision\n\nOutcome: go\n\nThe rationale.\n\nOutcome: no_go\n"
    )
    assert differing.outcome is None and differing.outcome_lines == 2
    assert differing.rationale == "The rationale."
    # A second outcome line in another section is that section's text, not an outcome.
    elsewhere = governance.parse_decision_record(
        "## Decision\n\nOutcome: go\n\nThe rationale.\n\n## Evidence\n\nOutcome: go\n"
    )
    assert elsewhere.outcome == "go" and elsewhere.outcome_lines == 1


def test_blank_values_include_markers_and_words_for_none() -> None:
    """Empty, a template marker, and "none" in its spellings are blank; text is not."""
    for blank in ("", "   ", "[fill in: the owner]", "none", "None.", "N/A", "-"):
        assert governance.is_blank(blank), repr(blank)
    assert not governance.is_blank("A stolen token is accepted until it expires.")
    assert governance.has_marker("x [fill in: y] z")


def test_normalized_text_reads_entities_escapes_and_invisible_characters() -> None:
    """A line is read as a reader sees it: entities decoded, escapes and invisibles removed."""
    assert governance.normalized_text("comp\\liant") == "compliant"
    assert governance.normalized_text("&#99;ertified") == "certified"
    assert governance.normalized_text("cert\u200bified") == "certified"
    assert governance.normalized_text("\uff28IPAA") == "HIPAA"
    assert governance.normalized_text("a plain line") == "a plain line"


def test_the_wording_scan_exempts_only_a_marked_quotation_of_the_named_claim() -> None:
    """Forbidden wording is named by line; only a quotation the named claim holds is skipped."""
    quotes = {"CL-90": "the gate makes coldline eu ai act compliant on logging."}
    text = (
        "Our mapping is for understanding.\n"
        "> Analysis (CL-90): makes Coldline EU AI Act\n"
        ">   compliant on logging.\n"
        "\n"
        "> Analysis (CL-90): Coldline is certified under everything.\n"
        "> Analysis (CL-91): makes Coldline EU AI Act compliant on logging.\n"
        "> A plain quote that says HIPAA.\n"
        "This file is GDPR-aligned, which is a claim.\n"
        "The control comp\\lies with nothing in particular.\n"
        "It is &#99;ertified by nobody.\n"
    )
    findings = governance.wording_findings(text, markdown=True, quotes=quotes)
    assert findings == [
        "line 5: 'certified'",
        "line 6: 'EU AI Act'",
        "line 6: 'compliant'",
        "line 7: 'HIPAA'",
        "line 8: 'GDPR'",
        "line 9: 'complies with'",
        "line 10: 'certified'",
    ]
    # Without the exemption (every file but the corrections), the marked quotation counts.
    without = governance.wording_findings(text, markdown=True)
    assert without[:2] == ["line 2: 'EU AI Act'", "line 3: 'compliant'"]
    assert governance.wording_findings("A compliance claim is not made here.", markdown=True) == []


def test_the_markdown_scan_reads_rendered_text_with_markup_removed_and_lines_joined() -> None:
    """The regressions round 3 named: an emphasis-split word and a phrase over two lines.

    The scan reads a Markdown file as it renders: `**com**pliant` renders as the word, so
    it is the word; a paragraph's lines render as one text, so `complies` at the end of
    one line and `with` at the start of the next is the phrase. Links keep their text,
    tags and comment delimiters go, code spans are read, and a heading, a table row and a
    fenced line are blocks of their own that join nothing. Each term is named by the line
    it starts on.
    """
    text = (
        "Coldline is **com**pliant with ISO 27001.\n"
        "Our records show the system\n"
        "complies\n"
        "with every rule a reviewer named.\n"
        "\n"
        "- The gate makes Coldline [EU](https://example.org/a) [AI Act](b) ready,\n"
        "  as the `cert`ified reviewer wrote.\n"
        "\n"
        "## A heading that ends with GD\n"
        "PR-aligned starts the next block.\n"
        "\n"
        "| cell | in comp*liance* with |\n"
        "<span>HI</span>PAA\n"
        "<!-- certi&#102;ication -->\n"
        "\n"
        "```\n"
        "complies with\n"
        "```\n"
        "> A quote that is ~~not~~ _com_pliant.\n"
    )
    assert governance.wording_findings(text, markdown=True) == [
        "line 1: 'compliant'",
        "line 3: 'complies with'",
        "line 6: 'EU AI Act'",
        "line 7: 'certified'",
        "line 12: 'in compliance with'",
        "line 13: 'HIPAA'",
        "line 14: 'certification'",
        "line 17: 'complies with'",
        "line 19: 'compliant'",
    ]
    assert governance.rendered_text("> **com**pliant [x](y) <b>z</b> <!-- w -->") == (
        "compliant x z  w "
    )
    blocks = governance.markdown_blocks(["a", "b", "", "- c", "  d", "# e", "f", "> g", "> h"])
    assert blocks == [
        (0, ["a", "b"]),
        (3, ["- c", "  d"]),
        (5, ["# e"]),
        (6, ["f"]),
        (7, ["> g", "> h"]),
    ]


def test_the_yaml_scan_reads_decoded_values_and_every_comment() -> None:
    """A YAML escape is read as the word it spells; every comment, trailing ones too, is read."""
    text = (
        "# A comment that says GDPR.\n"
        "risks:\n"
        '  - residual: "Coldline is \\x63ertified under ISO 27001."\n'
        "    owner: privacy-lead # Coldline is HIPAA compliant.\n"
        "  - residual: complies with nothing\n"
        "    owner: ''\n"
    )
    findings = governance.yaml_wording_findings(text, Path("docs/governance/risk-register.yaml"))
    assert findings == [
        "risks[0].residual: 'certified'",
        "risks[1].residual: 'complies with'",
        "line 1: 'GDPR'",
        "line 4: 'HIPAA'",
    ]
    broken = governance.yaml_wording_findings("a: 1\na: 2\n", Path("submission.yaml"))
    assert broken == ["submission.yaml is not restricted YAML, so its values were not scanned"]
    # The regression round 3 named: a mapping key is the student's text too, and a literal
    # block's line break does not split a phrase.
    keyed = governance.yaml_wording_findings(
        'risks: []\n"Coldline is HIPAA compliant": ""\n'
        "notes:\n  GDPR-ready: |\n    complies\n    with x\n",
        Path("docs/governance/risk-register.yaml"),
    )
    assert keyed == [
        "Coldline is HIPAA compliant (a key): 'HIPAA'",
        "notes.GDPR-ready (a key): 'GDPR'",
        "notes.GDPR-ready: 'complies with'",
    ]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("# whole line\nkey: value\n", [(1, " whole line")]),
        ("key: value # trailing\n", [(1, " trailing")]),
        ("key: value #no space after\n", [(1, "no space after")]),
        ('key: "a # inside double quotes" # outside\n', [(1, " outside")]),
        ("key: 'a # inside single quotes' # outside\n", [(1, " outside")]),
        ("key: 'it''s # still inside' # outside\n", [(1, " outside")]),
        ('key: "escaped \\" # still inside" # outside\n', [(1, " outside")]),
        (
            "key: the student's words # apostrophe opens nothing\n",
            [(1, " apostrophe opens nothing")],
        ),
        ("key: a#b\n", []),
        ("key: a#b # c\n", [(1, " c")]),
        (
            "key: >- # header comment\n  text with # inside\n\n  more # text\nnext: v # tail\n",
            [(1, " header comment"), (5, " tail")],
        ),
        ("list:\n  - |\n    # not a comment\n  - x # a comment\n", [(4, " a comment")]),
        ("flow: [\"a # x\", 'b # y'] # z\n", [(1, " z")]),
        ("", []),
    ],
    ids=[
        "whole-line",
        "trailing",
        "no-space-after-hash",
        "double-quoted",
        "single-quoted",
        "doubled-single-quote",
        "escaped-double-quote",
        "apostrophe-in-plain-scalar",
        "hash-inside-word",
        "hash-inside-word-then-comment",
        "block-scalar-content",
        "literal-block-in-list",
        "flow-sequence",
        "empty",
    ],
)
def test_yaml_comments_are_found_quote_aware_and_block_content_is_not_one(
    text: str, expected: list[tuple[int, str]]
) -> None:
    """A `#` after whitespace outside quotes starts a comment; elsewhere it is text."""
    assert governance.yaml_comments(text) == expected


def test_a_trailing_comment_in_the_register_fails_the_wording_scan(tmp_path: Path) -> None:
    """The regression round 2 named: a compliance claim in a trailing YAML comment is found.

    The register parses to the same values with or without the comment, so only the
    comment scan can see it; `student_file_wording_findings` (the assessed wording row)
    must name it.
    """
    (tmp_path / "docs/governance").mkdir(parents=True)
    (tmp_path / "docs/student").mkdir(parents=True)
    (tmp_path / governance.ANALYSIS_PATH).write_text("### CL-90\n\nA claim.\n", encoding="utf-8")
    (tmp_path / governance.CORRECTIONS_PATH).write_text("## Claim corrections\n", encoding="utf-8")
    (tmp_path / governance.DECISION_RECORD_PATH).write_text("## Decision\n", encoding="utf-8")
    (tmp_path / governance.SHEET_PATH).write_text("answers:\n  decision: go\n", encoding="utf-8")
    clean = _register_text()
    _write_register(tmp_path, clean)
    assert governance.student_file_wording_findings(tmp_path) == []
    commented = clean.replace(
        "    owner: 'platform-lead'\n",
        "    owner: 'platform-lead' # Coldline is HIPAA compliant.\n",
        1,
    )
    assert commented != clean
    _write_register(tmp_path, commented)
    line = (
        commented.splitlines().index("    owner: 'platform-lead' # Coldline is HIPAA compliant.")
        + 1
    )
    assert governance.student_file_wording_findings(tmp_path) == [
        f"docs/governance/risk-register.yaml: line {line}: 'HIPAA'"
    ]
    # The comment changes no parsed value: the register rows read the same register.
    assert (
        governance.register_fields(governance.load_register(tmp_path), "owner")
        == ["platform-lead"] * 5
    )


def test_the_student_file_scan_applies_the_exemption_to_the_corrections_only(
    tmp_path: Path,
) -> None:
    """The four files are scanned; a marked quotation is exempt in the corrections alone."""
    (tmp_path / "docs/governance").mkdir(parents=True)
    (tmp_path / "docs/student").mkdir(parents=True)
    (tmp_path / governance.ANALYSIS_PATH).write_text(
        "# Analysis\n\n### CL-90\n\nThe gate makes Coldline EU AI Act compliant on logging.\n",
        encoding="utf-8",
    )
    quote = "> Analysis (CL-90): makes Coldline EU AI Act compliant on logging.\n"
    (tmp_path / governance.CORRECTIONS_PATH).write_text(
        f"## Claim corrections\n\n### CL-90\n\n{quote}- What is wrong: it is not.\n",
        encoding="utf-8",
    )
    (tmp_path / governance.DECISION_RECORD_PATH).write_text(
        f"## Decision\n\nOutcome: go\n\n{quote}", encoding="utf-8"
    )
    (tmp_path / governance.REGISTER_PATH).write_text(
        'risks:\n  - residual: "\\x63ertified"\n', encoding="utf-8"
    )
    (tmp_path / governance.SHEET_PATH).write_text("answers:\n  decision: go\n", encoding="utf-8")
    assert governance.student_file_wording_findings(tmp_path) == [
        "docs/governance/risk-register.yaml: risks[0].residual: 'certified'",
        "docs/governance/decision-record.md: line 5: 'EU AI Act'",
        "docs/governance/decision-record.md: line 5: 'compliant'",
    ]
