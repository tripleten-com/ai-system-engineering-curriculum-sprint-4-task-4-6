"""Coldline.

===================

File:              tests/security/governance.py
Component:         Security tooling — Governance material readers and rules
Purpose:           Read the supplied governance material (the analysis's claim ids and texts, the
                    control matrix, the concerns, the owner roles), the student's four files (the
                    sheet, the corrections, the register, the decision record) and the attack
                    evidence, and state the structural rules the assessed rows apply.
Interacts With:    docs/governance/*, docs/student/governance-corrections.md,
                    docs/security/control-matrix.md, evidence/attack-dev.json,
                    tests/security/attack_scenario.py, tests/contract/submission_validation.py,
                    tests/contract/test_governance_contract.py
Sprint/Task:       Sprint 4 — Project 4 / Task 4.6
Concepts:          Structure checked by machine, content judged by the instructor, citations that
                    resolve, no compliance claim in a student's own words
Tools:             Python 3.12, PyYAML, pytest (collection only)

Everything here is structural: whether a claim id has a value, whether a cited test exists,
whether a cited stage is in the evidence file, whether a section is filled. Which value,
which test or which decision is right is the protected answer check's and the instructor's
question, and nothing in this module knows an answer.

Citation forms, read by the register's ``test`` and ``evidence`` fields, by the corrections'
``Evidence`` lines and by the decision record's condition entries:

- a test: ``<path>::<test name>`` (``tests/student/test_audit.py::<name>``); the path is
  collected with pytest and the name must be one of its collected cases, a parametrized
  case by its function name;
- an attack-evidence stage: ``attack-dev:<stage>`` with one of the four stage names;
- an earlier Task's pull request: ``task-4.<n> pull request <URL> commit <sha>``;
- (corrections and conditions only) a file of this repository by its path.

The register is read with the restricted YAML loader the answer sheet uses (no duplicate
keys, no aliases, no anchors, no merge keys, no non-JSON tags), holds ``risks`` as its one
top-level key, and its supplied metadata is pinned: exactly the five supplied entries, in
their order, each with its supplied id, threat and title (``SUPPLIED_RISKS``). Only the six
completion fields may change.

The two Markdown documents are parsed from what a reader sees: HTML comments
(``<!-- ... -->``, the templates' own headers among them) are removed before the sections,
entries, labelled lines and citations are read, so a heading or an entry inside a comment is
not there. The wording scan is separate and reads the raw text, comments included.

A condition of a conditional go, and a required change of a no go, carries an ``Applies to``
label naming the policy rule that applied and what it applied to: ``C1:attack-dev:<stage>``
for a ``limited`` stage, ``C2:<register id>`` for an entry whose evidence is an earlier
Task's run (``N1``, ``N2`` and ``N3`` likewise for a no go). For a conditional go the
required set follows from the evidence file and the register (``required_conditions``), and
the row requires exactly one complete entry per identifier.

The Decision section carries exactly one ``Outcome:`` line; a record with none or with
two has no outcome, and every outcome line is left out of the rationale.

The wording scan reads what the student wrote, not the bytes: YAML files are scanned over
their decoded scalar values and mapping keys (so a letter written as a YAML hexadecimal
escape is read as the word it spells) and every comment, a trailing comment after a value
included (``yaml_comments`` tokenizes each line quote-aware, so a ``#`` inside a quoted
scalar or a word is content); Markdown files over their rendered text: HTML entities,
backslash escapes, zero-width characters and compatibility forms normalized, inline markup
(emphasis, code, links, tags, the delimiters of an HTML comment) removed, and the lines of a
paragraph, a list item or a blockquote read as one text, so a word split by emphasis or a
phrase split over two lines is read as the word or the phrase (``markdown_blocks``,
``rendered_text``). One exemption exists, in the corrections file only: a blockquote whose
first line starts with ``> Analysis (CL-nn):`` and whose quoted text is text the named claim
of the analysis holds, which is how a correction quotes the analysis's own wording.
"""

from __future__ import annotations

import html
import json
import re
import subprocess
import sys
import unicodedata
from bisect import bisect_right
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from tests.contract.submission_validation import RestrictedYamlLoader
from tests.security.attack_scenario import LIMITED, OUTCOMES, STAGES

TASK_ROOT = Path(__file__).resolve().parents[2]
ANALYSIS_PATH = Path("docs/governance/ai-governance-analysis.md")
REGISTER_PATH = Path("docs/governance/risk-register.yaml")
OWNERS_PATH = Path("docs/governance/owners.md")
CONCERNS_PATH = Path("docs/governance/concerns.md")
DECISION_POLICY_PATH = Path("docs/governance/decision-policy.md")
DECISION_RECORD_PATH = Path("docs/governance/decision-record.md")
CORRECTIONS_PATH = Path("docs/student/governance-corrections.md")
CONTROL_MATRIX_PATH = Path("docs/security/control-matrix.md")
EVIDENCE_PATH = Path("evidence/attack-dev.json")
SHEET_PATH = Path("submission.yaml")
# The register's one top-level key.
REGISTER_KEY = "risks"
# The four files a Task 4.6 submission may change, in the order the lesson lists them.
STUDENT_FILES: tuple[str, ...] = (
    SHEET_PATH.as_posix(),
    CORRECTIONS_PATH.as_posix(),
    REGISTER_PATH.as_posix(),
    DECISION_RECORD_PATH.as_posix(),
)
# The classification values, in the order the sheet's comments state them.
CLAIM_VALUES: tuple[str, ...] = ("wrong_mapping", "unsupported", "overclaim", "supported")
SUPPORTED = "supported"
DECISIONS: tuple[str, ...] = ("go", "conditional_go", "no_go")
REGISTER_FIELDS: tuple[str, ...] = (
    "id",
    "threat",
    "title",
    "control",
    "test",
    "evidence",
    "owner",
    "residual",
    "mapping_note",
)
# The supplied metadata of every entry, which a submission keeps, and the six fields it fills.
SUPPLIED_FIELDS: tuple[str, ...] = ("id", "threat", "title")
COMPLETION_FIELDS: tuple[str, ...] = (
    "control",
    "test",
    "evidence",
    "owner",
    "residual",
    "mapping_note",
)
# The five supplied entries of docs/governance/risk-register.yaml, in their order: the
# register id, the Task 1 threat it stands for and its title. Pinned from the shipped
# starter register; `load_register` refuses a register whose entries are not exactly these.
SUPPLIED_RISKS: tuple[tuple[str, str, str], ...] = (
    ("R-01", "TH-01", "Summary read by anyone who can reach the API"),
    ("R-02", "TH-03", "Manipulated or malformed answer stored as the summary"),
    (
        "R-03",
        "TH-06",
        "Personal details in the handling note reach logs, the provider, and the record",
    ),
    ("R-04", "TH-05", "Summary reads leave no record of who read what"),
    ("R-05", "TH-07", "Provider key readable in the worker's configuration module"),
)
# The fields a student fills in every entry; `mapping_note` is filled in one.
FILLED_FIELDS: tuple[str, ...] = ("control", "test", "evidence", "owner", "residual")
TEMPLATE_MARKER = "[fill in:"
# The decision record's headings, and the one each outcome requires filled.
DECISION_SECTION = "Decision"
EVIDENCE_SECTION = "Evidence"
ACCEPTED_SECTION = "Accepted risk"
REQUIRED_SECTIONS: dict[str, str] = {
    "conditional_go": "Conditions (conditional go)",
    "no_go": "What must change first (no go)",
    "go": "Why no residual risk blocks a go (go)",
}
# The outcomes whose required section is read as entries (`### <heading>` plus the four
# labelled lines of CONDITION_LINES) rather than as prose: a condition and a required change
# must each say which rule it applies to, what must be true, who owns it and what evidence
# would show it.
ENTRY_OUTCOMES: tuple[str, ...] = ("conditional_go", "no_go")
APPLIES_TO_LINE = "applies to"
CONDITION_LINES: tuple[str, ...] = (APPLIES_TO_LINE, "what must be true", "owner", "evidence")
# The policy rules an entry may apply to, by outcome: a condition applies to a conditional-go
# rule, a required change to a no-go rule. A stage rule (C1, N1) is labelled with the stage it
# read, `C1:attack-dev:<stage>`; an entry rule (C2, N2, N3) with the register entry, `C2:R-nn`.
CONDITION_RULES: dict[str, tuple[str, ...]] = {
    "conditional_go": ("C1", "C2"),
    "no_go": ("N1", "N2", "N3"),
}
STAGE_RULES: frozenset[str] = frozenset({"C1", "N1"})
ENTRY_RULES: frozenset[str] = frozenset({"C2", "N2", "N3"})
# What `required_conditions` reads: the outcome that makes C1 apply to a stage, and the
# evidence kind that makes C2 apply to an entry.
C1_OUTCOME = LIMITED
C2_EVIDENCE = "pull_request"
ACCEPTED_LINES: tuple[str, ...] = (
    "Register id",
    "Owner",
    "Why it is acceptable now",
    "What evidence would change the decision",
)
# The corrections' two sections and the labelled lines each entry carries.
CLAIMS_SECTION = "Claim corrections"
OMITTED_SECTION = "Omitted risks"
CLAIM_ENTRY_LINES: tuple[str, ...] = ("what is wrong", "corrected statement", "evidence")
OMITTED_ENTRY_LINES: tuple[str, ...] = ("risk", "evidence")
_CLAIM_HEADING = re.compile(r"^### (CL-\d{2})\s*$", re.MULTILINE)
_CONCERN_HEADING = re.compile(r"^## (GC-\d{2})\b", re.MULTILINE)
_CONTROL_ROW = re.compile(r"^\| (C-\d{2}) \|", re.MULTILINE)
_ROLE_ROW = re.compile(r"^\| `([a-z][a-z-]*)` \|", re.MULTILINE)
_ENTRY_HEADING = re.compile(r"^### ([A-Z]{2}-\d{2})\s*$")
_ANY_ENTRY_HEADING = re.compile(r"^### (.+?)\s*$")
_SECTION_HEADING = re.compile(r"^## (.+?)\s*$")
_LABELLED_LINE = re.compile(r"^-\s+([A-Za-z][A-Za-z ]*?):\s*(.*)$")
_OUTCOME_LINE = re.compile(r"^Outcome:\s*`?([A-Za-z_]*)`?\s*$")
_ACCEPTED_LABELS = "|".join(re.escape(name) for name in ACCEPTED_LINES)
_ACCEPTED_LINE = re.compile(r"^(" + _ACCEPTED_LABELS + r"):\s*(.*)$")
_APPLIES_TO = re.compile(r"^([CN][1-3]):(?:attack-dev:(" + "|".join(STAGES) + r")|(R-\d{2}))$")
# An HTML comment, terminated or running to the end of the text: a reader sees nothing of it.
_HTML_COMMENT = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
# A YAML block scalar's header (`residual: >-`, `- |`, `key: >+2 # note`): the lines indented
# deeper than it are the scalar's content, in which a `#` is text, not a comment.
_BLOCK_SCALAR_HEADER = re.compile(
    r"^(\s*)(?:-\s+)?(?:[^\s#'\"][^#'\"]*?:\s+)?[|>](?:[+-]?[0-9]?|[0-9]?[+-]?)\s*(?:#.*)?$"
)
# A quote opens a quoted scalar only where a scalar can start: at the start of a line or after
# whitespace or a YAML indicator; an apostrophe inside a plain word (`student's`) is content.
_QUOTE_OPENERS = frozenset(" \t:-[{,")
_QUOTED_ANALYSIS = re.compile(r"^>\s*Analysis \((CL-\d{2})\):\s*(.*)$")
_QUOTE_LINE = re.compile(r"^>\s?(.*)$")
_CLAIM_ID = re.compile(r"^CL-\d{2}$")
_REGISTER_ID = re.compile(r"^R-\d{2}$")
STAGE_CITATION = re.compile(r"^attack-dev:(" + "|".join(STAGES) + r")$")
PULL_REQUEST_CITATION = re.compile(
    r"\btask-4\.[1-5] pull request https://[^\s`'\"]+/pull/\d+ commit [0-9a-f]{7,40}\b"
)
TEST_CITATION = re.compile(
    r"^(tests/[A-Za-z0-9_./-]+\.py)::([A-Za-z_][A-Za-z0-9_]*(?:::[A-Za-z_][A-Za-z0-9_]*)*)$"
)
_PATH_TOKEN = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_./-]*\.(?:md|py|yaml|yml|json|toml|sql|txt)$")
_TOKEN_SPLIT = re.compile(r"[\s,;()`'\"<>]+")
FORBIDDEN_WORDING = re.compile(
    r"(?i)\bcompliant\b|\bcomplies with\b|\bin compliance with\b|\bcertified\b|"
    r"\bcertification\b|\bEU AI Act\b|\bHIPAA\b|\bGDPR\b"
)
# What the scan strips before it reads a Markdown line or a decoded YAML value: a backslash
# before any character (a Markdown escape such as `comp\-liant`, or a backslash pushed into a
# word to split it), and the characters that split a word without showing (zero-width
# characters, the soft hyphen, the word joiner, the byte-order mark). HTML entities are
# decoded and compatibility forms (full-width letters, ligatures) folded by `normalized_text`.
_MARKDOWN_ESCAPE = re.compile(r"\\(.)")
_INVISIBLE = re.compile("[\u00ad\u200b\u200c\u200d\u2060\ufeff]")
_WHITESPACE = re.compile(r"\s+")
# Inline Markdown a reader does not see, removed by `rendered_text` after normalization: a
# link or an image (its text stays), a reference link, an HTML tag, the delimiters of an
# HTML comment (its text stays, so a comment is scanned like any other text), and the
# emphasis, code and strikethrough characters, so `**com**pliant` is read as the word.
_LINK = re.compile(r"!?\[([^\]]*)\]\((?:[^()]|\([^()]*\))*\)")
_REFERENCE_LINK = re.compile(r"!?\[([^\]]*)\]\[[^\]]*\]")
_HTML_TAG = re.compile(r"</?[A-Za-z][A-Za-z0-9-]*(?:\s[^<>]*)?/?>")
_COMMENT_DELIMITER = re.compile(r"<!--|-->")
_MARKUP = re.compile(r"[*_`~]")
_QUOTE_MARK = re.compile(r"^\s{0,3}>\s?")
# Markdown lines that render as a block of their own and never continue the line before: a
# heading, a table row, a rule or setext underline (`_OWN_BLOCK`); a list item starts a
# block that its continuation lines join (`_LIST_ITEM`); a fence opens or closes a code
# block whose lines are read one by one (`_FENCE`).
_OWN_BLOCK = re.compile(r"^(?:#{1,6}(?:\s|$)|\s*\||\s*[-=*_]{3,}\s*$)")
_LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
_FENCE = re.compile(r"^\s*(?:```|~~~)")
COLLECTION_TIMEOUT_SECONDS = 600
_NONE_WORDS = frozenset({"none", "n/a", "na", "-", "nil", "no residual risk"})


class GovernanceError(RuntimeError):
    """Report that a supplied or student file could not be read in its documented shape."""


# --- The supplied material ------------------------------------------------------------------


def _read(root: Path, relative: Path) -> str:
    """Return one file's text, or raise naming the file."""
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise GovernanceError(f"{relative.as_posix()} could not be read: {exc}") from exc


def _load_restricted(root: Path, relative: Path) -> object:
    """Return one file's single YAML document, read with the restricted loader."""
    try:
        documents = list(yaml.load_all(_read(root, relative), Loader=RestrictedYamlLoader))
    except yaml.YAMLError as exc:
        raise GovernanceError(
            f"{relative.as_posix()} is not restricted YAML (one document, no duplicate keys, "
            f"no aliases, anchors, merge keys or non-JSON tags): {exc}"
        ) from exc
    if len(documents) != 1:
        raise GovernanceError(f"{relative.as_posix()} must hold exactly one YAML document")
    return documents[0]


def claim_ids(root: Path = TASK_ROOT) -> tuple[str, ...]:
    """Return the analysis's numbered claim ids, in document order."""
    found = _CLAIM_HEADING.findall(_read(root, ANALYSIS_PATH))
    if not found:
        raise GovernanceError(f"{ANALYSIS_PATH.as_posix()} numbers no claim (`### CL-nn`)")
    if len(found) != len(set(found)):
        raise GovernanceError(f"{ANALYSIS_PATH.as_posix()} numbers a claim twice")
    return tuple(found)


def claim_texts(root: Path = TASK_ROOT) -> dict[str, str]:
    """Return each numbered claim's text by id, normalized for the quotation exemption."""
    text = _read(root, ANALYSIS_PATH)
    parts = _CLAIM_HEADING.split(text)
    # `split` with one group yields: preamble, id, body, id, body, ...
    found: dict[str, str] = {}
    for index in range(1, len(parts) - 1, 2):
        claim, body = parts[index], parts[index + 1]
        found[claim] = _collapsed(normalized_text(body))
    if not found:
        raise GovernanceError(f"{ANALYSIS_PATH.as_posix()} numbers no claim (`### CL-nn`)")
    return found


def control_ids(root: Path = TASK_ROOT) -> tuple[str, ...]:
    """Return the control matrix's control ids, in table order."""
    found = _CONTROL_ROW.findall(_read(root, CONTROL_MATRIX_PATH))
    if not found:
        raise GovernanceError(f"{CONTROL_MATRIX_PATH.as_posix()} lists no control (`| C-nn |`)")
    return tuple(dict.fromkeys(found))


def concern_ids(root: Path = TASK_ROOT) -> tuple[str, ...]:
    """Return the concern ids, in document order."""
    found = _CONCERN_HEADING.findall(_read(root, CONCERNS_PATH))
    if not found:
        raise GovernanceError(f"{CONCERNS_PATH.as_posix()} lists no concern (`## GC-nn`)")
    return tuple(dict.fromkeys(found))


def owner_roles(root: Path = TASK_ROOT) -> tuple[str, ...]:
    """Return the owner role ids, in table order."""
    found = _ROLE_ROW.findall(_read(root, OWNERS_PATH))
    if not found:
        raise GovernanceError(f"{OWNERS_PATH.as_posix()} lists no role (`| `role-id` |`)")
    return tuple(dict.fromkeys(found))


# --- Markers and blanks ---------------------------------------------------------------------


def has_marker(text: str) -> bool:
    """Return whether a template marker is still in the text."""
    return TEMPLATE_MARKER in text


def is_blank(text: str) -> bool:
    """Return whether a field is empty, still a template marker, or a word for 'none'."""
    stripped = text.strip()
    if not stripped or has_marker(stripped):
        return True
    return stripped.lower().rstrip(".").strip() in _NONE_WORDS


# --- The register ---------------------------------------------------------------------------


@dataclass(frozen=True)
class RegisterEntry:
    """One risk of the register, every field as text."""

    id: str
    threat: str
    title: str
    control: str
    test: str
    evidence: str
    owner: str
    residual: str
    mapping_note: str


def load_register(root: Path = TASK_ROOT) -> tuple[RegisterEntry, ...]:
    """Return the register's entries, validating the supplied shape and the supplied metadata.

    One mapping whose only key is `risks`, read with the restricted loader, holding
    exactly the supplied entries in their order: each item a mapping with exactly the nine
    supplied keys, every value a string (an empty one is a field not yet filled, which the
    rows report), and the `id`, `threat` and `title` of each entry equal to the supplied
    values (`SUPPLIED_RISKS`). A key beside `risks`, and an entry removed, added, reordered
    or renamed, are refused, so a submission can only fill the six completion fields.
    """
    document = _load_restricted(root, REGISTER_PATH)
    if not isinstance(document, dict) or set(document) != {REGISTER_KEY}:
        raise GovernanceError(
            f"{REGISTER_PATH.as_posix()} must hold exactly one top-level key, `{REGISTER_KEY}`, "
            "and nothing beside it"
        )
    risks = document[REGISTER_KEY]
    if not isinstance(risks, list) or not risks:
        raise GovernanceError(f"{REGISTER_PATH.as_posix()} must hold a non-empty `risks:` list")
    if len(risks) != len(SUPPLIED_RISKS):
        raise GovernanceError(
            f"{REGISTER_PATH.as_posix()} must hold exactly the {len(SUPPLIED_RISKS)} supplied "
            f"entries ({', '.join(risk[0] for risk in SUPPLIED_RISKS)}); it holds {len(risks)}"
        )
    entries: list[RegisterEntry] = []
    for position, (item, supplied) in enumerate(zip(risks, SUPPLIED_RISKS, strict=True), 1):
        if not isinstance(item, dict) or set(item) != set(REGISTER_FIELDS):
            raise GovernanceError(
                f"{REGISTER_PATH.as_posix()}: every entry has exactly the keys "
                f"{', '.join(REGISTER_FIELDS)}"
            )
        values: dict[str, str] = {}
        for name in REGISTER_FIELDS:
            value = item[name]
            if value is None:
                value = ""
            if not isinstance(value, str):
                raise GovernanceError(
                    f"{REGISTER_PATH.as_posix()}: the `{name}` field of {item.get('id')!r} "
                    "must be text"
                )
            values[name] = value
        if tuple(values[name] for name in SUPPLIED_FIELDS) != supplied:
            raise GovernanceError(
                f"{REGISTER_PATH.as_posix()}: entry {position} must keep the supplied id, "
                f"threat and title ({', '.join(supplied)}); the supplied entries stay in their "
                f"order and only {', '.join(COMPLETION_FIELDS)} change"
            )
        entries.append(RegisterEntry(**values))
    return tuple(entries)


# --- The evidence file ----------------------------------------------------------------------


def load_evidence(root: Path = TASK_ROOT) -> dict[str, Any]:
    """Return the evidence document `poe attack-dev` wrote, or raise saying it is missing."""
    path = root / EVIDENCE_PATH
    if not path.is_file():
        raise GovernanceError(
            f"{EVIDENCE_PATH.as_posix()} is missing: run `poe attack-dev` against the running "
            "stack first (`poe verify` runs it before this step)"
        )
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise GovernanceError(f"{EVIDENCE_PATH.as_posix()} could not be read: {exc}") from exc
    if not isinstance(document, dict):
        raise GovernanceError(f"{EVIDENCE_PATH.as_posix()} does not hold one JSON object")
    return document


def evidence_stages(document: Mapping[str, Any]) -> dict[str, str]:
    """Return each recorded stage's outcome by stage name; a stage with no outcome is left out."""
    stages = document.get("stages")
    found: dict[str, str] = {}
    if not isinstance(stages, dict):
        return found
    for name, stage in stages.items():
        outcome = stage.get("outcome") if isinstance(stage, dict) else None
        if isinstance(name, str) and outcome in OUTCOMES:
            found[name] = str(outcome)
    return found


def evidence_kind(text: str) -> str | None:
    """Return `stage` or `pull_request` for an evidence record in a documented form, else None."""
    stripped = text.strip()
    if STAGE_CITATION.match(stripped):
        return "stage"
    if PULL_REQUEST_CITATION.fullmatch(stripped):
        return "pull_request"
    return None


def cited_stage(text: str) -> str | None:
    """Return the stage name an `attack-dev:<stage>` record cites, or None."""
    match = STAGE_CITATION.match(text.strip())
    return match.group(1) if match else None


# --- Test citations -------------------------------------------------------------------------


@dataclass(frozen=True)
class TestCitation:
    """One cited test: the module path and the case name (a class path is kept whole)."""

    path: str
    name: str


def parse_test_citation(text: str) -> TestCitation | None:
    """Return the citation a `<path>::<name>` text names, or None when it is not one."""
    match = TEST_CITATION.match(text.strip())
    if match is None:
        return None
    return TestCitation(match.group(1), match.group(2))


def test_citations_in(text: str) -> list[TestCitation]:
    """Return every `<path>::<name>` token in a text."""
    found: list[TestCitation] = []
    for token in _TOKEN_SPLIT.split(text):
        citation = parse_test_citation(token.rstrip(".:"))
        if citation is not None:
            found.append(citation)
    return found


def collected_tests(root: Path, paths: Iterable[str]) -> dict[str, set[str]]:
    """Collect the cited test modules with pytest and return each one's case names.

    Only paths that exist are collected (a missing path has no cases, which the caller
    reports); the names are the node ids after the path, with the parameter id stripped,
    both as a whole (``Class::test_name``) and as the bare function name, so a citation
    may use either. A module that fails to collect yields no names.
    """
    existing = sorted({path for path in paths if (root / path).is_file()})
    found: dict[str, set[str]] = {path: set() for path in existing}
    if not existing:
        return found
    try:
        completed = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "-p",
                "no:cacheprovider",
                *existing,
            ],
            cwd=root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=COLLECTION_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GovernanceError(f"the cited tests could not be collected: {exc}") from exc
    for raw in completed.stdout.splitlines():
        line = raw.strip()
        if "::" not in line or line.startswith(("ERROR", "WARNING")):
            continue
        node_id = line.split("[", 1)[0]
        path, _, rest = node_id.partition("::")
        path = path.replace("\\", "/")
        if path in found and rest:
            found[path].add(rest)
            found[path].add(rest.rsplit("::", 1)[-1])
    return found


def test_exists(citation: TestCitation, collected: Mapping[str, set[str]]) -> bool:
    """Return whether the cited case was collected from the cited module."""
    return citation.name in collected.get(citation.path, set())


# --- Citations in free text -----------------------------------------------------------------


def resolved_citations(text: str, root: Path, collected: Mapping[str, set[str]]) -> list[str]:
    """Return the citations in a text that resolve: a file, a collected test, a stage, a PR.

    A file is a repository-relative path that exists; a test is a `<path>::<name>` whose
    case was collected; a stage is `attack-dev:<stage>`; a pull request citation is the
    documented form. The returned strings are the resolved citations, for a message.
    """
    found: list[str] = []
    for raw in _TOKEN_SPLIT.split(text):
        token = raw.rstrip(".:")
        if not token:
            continue
        if STAGE_CITATION.match(token):
            found.append(token)
            continue
        citation = parse_test_citation(token)
        if citation is not None:
            if test_exists(citation, collected):
                found.append(token)
            continue
        if _PATH_TOKEN.match(token) and (root / token).is_file():
            found.append(token)
    found.extend(match.group(0) for match in PULL_REQUEST_CITATION.finditer(text))
    return found


# --- Labelled entries: the corrections and the decision record's conditions ----------------


@dataclass(frozen=True)
class CorrectionEntry:
    """One `### <heading>` entry with its labelled lines by lower-cased label.

    The corrections' entries are headed by a claim or omitted-risk id; the decision
    record's conditions and required changes by any heading (`### Condition 1`).
    """

    entry_id: str
    fields: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class Corrections:
    """The corrections file: claim entries by claim id, omitted-risk entries by id, and repeats."""

    claims: dict[str, CorrectionEntry]
    omitted: dict[str, CorrectionEntry]
    duplicates: tuple[str, ...]


def _read_labelled_line(entry: CorrectionEntry, line: str, last_label: str | None) -> str | None:
    """Add one body line to an entry: a `- Label: value` line, or a continuation of the last."""
    labelled = _LABELLED_LINE.match(line)
    if labelled:
        label = labelled.group(1).strip().lower()
        entry.fields[label] = labelled.group(2).strip()
        return label
    if last_label is not None and line.strip():
        entry.fields[last_label] = f"{entry.fields[last_label]} {line.strip()}".strip()
    return last_label


def visible_markdown(text: str) -> str:
    """Return a Markdown text without its HTML comments, as a reader sees it rendered.

    The structural parsers read this: a section, an entry or a labelled line written
    inside `<!-- ... -->` (or after an unterminated `<!--`) renders as nothing and counts
    as nothing. The wording scan reads the raw text instead, so a student's own words
    are scanned wherever they are.
    """
    return _HTML_COMMENT.sub("", text)


def parse_corrections(text: str) -> Corrections:
    """Parse the corrections' two sections into their entries, from the visible Markdown.

    An entry starts at a `### XX-nn` heading under one of the two `##` sections and holds
    labelled lines (`- Label: value`); a line that is not a label continues the last
    label's value, so a correction may run over several lines. HTML comments are removed
    first (`visible_markdown`).
    """
    claims: dict[str, CorrectionEntry] = {}
    omitted: dict[str, CorrectionEntry] = {}
    duplicates: list[str] = []
    section: str | None = None
    current: CorrectionEntry | None = None
    last_label: str | None = None
    for line in visible_markdown(text).splitlines():
        heading = _SECTION_HEADING.match(line)
        if heading:
            title = heading.group(1)
            if title == CLAIMS_SECTION:
                section = "claims"
            elif title == OMITTED_SECTION:
                section = "omitted"
            else:
                section = None
            current, last_label = None, None
            continue
        entry = _ENTRY_HEADING.match(line)
        if entry:
            if section is None:
                current, last_label = None, None
                continue
            entry_id = entry.group(1)
            target = claims if section == "claims" else omitted
            if entry_id in target:
                duplicates.append(entry_id)
            current = CorrectionEntry(entry_id)
            target[entry_id] = current
            last_label = None
            continue
        if current is None or line.startswith("#"):
            continue
        last_label = _read_labelled_line(current, line, last_label)
    return Corrections(claims=claims, omitted=omitted, duplicates=tuple(duplicates))


def parse_entries(body: str) -> list[CorrectionEntry]:
    """Parse one section's body into its `### <heading>` entries with their labelled lines.

    The decision record's conditions (for a conditional go) and required changes (for a
    no go) are written this way: one entry per condition, headed by any text, with the
    three labelled lines of CONDITION_LINES. Text before the first heading is not an
    entry; a repeated heading is kept as its own entry.
    """
    entries: list[CorrectionEntry] = []
    current: CorrectionEntry | None = None
    last_label: str | None = None
    for line in body.splitlines():
        heading = _ANY_ENTRY_HEADING.match(line)
        if heading:
            current = CorrectionEntry(heading.group(1))
            entries.append(current)
            last_label = None
            continue
        if current is None or line.startswith("#"):
            continue
        last_label = _read_labelled_line(current, line, last_label)
    return entries


# --- The decision record --------------------------------------------------------------------


@dataclass(frozen=True)
class DecisionRecord:
    """The decision record: the outcome, the rationale, each section's body, the accepted lines.

    `outcome` is the value of the Decision section's one `Outcome:` line, and None when
    the section carries no such line or more than one (`outcome_lines` counts them).
    `rationale` is the Decision section without every `Outcome:` line: the text that says
    what is decided and which policy rules gave the outcome.
    """

    outcome: str | None
    rationale: str
    sections: dict[str, str]
    accepted: dict[str, str]
    outcome_lines: int = 0


def parse_decision_record(text: str) -> DecisionRecord:
    """Split the visible record into its `##` sections and read the labelled lines it must carry.

    HTML comments are removed first (`visible_markdown`): a record whose content sits
    inside a comment has no outcome, no sections and no accepted-risk lines. Every
    `Outcome:` line of the Decision section is counted and left out of the rationale, so
    a repeated outcome line is neither the outcome nor the rationale.
    """
    sections: dict[str, list[str]] = {}
    title: str | None = None
    for line in visible_markdown(text).splitlines():
        heading = _SECTION_HEADING.match(line)
        if heading:
            title = heading.group(1)
            sections.setdefault(title, [])
            continue
        if title is not None:
            sections[title].append(line)
    bodies = {name: "\n".join(lines).strip() for name, lines in sections.items()}
    outcomes: list[str] = []
    rationale: list[str] = []
    for line in sections.get(DECISION_SECTION, []):
        match = _OUTCOME_LINE.match(line.strip())
        if match:
            outcomes.append(match.group(1))
            continue
        rationale.append(line)
    accepted: dict[str, str] = {}
    for line in sections.get(ACCEPTED_SECTION, []):
        match = _ACCEPTED_LINE.match(line.strip())
        if match:
            accepted[match.group(1)] = match.group(2).strip()
    return DecisionRecord(
        outcome=outcomes[0] if len(outcomes) == 1 else None,
        rationale="\n".join(rationale).strip(),
        sections=bodies,
        accepted=accepted,
        outcome_lines=len(outcomes),
    )


def section_is_filled(record: DecisionRecord, name: str) -> bool:
    """Return whether a section exists, has text, and holds no template marker."""
    body = record.sections.get(name)
    return body is not None and bool(body.strip()) and not has_marker(body)


def section_entries(record: DecisionRecord, name: str) -> list[CorrectionEntry]:
    """Return one section's `### <heading>` entries (empty when the section is absent)."""
    return parse_entries(record.sections.get(name, ""))


# --- Conditions and required changes: which rule each entry applies to -----------------------


def applies_to(text: str, outcome: str) -> str | None:
    """Return the normalized `Applies to` label of an entry, or None when it is not one.

    A label is `<rule>:attack-dev:<stage>` for a stage rule or `<rule>:<register id>` for
    an entry rule, where the rule is one the outcome's group holds (`CONDITION_RULES`): a
    condition applies to C1 or C2, a required change to N1, N2 or N3. Backticks and
    surrounding whitespace are ignored; anything else (a rule of the other group, a stage
    rule with a register id, an unknown stage) is no label.
    """
    normalized = text.strip().strip("`").strip()
    match = _APPLIES_TO.match(normalized)
    if match is None:
        return None
    rule, stage, entry = match.groups()
    if rule not in CONDITION_RULES.get(outcome, ()):
        return None
    if (rule in STAGE_RULES) != (stage is not None) or (rule in ENTRY_RULES) != (entry is not None):
        return None
    return normalized


def required_conditions(stages: Mapping[str, str], register: Sequence[RegisterEntry]) -> list[str]:
    """Return the identifiers a conditional go's conditions must cover, in policy order.

    One `C1:attack-dev:<stage>` per stage whose recorded outcome is `limited`, in stage
    order, then one `C2:<register id>` per register entry whose evidence is a pull request
    citation, in register order: the two conditional-go rules of
    docs/governance/decision-policy.md, read from the evidence file and the register as the
    policy reads them. The list is empty when neither rule applies, which is not a
    conditional go.
    """
    required = [f"C1:attack-dev:{stage}" for stage in STAGES if stages.get(stage) == C1_OUTCOME]
    required.extend(
        f"C2:{entry.id}" for entry in register if evidence_kind(entry.evidence) == C2_EVIDENCE
    )
    return required


def condition_findings(
    entries: Sequence[CorrectionEntry], required: Sequence[str] | None, outcome: str
) -> list[str]:
    """Return what is wrong with the entries' `Applies to` labels; empty when nothing is.

    Every entry must carry a label of the outcome's group (`applies_to`). When `required`
    is given (a conditional go), the labels must be exactly the required identifiers, one
    entry each: an identifier no entry applies to, an identifier two entries apply to, and
    an entry applying to a rule that did not apply are each named. For a no go `required`
    is None: the shape is checked and which rule applied is the instructor's question.
    """
    findings: list[str] = []
    labels: dict[str, list[str]] = {}
    for entry in entries:
        label = applies_to(entry.fields.get(APPLIES_TO_LINE, ""), outcome)
        if label is None:
            rules = " or ".join(CONDITION_RULES.get(outcome, ()))
            findings.append(
                f"{entry.entry_id}: `Applies to` is not <rule>:attack-dev:<stage> or "
                f"<rule>:R-nn with the rule one of {rules}"
            )
            continue
        labels.setdefault(label, []).append(entry.entry_id)
    if required is None:
        return findings
    for identifier in required:
        holders = labels.get(identifier, [])
        if not holders:
            findings.append(f"no entry applies to {identifier}, a rule that applied")
        elif len(holders) > 1:
            findings.append(f"{len(holders)} entries apply to {identifier} ({', '.join(holders)})")
    for identifier, holders in labels.items():
        if identifier not in required:
            findings.append(
                f"{', '.join(holders)}: applies to {identifier}, which no rule of the current "
                "evidence and register requires"
            )
    return findings


# --- The wording scan -----------------------------------------------------------------------


def normalized_text(text: str) -> str:
    """Return a line or value as a reader sees it: entities decoded, escapes and invisibles gone."""
    unescaped = html.unescape(text)
    folded = unicodedata.normalize("NFKC", unescaped)
    return _INVISIBLE.sub("", _MARKDOWN_ESCAPE.sub(r"\1", folded))


def _collapsed(text: str) -> str:
    """Return a text with its whitespace runs collapsed, for the quotation comparison."""
    return _WHITESPACE.sub(" ", text).strip()


def rendered_text(line: str) -> str:
    """Return one Markdown line as a reader sees it: normalized, inline markup removed.

    After `normalized_text`, a link or an image keeps its text and loses its target, an
    HTML tag and the delimiters of an HTML comment are removed (the comment's text
    stays), and the emphasis, code and strikethrough characters are removed, so
    `**com**pliant`, `` `cert`ified `` and `[EU](x) AI Act` are read as the words they
    render. A leading blockquote marker is removed too.
    """
    text = normalized_text(_QUOTE_MARK.sub("", line))
    text = _LINK.sub(r"\1", text)
    text = _REFERENCE_LINK.sub(r"\1", text)
    text = _HTML_TAG.sub("", text)
    text = _COMMENT_DELIMITER.sub("", text)
    return _MARKUP.sub("", text)


def markdown_blocks(lines: Sequence[str]) -> list[tuple[int, list[str]]]:
    """Group a Markdown text's lines into the blocks a reader sees, as (first index, lines).

    A paragraph is the run of non-blank lines up to a blank line, a blockquote line or a
    line that renders as a block of its own (a heading, a table row, a rule, a fence); a
    list item runs on over its continuation lines the same way; a blockquote is the run
    of lines starting with `>`; a fenced code block's lines are one block each, read as
    they are. The lines of one block render as one text, so a phrase split over two of
    them is read as the phrase.
    """
    blocks: list[tuple[int, list[str]]] = []
    index = 0
    fenced = False
    while index < len(lines):
        line = lines[index]
        if fenced or _FENCE.match(line):
            if _FENCE.match(line):
                fenced = not fenced
            blocks.append((index, [line]))
            index += 1
            continue
        if not line.strip():
            index += 1
            continue
        if line.startswith(">"):
            end = index
            while end < len(lines) and lines[end].startswith(">"):
                end += 1
        elif _OWN_BLOCK.match(line):
            end = index + 1
        else:
            end = index + 1
            while (
                end < len(lines)
                and lines[end].strip()
                and not lines[end].startswith(">")
                and not _OWN_BLOCK.match(lines[end])
                and not _LIST_ITEM.match(lines[end])
                and not _FENCE.match(lines[end])
            ):
                end += 1
        blocks.append((index, list(lines[index:end])))
        index = end
    return blocks


def _block_findings(first: int, lines: Sequence[str], findings: list[str]) -> None:
    """Scan one block's rendered text and name each term found by the line it starts on."""
    rendered: list[str] = []
    starts: list[int] = []
    offset = 0
    for line in lines:
        text = rendered_text(line)
        starts.append(offset)
        rendered.append(text)
        offset += len(text) + 1
    seen: set[tuple[int, str]] = set()
    for match in FORBIDDEN_WORDING.finditer(" ".join(rendered)):
        found = (first + bisect_right(starts, match.start()), match.group(0))
        if found not in seen:
            seen.add(found)
            findings.append(f"line {found[0]}: {found[1]!r}")


def _quotation_is_exempt(lines: Sequence[str], quotes: Mapping[str, str] | None) -> bool:
    """Return whether a blockquote is a marked quotation of text the named claim holds."""
    if quotes is None or not lines:
        return False
    first = _QUOTED_ANALYSIS.match(lines[0])
    if first is None:
        return False
    claim = first.group(1)
    quoted = [first.group(2)]
    for line in lines[1:]:
        rest = _QUOTE_LINE.match(line)
        quoted.append(rest.group(1) if rest else line)
    text = _collapsed(normalized_text(" ".join(quoted))).casefold()
    return bool(text) and claim in quotes and text in quotes[claim].casefold()


def wording_findings(
    text: str, *, markdown: bool, quotes: Mapping[str, str] | None = None
) -> list[str]:
    """Return one finding per term found that claims compliance or certification, `line n: term`.

    A Markdown file is read as it renders: its lines grouped into blocks
    (`markdown_blocks`), each block's lines read as one text with inline markup removed
    (`rendered_text`), and each term found named by the line it starts on. A blockquote
    whose first line starts with `> Analysis (CL-nn):` and whose quoted text is text that
    claim holds in the analysis (`quotes`, by claim id) is quoted analysis text and is
    skipped whole; the exemption exists only where the caller supplies `quotes`, which the
    scan does for the corrections file alone. Every other block is the student's own
    words. A text that is not Markdown is read line by line, normalized.
    """
    findings: list[str] = []
    lines = text.splitlines()
    if not markdown:
        for index, line in enumerate(lines, start=1):
            match = FORBIDDEN_WORDING.search(normalized_text(line))
            if match:
                findings.append(f"line {index}: {match.group(0)!r}")
        return findings
    for first, block in markdown_blocks(lines):
        if block[0].startswith(">") and _quotation_is_exempt(block, quotes):
            continue
        _block_findings(first, block, findings)
    return findings


def _scalar_findings(value: object, address: str, findings: list[str]) -> None:
    """Scan one decoded YAML value, recursing into mappings and lists, naming the address.

    A mapping's keys are scanned as well as its values (a key is the student's text as
    much as a value is); a string is read with its whitespace collapsed, so a phrase a
    literal block scalar splits over two lines is read as the phrase.
    """
    if isinstance(value, str):
        match = FORBIDDEN_WORDING.search(normalized_text(_collapsed(value)))
        if match:
            findings.append(f"{address}: {match.group(0)!r}")
    elif isinstance(value, dict):
        for key, item in value.items():
            key_address = f"{address}.{key}" if address else str(key)
            if isinstance(key, str):
                match = FORBIDDEN_WORDING.search(normalized_text(_collapsed(key)))
                if match:
                    findings.append(f"{key_address} (a key): {match.group(0)!r}")
            _scalar_findings(item, key_address, findings)
    elif isinstance(value, list):
        for position, item in enumerate(value):
            _scalar_findings(item, f"{address}[{position}]", findings)


def _comment_of(line: str) -> str | None:
    """Return the comment one YAML line carries, or None, tokenizing the line quote-aware.

    A `#` starts a comment at the start of the line or after whitespace, outside a quoted
    scalar: inside `"..."` (with backslash escapes) or `'...'` (with `''` for one quote) it
    is text, and so is a `#` inside a word (`a#b`). A quote opens a scalar only where a
    scalar can start (`_QUOTE_OPENERS`), so the apostrophe of a plain `student's` opens
    nothing.
    """
    quote: str | None = None
    previous = " "
    index = 0
    while index < len(line):
        char = line[index]
        if quote == '"':
            if char == "\\":
                index += 2
                previous = char
                continue
            if char == '"':
                quote = None
        elif quote == "'":
            if char == "'":
                if line[index + 1 : index + 2] == "'":
                    index += 2
                    previous = char
                    continue
                quote = None
        elif char in "\"'" and previous in _QUOTE_OPENERS:
            quote = char
        elif char == "#" and previous in " \t":
            return line[index + 1 :]
        previous = char
        index += 1
    return None


def yaml_comments(text: str) -> list[tuple[int, str]]:
    """Return every comment of a YAML text as (line number, comment text).

    Comment-only lines and trailing comments after a value alike, found by `_comment_of`;
    the content lines of a block scalar (the lines indented deeper than a `>-` or `|`
    header, `_BLOCK_SCALAR_HEADER`) hold text, not comments, and are skipped. The value
    the block scalar holds is scanned with the decoded values.
    """
    found: list[tuple[int, str]] = []
    block_indent: int | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        indent = len(line) - len(line.lstrip(" "))
        if block_indent is not None:
            if not line.strip() or indent > block_indent:
                continue
            block_indent = None
        comment = _comment_of(line)
        if comment is not None:
            found.append((number, comment))
        if _BLOCK_SCALAR_HEADER.match(line):
            block_indent = indent
    return found


def yaml_wording_findings(text: str, relative: Path) -> list[str]:
    """Return the findings over a YAML file's decoded values, mapping keys and comments.

    The values and keys are what the student wrote once YAML escapes are decoded, keyed
    by their address (`risks[2].residual`); every comment, trailing comments included
    (`yaml_comments`), is scanned as text, by line number. A file the restricted loader
    refuses is reported as one finding, since the rows that read it name the same problem.
    """
    findings: list[str] = []
    try:
        documents = list(yaml.load_all(text, Loader=RestrictedYamlLoader))
    except yaml.YAMLError:
        return [f"{relative.as_posix()} is not restricted YAML, so its values were not scanned"]
    for document in documents:
        _scalar_findings(document, "", findings)
    for number, comment in yaml_comments(text):
        match = FORBIDDEN_WORDING.search(normalized_text(comment))
        if match:
            findings.append(f"line {number}: {match.group(0)!r}")
    return findings


def student_file_wording_findings(root: Path = TASK_ROOT) -> list[str]:
    """Scan the four student files; return findings prefixed with the file's path.

    The sheet and the register are scanned over their decoded values, keys and comments;
    the corrections and the decision record over their rendered text, with the quotation
    exemption available to the corrections only, against the analysis's own claim texts.
    """
    findings: list[str] = []
    quotes: dict[str, str] | None = None
    for relative in STUDENT_FILES:
        path = root / relative
        if not path.is_file():
            findings.append(f"{relative}: missing")
            continue
        text = path.read_text(encoding="utf-8")
        if relative.endswith(".md"):
            if relative == CORRECTIONS_PATH.as_posix():
                quotes = claim_texts(root) if quotes is None else quotes
                found = wording_findings(text, markdown=True, quotes=quotes)
            else:
                found = wording_findings(text, markdown=True)
        else:
            found = yaml_wording_findings(text, Path(relative))
        findings.extend(f"{relative}: {finding}" for finding in found)
    return findings


def valid_claim_id(text: str) -> bool:
    """Return whether a text has the claim-id form."""
    return bool(_CLAIM_ID.match(text))


def sheet_answers(root: Path = TASK_ROOT) -> dict[str, Any]:
    """Return the sheet's answers mapping, read as restricted YAML like the format check."""
    document = _load_restricted(root, SHEET_PATH)
    answers = document.get("answers") if isinstance(document, dict) else None
    if not isinstance(answers, dict):
        raise GovernanceError(f"{SHEET_PATH.as_posix()} must hold one `answers:` mapping")
    return dict(answers)


def register_fields(entries: Sequence[RegisterEntry], name: str) -> list[str]:
    """Return one field's value from every entry, in register order."""
    return [getattr(entry, name) for entry in entries]
