<!--
Coldline - Task 4.6
Template: your decision record. Student-editable. Keep every heading and the four labelled
lines under "Accepted risk"; replace every `[fill in: ...]` marker in the sections your
outcome requires and in "Decision", "Evidence" and "Accepted risk"; leave the sections your
outcome does not require as they are. The check reads the one `Outcome:` line under
"Decision" (exactly one; a repeated outcome line is no rationale) and the rationale under
it, the "Evidence" section, the one section your outcome requires and, for a
conditional go or a no go, each `### <heading>` entry in it with its four labelled lines
(an Applies to label naming the policy rule and what it applied to, an Owner that is a
role id of docs/governance/owners.md, an Evidence citation that resolves), and the
"Accepted risk" section, whose Owner is the owner your register records for that entry.
For a conditional go the Applies to labels must be exactly the rules that applied: one
`C1:attack-dev:<stage>` per `limited` stage of evidence/attack-dev.json and one `C2:R-nn`
per register entry whose evidence is an earlier Task's pull request, one entry each. The
check reads this file as it renders: anything inside an HTML comment like this one counts
as nothing.
-->
# Decision record: relying on the exception-resolution workflow

## Decision

Outcome: [fill in: go, conditional_go or no_go, the same value as answers.decision]

[fill in: one paragraph: what is decided, and the policy rules (by id) that gave this outcome]

## Evidence

[fill in: the register entries, the attack-dev stage outcomes and the earlier-Task citations this decision rests on, one per line]

## Conditions (conditional go)

[fill in: for a conditional go, one entry per rule that applied, in the shape below; remove this marker and add entries as needed]

### Condition 1

- Applies to: [fill in: C1:attack-dev:<stage> for a stage that recorded limited, or C2:R-nn for an entry whose evidence is an earlier Task's pull request]
- What must be true: [fill in: an observable statement about the system or its evidence, not an intention]
- Owner: [fill in: the role id from docs/governance/owners.md that can decide it]
- Evidence: [fill in: the test as path::name, the attack-dev:<stage>, the file or the pull request citation someone checks later]

## What must change first (no go)

[fill in: for a no go, one entry per required change, in the shape below; remove this marker and add entries as needed]

### Change 1

- Applies to: [fill in: N1:attack-dev:<stage> for a stage that recorded failed, N2:R-nn for an entry naming a control not in this Project, or N3:R-nn for an entry without a test or an evidence record]
- What must be true: [fill in: what would have to be true of the system or its evidence before relying on the workflow]
- Owner: [fill in: the role id from docs/governance/owners.md that can decide it]
- Evidence: [fill in: the test as path::name, the attack-dev:<stage>, the file or the pull request citation that would show it changed]

## Why no residual risk blocks a go (go)

[fill in: for a go, entry by entry, why no residual risk in the register blocks relying on the workflow]

## Accepted risk

Register id: [fill in: R-nn, the same value as answers.accepted_risk]
Owner: [fill in: the role id your register records as that entry's owner]
Why it is acceptable now: [fill in: the policy rules it meets, and the bound on what it can reach]
What evidence would change the decision: [fill in: the observation, test or record that would reopen it]
