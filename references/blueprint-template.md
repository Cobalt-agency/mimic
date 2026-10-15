# Blueprint and parity templates

Copy these into `mimic-work/`. The blueprint is the **only bridge** between the Lab and the Workshop, so it holds behavior in plain language: no pasted code, no copied assets, no secrets.

## BLUEPRINT.md

```markdown
# <Clone name> - Blueprint

## 1. Purpose
One paragraph: what the original does, for whom, and what this clone is for.

## 2. Tier and scope
- Tier: S / M / L / XL
- In scope (MVP):
- Later (P1/P2):
- Out of scope, and why:

## 3. Features
| # | Feature | Priority | Evidence | Label |
|---|---------|----------|----------|-------|
| 1 | | P0 | TRIAGE / NOTES / SOURCES ref | [CONFIRMED] |

## 4. Screens, windows or commands
For each:
- Purpose
- Elements and actions
- Where it comes from and where it leads
- Empty, loading and error states

## 5. User flows
3 to 5 main flows, step by step, from the user's point of view.

## 6. Data model
Entities, fields, relations, where stored, retention. Your own naming.

## 7. External interfaces
- APIs: METHOD /path, params, response shape (no keys, no tokens)
- File formats read and written
- Permissions / capabilities and why each is needed
- Backend plan: local-first / mock / self-hosted (never the original's servers)

## 8. Design tokens (original, not copied)
Palette, type scale, spacing, radius, icon style, tone of copy.

## 9. Architecture
Chosen stack and why, module breakdown, folder structure, build/run commands.

## 10. Beat the original
2 or 3 improvements, each tied to evidence (complaint, missing feature, privacy, price).

## 11. Not-to-reuse list
Original names, strings, assets and identifiers that must NOT appear in the build
(used by the contamination sweep in PROVE).

## 12. Unknowns and decisions
What could not be determined, and what was decided instead.
```

## PARITY.md

```markdown
# Parity report

| Feature | Original behavior (blueprint) | Clone behavior | How verified | Status |
|---------|-------------------------------|----------------|--------------|--------|
| | | | command / screenshot / test name | pass / partial / fail |

## Contamination sweep
- Command run and result:

## Secret sweep
- Command run and result:

## Known gaps
- Gap, reason, proposed next step
```

## STATE.md example

```
[INTAKE] done | target: notes.apk, goal: MVP, stack: Kotlin+Compose | next: SCAN | none
[SCAN] done | triage -> native Kotlin, 6 permissions, 2 hosts | next: PROFILE | none
[PROFILE] in-progress | 7/11 screens mapped | next: finish settings + sync screens | none
```
