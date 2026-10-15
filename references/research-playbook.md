# Research playbook

Use when the user gives only a name, the file is opaque or hardened, or the file leaves gaps (pricing, onboarding, backend behavior).

## Contents
1. Budget
2. The eight angles
3. Query patterns
4. Source quality
5. Evidence log
6. Mining reviews for "beat the original"
7. When sources are thin

## 1. Budget

A non-trivial app deserves **8 to 15 searches**. Search each angle separately. Combined queries return shallow results. Stop when every blueprint section is backed by something you retrieved.

## 2. The eight angles

1. **Official site and docs:** feature list, pricing tiers, FAQ, changelog, status page.
2. **Store listings:** Play Store, App Store, Microsoft Store: description, screenshots, "What's new", data-safety section (reveals data types and permissions).
3. **Reviews and complaints:** what users love, what breaks, what is missing.
4. **API and developer docs:** public API, SDKs, webhooks, open specs, OpenAPI files.
5. **Source code:** is it open source? Forks? Similar open-source projects? Read their architecture docs.
6. **Tutorials, videos, transcripts:** how people actually use it, step by step.
7. **Tech stack hints:** engineering blog posts, job listings, conference talks, package registries.
8. **Alternatives:** competitors and open-source equivalents, to see which features are table stakes.

## 3. Query patterns

Keep queries short and specific, then narrow.

```
<name> features
<name> changelog
<name> pricing plans
<name> api documentation
<name> github
<name> open source alternative
<name> review problems
<name> vs <competitor>
<name> how it works
<name> tech stack
<name> data safety permissions
```

Fetch full pages for the important ones. Snippets are too thin to specify behavior.

## 4. Source quality

| Tier | Source | Use for |
|---|---|---|
| 1 | Official docs, changelogs, source repos, store listings | Features, behavior, API |
| 2 | Engineering blogs, conference talks, reputable reviews | Architecture, rationale |
| 3 | Forums, tutorials, community wikis | Real-world usage, quirks |
| 4 | SEO listicles, aggregators | Last resort. Cross-check |

Prefer original sources over aggregators. Ignore sources that promote cracks, mods or license bypasses.

## 5. Evidence log

Keep `mimic-work/lab/SOURCES.md`:

```markdown
| # | Claim | Source (title / URL) | Tier | Label |
|---|-------|----------------------|------|-------|
| 1 | Offline mode exists | Official docs, "Offline" page | 1 | [CONFIRMED] |
| 2 | Uses Firebase for sync | Job listing + store data-safety | 2/1 | [LIKELY] |
| 3 | Sync conflict = last write wins | (guess) | - | [ASSUMED] |
```

Paraphrase what you read. Cite where it came from. Do not paste long passages into the blueprint.

## 6. Mining reviews for "beat the original"

Read the 1 to 3 star reviews and the most upvoted complaints. Group them:
- **Recurring bug or slowness:** your clone can be faster/simpler.
- **Missing feature:** candidate P1 differentiator.
- **Price or paywall frustration:** your clone can be fully free and local-first.
- **Privacy complaints:** your clone can collect nothing.

Pick 2 or 3 and put them in the blueprint under "Beat the original".

## 7. When sources are thin

- Say so in the blueprint and mark the affected features [ASSUMED].
- Ask the user one targeted question (e.g. "which 3 features do you use most?") instead of guessing.
- If the software is obscure, look at the closest well-documented alternative and clone the shared core.
