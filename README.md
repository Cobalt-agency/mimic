# Mimic

An agent skill that takes the shape of any software and rebuilds it as an original, working look-alike.

Give it a file (APK, EXE, JAR, AppImage, extension, web app...) or just a software name. It fingerprints or researches the target, writes a behavior-only blueprint, builds a clean-room clone and proves it works.

## What makes it different

- **Clean-room by design.** A "Lab / Workshop" firewall keeps the original's code and assets out of the clone. The only bridge is a plain-language blueprint.
- **Built-in triage.** `scripts/triage.py` is a read-only, standard-library Python fingerprinter: real file type, framework, native libs, permissions, network hosts, packer hints, and secret *findings* (values are never printed). It runs on a phone.
- **Two input modes.** File analysis for APK/EXE/JAR/etc., or deep research mode when you only know the name.
- **Resumable.** A `STATE.md` log lets an agent pick up exactly where it stopped after a crash or timeout.
- **Honest.** Every claim is tagged `[CONFIRMED]`, `[LIKELY]` or `[ASSUMED]`. Every run ends with a parity report, a contamination sweep and a secret sweep.
- **Beat the original.** The blueprint mines user complaints to pick 2 or 3 improvements worth building.

## Pipeline

```
INTAKE -> SCAN -> PROFILE -> BLUEPRINT -> FORGE -> PROVE -> SHIP
```

## Install

Copy this folder into your agent's skills directory.

```bash
# Claude Code (personal skills)
cp -r mimic ~/.claude/skills/mimic

# Claude Code (single project)
cp -r mimic <project>/.claude/skills/mimic
```

For other agents, point them at `SKILL.md`. The `references/` files are loaded on demand.

## Use

Just ask:

- "Clone this app" (attach an APK or EXE)
- "Make my own version of <software name>"
- "Build an open-source alternative to <tool>"

Or run the fingerprinter by hand:

```bash
python3 scripts/triage.py app.apk > TRIAGE.md
python3 scripts/triage.py app.exe --json
```

## Layout

```
mimic/
  SKILL.md                         workflow and rules
  scripts/triage.py                static fingerprinter
  references/android.md            APK / XAPK / AAB / IPA playbook
  references/desktop.md            EXE / ELF / JAR / Electron playbook
  references/research-playbook.md  name-only research
  references/blueprint-template.md blueprint, parity and state templates
```

## What it will not do

It will not crack or patch software, strip licenses or DRM, defeat commercial protection, copy decompiled code or proprietary assets, reuse secrets found in a target, redistribute the original binary, or build clones meant to impersonate the original.

Use it to learn, to build personal tools, and to create legitimate alternatives.

## License

Choose one that fits your project (MIT is a common default).
