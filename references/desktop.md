# Desktop / binary analysis

Goal: learn **behavior**. Everything here is static analysis. Never run an untrusted binary on the user's host.

## Contents
1. First step: identify the runtime
2. Per-runtime playbook
3. Installers and bundles
4. macOS and Linux notes
5. What to capture
6. Stop conditions

## 1. First step: identify the runtime

Run `scripts/triage.py` first. Its `Runtime hints`, `Imports`, `Signatures` and `PE sections` decide the path. The runtime decides how much of the app is readable.

## 2. Per-runtime playbook

| Runtime | Signal | Readability | Approach |
|---|---|---|---|
| **Electron** | `resources/app.asar`, CEF/Chromium imports | High | `npx asar extract app.asar out/`. The JS *is* the behavior: screens, state, IPC, API calls |
| **.NET** | `mscoree.dll`, CLR header | High | `ilspycmd` or `monodis` for structure. Summarize classes and flows, do not copy |
| **Java / JAR** | `META-INF/MANIFEST.MF`, `jvm.dll` | High | Read manifest for `Main-Class`; cfr/fernflower/jadx for structure |
| **Python bundle** | PyInstaller / py2exe signature | Medium | Identify and describe behavior from resources/strings; rebuild from behavior |
| **Qt / C++ native** | Qt DLLs, MSVC runtime | Low | Read resources, menus, dialogs, config formats, CLI `--help`. Use Ghidra/radare2 only for a specific question, never to transcribe |
| **Go / Rust** | `Go build ID`, `/rustc/` | Low | Strings, embedded assets, CLI help, config. Research for the rest |
| **Unity** | `UnityPlayer.dll`, `Managed/` | Mono: high, IL2CPP: low | Mono: ilspy. IL2CPP: assets + research |
| **Packed / protected** | High entropy, Themida/VMProtect/UPX hints | None | **Do not unpack.** Research mode + public behavior |

## 3. Installers and bundles

If `triage.py` flags an installer (NSIS, Inno, InstallShield, WiX, large overlay):
- Unpack the payload with `7z x`, `innoextract` or `msiextract` (whichever exists).
- Re-run `triage.py` on the extracted main executable and folders.
- Installers also reveal: install paths, file associations, registry keys, bundled runtimes, services.

## 4. macOS and Linux notes

- `.app` is a folder: read `Contents/Info.plist` (bundle id, URL schemes, document types), `Contents/Resources`, and `Contents/MacOS/<binary>`.
- `.dmg`: extract with `7z` or `dmg2img`, then treat the `.app` as above.
- AppImage: it is an ELF with a squashfs payload. `./App.AppImage --appimage-extract` unpacks it, but that **executes** the file. Prefer `7z x` or `unsquashfs` on the payload.
- ELF: `readelf -d`, `strings`, and linked libraries tell you the UI toolkit (GTK/Qt/SDL).

## 5. What to capture

- Windows, dialogs, menus, shortcuts, tray behavior
- File formats read and written (extensions, schema, magic bytes)
- Config locations (AppData, `~/.config`, registry keys) and keys
- CLI flags (`--help`) and exit codes
- Network calls (hosts, endpoints, update checks, telemetry)
- Plugins/extension points and bundled third-party libraries
- Install/uninstall/update behavior

## 6. Stop conditions

Stop analysis and switch to research mode when you hit:
- Packing, encryption, virtualization-based protection, anti-debug
- Anything requiring you to defeat a license or integrity check
- Behavior you can only learn by running untrusted code outside a sandbox

Say so in `STATE.md` and tell the user plainly. Continue with public sources.
