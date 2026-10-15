# Android / mobile analysis

Goal: learn **behavior**. Notes go in `mimic-work/lab/NOTES.md`. Nothing here gets copied into the build.

## Contents
1. Tool ladder
2. What to read, in order
3. Per-framework notes
4. Network and data
5. iOS (IPA)
6. Mapping findings to the blueprint

## 1. Tool ladder (use the first that exists)

```bash
apktool d app.apk -o mimic-work/lab/apktool      # manifest, resources, smali
jadx -d mimic-work/lab/jadx app.apk              # readable Java/Kotlin, for understanding only
aapt2 dump badging app.apk                   # package, version, permissions, launcher
unzip -o app.apk -d mimic-work/lab/unzipped      # always available
```

Fallbacks: Python `zipfile`, `strings`, `pip install androguard`. The binary `AndroidManifest.xml` is not plain text, so use apktool/aapt2/androguard to read it properly.

XAPK / split APKs: unzip, then work on `base.apk` (or the biggest `.apk`). AAB: unzip, look in `base/`.

## 2. What to read, in order

1. **Manifest:** package, SDK levels, permissions, activities, services, receivers, deep links, intent filters. The launcher activity is the app's front door.
2. **Resources:** `res/layout*`, `res/navigation`, `res/menu`, `res/values/strings.xml`, `colors.xml`, `themes.xml`, `dimens.xml`.
   - Strings are the app's vocabulary: feature names, errors, onboarding text. Use them to understand flows. Write your own copy in the clone.
   - Colors/dimens: note the *style* (dark, rounded, dense). Define your own tokens.
3. **Screen graph:** list every screen and what leads where.
4. **Logic path (understand, don't copy):** launcher activity -> ViewModel/presenter -> repository -> network/db. Summarize each hop in one sentence.
5. **Native libs:** `lib/*/*.so`. Treat as black boxes. `strings` for hints only.

## 3. Per-framework notes

| Framework | Where the app really lives | Approach |
|---|---|---|
| Native Java/Kotlin | `classes*.dex` | jadx for structure; trust the resources more than the decompiled logic |
| Jetpack Compose | dex (UI is code, few layout XMLs) | Infer screens from navigation + strings + research |
| Flutter | `libapp.so` (AOT Dart) + `assets/flutter_assets` | Decompiling is low-yield. Use assets, strings, endpoints, research |
| React Native | `assets/index.android.bundle` | Plain JS: read it. Hermes bytecode: not readable, use research |
| Cordova / Capacitor | `assets/www/` | It is a web app. Read it directly |
| Unity | `libil2cpp.so` + `global-metadata.dat` or `Assembly-CSharp.dll` | IL2CPP: research + assets. Mono: ilspy on the dll |
| Xamarin / MAUI | `assemblies/*.dll` | ilspy for structure |
| Godot / Cocos | `.pck` / `libcocos*` | Assets + research; rebuild gameplay from observed rules |

**Hardened apps** (commercial packers, encrypted dex): do not unpack. Use research mode.

## 4. Network and data

- Hosts and endpoints: `triage.py` lists hosts seen in strings. From code/JS, document `METHOD /path -> response shape` in the blueprint.
- Auth model: token type, refresh flow, scopes. Describe it, do not reuse any credential.
- Storage: Room/SQLite schema, SharedPreferences keys, files. Reproduce the *model*, with your own naming.
- If the backend is private, the clone gets a local-first store or a mock server. Never call the original's servers.

## 5. iOS (IPA)

IPA is a zip: `Payload/<Name>.app/`. Read `Info.plist` (permissions, URL schemes), storyboards/nibs, `Assets.car` names, strings files. Native code is compiled, so lean on resources and research.

## 6. Mapping findings to the blueprint

| Finding | Blueprint section |
|---|---|
| Launcher activity, nav graph | Screens and flows |
| Permissions + their usage | Capabilities (with justification) |
| Room/prefs schema | Data model |
| Endpoints | External interfaces |
| Colors/dimens/themes | Design tokens (re-defined as your own) |
| Reviews/complaints (research) | "Beat the original" |
