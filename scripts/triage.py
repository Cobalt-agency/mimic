#!/usr/bin/env python3
"""
mimic / triage.py

Static, read-only fingerprint of a software file or folder.
Python standard library only. It NEVER executes the target.

    python3 triage.py <file-or-folder> [--json] [--max-mb 64]

What it reports: real file type (by content, not extension), framework /
runtime, entry facts, native libs, Android permissions, network hosts,
installer/packer hints, hardcoded-secret FINDINGS (type + location only,
the value is never printed), which analysis tools exist on this machine,
and a suggested next route.
"""
import argparse
import collections
import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import zipfile
from urllib.parse import urlparse

TOOLS = ["apktool", "jadx", "aapt2", "aapt", "adb", "java", "node", "npm",
         "python3", "git", "7z", "unzip", "strings", "file", "binwalk",
         "innoextract", "msiextract", "ilspycmd", "monodis", "ghidra",
         "r2", "objdump", "readelf"]

ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
U16_RE = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
URL_RE = re.compile(r"https?://[A-Za-z0-9._~:/?#@!$&*+,;=%\-]{4,200}")
PERM_RE = re.compile(r"[A-Za-z0-9_.]+\.permission\.[A-Z0-9_]+")

SECRETS = {
    "google_api_key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "aws_access_key_id": re.compile(r"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "slack_token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    "stripe_live_key": re.compile(r"sk_live_[0-9A-Za-z]{16,}"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
}

NOISE_HOSTS = ("schemas.android.com", "w3.org", "apache.org", "xmlpull.org",
               "schemas.microsoft.com", "ns.adobe.com", "example.com",
               "schema.org", "localhost", "purl.org", "openxmlformats.org")

SIGS = {
    b"Nullsoft Install System": "NSIS installer",
    b"Inno Setup": "Inno Setup installer",
    b"InstallShield": "InstallShield installer",
    b"WixBundle": "WiX bundle installer",
    b"UPX!": "UPX packed",
    b"PyInstaller": "PyInstaller bundle",
    b"MEIPASS": "PyInstaller bundle",
    b"py2exe": "py2exe bundle",
    b"app.asar": "Electron (asar)",
    b"Themida": "Themida protector",
    b"VMProtect": "VMProtect protector",
    b"Go build ID": "Go binary",
    b"/rustc/": "Rust binary",
}

FRAMEWORKS = [
    ("Flutter", ["libflutter.so", "flutter_assets/"]),
    ("React Native", ["index.android.bundle", "libreactnativejni.so", "libhermes.so"]),
    ("Unity", ["libunity.so", "assets/bin/Data/"]),
    ("Xamarin / .NET MAUI", ["libmonodroid.so", "libmonosgen-2.0.so", "assemblies/"]),
    ("Cordova", ["cordova.js", "assets/www/"]),
    ("Capacitor", ["capacitor.config.json", "capacitor.plugins.json"]),
    ("Godot", ["libgodot_android.so"]),
    ("Cocos2d", ["libcocos2d", "libcocos"]),
    ("Jetpack Compose", ["androidx/compose/"]),
    ("Kotlin", ["kotlin/", "kotlin-tooling-metadata.json"]),
    ("Electron", ["resources/app.asar"]),
]

# Commercial app hardening (packers). We only DETECT these. We never bypass them.
HARDENING = ["libjiagu", "libDexHelper", "libsecexe", "libprotectClass", "libshella",
             "libegis", "libmobisec", "libijiami", "libnqshield", "libbaiduprotect",
             "libapp-protect", "libdexjni", "libtup"]

PE_DLL_HINTS = {
    "mscoree.dll": ".NET (managed)", "qt5core.dll": "Qt5", "qt6core.dll": "Qt6",
    "wxmsw": "wxWidgets", "python3": "embedded Python", "jvm.dll": "Java (JVM)",
    "libcef.dll": "Chromium Embedded (CEF)", "unityplayer.dll": "Unity",
    "sdl2.dll": "SDL2", "d3d11.dll": "Direct3D 11", "d3d12.dll": "Direct3D 12",
    "vulkan-1.dll": "Vulkan", "winhttp.dll": "WinHTTP (network)",
    "wininet.dll": "WinINet (network)", "ws2_32.dll": "Winsock (network)",
    "libgcc": "MinGW build", "vcruntime": "MSVC runtime",
}

ELF_MACHINES = {3: "x86", 62: "x86-64", 40: "ARM", 183: "AArch64", 243: "RISC-V"}
ELF_TYPES = {1: "relocatable", 2: "executable", 3: "shared object / PIE"}
MACHO_MAGICS = {b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe",
                b"\xcf\xfa\xed\xfe"}
HERMES_MAGIC = bytes.fromhex("c61fbc03c1031919")


# ----------------------------------------------------------------- helpers
def probe_tools():
    return {n: bool(shutil.which(n)) for n in TOOLS}


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in collections.Counter(data).values())


def text_strings(blob):
    out = [m.group().decode("ascii", "ignore") for m in ASCII_RE.finditer(blob)]
    out += [m.group().decode("utf-16le", "ignore") for m in U16_RE.finditer(blob)]
    return out


class Harvest:
    """Collects hosts, secret FINDINGS (never values), permissions, signatures."""

    def __init__(self):
        self.hosts = collections.Counter()
        self.secrets = collections.Counter()
        self.perms = set()
        self.sigs = set()

    def feed(self, label, blob, want_perms=False):
        text = "\n".join(text_strings(blob))
        for url in URL_RE.findall(text):
            try:
                host = urlparse(url).hostname
            except ValueError:
                continue
            if host and "." in host and not host.endswith(NOISE_HOSTS):
                self.hosts[host] += 1
        for kind, rx in SECRETS.items():
            n = len(rx.findall(text))
            if n:
                self.secrets[(kind, label)] += n
        if want_perms:
            self.perms.update(PERM_RE.findall(text))
        for sig, name in SIGS.items():
            if sig in blob:
                self.sigs.add(name)

    def export(self):
        return {
            "hosts": self.hosts.most_common(25),
            "secret_findings": [
                {"kind": k, "where": w, "count": c, "value": "REDACTED"}
                for (k, w), c in sorted(self.secrets.items())
            ],
            "permissions": sorted(self.perms),
            "signatures": sorted(self.sigs),
        }


# ----------------------------------------------------------------- zip family
SCAN_EXT = (".dex", ".arsc", ".xml", ".js", ".mjs", ".json", ".html", ".htm",
            ".txt", ".properties", ".config", ".plist")


def analyze_zip(path, budget):
    r = {}
    hv = Harvest()
    try:
        z = zipfile.ZipFile(path)
    except zipfile.BadZipFile:
        return {"kind": "corrupt-or-odd zip", "note": "zip header present but archive unreadable"}
    with z:
        infos = z.infolist()
        names = [i.filename for i in infos]
        lower = [n.lower() for n in names]
        has = lambda s: any(s in n for n in names)

        top_manifest = None
        if "manifest.json" in names:
            try:
                top_manifest = json.loads(z.read("manifest.json").decode("utf-8", "ignore"))
            except Exception:
                top_manifest = None

        if "AndroidManifest.xml" in names and (has("classes") or "resources.arsc" in names):
            r["kind"] = "android-apk"
        elif "BundleConfig.pb" in names or has("base/manifest/AndroidManifest.xml"):
            r["kind"] = "android-aab"
        elif any(n.endswith(".apk") for n in lower) and "AndroidManifest.xml" not in names:
            r["kind"] = "android-xapk (split apks)"
            if isinstance(top_manifest, dict):
                r["xapk_manifest"] = {k: top_manifest.get(k) for k in
                                      ("package_name", "name", "version_name", "min_sdk_version")}
            r["inner_apks"] = [n for n in names if n.lower().endswith(".apk")][:20]
        elif any(n.startswith("Payload/") and ".app/" in n for n in names):
            r["kind"] = "ios-ipa"
        elif isinstance(top_manifest, dict) and "manifest_version" in top_manifest:
            r["kind"] = "browser-extension"
            r["extension"] = {
                "name": top_manifest.get("name"),
                "version": top_manifest.get("version"),
                "manifest_version": top_manifest.get("manifest_version"),
                "permissions": top_manifest.get("permissions"),
                "host_permissions": top_manifest.get("host_permissions"),
            }
        elif "META-INF/MANIFEST.MF" in names:
            r["kind"] = "java-jar"
            try:
                mf = z.read("META-INF/MANIFEST.MF").decode("utf-8", "ignore")
                r["jar_manifest"] = {k: v.strip() for k, v in
                                     (ln.split(":", 1) for ln in mf.splitlines() if ":" in ln)
                                     if k in ("Main-Class", "Implementation-Title",
                                              "Implementation-Version", "Created-By")}
            except Exception:
                pass
        else:
            r["kind"] = "zip (generic: installer payload, docx, or other)"

        # framework / hardening hints
        fw = [name for name, pats in FRAMEWORKS if any(p in n for p in pats for n in names)]
        r["frameworks"] = fw
        r["hardening_detected"] = sorted({h for h in HARDENING for n in names if h in n})

        # android structure facts
        if r["kind"].startswith("android"):
            r["dex_files"] = sum(1 for n in names if re.fullmatch(r"classes\d*\.dex", n))
            so = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
            r["native_abis"] = sorted({n.split("/")[1] for n in so if n.count("/") >= 2})
            r["native_libs"] = sorted({os.path.basename(n) for n in so})[:40]
            r["layouts"] = sum(1 for n in names if n.startswith("res/layout"))
            r["drawables"] = sum(1 for n in names if n.startswith("res/drawable")
                                 or n.startswith("res/mipmap"))
            r["asset_files"] = sum(1 for n in names if n.startswith("assets/"))
            r["signed"] = any(n.startswith("META-INF/") and
                              n.endswith((".RSA", ".DSA", ".EC", ".SF")) for n in names)
            if "assets/index.android.bundle" in names:
                head = z.read("assets/index.android.bundle")[:8]
                r["rn_bundle"] = "hermes-bytecode" if head == HERMES_MAGIC else "plain-js"
            r["il2cpp"] = has("libil2cpp.so") or has("global-metadata.dat")

        # scan useful members under the byte budget
        def prio(i):
            n = i.filename
            if n == "AndroidManifest.xml":
                return 0
            if n.endswith(".dex"):
                return 1
            if n.endswith(".arsc"):
                return 2
            return 3

        scanned = 0
        for info in sorted(infos, key=prio):
            n = info.filename
            if budget["left"] <= 0:
                break
            if not n.lower().endswith(SCAN_EXT) or info.file_size > 16 * 1024 * 1024:
                continue
            try:
                blob = z.read(n)
            except Exception:
                continue
            budget["left"] -= len(blob)
            hv.feed(n, blob, want_perms=(n == "AndroidManifest.xml"))
            scanned += 1
        r["members_scanned"] = scanned
        r["member_count"] = len(names)
    r.update(hv.export())
    return r


def aapt_badging(path):
    exe = shutil.which("aapt2") or shutil.which("aapt")
    if not exe:
        return None
    try:
        cmd = [exe, "dump", "badging", path]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=40).stdout
    except Exception:
        return None
    info = {}
    m = re.search(r"package: name='([^']*)' versionCode='([^']*)' versionName='([^']*)'", out)
    if m:
        info.update(package=m.group(1), versionCode=m.group(2), versionName=m.group(3))
    for key, rx in (("label", r"application-label:'([^']*)'"),
                    ("minSdk", r"sdkVersion:'([^']*)'"),
                    ("targetSdk", r"targetSdkVersion:'([^']*)'"),
                    ("launcher_activity", r"launchable-activity: name='([^']*)'")):
        mm = re.search(rx, out)
        if mm:
            info[key] = mm.group(1)
    return info or None


# ----------------------------------------------------------------- PE
def analyze_pe(path, budget):
    r = {"kind": "windows-pe"}
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        f.seek(0x3C)
        e_lfanew = struct.unpack("<I", f.read(4))[0]
        f.seek(e_lfanew)
        if f.read(4) != b"PE\0\0":
            r["kind"] = "dos/legacy executable (MZ without PE header)"
            return r
        machine, nsec, ts, _, _, optsize, chars = struct.unpack("<HHIIIHH", f.read(20))
        opt = f.read(optsize)
        magic = struct.unpack_from("<H", opt, 0)[0]
        plus = magic == 0x20B
        r["arch"] = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "ARM", 0xAA64: "ARM64"}.get(machine, hex(machine))
        r["format"] = "PE32+" if plus else "PE32"
        r["is_dll"] = bool(chars & 0x2000)
        r["subsystem"] = {2: "GUI", 3: "console"}.get(struct.unpack_from("<H", opt, 68)[0], "other")
        r["compile_timestamp"] = ts
        dd_off = 112 if plus else 96
        ndd = struct.unpack_from("<I", opt, dd_off - 4)[0]
        dirs = []
        for i in range(min(ndd, 16)):
            if dd_off + 8 * i + 8 <= len(opt):
                dirs.append(struct.unpack_from("<II", opt, dd_off + 8 * i))
        secs = []
        for _ in range(nsec):
            nm, vsz, vaddr, rsz, rptr, ch = struct.unpack("<8sIIII12xI", f.read(40))
            secs.append((nm.rstrip(b"\0").decode("ascii", "ignore"), vsz, vaddr, rsz, rptr))

        def rva2off(rva):
            for _, vsz, vaddr, rsz, rptr in secs:
                if vaddr <= rva < vaddr + max(vsz, rsz):
                    return rva - vaddr + rptr
            return None

        r["sections"] = []
        end_of_image = 0
        for nm, vsz, vaddr, rsz, rptr in secs:
            f.seek(rptr)
            e = round(entropy(f.read(min(rsz, 2 * 1024 * 1024))), 2)
            r["sections"].append({"name": nm, "raw_size": rsz, "entropy": e})
            end_of_image = max(end_of_image, rptr + rsz)
        r["overlay_bytes"] = max(0, size - end_of_image)
        if any(s["entropy"] > 7.2 for s in r["sections"]):
            r["packed_hint"] = "high-entropy section(s): likely packed/encrypted"
        if len(dirs) > 14 and dirs[14][0]:
            r["dotnet_managed"] = True

        imports = []
        if len(dirs) > 1 and dirs[1][0]:
            off = rva2off(dirs[1][0])
            if off is not None:
                for i in range(200):
                    f.seek(off + 20 * i)
                    d = f.read(20)
                    if len(d) < 20 or d == b"\0" * 20:
                        break
                    name_rva = struct.unpack_from("<I", d, 12)[0]
                    noff = rva2off(name_rva)
                    if noff is None:
                        continue
                    f.seek(noff)
                    imports.append(f.read(128).split(b"\0")[0].decode("ascii", "ignore"))
        r["imports"] = imports
        low = [d.lower() for d in imports]
        r["runtime_hints"] = sorted({v for k, v in PE_DLL_HINTS.items() if any(k in d for d in low)})

        f.seek(0)
        blob = f.read(min(size, budget["left"], 48 * 1024 * 1024))
    budget["left"] -= len(blob)
    hv = Harvest()
    hv.feed("binary", blob)
    r.update(hv.export())
    return r


# ----------------------------------------------------------------- ELF / Mach-O / misc
def analyze_elf(path, head, budget):
    r = {"kind": "linux-elf"}
    endian = "<" if head[5] == 1 else ">"
    etype, machine = struct.unpack(endian + "HH", head[16:20])
    r.update(bits={1: "32-bit", 2: "64-bit"}.get(head[4], "?"),
             type=ELF_TYPES.get(etype, str(etype)),
             arch=ELF_MACHINES.get(machine, str(machine)))
    if head[8:11] == b"AI\x02":
        r["kind"] = "appimage (type 2)"
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        blob = f.read(min(size, budget["left"], 48 * 1024 * 1024))
    budget["left"] -= len(blob)
    hv = Harvest()
    hv.feed("binary", blob)
    libs = (b"libQt5Core", b"libQt6Core", b"libgtk-3", b"libgtk-4",
            b"libSDL2", b"libcef", b"libpython3", b"libjvm")
    r["linked_hints"] = sorted(n.decode() for n in libs if n in blob)
    r.update(hv.export())
    return r


def analyze_macho(path, budget):
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        blob = f.read(min(size, budget["left"], 32 * 1024 * 1024))
    budget["left"] -= len(blob)
    hv = Harvest()
    hv.feed("binary", blob)
    r = {"kind": "macos-mach-o"}
    r.update(hv.export())
    return r


def analyze_generic(path, budget):
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        blob = f.read(min(size, budget["left"], 16 * 1024 * 1024))
    budget["left"] -= len(blob)
    hv = Harvest()
    hv.feed("file", blob)
    r = {"kind": "unknown", "entropy_first_4mb": round(entropy(blob[:4 * 1024 * 1024]), 2)}
    r.update(hv.export())
    return r


def analyze_file(path, budget):
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(4096)
    ext = os.path.splitext(path)[1].lower()
    r = {"size_bytes": size, "sha256": sha256(path), "extension": ext}
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        r.update(analyze_zip(path, budget))
    elif head[:2] == b"MZ":
        r.update(analyze_pe(path, budget))
    elif head[:4] == b"\x7fELF":
        r.update(analyze_elf(path, head, budget))
    elif head[:4] in MACHO_MAGICS:
        r.update(analyze_macho(path, budget))
    elif head[:4] == b"\xca\xfe\xba\xbe":
        r.update(kind="java .class or macOS universal binary (ambiguous)" if ext != ".class"
                 else "java-class")
    elif head[:4] == b"Cr24":
        r.update(kind="chrome-extension .crx (zip after header; strip header and re-run)")
    elif head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        g = analyze_generic(path, budget)
        g["kind"] = "ole2 compound file (probably .msi installer)"
        r.update(g)
    elif ext == ".asar":
        r.update(kind="electron asar archive (extract with: npx asar extract)")
    elif ext == ".dmg":
        r.update(kind="apple dmg disk image (unverified; extract with 7z or dmg2img)")
    else:
        r.update(analyze_generic(path, budget))
    if ext == ".apk" and r.get("kind") == "android-apk":
        info = aapt_badging(path)
        if info:
            r["badging"] = info
    return r


# ----------------------------------------------------------------- directories
def analyze_dir(path, budget):
    r = {"kind": "folder"}
    markers = {"package.json": "Node/JS project", "pubspec.yaml": "Flutter/Dart project",
               "manifest.json": "extension or PWA manifest", "index.html": "web entry",
               "Cargo.toml": "Rust project", "build.gradle": "Gradle/Android project",
               "build.gradle.kts": "Gradle/Android project", "AndroidManifest.xml": "Android manifest",
               "Info.plist": "Apple bundle", "app.asar": "Electron asar",
               "requirements.txt": "Python project", "pom.xml": "Maven/Java project"}
    found, exts, count = {}, collections.Counter(), 0
    hv = Harvest()
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__")]
        for fn in files:
            count += 1
            if count > 20000:
                break
            exts[os.path.splitext(fn)[1].lower() or "(none)"] += 1
            if fn in markers:
                found[os.path.relpath(os.path.join(root, fn), path)] = markers[fn]
            if fn.endswith(".csproj"):
                found[os.path.relpath(os.path.join(root, fn), path)] = ".NET project"
            fp = os.path.join(root, fn)
            if budget["left"] > 0 and fn.lower().endswith(SCAN_EXT):
                try:
                    if os.path.getsize(fp) <= 1024 * 1024:
                        with open(fp, "rb") as f:
                            blob = f.read()
                        budget["left"] -= len(blob)
                        hv.feed(os.path.relpath(fp, path), blob)
                except OSError:
                    pass
    r["file_count"] = count
    r["top_extensions"] = exts.most_common(10)
    r["markers"] = found
    r["top_level"] = sorted(os.listdir(path))[:40]
    pj = os.path.join(path, "package.json")
    if os.path.isfile(pj):
        try:
            data = json.load(open(pj, encoding="utf-8"))
            r["package_json"] = {"name": data.get("name"), "version": data.get("version"),
                                 "dependencies": sorted((data.get("dependencies") or {}))[:30]}
        except Exception:
            pass
    r.update(hv.export())
    return r


# ----------------------------------------------------------------- route advice
def suggest_route(rep):
    k = rep.get("kind", "")
    fw = rep.get("frameworks", [])
    s = []
    if rep.get("hardening_detected"):
        s.append("Commercial app hardening detected. Do NOT try to unpack or bypass it. "
                 "Switch to RESEARCH mode plus UI/behavior documentation from public sources.")
    if k.startswith("android"):
        if "Flutter" in fw:
            s.append("Flutter: logic is AOT-compiled Dart (libapp.so), decompiling is low-yield. "
                     "Use assets/flutter_assets, strings, endpoints and research to rebuild behavior.")
        if "React Native" in fw:
            if rep.get("rn_bundle") == "plain-js":
                s.append("React Native with PLAIN JS bundle: read assets/index.android.bundle for screens, state and API calls.")
            else:
                s.append("React Native with Hermes bytecode: not human-readable. Use resources, strings, endpoints and research.")
        if "Unity" in fw or rep.get("il2cpp"):
            s.append("Unity: IL2CPP is compiled (use research + assets); Mono builds expose Assembly-CSharp.dll (readable with ilspy).")
        if "Cordova" in fw or "Capacitor" in fw:
            s.append("Cordova/Capacitor: assets/www IS the app. Read it directly.")
        if not fw or fw == ["Kotlin"] or fw == ["Jetpack Compose", "Kotlin"]:
            s.append("Native Java/Kotlin: apktool (manifest/resources) + jadx (understanding only). See references/android.md.")
        if k == "android-xapk (split apks)":
            s.append("Unzip the XAPK, then run triage on the base APK.")
    elif k == "windows-pe":
        hints = rep.get("runtime_hints", [])
        if ".NET (managed)" in hints or rep.get("dotnet_managed"):
            s.append(".NET: ilspycmd/monodis shows structure. Describe behavior, do not copy code.")
        if any("Electron" in x or "asar" in x for x in rep.get("signatures", [])):
            s.append("Electron: extract resources/app.asar, the JS is the behavior.")
        if any("installer" in x for x in rep.get("signatures", [])) or rep.get("overlay_bytes", 0) > 1_000_000:
            s.append("Installer/SFX: unpack payload (7z / innoextract / msiextract), then re-run triage on the payload.")
        if rep.get("packed_hint"):
            s.append("Packed/protected: do not unpack. Use research mode and observable behavior.")
        s.append("See references/desktop.md.")
    elif k.startswith("browser-extension") or k == "java-jar":
        s.append("Readable by nature: read manifest + scripts (extension) or structure via decompiler (jar).")
    elif k == "folder":
        s.append("Source/web folder: read entry points and package manifest, then go straight to PROFILE.")
    if not s:
        s.append("No automatic route. Fall back to RESEARCH mode (references/research-playbook.md).")
    return s


# ----------------------------------------------------------------- output
def to_markdown(rep):
    L = []
    L.append("# TRIAGE REPORT\n")
    L.append(f"- **Target:** `{rep['target']}`")
    L.append(f"- **Detected type:** {rep.get('kind')}")
    for key in ("size_bytes", "sha256", "arch", "format", "subsystem", "bits", "type"):
        if key in rep:
            L.append(f"- **{key}:** {rep[key]}")
    if rep.get("badging"):
        L.append(f"- **Android badging:** {rep['badging']}")
    for key in ("xapk_manifest", "jar_manifest", "extension", "package_json"):
        if rep.get(key):
            L.append(f"- **{key}:** {rep[key]}")
    if rep.get("frameworks"):
        L.append(f"- **Frameworks:** {', '.join(rep['frameworks'])}")
    if rep.get("runtime_hints"):
        L.append(f"- **Runtime hints:** {', '.join(rep['runtime_hints'])}")
    if rep.get("linked_hints"):
        L.append(f"- **Linked libs:** {', '.join(rep['linked_hints'])}")
    if rep.get("signatures"):
        L.append(f"- **Signatures:** {', '.join(rep['signatures'])}")
    if rep.get("hardening_detected"):
        L.append(f"- **Hardening (do not bypass):** {', '.join(rep['hardening_detected'])}")
    for key in ("dex_files", "native_abis", "layouts", "drawables", "asset_files", "signed",
                "rn_bundle", "il2cpp", "overlay_bytes", "packed_hint", "member_count"):
        if key in rep:
            L.append(f"- **{key}:** {rep[key]}")
    if rep.get("native_libs"):
        L.append(f"- **Native libs:** {', '.join(rep['native_libs'])}")
    if rep.get("sections"):
        L.append("- **PE sections:** " + ", ".join(f"{s['name']}(H={s['entropy']})" for s in rep["sections"]))
    if rep.get("imports"):
        L.append(f"- **Imports (DLLs):** {', '.join(rep['imports'][:30])}")
    if rep.get("markers"):
        L.append(f"- **Project markers:** {rep['markers']}")
    if rep.get("top_level"):
        L.append(f"- **Top level:** {', '.join(rep['top_level'])}")
    if rep.get("permissions"):
        L.append("\n## Android permissions\n" + "\n".join(f"- `{p}`" for p in rep["permissions"]))
    if rep.get("hosts"):
        L.append("\n## Network hosts seen in strings (top)\n" +
                 "\n".join(f"- {h} (x{c})" for h, c in rep["hosts"]))
    if rep.get("secret_findings"):
        L.append("\n## SECRET FINDINGS (values redacted, never reuse them)\n" +
                 "\n".join(f"- {s['kind']} in `{s['where']}` (x{s['count']})" for s in rep["secret_findings"]))
    miss = [t for t, ok in rep["tools"].items() if not ok]
    have = [t for t, ok in rep["tools"].items() if ok]
    L.append(f"\n## Tools on this machine\n- **Available:** {', '.join(have) or 'none'}\n- **Missing:** {', '.join(miss)}")
    L.append("\n## Suggested route\n" + "\n".join(f"- {x}" for x in rep["route"]))
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Static triage of a software file/folder.")
    ap.add_argument("target")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    ap.add_argument("--max-mb", type=int, default=64, help="max megabytes of content to scan")
    args = ap.parse_args()
    if not os.path.exists(args.target):
        sys.exit(f"target not found: {args.target}")
    budget = {"left": args.max_mb * 1024 * 1024}
    rep = {"target": os.path.abspath(args.target)}
    rep.update(analyze_dir(args.target, budget) if os.path.isdir(args.target)
               else analyze_file(args.target, budget))
    rep["tools"] = probe_tools()
    rep["route"] = suggest_route(rep)
    print(json.dumps(rep, indent=2, default=str) if args.json else to_markdown(rep))


if __name__ == "__main__":
    main()
