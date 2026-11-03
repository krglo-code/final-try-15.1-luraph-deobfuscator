#!/usr/bin/env python3
"""Luraph 15.1 suite audit. Reports what's present, what's missing, and the
exact commands to close the gaps for a perfect 15.1 deob pipeline."""
from pathlib import Path
import shutil

ROOT = Path(__file__).resolve().parent
BIN = ROOT / "bin"
CORE = ROOT / "core"
EXT = ROOT / "deobfuscator-luraph-v15.1"

checks = []

def check(name, ok, detail, fix):
    checks.append((name, ok, detail, fix))

# Core files
check("deob.py orchestrator", (ROOT / "deob.py").is_file(), str(ROOT / "deob.py"), "present")
check("detect.py fingerprinter", (CORE / "detect.py").is_file(), str(CORE / "detect.py"), "present")
check("static_unpack.py", (CORE / "static_unpack.py").is_file(), str(CORE / "static_unpack.py"), "present")
check("ipc_repl.py", (CORE / "ipc_repl.py").is_file(), str(CORE / "ipc_repl.py"), "present")
check("runtime/envlog.luau", (ROOT / "runtime" / "envlog.luau").is_file(), str(ROOT / "runtime" / "envlog.luau"), "present")

# Luau binaries
luau_candidates = [BIN / "luau", BIN / "luau.exe"]
luau = next((p for p in luau_candidates if p.is_file()), shutil.which("luau"))
check("luau binary", luau is not None, str(luau) if luau else "missing", "download luau-lang/luau release, place in bin/")
check("luau.exe (Windows)", (BIN / "luau.exe").is_file(), str(BIN / "luau.exe"), "needed on Windows; rename luau or download luau.exe")

# v15.1 detection patterns in detect.py
detect_txt = (CORE / "detect.py").read_text(errors="replace") if (CORE / "detect.py").is_file() else ""
v151_markers = ["Luraph Obfuscator v15.1", "LPH_ENCSTR2", "_bsdata0", "superflow_bytecode"]
found = [m for m in v151_markers if m in detect_txt]
check("detect.py v15.1 patterns", len(found) >= 2, f"found {len(found)}/4: {found}", "detect.py already covers v15.1 headers")

# External engines referenced but missing
krypt = ROOT / "luraph-v15-deob-krypt"
psu = ROOT / "psu-deobfuscator"
check("Optional KryptIT engine", krypt.is_dir(), str(krypt), "optional dependency; built-in v15.1 module is separate")
check("Optional caomod engine", psu.is_dir(), str(psu), "optional dependency; built-in v15.1 module is separate")

# kers module versions
kers_v15 = EXT / "core" / "obfuscators" / "luraph_v15"
kers_v14 = EXT / "core" / "obfuscators" / "luraph_v14"
kers_v151_shim = EXT / "core" / "obfuscators" / "luraph_v15.1"
kers_v151_impl = EXT / "core" / "obfuscators" / "luraph_v15_1"
check("kers luraph_v15.1 compatibility shim", kers_v151_shim.is_dir(), str(kers_v151_shim), "restore the v15.1 import shim")
check("kers luraph_v15.1 implementation", kers_v151_impl.is_dir(), str(kers_v151_impl), "restore the dedicated v15.1 implementation")
check("kers luraph_v15 module", kers_v15.is_dir(), str(kers_v15), "present")
check("kers luraph_v14 module", kers_v14.is_dir(), str(kers_v14), "present")

# Verify the dedicated package is actually importable, not merely present.
import subprocess
probe = subprocess.run(
    [__import__("sys").executable, "-c",
     "import sys; from pathlib import Path; "
     "sys.path.insert(0, str(Path('deobfuscator-luraph-v15.1/core').resolve())); "
     "import obfuscators.luraph_v15_1 as m; assert callable(m.run)"],
    cwd=ROOT, capture_output=True, text=True, timeout=30,
)
check("v15.1 package import", probe.returncode == 0,
      "dedicated driver imports" if probe.returncode == 0 else probe.stderr.strip(),
      "repair the v15.1 package driver/import chain")

# Static syntax validation: compile source text without importing or executing it.
import py_compile
python_files = list(ROOT.rglob("*.py"))
syntax_errors = []
for source_file in python_files:
    try:
        py_compile.compile(str(source_file), doraise=True)
    except Exception as exc:
        syntax_errors.append(f"{source_file.relative_to(ROOT)}: {exc}")
check("Python syntax compilation", not syntax_errors,
      f"{len(python_files)} Python files checked" if not syntax_errors else "; ".join(syntax_errors),
      "fix reported syntax errors")

print("=" * 64)
print("  Luraph 15.1 Suite Audit")
print("=" * 64)
for name, ok, detail, fix in checks:
    flag = "[OK ]" if ok else "[-- ]"
    print(f"{flag} {name}")
    print(f"       {detail}")
    if fix and fix != "present":
        print(f"       fix: {fix}")
print()

missing = [c for c in checks if not c[1]]
if missing:
    print(f"  {len(missing)} check(s) not satisfied. Missing optional engines do not prove the built-in engine is broken.")
    print("  This audit checks structure and syntax only; real sample-based recovery remains unverified.")
else:
    print("  Structural checks passed. Real sample-based v15.1 recovery remains unverified.")
