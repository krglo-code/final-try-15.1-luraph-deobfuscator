import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CORE_DIR = os.path.join(HERE, "..", "core")
if CORE_DIR not in sys.path:
    sys.path.insert(0, CORE_DIR)

cmd = sys.argv[1]

if cmd == "pipeline":

    config_file = sys.argv[2]
    with open(config_file, "r", encoding="utf-8") as f:
        c = json.load(f)

    from obfuscators.base import Job
    from obfuscators.luraph_v15 import driver
    import harness

    class DummyArgs:
        DEFAULTS = {
            # --cfg KEY=VALUE list consumed by harness.user_cfg (the node cfg
            # extras already travel inside c["cfg"], so this stays empty)
            "cfg":           [],
            "keep_harness":  False,
            "no_hooks":      False,
            "no_devirt":     False,
            "max_runs":      1,
            "raw":           None,
            "input_text":    None,
            "port":          None,
            # ── Fields the v15 Python driver reads unconditionally ──────────
            # Without these, __getattr__ returns False (= 0 for numeric fields),
            # which causes:
            #   budget=0      → harness time_budget is zero, no sandbox runs
            #   timeout=0     → lift() immediately times out
            #   devirt_rounds=0 → devirt loop never iterates
            #   executor=False → harness expects None or a string
            "budget":        30,
            "timeout":       600,
            "devirt_rounds": 8,
            "executor":      None,
            "strings":       False,
            "studio":        False,
            "no_fold":       False,
            "no_cff":        False,
            "no_ssa":        False,
            "no_dead":       False,
        }

        def __init__(self, d):
            for k, v in d.items():
                setattr(self, k, v)

        def __getattr__(self, k):
            # the python driver reads attrs the node CLI never passes
            return DummyArgs.DEFAULTS.get(k, False)

    args = DummyArgs(c["args"])
    job = Job(c["input"], c["source"], args, c["trace_path"], c["debug"], c["obfuscator"])
    job.source_path = c["source_path"]
    job.credit_header = lambda: ""

    runner = harness.Runner(job)
    runner.luau = c["luau_exe"]

    profiler = None
    prof_path = os.environ.get("DEOB_PROFILE")
    if prof_path:
        import cProfile
        profiler = cProfile.Profile()

    if profiler:
        profiler.enable()
    driver.lift(
        job,
        runner,
        c["patched"],
        c["cfg"],
        c.get("chunks", {}),
        c["run_text"],
        c["ppath"],
        c["dpath"],
        c.get("chunk_paths", []),
    )
    if profiler:
        profiler.disable()
        profiler.dump_stats(prof_path)
        sys.stderr.write("[*] cProfile stats written to %s\n" % prof_path)
    runner.finish()

    dpath = c["dpath"]
    if os.path.exists(dpath):
        with open(dpath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        clean = []
        skip_header = True
        for line in lines:
            stripped = line.strip()
            if skip_header and (
                stripped.startswith("-- Deobfuscated by") or
                stripped.startswith("-- Detected obfuscation") or
                stripped.startswith("-- Local names are inferred") or
                stripped.startswith("-- source:") or
                stripped.startswith("-- NOTE: reconstructed") or
                stripped.startswith("--       during the trace")
            ):
                continue
            if skip_header and stripped == "":
                continue
            skip_header = False
            clean.append(line)
        with open(dpath, "w", encoding="utf-8", newline="\n") as f:
            f.writelines(clean)

    print(json.dumps({"success": True, "output": c["dpath"]}))

else:
    sys.exit(f"Unknown command: {cmd} (expected: pipeline)")
