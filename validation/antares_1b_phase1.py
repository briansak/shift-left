#!/usr/bin/env python3
"""Phase 1: Antares-1B load, template, protocol, and memory checks (report-only)."""

from __future__ import annotations

import gc
import json
import os
import resource
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ANTARES_SERVER = ROOT / "services" / "antares-server"
SHARED = ROOT / "services" / "shift-left-shared"
for path in (SHARED, ANTARES_SERVER):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

from antares_server.agent_loop import _SYSTEM_PROMPT, default_cwe_description
from antares_server.agent_tools import parse_agent_action

MODEL_PATH = ROOT / "models" / "1b"
FOUNDATION_Q4 = ROOT / "models" / "foundation-sec-q4_k_m" / "foundation-sec-1.1-8b-instruct-q4_k_m.gguf"


def rss_mib() -> float:
    import psutil

    return psutil.Process().memory_info().rss / (1024 * 1024)


def peak_rss_mib() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    # macOS reports ru_maxrss in bytes; Linux in kilobytes.
    if sys.platform == "darwin":
        return usage.ru_maxrss / (1024 * 1024)
    return usage.ru_maxrss / 1024


def load_report() -> dict:
    device = "mps" if torch.backends.mps.is_available() else "cpu"
    dtype = torch.bfloat16 if device == "mps" else torch.float32
    started = time.monotonic()
    rss_before = rss_mib()

    tokenizer = AutoTokenizer.from_pretrained(str(MODEL_PATH), local_files_only=True)
    model = AutoModelForCausalLM.from_pretrained(
        str(MODEL_PATH),
        local_files_only=True,
        torch_dtype=dtype,
        trust_remote_code=False,
    )
    model.to(device)
    model.eval()
    load_s = time.monotonic() - started
    rss_after = rss_mib()

    # Quick NaN / degenerate token probe at float16 vs bfloat16 on MPS.
    float16_nan = None
    if device == "mps" and os.environ.get("SKIP_FLOAT16_PROBE") != "1":
        probe = AutoModelForCausalLM.from_pretrained(
            str(MODEL_PATH),
            local_files_only=True,
            torch_dtype=torch.float16,
            trust_remote_code=False,
        ).to(device)
        probe.eval()
        ids = tokenizer("JSON array:", return_tensors="pt").to(device)
        with torch.no_grad():
            out = probe.generate(**ids, max_new_tokens=8, do_sample=False)
        text = tokenizer.decode(out[0][ids["input_ids"].shape[-1] :], skip_special_tokens=False)
        float16_nan = ("nan" in text.lower()) or ("!" in text and text.strip() == "!")
        del probe
        torch.mps.empty_cache()
        gc.collect()

    return {
        "device": device,
        "dtype_selected": str(dtype),
        "model_type": model.config.model_type,
        "architectures": list(getattr(model.config, "architectures", [])),
        "trust_remote_code": False,
        "transformers_version": __import__("transformers").__version__,
        "load_time_s": round(load_s, 2),
        "rss_before_mib": round(rss_before, 1),
        "rss_after_load_mib": round(rss_after, 1),
        "peak_rss_mib": round(peak_rss_mib(), 1),
        "float16_degenerate_on_mps": float16_nan,
        "tokenizer": tokenizer,
        "model": model,
    }


def build_agent_prompt(task_cwe: str = "CWE-89") -> str:
    system_prompt = _SYSTEM_PROMPT.format(
        max_calls=8,
        task_cwe=task_cwe,
        task_cwe_description=default_cwe_description(task_cwe),
        repo_root="/workspace/repo",
        changed_paths="app/db.py",
    )
    return system_prompt


def protocol_test(model, tokenizer, device: str) -> dict:
    prompt = build_agent_prompt("CWE-89")
    inputs = tokenizer(prompt, return_tensors="pt").to(device)
    started = time.monotonic()
    with torch.no_grad():
        output = model.generate(
            **inputs,
            max_new_tokens=512,
            do_sample=False,
            temperature=None,
            top_p=None,
            pad_token_id=tokenizer.pad_token_id or tokenizer.eos_token_id,
        )
    gen_s = time.monotonic() - started
    raw = tokenizer.decode(output[0][inputs["input_ids"].shape[-1] :], skip_special_tokens=False)
    action = parse_agent_action(raw)
    return {
        "prompt_chars": len(prompt),
        "generation_time_s": round(gen_s, 2),
        "raw_completion": raw,
        "has_redacted_thinking": "<think>" in raw,
        "has_tool_call": "<tool_call>" in raw,
        "parse_agent_action": None
        if action is None
        else {
            "type": type(action).__name__,
            "command": getattr(action, "command", None),
            "ranked_files": getattr(action, "ranked_files", None),
        },
        "parse_ok": action is not None,
    }


def template_compare() -> dict:
    t350 = (ROOT / "models" / "350m" / "chat_template.jinja").read_text()
    t1b = (ROOT / "models" / "1b" / "chat_template.jinja").read_text()
    return {
        "identical": t350 == t1b,
        "len_350m": len(t350),
        "len_1b": len(t1b),
        "generation_prompt_suffix": t1b.strip().splitlines()[-3:],
    }


def memory_with_foundation_q4(model, device: str) -> dict:
    """Load Foundation-Sec Q4_K_M in a child process and sample combined RSS."""
    import subprocess

    import psutil

    gguf = str(FOUNDATION_Q4)
    if not Path(gguf).exists():
        return {"error": f"missing {gguf}"}

    fss_python = ROOT / "services" / "foundation-sec-server" / ".venv" / "bin" / "python"
    holder = """
import time
from llama_cpp import Llama
Llama(model_path=%r, n_ctx=2048, n_gpu_layers=-1, verbose=False)
while True:
    time.sleep(3600)
""" % (
        gguf,
    )
    proc = subprocess.Popen(
        [str(fss_python), "-c", holder],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(8)
    antares_rss = rss_mib()
    foundation_rss = 0.0
    if proc.poll() is None:
        try:
            foundation_rss = psutil.Process(proc.pid).memory_info().rss / (1024 * 1024)
        except psutil.Error:
            foundation_rss = -1.0
    vm = psutil.virtual_memory()
    swap_used_mib: float | None = None
    try:
        swap_used_mib = round(psutil.swap_memory().used / (1024 * 1024), 1)
    except OSError:
        pass
    proc.terminate()
    proc.wait(timeout=10)
    return {
        "antares_process_rss_mib": round(antares_rss, 1),
        "foundation_q4_process_rss_mib": round(foundation_rss, 1),
        "combined_rss_mib": round(antares_rss + max(foundation_rss, 0), 1),
        "system_available_mib": round(vm.available / (1024 * 1024), 1),
        "system_used_mib": round(vm.used / (1024 * 1024), 1),
        "swap_used_mib": swap_used_mib,
        "host_total_gib": round(vm.total / (1024 ** 3), 1),
    }


def main() -> int:
    report: dict = {"model_path": str(MODEL_PATH)}
    report["staging"] = {
        "model_safetensors_bytes": (MODEL_PATH / "model.safetensors").stat().st_size,
        "chat_template_present": (MODEL_PATH / "chat_template.jinja").exists(),
    }
    report["template"] = template_compare()
    report["runtime_note"] = (
        "agent_loop joins system prompt + transcript with '\\n\\n'; "
        "inference.generate_agent tokenizes prompt directly — chat_template.jinja is not applied."
    )

    out = ROOT / "validation" / "reports" / "antares-1b-phase1.json"
    out.parent.mkdir(parents=True, exist_ok=True)

    load = load_report()
    report["load"] = {k: v for k, v in load.items() if k not in {"tokenizer", "model"}}
    report["protocol"] = protocol_test(load["model"], load["tokenizer"], load["device"])
    out.write_text(json.dumps(report, indent=2))

    report["memory_concurrency"] = memory_with_foundation_q4(load["model"], load["device"])
    out.write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return 0 if report["protocol"]["parse_ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
