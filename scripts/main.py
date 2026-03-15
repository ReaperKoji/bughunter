#!/usr/bin/env python3
"""HunterOps main orchestrator.

Professional model:
- Python as controller
- External high-performance tools (mostly Go binaries) via subprocess
"""

from __future__ import annotations

import argparse
import datetime as dt
import shlex
import shutil
import subprocess
from pathlib import Path


def run_cmd(command: str, output_file: Path) -> int:
    parts = shlex.split(command)
    tool = parts[0]
    if shutil.which(tool) is None:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(f"[skip] tool not found: {tool}\n", encoding="utf-8")
        return 127

    proc = subprocess.run(parts, capture_output=True, text=True, check=False)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text((proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else ""), encoding="utf-8")
    return proc.returncode


def load_targets(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [x.strip() for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def cmd_subfinder(target: str) -> str:
    return f"subfinder -d {target} -silent"


def cmd_amass(target: str) -> str:
    return f"amass enum -passive -d {target}"


def cmd_assetfinder(target: str) -> str:
    return f"assetfinder --subs-only {target}"


def cmd_httpx(input_file: Path) -> str:
    return f"httpx -l {input_file} -silent -status-code -title -tech-detect"


def cmd_katana(url: str) -> str:
    return f"katana -silent -u {url}"


def cmd_ffuf(url: str, wordlist: str) -> str:
    return f"ffuf -w {wordlist} -u {url}/FUZZ -mc 200,204,301,302,307,401,403"


def _nuclei_templates_path() -> str:
    curated = Path("templates/nuclei-curated")
    if curated.exists():
        if any(curated.rglob("*.yaml")) or any(curated.rglob("*.yml")):
            return str(curated)
    return "templates/nuclei"


def cmd_nuclei(input_file: Path) -> str:
    templates = _nuclei_templates_path()
    return f"nuclei -l {input_file} -silent -severity critical,high,medium -t {templates}"


def main() -> None:
    parser = argparse.ArgumentParser(description="HunterOps professional orchestrator")
    parser.add_argument("--in", dest="input_file", default="data/targets/in_scope_hosts.txt")
    parser.add_argument("--date", default=dt.date.today().isoformat())
    parser.add_argument("--wordlist", default="wordlists/common.txt")
    parser.add_argument(
        "--phases",
        default="recon,probe,crawl,fuzz,scan",
        help="Comma-separated phases: recon,probe,crawl,fuzz,scan",
    )
    args = parser.parse_args()

    phases = {x.strip().lower() for x in args.phases.split(",") if x.strip()}
    targets = load_targets(Path(args.input_file))
    if not targets:
        raise SystemExit("No targets found. Run scope guard first and populate input targets.")

    raw_dir = Path("data/raw") / args.date
    raw_dir.mkdir(parents=True, exist_ok=True)

    subdomain_files: list[Path] = []

    if "recon" in phases:
        for target in targets:
            safe = target.replace("*", "wildcard").replace("/", "_")
            f1 = raw_dir / f"{safe}.subfinder.txt"
            f2 = raw_dir / f"{safe}.amass.txt"
            f3 = raw_dir / f"{safe}.assetfinder.txt"
            run_cmd(cmd_subfinder(target), f1)
            run_cmd(cmd_amass(target), f2)
            run_cmd(cmd_assetfinder(target), f3)
            subdomain_files.extend([f1, f2, f3])
        print("[main] recon phase completed")

    merged_hosts = raw_dir / "merged_hosts.txt"
    if subdomain_files:
        hosts: set[str] = set()
        for file in subdomain_files:
            if not file.exists():
                continue
            for line in file.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if line and not line.startswith("[skip]"):
                    hosts.add(line)
        merged_hosts.write_text("\n".join(sorted(hosts)) + ("\n" if hosts else ""), encoding="utf-8")
    else:
        merged_hosts.write_text("\n".join(targets) + "\n", encoding="utf-8")

    alive_urls = raw_dir / "alive_urls.txt"
    if "probe" in phases:
        run_cmd(cmd_httpx(merged_hosts), alive_urls)
        print("[main] probe phase completed")

    if "crawl" in phases:
        for target in targets:
            out = raw_dir / f"{target.replace('*', 'wildcard')}.katana.txt"
            run_cmd(cmd_katana(f"https://{target}"), out)
        print("[main] crawl phase completed")

    if "fuzz" in phases:
        wordlist_path = Path(args.wordlist)
        if not wordlist_path.exists():
            print(f"[warn] wordlist not found, skipping fuzz phase: {wordlist_path}")
        else:
            for target in targets:
                out = raw_dir / f"{target.replace('*', 'wildcard')}.ffuf.txt"
                run_cmd(cmd_ffuf(f"https://{target}", args.wordlist), out)
            print("[main] fuzz phase completed")

    if "scan" in phases:
        scan_in = alive_urls if alive_urls.exists() else merged_hosts
        run_cmd(cmd_nuclei(scan_in), raw_dir / "nuclei.txt")
        print("[main] scan phase completed")

    print(f"[main] pipeline completed date={args.date}")


if __name__ == "__main__":
    main()
