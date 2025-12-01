import asyncio
import base64
import contextlib
import json
import os
import time
from pathlib import Path
from typing import Dict, Optional, Tuple, TypedDict
from urllib.parse import urlparse

import requests


class CacheEntry(TypedDict):
    status: bool
    checked_at: float


CacheStore = Dict[str, CacheEntry]


BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "githubmirror"
CACHE_DIR = BASE_DIR / ".cache"
CACHE_FILE = CACHE_DIR / "server_status.json"

MAX_CONCURRENCY = int(os.getenv("VPN_CHECK_MAX_CONCURRENCY", "256"))
CHECK_TIMEOUT = float(os.getenv("VPN_CHECK_TIMEOUT", "1.5"))
CACHE_TTL_SUCCESS = int(os.getenv("VPN_CACHE_TTL_SUCCESS", "3600"))
CACHE_TTL_FAILURE = int(os.getenv("VPN_CACHE_TTL_FAILURE", "900"))


CONFIG_URLS = {
    "6.txt": "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/6.txt",
    "22.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/22.txt",
    "23.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/23.txt",
    "24.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/24.txt",
    "25.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/25.txt",
    "26.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
}


def fetch_text(url: str, timeout: int = 15) -> str:
    resp = requests.get(url, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def _safe_b64decode(data: str) -> bytes:
    # add padding if required
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def parse_vmess(line: str) -> Optional[Tuple[str, int]]:
    try:
        encoded = line[len("vmess://") :].strip()
        raw = _safe_b64decode(encoded).decode("utf-8", errors="ignore")
        cfg = json.loads(raw)
        host = cfg.get("add")
        port = int(cfg.get("port"))
        if host and port:
            return host, port
    except Exception:
        return None
    return None


def parse_url_like(line: str) -> Optional[Tuple[str, int]]:
    """Parse URL-like configs: vless://, trojan://, ss:// (host:port part)."""
    try:
        parsed = urlparse(line)
        if not parsed.hostname or not parsed.port:
            # try to recover from manually added scheme-less forms
            return None
        return parsed.hostname, int(parsed.port)
    except Exception:
        return None


def extract_host_port(line: str) -> Optional[Tuple[str, int]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if line.startswith("vmess://"):
        return parse_vmess(line)

    if line.startswith(("vless://", "trojan://", "ss://")):
        return parse_url_like(line)

    # Unknown format — do not attempt to parse
    return None


def load_cache() -> CacheStore:
    if CACHE_FILE.exists():
        with CACHE_FILE.open("r", encoding="utf-8") as fh:
            try:
                data = json.load(fh)
                return {
                    str(k): CacheEntry(
                        status=bool(v["status"]),
                        checked_at=float(v["checked_at"]),
                    )
                    for k, v in data.items()
                }
            except Exception:
                return {}
    return {}


def save_cache(cache: CacheStore) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with CACHE_FILE.open("w", encoding="utf-8") as fh:
        json.dump(cache, fh)


def cache_key(host: str, port: int) -> str:
    return f"{host}:{port}"


def cache_entry_valid(entry: CacheEntry) -> bool:
    ttl = CACHE_TTL_SUCCESS if entry["status"] else CACHE_TTL_FAILURE
    return (time.time() - entry["checked_at"]) <= ttl


async def _check_server_async(host: str, port: int, semaphore: asyncio.Semaphore) -> bool:
    async with semaphore:
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=CHECK_TIMEOUT)
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
            return True
        except Exception:
            return False


async def run_checks(entries):
    if not entries:
        return []

    semaphore = asyncio.Semaphore(max(1, min(MAX_CONCURRENCY, len(entries))))

    async def runner(entry):
        try:
            status = await _check_server_async(entry["host"], entry["port"], semaphore)
        except Exception:
            status = False
        return entry, status

    tasks = [asyncio.create_task(runner(entry)) for entry in entries]
    results = []
    for task in asyncio.as_completed(tasks):
        results.append(await task)
    return results


def filter_config_lines(text: str, cache: CacheStore) -> str:
    lines = [raw.rstrip("\n") for raw in text.splitlines()]
    kept_lines: list[Optional[str]] = [None] * len(lines)
    to_check = []

    for idx, line in enumerate(lines):
        parsed = extract_host_port(line)
        if parsed is None:
            kept_lines[idx] = line
            continue

        host, port = parsed
        key = cache_key(host, port)
        cached_entry = cache.get(key)

        if cached_entry and cache_entry_valid(cached_entry):
            if cached_entry["status"]:
                kept_lines[idx] = line
            continue

        to_check.append(
            {
                "idx": idx,
                "line": line,
                "host": host,
                "port": port,
                "key": key,
            }
        )

    if to_check:
        loop_results = asyncio.run(run_checks(to_check))

        now = time.time()
        for entry, alive in loop_results:
            cache[entry["key"]] = {"status": alive, "checked_at": now}
            if alive:
                kept_lines[entry["idx"]] = entry["line"]

    filtered = [line for line in kept_lines if line is not None]
    return "\n".join(filtered) + ("\n" if filtered else "")


def ensure_output_dir() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def main() -> None:
    ensure_output_dir()
    cache = load_cache()

    for filename, url in CONFIG_URLS.items():
        try:
            original_text = fetch_text(url)
        except Exception as e:
            # If download fails, skip this file to avoid wiping existing data
            print(f"Failed to download {url}: {e}")
            continue

        filtered_text = filter_config_lines(original_text, cache)

        output_path = OUTPUT_DIR / filename
        output_path.write_text(filtered_text, encoding="utf-8")
        print(f"Updated {output_path}")

    save_cache(cache)


if __name__ == "__main__":
    main()


