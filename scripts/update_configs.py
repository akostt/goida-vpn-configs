import base64
import json
import socket
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

import requests


BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "githubmirror"


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


def is_server_alive(host: str, port: int, timeout: int = 3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def filter_config_lines(text: str) -> str:
    result_lines = []
    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")

        parsed = extract_host_port(line)
        if parsed is None:
            # Keep comments, empty lines and unknown formats as-is
            result_lines.append(line)
            continue

        host, port = parsed
        if is_server_alive(host, port):
            result_lines.append(line)
        # If server is down, we simply skip this line (do not add to result)

    return "\n".join(result_lines) + "\n"


def ensure_output_dir() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def main() -> None:
    ensure_output_dir()

    for filename, url in CONFIG_URLS.items():
        try:
            original_text = fetch_text(url)
        except Exception as e:
            # If download fails, skip this file to avoid wiping existing data
            print(f"Failed to download {url}: {e}")
            continue

        filtered_text = filter_config_lines(original_text)

        output_path = OUTPUT_DIR / filename
        output_path.write_text(filtered_text, encoding="utf-8")
        print(f"Updated {output_path}")


if __name__ == "__main__":
    main()


