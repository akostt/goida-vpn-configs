import asyncio
import base64
import contextlib
import json
import os
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse

import requests


BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "githubmirror"

MAX_CONCURRENCY = int(os.getenv("VPN_CHECK_MAX_CONCURRENCY", "256"))
CHECK_TIMEOUT = float(os.getenv("VPN_CHECK_TIMEOUT", "2.5"))
RETRY_DELAY = float(os.getenv("VPN_CHECK_RETRY_DELAY", "0.3"))
MAX_RETRIES = int(os.getenv("VPN_CHECK_MAX_RETRIES", "1"))


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


def cache_key(host: str, port: int) -> str:
    """Создает ключ для кэша из host и port."""
    return f"{host}:{port}"


async def _check_server_async(host: str, port: int, semaphore: asyncio.Semaphore) -> bool:
    """Проверяет доступность VPN сервера с повторными попытками и улучшенной обработкой ошибок."""
    async with semaphore:
        for attempt in range(MAX_RETRIES + 1):
            try:
                # Попытка установить TCP соединение
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=CHECK_TIMEOUT)
                
                # Дополнительная проверка: отправляем минимальный байт и проверяем, что соединение активно
                # Это помогает отфильтровать серверы, которые принимают соединение, но не отвечают
                try:
                    writer.write(b"\x00")
                    await asyncio.wait_for(writer.drain(), timeout=0.5)
                except (asyncio.TimeoutError, OSError):
                    # Если не можем отправить данные, сервер скорее всего не работает
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()
                    if attempt < MAX_RETRIES:
                        await asyncio.sleep(RETRY_DELAY)
                        continue
                    return False
                
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
                return True
                
            except asyncio.TimeoutError:
                # Для timeout делаем повторную попытку
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_DELAY)
                    continue
                return False
                
            except (ConnectionRefusedError, OSError):
                # Connection refused - сервер точно не работает, не делаем повторные попытки
                return False
                
            except Exception:
                # Для других ошибок делаем повторную попытку
                if attempt < MAX_RETRIES:
                    await asyncio.sleep(RETRY_DELAY)
                    continue
                return False
        
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


def filter_config_lines(text: str, session_cache: Dict[str, bool]) -> str:
    """
    Фильтрует конфигурационные строки, проверяя доступность серверов.
    session_cache - простой dict для хранения результатов проверки в рамках одного запуска.
    """
    lines = [raw.rstrip("\n") for raw in text.splitlines()]
    kept_lines: list[Optional[str]] = [None] * len(lines)
    to_check = []

    for idx, line in enumerate(lines):
        parsed = extract_host_port(line)
        if parsed is None:
            # Не VPN конфиг - оставляем как есть
            kept_lines[idx] = line
            continue

        host, port = parsed
        key = cache_key(host, port)
        
        # Проверяем, был ли этот сервер уже проверен в этом запуске
        if key in session_cache:
            if session_cache[key]:
                kept_lines[idx] = line
            # Если False - просто пропускаем (не добавляем в список)
            continue

        # Сервер еще не проверялся - добавляем в очередь проверки
        to_check.append(
            {
                "idx": idx,
                "line": line,
                "host": host,
                "port": port,
                "key": key,
            }
        )

    # Проверяем все серверы, которые еще не были проверены
    if to_check:
        loop_results = asyncio.run(run_checks(to_check))

        for entry, alive in loop_results:
            # Сохраняем результат в кэш сессии
            session_cache[entry["key"]] = alive
            if alive:
                kept_lines[entry["idx"]] = entry["line"]

    filtered = [line for line in kept_lines if line is not None]
    return "\n".join(filtered) + ("\n" if filtered else "")


def ensure_output_dir() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def main() -> None:
    ensure_output_dir()
    # Простой in-memory кэш для хранения результатов проверки в рамках одного запуска
    # Ключ: "host:port", значение: bool (True = сервер работает, False = не работает)
    session_cache: Dict[str, bool] = {}

    for filename, url in CONFIG_URLS.items():
        try:
            original_text = fetch_text(url)
        except Exception as e:
            # If download fails, skip this file to avoid wiping existing data
            print(f"Failed to download {url}: {e}")
            continue

        filtered_text = filter_config_lines(original_text, session_cache)

        output_path = OUTPUT_DIR / filename
        output_path.write_text(filtered_text, encoding="utf-8")
        print(f"Updated {output_path}")


if __name__ == "__main__":
    main()


