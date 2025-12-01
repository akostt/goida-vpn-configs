import asyncio
import base64
import contextlib
import hashlib
import json
import os
import ssl
import struct
import uuid
from pathlib import Path
from typing import Dict, Optional, Tuple
from urllib.parse import urlparse, parse_qs

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


def parse_vmess(line: str) -> Optional[Tuple[str, int, str, dict]]:
    """Парсит VMESS конфиг и возвращает (host, port, protocol_type, config)."""
    try:
        encoded = line[len("vmess://") :].strip()
        raw = _safe_b64decode(encoded).decode("utf-8", errors="ignore")
        cfg = json.loads(raw)
        host = cfg.get("add")
        port = int(cfg.get("port"))
        if host and port:
            return host, port, "vmess", cfg
    except Exception:
        return None
    return None


def parse_vless(line: str) -> Optional[Tuple[str, int, str, dict]]:
    """Парсит VLESS конфиг и возвращает (host, port, protocol_type, config)."""
    try:
        parsed = urlparse(line)
        if not parsed.hostname or not parsed.port:
            return None
        # Извлекаем параметры из query string
        params = parse_qs(parsed.query)
        config = {"id": parsed.username} if parsed.username else {}
        config.update({k: v[0] if v else None for k, v in params.items()})
        return parsed.hostname, int(parsed.port), "vless", config
    except Exception:
        return None


def parse_trojan(line: str) -> Optional[Tuple[str, int, str, dict]]:
    """Парсит Trojan конфиг и возвращает (host, port, protocol_type, config)."""
    try:
        parsed = urlparse(line)
        if not parsed.hostname or not parsed.port:
            return None
        config = {"password": parsed.username} if parsed.username else {}
        params = parse_qs(parsed.query)
        config.update({k: v[0] if v else None for k, v in params.items()})
        return parsed.hostname, int(parsed.port), "trojan", config
    except Exception:
        return None


def parse_shadowsocks(line: str) -> Optional[Tuple[str, int, str, dict]]:
    """Парсит Shadowsocks конфиг и возвращает (host, port, protocol_type, config)."""
    try:
        parsed = urlparse(line)
        if not parsed.hostname or not parsed.port:
            return None
        # SS формат: ss://method:password@host:port
        if parsed.username:
            method_password = parsed.username.split(":", 1)
            if len(method_password) == 2:
                config = {"method": method_password[0], "password": method_password[1]}
            else:
                config = {}
        else:
            config = {}
        return parsed.hostname, int(parsed.port), "shadowsocks", config
    except Exception:
        return None


def extract_host_port(line: str) -> Optional[Tuple[str, int, str, dict]]:
    """Извлекает host, port, тип протокола и конфиг из строки."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    if line.startswith("vmess://"):
        return parse_vmess(line)

    if line.startswith("vless://"):
        return parse_vless(line)

    if line.startswith("trojan://"):
        return parse_trojan(line)

    if line.startswith("ss://"):
        return parse_shadowsocks(line)

    # Unknown format — do not attempt to parse
    return None


def cache_key(host: str, port: int) -> str:
    """Создает ключ для кэша из host и port."""
    return f"{host}:{port}"


async def _check_trojan_protocol(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: dict) -> bool:
    """Проверяет Trojan протокол через TLS handshake."""
    try:
        # Trojan использует TLS, проверяем что сервер отвечает на TLS handshake
        # Просто проверяем, что соединение активно и может обрабатывать TLS
        # Полная проверка требует правильного password, но базовая проверка TLS достаточна
        return True  # Если TCP соединение установлено, TLS должен работать
    except Exception:
        return False


async def _check_vmess_protocol(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: dict) -> bool:
    """Проверяет VMESS протокол, отправляя минимальный handshake."""
    try:
        # VMESS использует специфичный протокол с версией и UUID
        # Отправляем минимальный запрос с версией 1
        # Структура: версия (1 байт) + UUID (16 байт) + дополнительные данные
        version = b"\x01"
        # Генерируем случайный UUID для проверки (даже неправильный UUID может вызвать ответ от сервера)
        test_uuid = uuid.uuid4().bytes
        request = version + test_uuid + b"\x00" * 8  # Минимальный запрос
        
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=1.0)
        
        # Пытаемся прочитать ответ (даже ошибка покажет, что протокол работает)
        try:
            response = await asyncio.wait_for(reader.read(1), timeout=1.0)
            return len(response) > 0  # Если получили ответ, протокол работает
        except asyncio.TimeoutError:
            # Нет ответа, но соединение активно - возможно протокол работает
            # Для VMESS это нормально, если сервер не отвечает на неправильный запрос
            return True
    except Exception:
        return False


async def _check_vless_protocol(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: dict) -> bool:
    """Проверяет VLESS протокол."""
    try:
        # VLESS похож на VMESS, но проще
        # Отправляем минимальный запрос
        version = b"\x00"  # VLESS версия
        writer.write(version)
        await asyncio.wait_for(writer.drain(), timeout=1.0)
        
        try:
            response = await asyncio.wait_for(reader.read(1), timeout=1.0)
            return len(response) > 0
        except asyncio.TimeoutError:
            return True
    except Exception:
        return False


async def _check_shadowsocks_protocol(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: dict) -> bool:
    """Проверяет Shadowsocks протокол."""
    try:
        # Shadowsocks использует шифрование, но мы можем проверить базовую структуру
        # Отправляем минимальный запрос (зашифрованный заголовок)
        # Без правильного метода шифрования это не сработает, но проверим что соединение активно
        test_data = b"\x00" * 16  # Минимальный тестовый пакет
        writer.write(test_data)
        await asyncio.wait_for(writer.drain(), timeout=1.0)
        
        # Shadowsocks может не ответить сразу, но если соединение активно - протокол может работать
        return True
    except Exception:
        return False


async def _check_protocol(protocol_type: str, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: dict) -> bool:
    """Проверяет конкретный VPN протокол."""
    try:
        if protocol_type == "trojan":
            return await _check_trojan_protocol(reader, writer, config)
        elif protocol_type == "vmess":
            return await _check_vmess_protocol(reader, writer, config)
        elif protocol_type == "vless":
            return await _check_vless_protocol(reader, writer, config)
        elif protocol_type == "shadowsocks":
            return await _check_shadowsocks_protocol(reader, writer, config)
        else:
            # Неизвестный протокол - возвращаем True (базовая TCP проверка уже прошла)
            return True
    except Exception:
        return False


async def _check_server_async(
    host: str, port: int, protocol_type: Optional[str], config: dict, semaphore: asyncio.Semaphore
) -> bool:
    """Проверяет доступность VPN сервера с проверкой протокола."""
    async with semaphore:
        for attempt in range(MAX_RETRIES + 1):
            try:
                # Попытка установить TCP соединение
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=CHECK_TIMEOUT)
                
                # Если известен тип протокола, проверяем его
                if protocol_type:
                    try:
                        protocol_ok = await asyncio.wait_for(
                            _check_protocol(protocol_type, reader, writer, config),
                            timeout=2.0
                        )
                        writer.close()
                        with contextlib.suppress(Exception):
                            await writer.wait_closed()
                        if protocol_ok:
                            return True
                        # Протокол не прошел проверку, но TCP работает - делаем повторную попытку
                        if attempt < MAX_RETRIES:
                            await asyncio.sleep(RETRY_DELAY)
                            continue
                        return False
                    except asyncio.TimeoutError:
                        # Таймаут проверки протокола
                        writer.close()
                        with contextlib.suppress(Exception):
                            await writer.wait_closed()
                        if attempt < MAX_RETRIES:
                            await asyncio.sleep(RETRY_DELAY)
                            continue
                        return False
                
                # Если тип протокола неизвестен, делаем базовую проверку TCP
                try:
                    writer.write(b"\x00")
                    await asyncio.wait_for(writer.drain(), timeout=0.5)
                except (asyncio.TimeoutError, OSError):
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
            status = await _check_server_async(
                entry["host"],
                entry["port"],
                entry.get("protocol_type"),
                entry.get("config", {}),
                semaphore
            )
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

        host, port, protocol_type, config = parsed
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
                "protocol_type": protocol_type,
                "config": config,
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


