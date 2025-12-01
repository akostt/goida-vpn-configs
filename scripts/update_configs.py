"""VPN конфигурации фильтр и валидатор.

Скачивает VPN конфигурации из исходного репозитория, проверяет доступность серверов
и сохраняет только рабочие конфигурации. Также создает специальный файл TM.txt
с отфильтрованными записями из 26.txt.
"""
import asyncio
import base64
import contextlib
import json
import logging
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Callable, Dict, List, Optional, Protocol, Tuple
from urllib.parse import parse_qs, unquote, urlparse

import requests

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class ProtocolType(Enum):
    """Типы VPN протоколов."""

    VMESS = "vmess"
    VLESS = "vless"
    TROJAN = "trojan"
    SHADOWSOCKS = "shadowsocks"


@dataclass(frozen=True)
class AppConfig:
    """Конфигурация приложения."""

    base_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    output_dir: Path = field(init=False)
    max_concurrency: int = field(default_factory=lambda: int(os.getenv("VPN_CHECK_MAX_CONCURRENCY", "256")))
    check_timeout: float = field(default_factory=lambda: float(os.getenv("VPN_CHECK_TIMEOUT", "2.5")))
    retry_delay: float = field(default_factory=lambda: float(os.getenv("VPN_CHECK_RETRY_DELAY", "0.3")))
    max_retries: int = field(default_factory=lambda: int(os.getenv("VPN_CHECK_MAX_RETRIES", "1")))
    download_timeout: int = field(default_factory=lambda: int(os.getenv("VPN_DOWNLOAD_TIMEOUT", "15")))

    config_urls: Dict[str, str] = field(
        default_factory=lambda: {
            "6.txt": "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/6.txt",
            "22.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/22.txt",
            "23.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/23.txt",
            "24.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/24.txt",
            "25.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/25.txt",
            "26.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
        }
    )

    tm_filter_prefixes: List[str] = field(
        default_factory=lambda: [
            "Finland — ",
            "] [vl-re",
            "Aeza Group LLC — ",
            "Yandex — ",
            "JSC Selectel —",
            "Saint-Petersburg ",
            "Poland — ",
            "Channel id: @ShadowProxy66",
            "Germany — ",
            "Poland — ",
            "Эстония(Мегафон, T2, Yota-4"
        ]
    )

    tm_source_file: str = "26.txt"

    def __post_init__(self):
        object.__setattr__(self, "output_dir", self.base_dir / "githubmirror")


@dataclass(frozen=True)
class ServerConfig:
    """Конфигурация VPN сервера."""

    host: str
    port: int
    protocol_type: ProtocolType
    config: Dict
    original_line: str

    def __post_init__(self):
        """Валидация конфигурации."""
        if not self.host or not (1 <= self.port <= 65535):
            raise ValueError(f"Invalid server config: host={self.host}, port={self.port}")

    @property
    def cache_key(self) -> str:
        """Ключ для кэширования."""
        return f"{self.host}:{self.port}"


class ConfigParser(ABC):
    """Абстрактный парсер конфигураций."""

    @abstractmethod
    def can_parse(self, line: str) -> bool:
        """Проверяет, может ли парсер обработать строку."""
        pass

    @abstractmethod
    def parse(self, line: str) -> Optional[ServerConfig]:
        """Парсит строку в конфигурацию сервера."""
        pass


class VMessParser(ConfigParser):
    """Парсер VMESS конфигураций."""

    def can_parse(self, line: str) -> bool:
        return line.strip().startswith("vmess://")

    def parse(self, line: str) -> Optional[ServerConfig]:
        try:
            encoded = line[len("vmess://") :].strip()
            raw = self._safe_b64decode(encoded).decode("utf-8", errors="ignore")
            cfg = json.loads(raw)
            host = cfg.get("add")
            port = int(cfg.get("port", 0))
            if host and port:
                return ServerConfig(host, port, ProtocolType.VMESS, cfg, line)
        except (ValueError, KeyError, json.JSONDecodeError) as e:
            logger.debug(f"Failed to parse VMESS config: {e}")
        return None

    @staticmethod
    def _safe_b64decode(data: str) -> bytes:
        padding = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)


class VLessParser(ConfigParser):
    """Парсер VLESS конфигураций."""

    def can_parse(self, line: str) -> bool:
        return line.strip().startswith("vless://")

    def parse(self, line: str) -> Optional[ServerConfig]:
        try:
            parsed = urlparse(line)
            if not parsed.hostname or not parsed.port:
                return None
            params = parse_qs(parsed.query)
            config = {"id": parsed.username} if parsed.username else {}
            config.update({k: v[0] if v else None for k, v in params.items()})
            return ServerConfig(parsed.hostname, int(parsed.port), ProtocolType.VLESS, config, line)
        except (ValueError, AttributeError) as e:
            logger.debug(f"Failed to parse VLESS config: {e}")
        return None


class TrojanParser(ConfigParser):
    """Парсер Trojan конфигураций."""

    def can_parse(self, line: str) -> bool:
        return line.strip().startswith("trojan://")

    def parse(self, line: str) -> Optional[ServerConfig]:
        try:
            parsed = urlparse(line)
            if not parsed.hostname or not parsed.port:
                return None
            config = {"password": parsed.username} if parsed.username else {}
            params = parse_qs(parsed.query)
            config.update({k: v[0] if v else None for k, v in params.items()})
            return ServerConfig(parsed.hostname, int(parsed.port), ProtocolType.TROJAN, config, line)
        except (ValueError, AttributeError) as e:
            logger.debug(f"Failed to parse Trojan config: {e}")
        return None


class ShadowsocksParser(ConfigParser):
    """Парсер Shadowsocks конфигураций."""

    def can_parse(self, line: str) -> bool:
        return line.strip().startswith("ss://")

    def parse(self, line: str) -> Optional[ServerConfig]:
        try:
            parsed = urlparse(line)
            if not parsed.hostname or not parsed.port:
                return None
            config = {}
            if parsed.username:
                method_password = parsed.username.split(":", 1)
                if len(method_password) == 2:
                    config = {"method": method_password[0], "password": method_password[1]}
            return ServerConfig(parsed.hostname, int(parsed.port), ProtocolType.SHADOWSOCKS, config, line)
        except (ValueError, AttributeError) as e:
            logger.debug(f"Failed to parse Shadowsocks config: {e}")
        return None


class ConfigParserRegistry:
    """Реестр парсеров конфигураций."""

    def __init__(self):
        self._parsers: List[ConfigParser] = [
            VMessParser(),
            VLessParser(),
            TrojanParser(),
            ShadowsocksParser(),
        ]

    def parse(self, line: str) -> Optional[ServerConfig]:
        """Парсит строку используя подходящий парсер."""
        line = line.strip()
        if not line or line.startswith("#"):
            return None

        for parser in self._parsers:
            if parser.can_parse(line):
                return parser.parse(line)
        return None


class ProtocolChecker(Protocol):
    """Протокол для проверки VPN протоколов."""

    async def __call__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: Dict
    ) -> bool:
        ...


class TrojanProtocolChecker:
    """Проверка Trojan протокола."""

    async def __call__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: Dict
    ) -> bool:
        return True  # TLS поверх TCP уже установлен


class VMessProtocolChecker:
    """Проверка VMESS протокола."""

    async def __call__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: Dict
    ) -> bool:
        try:
            version = b"\x01"
            test_uuid = uuid.uuid4().bytes
            request = version + test_uuid + b"\x00" * 8

            writer.write(request)
            await asyncio.wait_for(writer.drain(), timeout=1.0)

            try:
                response = await asyncio.wait_for(reader.read(1), timeout=1.0)
                return len(response) > 0
            except asyncio.TimeoutError:
                return True
        except Exception:
            return False


class VLessProtocolChecker:
    """Проверка VLESS протокола."""

    async def __call__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: Dict
    ) -> bool:
        try:
            version = b"\x00"
            writer.write(version)
            await asyncio.wait_for(writer.drain(), timeout=1.0)

            try:
                response = await asyncio.wait_for(reader.read(1), timeout=1.0)
                return len(response) > 0
            except asyncio.TimeoutError:
                return True
        except Exception:
            return False


class ShadowsocksProtocolChecker:
    """Проверка Shadowsocks протокола."""

    async def __call__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, config: Dict
    ) -> bool:
        try:
            test_data = b"\x00" * 16
            writer.write(test_data)
            await asyncio.wait_for(writer.drain(), timeout=1.0)
            return True
        except Exception:
            return False


class ProtocolCheckerFactory:
    """Фабрика для создания проверщиков протоколов."""

    _checkers: Dict[ProtocolType, ProtocolChecker] = {
        ProtocolType.TROJAN: TrojanProtocolChecker(),
        ProtocolType.VMESS: VMessProtocolChecker(),
        ProtocolType.VLESS: VLessProtocolChecker(),
        ProtocolType.SHADOWSOCKS: ShadowsocksProtocolChecker(),
    }

    @classmethod
    def get_checker(cls, protocol_type: ProtocolType) -> Optional[ProtocolChecker]:
        """Возвращает проверщик для указанного протокола."""
        return cls._checkers.get(protocol_type)


class ServerChecker:
    """Класс для проверки доступности VPN серверов."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.semaphore = asyncio.Semaphore(max(1, config.max_concurrency))

    async def check_server(self, server_config: ServerConfig) -> bool:
        """Проверяет доступность сервера."""
        async with self.semaphore:
            for attempt in range(self.config.max_retries + 1):
                try:
                    if await self._check_connection(server_config):
                        return True
                    if attempt < self.config.max_retries:
                        await asyncio.sleep(self.config.retry_delay)
                except (ConnectionRefusedError, OSError):
                    return False
                except Exception as e:
                    logger.debug(f"Error checking server {server_config.cache_key}: {e}")
                    if attempt < self.config.max_retries:
                        await asyncio.sleep(self.config.retry_delay)
            return False

    async def _check_connection(self, server_config: ServerConfig) -> bool:
        """Проверяет соединение с сервером."""
        try:
            conn = asyncio.open_connection(server_config.host, server_config.port)
            reader, writer = await asyncio.wait_for(conn, timeout=self.config.check_timeout)

            try:
                if await self._check_protocol(server_config, reader, writer):
                    return True
            finally:
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()
        except asyncio.TimeoutError:
            return False
        return False

    async def _check_protocol(
        self, server_config: ServerConfig, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> bool:
        """Проверяет протокол сервера."""
        checker = ProtocolCheckerFactory.get_checker(server_config.protocol_type)
        if checker:
            try:
                return await asyncio.wait_for(
                    checker(reader, writer, server_config.config), timeout=2.0
                )
            except asyncio.TimeoutError:
                return False

        # Базовая TCP проверка для неизвестных протоколов
        try:
            writer.write(b"\x00")
            await asyncio.wait_for(writer.drain(), timeout=0.5)
            return True
        except (asyncio.TimeoutError, OSError):
            return False


class ConfigFilter:
    """Класс для фильтрации конфигураций."""

    def __init__(self, config: AppConfig, parser_registry: ConfigParserRegistry, server_checker: ServerChecker):
        self.config = config
        self.parser_registry = parser_registry
        self.server_checker = server_checker
        self.session_cache: Dict[str, bool] = {}

    async def filter_lines(self, lines: List[str]) -> Tuple[List[str], List[str]]:
        """
        Фильтрует строки конфигурации.

        Returns:
            Tuple[List[str], List[str]]: (отфильтрованные строки, строки для TM.txt)
        """
        kept_lines: List[Optional[str]] = [None] * len(lines)
        tm_lines: List[str] = []
        to_check: List[Tuple[int, ServerConfig]] = []

        for idx, line in enumerate(lines):
            server_config = self.parser_registry.parse(line)
            if server_config is None:
                kept_lines[idx] = line
                continue

            # Проверяем кэш
            if server_config.cache_key in self.session_cache:
                if self.session_cache[server_config.cache_key]:
                    kept_lines[idx] = line
                    if self._should_add_to_tm(line):
                        tm_lines.append(line)
                continue

            to_check.append((idx, server_config))

        # Проверяем серверы параллельно
        if to_check:
            tasks = [
                self._check_and_update(idx, server_config, kept_lines, tm_lines)
                for idx, server_config in to_check
            ]
            await asyncio.gather(*tasks)

        filtered = [line for line in kept_lines if line is not None]
        return filtered, tm_lines

    async def _check_and_update(
        self, idx: int, server_config: ServerConfig, kept_lines: List[Optional[str]], tm_lines: List[str]
    ):
        """Проверяет сервер и обновляет результаты."""
        is_alive = await self.server_checker.check_server(server_config)
        self.session_cache[server_config.cache_key] = is_alive

        if is_alive:
            kept_lines[idx] = server_config.original_line
            if self._should_add_to_tm(server_config.original_line):
                tm_lines.append(server_config.original_line)

    def _should_add_to_tm(self, line: str) -> bool:
        """Проверяет, нужно ли добавить строку в TM.txt.
        
        Учитывает как обычные строки, так и URL-encoded версии.
        """
        # Проверяем оригинальную строку
        if any(prefix in line for prefix in self.config.tm_filter_prefixes):
            return True
        
        # Декодируем URL-encoded строку и проверяем снова
        try:
            decoded_line = unquote(line, encoding='utf-8')
            return any(prefix in decoded_line for prefix in self.config.tm_filter_prefixes)
        except Exception:
            # Если декодирование не удалось, возвращаем результат проверки оригинальной строки
            return False


class ConfigDownloader:
    """Класс для скачивания конфигураций."""

    def __init__(self, config: AppConfig):
        self.config = config

    def download(self, url: str) -> str:
        """Скачивает конфигурацию по URL."""
        try:
            response = requests.get(url, timeout=self.config.download_timeout)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            logger.error(f"Failed to download {url}: {e}")
            raise


class ConfigProcessor:
    """Основной класс для обработки конфигураций."""

    def __init__(self, config: AppConfig):
        self.config = config
        self.parser_registry = ConfigParserRegistry()
        self.server_checker = ServerChecker(config)
        self.downloader = ConfigDownloader(config)
        self.filter = ConfigFilter(config, self.parser_registry, self.server_checker)

    async def process_all(self) -> None:
        """Обрабатывает все конфигурации."""
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        tm_lines: List[str] = []

        for filename, url in self.config.config_urls.items():
            try:
                original_text = self.downloader.download(url)
                lines = [line.rstrip("\n") for line in original_text.splitlines()]

                filtered_lines, file_tm_lines = await self.filter.filter_lines(lines)

                # Собираем записи для TM.txt только из указанного файла
                if filename == self.config.tm_source_file:
                    tm_lines.extend(file_tm_lines)

                output_path = self.config.output_dir / filename
                output_text = "\n".join(filtered_lines) + ("\n" if filtered_lines else "")
                output_path.write_text(output_text, encoding="utf-8")
                logger.info(f"Updated {output_path} ({len(filtered_lines)} lines)")

            except requests.RequestException:
                logger.warning(f"Skipping {filename} due to download error")
                continue

        # Создаем TM.txt
        self._create_tm_file(tm_lines)

    def _create_tm_file(self, tm_lines: List[str]) -> None:
        """Создает файл TM.txt."""
        if tm_lines:
            tm_path = self.config.output_dir / "TM.txt"
            tm_content = "\n".join(tm_lines) + "\n"
            tm_path.write_text(tm_content, encoding="utf-8")
            logger.info(f"Created {tm_path} ({len(tm_lines)} lines)")
        else:
            logger.info("No entries for TM.txt")


async def main_async() -> None:
    """Асинхронная основная функция."""
    config = AppConfig()
    processor = ConfigProcessor(config)
    await processor.process_all()


def main() -> None:
    """Точка входа в приложение."""
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
