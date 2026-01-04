"""VPN конфигурации фильтр и валидатор.

Скачивает VPN конфигурации из исходного репозитория, проверяет доступность серверов
и сохраняет только рабочие конфигурации. Также создает специальный файл TM.txt
с отфильтрованными записями из 26.txt, которые соответствуют заданным IP-диапазонам.
Для доменных имён выполняется DNS резолв с последующей проверкой IP адреса.
"""
import asyncio
import base64
import contextlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Protocol, Set, Tuple
from urllib.parse import parse_qs, urlparse

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
    max_concurrency: int = field(default_factory=lambda: int(os.getenv("VPN_CHECK_MAX_CONCURRENCY", "128")))
    check_timeout: float = field(default_factory=lambda: float(os.getenv("VPN_CHECK_TIMEOUT", "2.0")))
    retry_delay: float = field(default_factory=lambda: float(os.getenv("VPN_CHECK_RETRY_DELAY", "0.2")))
    max_retries: int = field(default_factory=lambda: int(os.getenv("VPN_CHECK_MAX_RETRIES", "1")))
    download_timeout: int = field(default_factory=lambda: int(os.getenv("VPN_DOWNLOAD_TIMEOUT", "15")))
    dns_timeout: float = field(default_factory=lambda: float(os.getenv("DNS_RESOLVER_TIMEOUT", "3.0")))
    enable_connectivity_check: bool = field(
        default_factory=lambda: os.getenv("VPN_ENABLE_CONNECTIVITY_CHECK", "true").lower() == "true"
    )
    connectivity_check_timeout: float = field(
        default_factory=lambda: float(os.getenv("VPN_CONNECTIVITY_CHECK_TIMEOUT", "4.0"))
    )
    connectivity_test_url: str = field(
        default_factory=lambda: os.getenv("VPN_CONNECTIVITY_TEST_URL", "http://www.google.com/generate_204")
    )
    v2ray_path: Optional[str] = field(
        default_factory=lambda: os.getenv("V2RAY_PATH") or shutil.which("v2ray") or shutil.which("xray")
    )
    socks_proxy_port_start: int = field(
        default_factory=lambda: int(os.getenv("SOCKS_PROXY_PORT_START", "20000"))
    )
    max_total_time: float = field(
        default_factory=lambda: float(os.getenv("VPN_MAX_TOTAL_TIME", "900.0"))  # 15 минут по умолчанию
    )

    config_urls: Dict[str, str] = field(
        default_factory=lambda: {
            "6.txt": "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/6.txt",
            "22.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/22.txt",
            "24.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/24.txt",
            "25.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/25.txt",
            "26.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
        }
    )

    tm_source_file: str = "26.txt"

    # IP-диапазоны для фильтрации TM.txt
    tm_allowed_ip_patterns: List[str] = field(
        default_factory=lambda: [
            r"51\.250\.",
            r"84\.201\.",
            r"158\.160\.",
            r"89\.208\.",
            r"212\.233\.",
            r"151\.236\.93\."
        ]
    )
    _compiled_patterns: List[re.Pattern] = field(init=False, repr=False)

    def __post_init__(self):
        object.__setattr__(self, "output_dir", self.base_dir / "githubmirror")
        # Компилируем regex паттерны для оптимизации
        compiled = [re.compile(pattern) for pattern in self.tm_allowed_ip_patterns]
        object.__setattr__(self, "_compiled_patterns", compiled)


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

    def __init__(
        self,
        config: AppConfig,
        connectivity_checker: Optional["V2RayConnectivityChecker"] = None,
    ):
        self.config = config
        self.semaphore = asyncio.Semaphore(max(1, config.max_concurrency))
        self.connectivity_checker = connectivity_checker

    async def check_server(self, server_config: ServerConfig) -> bool:
        """Проверяет доступность сервера."""
        async with self.semaphore:
            for attempt in range(self.config.max_retries + 1):
                try:
                    # Сначала проверяем базовое соединение
                    if not await self._check_connection(server_config):
                        if attempt < self.config.max_retries:
                            await asyncio.sleep(self.config.retry_delay)
                        continue

                    # Если включена проверка работоспособности - проверяем через v2ray
                    if self.config.enable_connectivity_check and self.connectivity_checker:
                        if not await self.connectivity_checker.check_connectivity(server_config):
                            logger.debug(f"Connectivity check failed for {server_config.cache_key}")
                            if attempt < self.config.max_retries:
                                await asyncio.sleep(self.config.retry_delay)
                            continue

                    return True
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


class PortManager:
    """Менеджер портов для SOCKS5 прокси."""

    def __init__(self, start_port: int = 20000, max_ports: int = 1000):
        self.start_port = start_port
        self.max_ports = max_ports
        self.used_ports: Set[int] = set()
        self.lock = asyncio.Lock()

    async def get_free_port(self) -> Optional[int]:
        """Получает свободный порт."""
        async with self.lock:
            for port in range(self.start_port, self.start_port + self.max_ports):
                if port not in self.used_ports:
                    if self._is_port_free(port):
                        self.used_ports.add(port)
                        return port
            return None

    async def release_port(self, port: int) -> None:
        """Освобождает порт."""
        async with self.lock:
            self.used_ports.discard(port)

    @staticmethod
    def _is_port_free(port: int) -> bool:
        """Проверяет, свободен ли порт."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return True
        except OSError:
            return False


class V2RayConfigConverter:
    """Конвертер VPN конфигов в формат v2ray."""

    @staticmethod
    def convert_to_v2ray_config(server_config: ServerConfig, local_port: int) -> Dict:
        """Конвертирует VPN конфиг в формат v2ray."""
        config = server_config.config
        protocol_type = server_config.protocol_type

        if protocol_type == ProtocolType.VMESS:
            return V2RayConfigConverter._convert_vmess(config, server_config, local_port)
        elif protocol_type == ProtocolType.VLESS:
            return V2RayConfigConverter._convert_vless(config, server_config, local_port)
        elif protocol_type == ProtocolType.TROJAN:
            return V2RayConfigConverter._convert_trojan(config, server_config, local_port)
        elif protocol_type == ProtocolType.SHADOWSOCKS:
            return V2RayConfigConverter._convert_shadowsocks(config, server_config, local_port)
        else:
            raise ValueError(f"Unsupported protocol: {protocol_type}")

    @staticmethod
    def _convert_vmess(config: Dict, server_config: ServerConfig, local_port: int) -> Dict:
        """Конвертирует VMESS конфиг."""
        # Извлекаем параметры из конфига
        user_id = config.get("id", "")
        alter_id = int(config.get("aid", config.get("alterId", 0)))
        security = config.get("scy", config.get("security", "auto"))
        
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "port": local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True},
                }
            ],
            "outbounds": [
                {
                    "protocol": "vmess",
                    "settings": {
                        "vnext": [
                            {
                                "address": server_config.host,
                                "port": server_config.port,
                                "users": [
                                    {
                                        "id": user_id,
                                        "alterId": alter_id,
                                        "security": security,
                                    }
                                ],
                            }
                        ]
                    },
                    "streamSettings": V2RayConfigConverter._get_stream_settings(config),
                }
            ],
        }

    @staticmethod
    def _convert_vless(config: Dict, server_config: ServerConfig, local_port: int) -> Dict:
        """Конвертирует VLESS конфиг."""
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "port": local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True},
                }
            ],
            "outbounds": [
                {
                    "protocol": "vless",
                    "settings": {
                        "vnext": [
                            {
                                "address": server_config.host,
                                "port": server_config.port,
                                "users": [
                                    {
                                        "id": config.get("id", ""),
                                        "encryption": config.get("encryption", "none"),
                                        "flow": config.get("flow", ""),
                                    }
                                ],
                            }
                        ]
                    },
                    "streamSettings": V2RayConfigConverter._get_stream_settings(config),
                }
            ],
        }

    @staticmethod
    def _convert_trojan(config: Dict, server_config: ServerConfig, local_port: int) -> Dict:
        """Конвертирует Trojan конфиг."""
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "port": local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True},
                }
            ],
            "outbounds": [
                {
                    "protocol": "trojan",
                    "settings": {
                        "servers": [
                            {
                                "address": server_config.host,
                                "port": server_config.port,
                                "password": config.get("password", ""),
                            }
                        ]
                    },
                    "streamSettings": V2RayConfigConverter._get_stream_settings(config),
                }
            ],
        }

    @staticmethod
    def _convert_shadowsocks(config: Dict, server_config: ServerConfig, local_port: int) -> Dict:
        """Конвертирует Shadowsocks конфиг."""
        method = config.get("method", "aes-256-gcm")
        password = config.get("password", "")
        
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {
                    "port": local_port,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {"udp": True},
                }
            ],
            "outbounds": [
                {
                    "protocol": "shadowsocks",
                    "settings": {
                        "servers": [
                            {
                                "address": server_config.host,
                                "port": server_config.port,
                                "method": method,
                                "password": password,
                            }
                        ]
                    },
                }
            ],
        }

    @staticmethod
    def _get_stream_settings(config: Dict) -> Dict:
        """Получает настройки потоков из конфига."""
        network = config.get("net", config.get("network", "tcp"))
        security = config.get("tls", config.get("security", ""))
        stream_settings = {"network": network}

        if network == "ws":
            ws_path = config.get("path", config.get("ws-path", "/"))
            ws_host = config.get("host", config.get("ws-host", ""))
            stream_settings["wsSettings"] = {
                "path": ws_path,
                "headers": {"Host": ws_host} if ws_host else {},
            }
        elif network == "h2":
            h2_host = config.get("host", config.get("h2-host", ""))
            h2_path = config.get("path", config.get("h2-path", "/"))
            stream_settings["httpSettings"] = {
                "host": h2_host.split(",") if h2_host else [],
                "path": h2_path,
            }
        elif network == "grpc":
            grpc_path = config.get("path", config.get("grpc-service-name", ""))
            stream_settings["grpcSettings"] = {
                "serviceName": grpc_path,
            }

        if security == "tls" or security == "reality":
            tls_settings = {"allowInsecure": True}
            sni = config.get("sni", config.get("serverName", ""))
            if sni:
                tls_settings["serverName"] = sni
            if security == "reality":
                tls_settings["reality"] = {
                    "show": False,
                    "dest": sni or config.get("dest", ""),
                    "xver": 0,
                }
            stream_settings["security"] = security
            stream_settings["tlsSettings"] = tls_settings

        return stream_settings


class V2RayConnectivityChecker:
    """Проверка работоспособности VPN через v2ray/xray."""

    def __init__(self, config: AppConfig, port_manager: PortManager):
        self.config = config
        self.port_manager = port_manager
        self.v2ray_path = config.v2ray_path
        if not self.v2ray_path:
            logger.warning("v2ray/xray not found. Connectivity check will be disabled.")
        self._processes: Dict[int, subprocess.Popen] = {}
        self._temp_dirs: Dict[int, Path] = {}

    async def check_connectivity(self, server_config: ServerConfig) -> bool:
        """Проверяет работоспособность VPN через v2ray."""
        if not self.config.enable_connectivity_check or not self.v2ray_path:
            return True

        local_port = await self.port_manager.get_free_port()
        if not local_port:
            logger.warning("No free port available for connectivity check")
            return False

        try:
            return await self._test_vpn_connectivity(server_config, local_port)
        finally:
            await self.port_manager.release_port(local_port)
            await self._cleanup_process(local_port)

    async def _test_vpn_connectivity(self, server_config: ServerConfig, local_port: int) -> bool:
        """Тестирует VPN через v2ray."""
        try:
            # Создаём временный конфиг v2ray
            v2ray_config = V2RayConfigConverter.convert_to_v2ray_config(server_config, local_port)
            config_file = await self._create_temp_config(v2ray_config, local_port)

            # Запускаем v2ray
            process = await self._start_v2ray(config_file, local_port)
            if not process:
                return False

            # Ждём запуска v2ray и проверяем, что процесс не упал
            await asyncio.sleep(0.5)
            if process.poll() is not None:
                logger.debug(f"v2ray process exited early for {server_config.cache_key}")
                return False

            # Проверяем через SOCKS5 прокси
            success = await self._test_http_via_socks5(local_port)

            return success
        except Exception as e:
            logger.debug(f"VPN connectivity test failed for {server_config.cache_key}: {e}")
            return False

    async def _create_temp_config(self, config: Dict, port: int) -> Path:
        """Создаёт временный конфиг файл."""
        temp_dir = Path(tempfile.mkdtemp(prefix="v2ray_check_"))
        self._temp_dirs[port] = temp_dir
        config_file = temp_dir / "config.json"
        config_file.write_text(json.dumps(config, indent=2), encoding="utf-8")
        return config_file

    async def _start_v2ray(self, config_file: Path, port: int) -> Optional[subprocess.Popen]:
        """Запускает v2ray процесс."""
        try:
            # Проверяем, что v2ray доступен
            if not self.v2ray_path or not os.path.exists(self.v2ray_path):
                logger.debug("v2ray/xray binary not found")
                return None

            process = subprocess.Popen(
                [self.v2ray_path, "run", "-config", str(config_file)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            self._processes[port] = process
            return process
        except Exception as e:
            logger.debug(f"Failed to start v2ray: {e}")
            return None

    async def _test_http_via_socks5(self, port: int) -> bool:
        """Тестирует HTTP запрос через SOCKS5 прокси."""
        try:
            # Используем requests с SOCKS5 прокси (требует PySocks)
            proxies = {"http": f"socks5://127.0.0.1:{port}", "https": f"socks5://127.0.0.1:{port}"}
            # Используем короткий таймаут для быстрой проверки
            timeout = min(self.config.connectivity_check_timeout, 3.0)
            response = requests.get(
                self.config.connectivity_test_url,
                proxies=proxies,
                timeout=timeout,
                allow_redirects=False,
            )
            return response.status_code in (200, 204, 301, 302, 307, 308)
        except Exception as e:
            logger.debug(f"HTTP test via SOCKS5 failed: {e}")
            return False

    async def _cleanup_process(self, port: int) -> None:
        """Очищает процесс и временные файлы."""
        if port in self._processes:
            process = self._processes.pop(port)
            try:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
            except Exception:
                pass

        if port in self._temp_dirs:
            temp_dir = self._temp_dirs.pop(port)
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass


class DNSResolver:
    """Асинхронный резолвер DNS с кэшированием."""

    def __init__(self, timeout: float = 3.0, max_workers: int = 10):
        self.timeout = timeout
        self._cache: Dict[str, Optional[str]] = {}
        self._executor: Optional[ThreadPoolExecutor] = ThreadPoolExecutor(
            max_workers=max_workers, thread_name_prefix="dns_resolver"
        )

    async def resolve(self, hostname: str) -> Optional[str]:
        """Резолвит доменное имя в IP адрес."""
        if hostname in self._cache:
            return self._cache[hostname]

        if not self._executor:
            return None

        try:
            loop = asyncio.get_event_loop()
            ip = await asyncio.wait_for(
                loop.run_in_executor(self._executor, self._resolve_sync, hostname),
                timeout=self.timeout,
            )
            self._cache[hostname] = ip
            return ip
        except (asyncio.TimeoutError, OSError, socket.gaierror) as e:
            logger.debug(f"DNS resolution failed for {hostname}: {e}")
            self._cache[hostname] = None
            return None

    @staticmethod
    def _resolve_sync(hostname: str) -> Optional[str]:
        """Синхронный DNS резолв."""
        try:
            return socket.gethostbyname(hostname)
        except (OSError, socket.gaierror):
            return None

    @staticmethod
    def is_ip_address(host: str) -> bool:
        """Проверяет, является ли строка IP адресом."""
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def close(self) -> None:
        """Закрывает executor."""
        if self._executor:
            self._executor.shutdown(wait=False)
            self._executor = None

    async def __aenter__(self):
        """Асинхронный context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Асинхронный context manager exit."""
        self.close()


class ConfigFilter:
    """Класс для фильтрации конфигураций."""

    def __init__(
        self,
        config: AppConfig,
        parser_registry: ConfigParserRegistry,
        server_checker: ServerChecker,
        dns_resolver: DNSResolver,
    ):
        self.config = config
        self.parser_registry = parser_registry
        self.server_checker = server_checker
        self.dns_resolver = dns_resolver
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
                    if await self._should_add_to_tm(server_config):
                        tm_lines.append(line)
                continue

            to_check.append((idx, server_config))

        # Проверяем серверы параллельно с ограничением на количество одновременных задач
        if to_check:
            # Ограничиваем количество одновременных проверок для оптимизации
            semaphore = asyncio.Semaphore(self.config.max_concurrency)
            
            async def check_with_semaphore(idx: int, server_config: ServerConfig):
                async with semaphore:
                    return await self._check_and_update(idx, server_config, kept_lines, tm_lines)
            
            tasks = [
                check_with_semaphore(idx, server_config)
                for idx, server_config in to_check
            ]
            await asyncio.gather(*tasks)

        filtered = [line for line in kept_lines if line is not None]
        return filtered, tm_lines

    async def _check_and_update(
        self,
        idx: int,
        server_config: ServerConfig,
        kept_lines: List[Optional[str]],
        tm_lines: List[str],
    ):
        """Проверяет сервер и обновляет результаты."""
        is_alive = await self.server_checker.check_server(server_config)
        self.session_cache[server_config.cache_key] = is_alive

        if is_alive:
            kept_lines[idx] = server_config.original_line
            if await self._should_add_to_tm(server_config):
                tm_lines.append(server_config.original_line)

    async def _should_add_to_tm(self, server_config: ServerConfig) -> bool:
        """Проверяет, соответствует ли сервер критериям для TM.txt.
        
        Критерий: IP-адрес (или IP адрес доменного имени) входит в доверенный пул.
        """
        host = server_config.host

        # Если это IP адрес - проверяем напрямую
        if DNSResolver.is_ip_address(host):
            return self._matches_ip_patterns(host)

        # Если это доменное имя - резолвим и проверяем IP
        resolved_ip = await self.dns_resolver.resolve(host)
        if resolved_ip:
            return self._matches_ip_patterns(resolved_ip)

        return False

    def _matches_ip_patterns(self, ip: str) -> bool:
        """Проверяет, соответствует ли IP адрес паттернам."""
        return any(pattern.search(ip) for pattern in self.config._compiled_patterns)


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
        self.port_manager = PortManager(start_port=config.socks_proxy_port_start)
        self.connectivity_checker = (
            V2RayConnectivityChecker(config, self.port_manager)
            if config.enable_connectivity_check
            else None
        )
        self.server_checker = ServerChecker(config, self.connectivity_checker)
        self.downloader = ConfigDownloader(config)
        self.dns_resolver = DNSResolver(timeout=config.dns_timeout)
        self.filter = ConfigFilter(config, self.parser_registry, self.server_checker, self.dns_resolver)

    async def process_all(self) -> None:
        """Обрабатывает все конфигурации."""
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        tm_lines: List[str] = []

        try:
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
        finally:
            self.dns_resolver.close()

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
    start_time = time.time()
    config = AppConfig()
    processor = ConfigProcessor(config)
    
    try:
        # Запускаем с таймаутом
        await asyncio.wait_for(processor.process_all(), timeout=config.max_total_time)
        elapsed = time.time() - start_time
        logger.info(f"Process completed in {elapsed:.2f} seconds")
    except asyncio.TimeoutError:
        elapsed = time.time() - start_time
        logger.error(f"Process exceeded maximum time limit of {config.max_total_time} seconds (elapsed: {elapsed:.2f}s)")
        raise


def main() -> None:
    """Точка входа в приложение."""
    asyncio.run(main_async())


if __name__ == "__main__":
    main()
