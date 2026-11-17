#!/usr/bin/env python3.11

"""VPN Gate OpenVPN 节点抓取与转换。

供 main.py 的 mihomo / sing-box 转换器按需注入 OpenVPN 节点：

    nodes = fetch_openvpn_proxies(api_url, countries, limit, sort_mode)
    # mihomo：to_mihomo_proxy(node) 转 type=openvpn 节点
    # sing-box：to_singbox_endpoint(node, tag, detour) 转 endpoint

抓取、解析、筛选、命名全部共用，fetch_openvpn_proxies 返回中性节点；
只有最后一步由 to_mihomo_proxy / to_singbox_endpoint 按目标格式渲染。
"""

from __future__ import annotations

import base64
import binascii
import csv
import os
import re
import socket
import time
import urllib.request
from collections.abc import Iterable
from typing import Any

DEFAULT_API_URL = "https://www.vpngate.net/api/iphone/"
# 单份订阅里 OpenVPN 节点的数量上限（用户自定，默认 10）；总数上限 MAX_TOTAL_NODES 在 main.py
MAX_OPENVPN_NODES = 100

INLINE_BLOCK_TAGS = {
    "ca",
    "cert",
    "key",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "dh",
    "secret",
}

COMMON_LOCAL_PROXY_PORTS = (10808, 10801, 7890, 7897, 2080, 10809, 1080, 8080, 8889)

ENV_PROXY_VARS = (
    "HTTPS_PROXY",
    "https_proxy",
    "HTTP_PROXY",
    "http_proxy",
    # "ALL_PROXY",
    # "all_proxy",
)


def find_local_proxy(
    ports: Iterable[int] = COMMON_LOCAL_PROXY_PORTS,
) -> str | None:
    """探测本机常见 HTTP/mixed 代理端口，返回 http://127.0.0.1:port。"""
    for port in ports:
        try:
            with socket.create_connection(("127.0.0.1", int(port)), timeout=0.4):
                return f"http://127.0.0.1:{int(port)}"
        except OSError:
            continue
    return None


def proxy_candidates(explicit: str | None) -> list[str | None]:
    """抓取候选顺序：显式代理只试它；否则 环境变量代理 → 本机端口探测 → 直连。"""
    if explicit:
        return [explicit if "://" in explicit else "http://" + explicit]

    candidates: list[str | None] = []
    for name in ENV_PROXY_VARS:
        value = os.environ.get(name)
        if value and "://" in value and value not in candidates:
            candidates.append(value)

    detected = find_local_proxy()
    if detected and detected not in candidates:
        candidates.append(detected)
    candidates.append(None)
    return candidates


def http_get(url: str, proxy: str | None, timeout: float, retries: int) -> bytes:
    """带重试的 HTTP GET；显式禁用环境代理，避免坏代理导致静默失败。"""
    handlers: list[urllib.request.BaseHandler] = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        handlers.append(urllib.request.ProxyHandler({}))
    opener = urllib.request.build_opener(*handlers)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0 Safari/537.36"
        ),
        "Accept": "text/plain,*/*",
    }

    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        request = urllib.request.Request(url, headers=headers)
        try:
            with opener.open(request, timeout=timeout) as response:
                data = response.read()
            if not data:
                raise RuntimeError("服务器返回空内容")
            return data
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            if attempt < retries:
                wait = min(2**attempt, 10)
                time.sleep(wait)

    raise RuntimeError(f"抓取失败: {last_error}")


def fetch_rows(
    api_url: str = DEFAULT_API_URL,
    proxy: str | None = None,
    timeout: float = 60.0,
    retries: int = 3,
) -> list[dict[str, str]]:
    """按候选顺序抓取 VPN Gate API，返回 CSV 行字典列表。"""
    last_error: Exception | None = None
    for candidate in proxy_candidates(proxy):
        try:
            raw = http_get(api_url, candidate, timeout, max(1, retries))
            return parse_vpngate_csv(raw)
        except Exception as exc:  # noqa: BLE001
            last_error = exc

    hint = "；如无法直连 VPN Gate，可设置本机代理，使用代理抓取（如 http://127.0.0.1:7897）"
    raise RuntimeError(f"{last_error}{hint}")


def parse_vpngate_csv(raw: bytes) -> list[dict[str, str]]:
    """把 VPN Gate API 返回的 CSV 解析成字典列表。"""
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")

    lines = [
        line for line in text.splitlines() if line.strip() and not line.startswith("*")
    ]
    if not lines:
        raise RuntimeError("VPN Gate 返回内容为空")

    header_line = lines[0].lstrip("#").strip()
    header = next(csv.reader([header_line]))
    rows: list[dict[str, str]] = []

    for line in lines[1:]:
        try:
            values = next(csv.reader([line]))
        except csv.Error:
            continue
        if len(values) < len(header):
            values += [""] * (len(header) - len(values))
        row = {name: values[i] for i, name in enumerate(header) if i < len(values)}
        if row.get("OpenVPN_ConfigData_Base64"):
            rows.append(row)

    if not rows:
        raise RuntimeError("没有解析到任何 OpenVPN 节点")
    return rows


def _split_ciphers(value: str) -> list[str]:
    return [item for item in re.split(r"[:\s]+", value.strip()) if item]


def parse_ovpn(ovpn_text: str) -> dict[str, Any]:
    """解析 OpenVPN 客户端配置，返回转换需要的字段。"""
    result: dict[str, Any] = {
        "remote_host": None,
        "remote_port": None,
        "proto": "udp",
        "dev": "tun",
        "cipher": None,
        "data_ciphers": [],
        "data_ciphers_fallback": None,
        "auth": None,
        "comp_lzo": None,
        "mtu": None,
        "key_direction": None,
        "tls_auth": None,
        "tls_crypt": None,
        "tls_crypt_v2": None,
        "ca": None,
        "cert": None,
        "key": None,
    }

    current_tag: str | None = None
    block_buffer: list[str] = []

    def finish_block(tag: str, lines: list[str]) -> None:
        content = "\n".join(line.strip() for line in lines if line.strip()).strip()
        if not content:
            return
        mapping = {
            "ca": "ca",
            "cert": "cert",
            "key": "key",
            "tls-auth": "tls_auth",
            "tls-crypt": "tls_crypt",
            "tls-crypt-v2": "tls_crypt_v2",
        }
        key = mapping.get(tag)
        if key:
            result[key] = content

    for raw_line in ovpn_text.splitlines():
        line = raw_line.strip()

        if current_tag is not None:
            if line.lower().startswith(f"</{current_tag}"):
                finish_block(current_tag, block_buffer)
                current_tag = None
                block_buffer = []
            else:
                block_buffer.append(raw_line)
            continue

        if line.startswith("<"):
            match = re.match(r"<([A-Za-z0-9_.-]+)>", line)
            if match:
                tag = match.group(1).lower()
                if tag in INLINE_BLOCK_TAGS:
                    current_tag = tag
                    block_buffer = []
                continue

        if not line or line.startswith(("#", ";")):
            continue

        parts = line.split()
        if not parts:
            continue
        directive = parts[0].lower()
        args = parts[1:]

        if directive == "remote" and args:
            host = args[0]
            port = 1194
            if len(args) >= 2:
                try:
                    port = int(args[1])
                except ValueError:
                    continue
            if result["remote_host"] is None:
                result["remote_host"] = host
                result["remote_port"] = port
        elif directive == "proto" and args:
            proto = args[0].lower()
            result["proto"] = "tcp" if proto.startswith("tcp") else "udp"
        elif directive == "dev" and args:
            result["dev"] = args[0].lower()
        elif directive == "cipher" and args:
            result["cipher"] = args[0]
        elif directive in ("data-ciphers", "ncp-ciphers") and args:
            result["data_ciphers"] = _split_ciphers(" ".join(args))
        elif directive == "data-ciphers-fallback" and args:
            result["data_ciphers_fallback"] = args[0]
        elif directive == "auth" and args:
            result["auth"] = args[0].upper()
        elif directive == "comp-lzo":
            result["comp_lzo"] = args[0].lower() if args else "yes"
        elif directive in ("tun-mtu", "mtu") and args:
            try:
                result["mtu"] = int(args[0])
            except ValueError:
                pass
        elif directive == "key-direction" and args:
            result["key_direction"] = args[0]

    return result


def _sanitize_name_part(value: str, fallback: str = "node") -> str:
    value = re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-.")
    return value or fallback


def build_openvpn_node(
    row: dict[str, str], index: int, taken_names: set[str]
) -> dict[str, Any] | None:
    """把一条 VPN Gate 数据转换成中性 OpenVPN 节点。

    中性结构只承载 OpenVPN 本身的字段，不掺任何目标格式专属键；
    mihomo / sing-box 各自的形态由 to_mihomo_proxy / to_singbox_endpoint 渲染。
    """
    encoded = row.get("OpenVPN_ConfigData_Base64", "").strip()
    if not encoded:
        return None

    try:
        ovpn_text = base64.b64decode(encoded, validate=False).decode(
            "utf-8", errors="replace"
        )
    except (binascii.Error, ValueError):
        return None

    ovpn = parse_ovpn(ovpn_text)
    if not ovpn["remote_host"] or not ovpn["remote_port"]:
        return None

    if ovpn["dev"] not in ("tun", "tun0", ""):
        return None
    if not ovpn["ca"]:
        return None

    country = (row.get("CountryShort") or "XX").strip().upper()
    host_name = row.get("HostName") or row.get("IP") or "vpngate"
    base_name = "VPNGate-{}-{:02d}-{}".format(
        _sanitize_name_part(country, "XX"),
        index,
        _sanitize_name_part(host_name, "node"),
    )
    name = base_name
    suffix = 2
    while name in taken_names:
        name = f"{base_name}-{suffix}"
        suffix += 1
    taken_names.add(name)

    cipher = ovpn["cipher"]
    data_ciphers = list(ovpn["data_ciphers"])
    if not cipher and data_ciphers:
        cipher = data_ciphers[0]
    if cipher and not data_ciphers:
        data_ciphers = [cipher]

    return {
        "name": name,
        "server": str(row.get("IP") or ovpn["remote_host"]).strip(),
        "port": int(ovpn["remote_port"]),
        "proto": ovpn["proto"],
        "cipher": cipher,
        "data_ciphers": data_ciphers,
        "data_ciphers_fallback": ovpn["data_ciphers_fallback"],
        "auth": ovpn["auth"],
        "comp_lzo": ovpn["comp_lzo"],
        "mtu": ovpn["mtu"],
        "ca": ovpn["ca"],
        "cert": ovpn["cert"],
        "key": ovpn["key"],
        "tls_auth": ovpn["tls_auth"],
        "tls_crypt": ovpn["tls_crypt"],
        "tls_crypt_v2": ovpn["tls_crypt_v2"],
        "key_direction": ovpn["key_direction"],
    }


def to_mihomo_proxy(node: dict[str, Any]) -> dict[str, Any]:
    """把中性 OpenVPN 节点渲染成 mihomo `type: openvpn` 节点。"""
    proxy: dict[str, Any] = {
        "name": node["name"],
        "type": "openvpn",
        "server": str(node["server"]),
        "port": int(node["port"]),
        "proto": node["proto"],
    }
    if node.get("cipher"):
        proxy["cipher"] = node["cipher"]
    if node.get("data_ciphers"):
        proxy["data-ciphers"] = list(node["data_ciphers"])
    if node.get("data_ciphers_fallback"):
        proxy["data-ciphers-fallback"] = node["data_ciphers_fallback"]
    if node.get("auth"):
        proxy["auth"] = node["auth"]
    if node.get("comp_lzo"):
        proxy["comp-lzo"] = node["comp_lzo"]
    if node.get("mtu"):
        proxy["mtu"] = int(node["mtu"])

    proxy["ca"] = node["ca"]
    if node.get("cert"):
        proxy["cert"] = node["cert"]
    if node.get("key"):
        proxy["key"] = node["key"]

    if node.get("tls_auth"):
        proxy["tls-auth"] = node["tls_auth"]
        if node.get("key_direction"):
            proxy["key-direction"] = node["key_direction"]
    elif node.get("tls_crypt"):
        proxy["tls-crypt"] = node["tls_crypt"]
    elif node.get("tls_crypt_v2"):
        proxy["tls-crypt-v2"] = node["tls_crypt_v2"]

    proxy["udp"] = node["proto"] == "udp"
    return proxy


def to_singbox_endpoint(
    node: dict[str, Any], tag: str, detour: str | None = None
) -> dict[str, Any]:
    """把中性 OpenVPN 节点渲染成 sing-box `openvpn-client` endpoint。"""
    if not node.get("server"):
        raise ValueError(f"节点 {tag} 缺少 server")
    if node.get("port") is None:
        raise ValueError(f"节点 {tag} 缺少 port")

    tls: dict[str, Any] = {"certificate": node.get("ca")}
    if node.get("cert"):
        tls["client_certificate"] = node["cert"]
    if node.get("key"):
        tls["client_key"] = node["key"]

    if node.get("tls_crypt"):
        tls["control_wrap"] = {"type": "tls_crypt", "key": node["tls_crypt"]}
    elif node.get("tls_auth"):
        wrap: dict[str, Any] = {"type": "tls_auth", "key": node["tls_auth"]}
        direction = str(node.get("key_direction") or "").strip()
        if direction in ("0", "1"):
            wrap["direction"] = "client" if direction == "1" else "server"
        tls["control_wrap"] = wrap
    elif node.get("tls_crypt_v2"):
        tls["control_wrap"] = {
            "type": "tls_crypt_v2",
            "key": node["tls_crypt_v2"],
        }

    endpoint: dict[str, Any] = {
        "type": "openvpn-client",
        "tag": tag,
        "server": str(node["server"]),
        "server_port": int(node["port"]),
        "network": (
            "tcp" if str(node.get("proto", "udp")).lower().startswith("tcp") else "udp"
        ),
        "tls": tls,
        "route_no_pull": True,
    }
    if detour:
        endpoint["detour"] = detour

    data_ciphers = list(node.get("data_ciphers") or [])
    if not data_ciphers and node.get("cipher"):
        data_ciphers = [node["cipher"]]
    if data_ciphers:
        endpoint["data_ciphers"] = data_ciphers
    if node.get("data_ciphers_fallback"):
        endpoint["data_ciphers_fallback"] = node["data_ciphers_fallback"]
    if node.get("auth"):
        endpoint["auth"] = node["auth"]
    if node.get("comp_lzo"):
        endpoint["compression_lzo"] = str(node["comp_lzo"])
    if node.get("mtu"):
        endpoint["mtu"] = int(node["mtu"])
    return endpoint


def sort_rows(rows: list[dict[str, str]], mode: str) -> list[dict[str, str]]:
    """按 score/ping/speed 排序；api 保持接口原顺序。"""
    if mode == "api":
        return rows

    def number(row: dict[str, str], key: str) -> float:
        try:
            return float(row.get(key) or 0)
        except ValueError:
            return 0.0

    if mode == "ping":
        return sorted(rows, key=lambda r: (number(r, "Ping") <= 0, number(r, "Ping")))
    if mode == "speed":
        return sorted(rows, key=lambda r: number(r, "Speed"), reverse=True)
    return sorted(rows, key=lambda r: number(r, "Score"), reverse=True)


def fetch_openvpn_proxies(
    api_url: str = DEFAULT_API_URL,
    countries: str = "",
    limit: int = 10,
    sort_mode: str = "api",
    proxy: str | None = None,
    timeout: float = 60.0,
    retries: int = 3,
    taken_names: set[str] | None = None,
) -> list[dict[str, Any]]:
    """抓取并筛选 VPN Gate 节点，返回中性 OpenVPN 节点列表。"""
    if not 1 <= limit <= MAX_OPENVPN_NODES:
        raise ValueError(
            f"OpenVPN 节点数量必须为 1~{MAX_OPENVPN_NODES}，当前为 {limit}"
        )

    rows = fetch_rows(api_url, proxy, timeout, retries)

    allowed = {item.strip().upper() for item in countries.split(",") if item.strip()}
    if allowed:
        rows = [
            row for row in rows if (row.get("CountryShort") or "").upper() in allowed
        ]

    rows = sort_rows(rows, sort_mode)[:limit]

    taken = taken_names if taken_names is not None else set()
    nodes: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        built = build_openvpn_node(row, index, taken)
        if built:
            nodes.append(built)

    if not nodes:
        raise RuntimeError("没有生成任何可用的 OpenVPN 节点")
    return nodes
