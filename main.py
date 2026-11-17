#!/usr/bin/env python3.11

"""cfwarp-converter 命令行工具。

把 Cloudflare WARP 的两种传输 (WireGuard/MASQUE) 配置，转换成第三方代理软件
可用的节点分享链接或完整配置文件。每个子命令都支持 csv/txt 两种优选 IP 数据源。

子命令与协议：
    nekoray    wg → nekoray://custom# 分享链接，NekoBox (原4.0.1 - Throne 4.2.7 2024年历史版本)
    sn         wg → sn://wg? 分享链接（Android NekoBox）
    v2rayn     wg → wireguard:// 链接（v2rayN/v2rayNG），有bug，导不入v2rayNG
    nyamebox   wg → nekoray://wireguard# 链接（NyameBox；--amnezia 时输出 wg:// 链接）
    throne     wg/masque → Throne 分享链接，Throne新版本
    hiddify    wg/masque → Hiddify 分享链接（wg + --amnezia 输出 awg://）
    singbox    wg/masque → sing-box(-lx) 完整配置
    mihomo     wg/masque → mihomo 完整配置
    clashrs    wg -> clash-rs 完整配置
    server     启动本地订阅页面，网页展示 sub.txt/sub.yaml/sub.json 内容


--protocol 支持两位简写与全称: wg|wireguard、mq|masque、mix|wg+masque|masque+wg
（awg 不是独立协议：wg + --amnezia 即为 awg；mix 为对半混合：同一数据源按
前后对半切分；不同数据源各占上限一半，短缺互补）。

统一约定：
    * MTU 通过 --mtu 指定（省略则用配置文件值或协议默认值 wg=1340 / masque=1361），取值 1280~1500；
    * 节点/分组别名统一为「【01】ip(port)」，SN 链接因不支持中文改用「[01]」；
    * CLI命令执行的输出文件默认生成在脚本所在目录。

用法示例：
    python main.py --help
    python main.py throne  --source csv  --amnezia
    python main.py hiddify --source csv --amnezia
    python main.py mihomo  --protocol mq --source csv --limit 30
    python main.py singbox --protocol masque --source txt
    python main.py nekoray --source csv --server
    python main.py server
    python main.py         （不带参数 = 同 server，启动本地订阅页面）
"""

from __future__ import annotations

import argparse
import ast
import base64
import builtins
import json
import re
import sys
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import openvpn
from amnezia import (
    add_amnezia_arg,
    amnezia_config_fields,
    amnezia_mode,
    generate_amnezia_params,
)

# ============================================================================
# 第一部分 常量与路径
# ============================================================================

# PyInstaller 打包后 __file__ 指向 _internal 临时目录，需改用 exe 所在目录
IS_FROZEN = getattr(sys, "frozen", False)
if IS_FROZEN:
    BASE_DIR = Path(sys.executable).resolve().parent
    # 帮助文本里的程序名跟随实际 exe 文件名（重命名 exe 后自动变化）
    PROG_NAME = Path(sys.executable).name
else:
    BASE_DIR = Path(__file__).resolve().parent
    PROG_NAME = f"python {Path(sys.argv[0]).name}"

DIR_WG_CONF = BASE_DIR / "配置文件" / "wg-config.conf"
DIR_USQUE_CONF = BASE_DIR / "配置文件" / "masque-config.json"
DIR_CLASH_TEMPLATE = BASE_DIR / "配置文件" / "clash.yaml"
DIR_CLASHRS_TEMPLATE = BASE_DIR / "配置文件" / "clash-rs.yaml"
DIR_SINGBOX_TEMPLATE = BASE_DIR / "配置文件" / "sing-box.json"
DIR_RESULT_CSV = BASE_DIR / "result.csv"
DIR_IP_TXT = BASE_DIR / "ip.txt"

WG_FALLBACK_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WG_FALLBACK_PRIVATE_KEY = "+HfkMSyh7obEkX4J8Qa7Xk77CLVn45AW4CdBbnFNaGc="
WG_FALLBACK_ADDRESS = "172.16.0.2/32"

# CSV（result.csv）延迟筛选阈值（ms）
CSV_MAX_DELAY_MS = 500

# 单份配置的节点总数上限（含 OpenVPN 注入），避免订阅体积与内核负担失控
MAX_TOTAL_NODES = 150

# wg 节点统一的远程 DNS 列表（mihomo/sing-box 节点用列表，v2rayN 链接用逗号串）
WG_DNS_SERVERS = ("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001")

# 统一的协议默认 MTU：wg=1340、masque=1361
# （仅在配置文件里没有 MTU 且未用 --mtu 指定时生效）
DEFAULT_MTU_WG = 1340
DEFAULT_MTU_MASQUE = 1361

# AmneziaWG 常量与工具在 amnezia.py（见顶部 import）。

# OpenVPN(VPN Gate) 注入：手动组与底层拨号组，名称与 配置文件/ 两个模板保持一致
OPENVPN_AI_GROUP = "🤖 AI 专线"
MIHOMO_AUTO_GROUP = "♻️ 自动选择"
SINGBOX_DIAL_GROUP = "⚡自动"

# AI 分流规则集（命中即走 OpenVPN 手动组）
MIHOMO_AI_RULE_TAG = "ai-all"
MIHOMO_AI_RULE_URL = (
    "https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/refs/heads/main/"
    "rules/clash/all.yaml"
)
SINGBOX_AI_RULE_TAG = "ai-all"
SINGBOX_AI_RULE_URL = (
    "https://raw.githubusercontent.com/VPSDance/ai-proxy-rules/refs/heads/main/"
    "rules/sing-box/all.json"
)

# MASQUE 节点统一的 TLS SNI
MASQUE_SERVER_NAME = "consumer-masque.cloudflareclient.com"

# mihomo / sing-box 模板里的占位节点（与 配置文件/clash.yaml、sing-box.json 对应）
# 正则容忍冒号后与方括号内的 0 个或多个空格
# （proxies:[]、proxies: []、proxies:    []、proxies: [ ]、proxies:[   ]）
CLASH_TEMPLATE_NODE_PLACEHOLDER = re.compile(
    r"^proxies:[ \t]*\[[ \t]*\][ \t]*\r?$", re.MULTILINE
)
SINGBOX_SELECTOR_PLACEHOLDER = "{all}"


# ============================================================================
# 第二部分 通用工具
# ============================================================================


def die(message: str, code: int = 1) -> None:
    """打印错误并退出。"""
    print(f"[!] {message}")
    sys.exit(code)


def ensure_readable_file(path: Path) -> None:
    """检查文件存在且非空。"""
    if not path.exists() or path.stat().st_size == 0:
        die(f"文件不存在或为空：{path}")


@dataclass(frozen=True)
class Endpoint:
    """一个 ip:port 优选节点。"""

    raw: str  # 原始字符串，如 [2606:...]:443
    host: str  # 冒号前部分，IPv6 带中括号
    host_bare: str  # 去掉中括号后的主机部分
    port: str

    @property
    def bracketed(self) -> str:
        """显示用：IPv6 加回中括号，IPv4 原样。"""
        return f"{self.host}:{self.port}"


def split_endpoint(raw: str) -> Endpoint:
    host = raw.rsplit(":", 1)[0]
    port = raw.rsplit(":", 1)[1]
    host_bare = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    return Endpoint(raw=raw, host=host, host_bare=host_bare, port=port)


def node_name(index: int, total: int, ip: str, port, ascii_only: bool = False) -> str:
    """统一的节点/分组别名：【01】ip(port)。

    SN 链接的名称不支持中文，ascii_only=True 时用 [01] 隔离序号。
    """
    left, right = ("[", "]") if ascii_only else ("【", "】")
    return f"{left}{str(index).zfill(len(str(total)))}{right}{ip}({port})"


def parse_endpoint_strict(raw: str) -> tuple[str, int] | None:
    """严格解析 ip:port（IPv4 或带中括号的 IPv6），失败返回 None。"""
    match_v6 = re.match(r"^\[(.+)\]:(\d+)$", raw)
    if match_v6:
        return match_v6.group(1), int(match_v6.group(2))
    match_v4 = re.match(r"^(\d+\.\d+\.\d+\.\d+):(\d+)$", raw)
    if match_v4:
        return match_v4.group(1), int(match_v4.group(2))
    return None


_IPV4_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)
_IPV6_PATTERN = re.compile(
    r"^(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:"
    r"|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}"
    r"(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}"
    r"|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}"
    r"(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})"
    r"|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:))$"
)


def ip_version(ip: str) -> str:
    """返回 IPv4 / IPv6 / Invalid。"""
    if _IPV4_PATTERN.match(ip):
        return "IPv4"
    if _IPV6_PATTERN.match(ip):
        return "IPv6"
    return "Invalid"


def write_text_file(path: Path, text: str) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def write_lines(path: Path, lines: list[str], trailing_newline: bool = True) -> None:
    """写出行列表；trailing_newline 决定末尾是否有换行。"""
    text = "\n".join(lines)
    if trailing_newline and lines:
        text += "\n"
    write_text_file(path, text)


# ============================================================================
# 第三部分 WireGuard 配置解析（wg-config.conf）
# ============================================================================


@dataclass
class WgProfile:
    """wg-config.conf 中转换器会用到的字段。"""

    private_key: str | None = None
    public_key: str | None = None
    addresses: list[str] = field(default_factory=list)
    mtu: str | None = None
    reserved_raw: str = ""

    @property
    def reserved_list(self) -> list[int]:
        return parse_reserved(self.reserved_raw)


def parse_wg_conf(conf_file: Path) -> WgProfile:
    """读取 wg-config.conf。"""
    profile = WgProfile()
    with open(conf_file, mode="r", encoding="utf-8") as rf:
        for line in rf:
            trim_line = line.strip()
            if not trim_line:
                continue
            key, sep, value = trim_line.replace(" ", "").partition("=")
            if not sep:
                continue
            if key == "PrivateKey":
                profile.private_key = value
            elif key == "PublicKey":
                profile.public_key = value
            elif key == "Address":
                profile.addresses = [item for item in value.split(",") if item]
            elif key == "MTU":
                profile.mtu = value
            elif key == "Reserved":
                profile.reserved_raw = value
    return profile


def is_valid_base64_4chars(s: str) -> bool:
    """判断是否是合法的 4 字符 Base64 字符串。"""
    if not re.fullmatch(r"[A-Za-z0-9+/=]{4}", s):
        return False
    try:
        base64.b64decode(s, validate=True)
        return True
    except Exception:  # noqa: BLE001
        return False


def parse_reserved(raw: str) -> list[int]:
    """把 Reserved 值统一转换为整数列表（支持 [n, n, n] 与 4 字符 Base64 两种写法）。"""
    s = str(raw).strip()
    if s.startswith("[") and s.endswith("]"):
        try:
            lst = ast.literal_eval(s)  # 安全解析
            if isinstance(lst, list) and all(isinstance(x, int) for x in lst):
                return lst
        except (ValueError, SyntaxError):
            return []
        return []
    if is_valid_base64_4chars(s):
        try:
            return list(base64.b64decode(s))
        except Exception:  # noqa: BLE001
            return []
    return []


def resolve_mtu(flag_value: int | None, conf_mtu: str | None, default: int) -> int:
    """MTU 优先级：命令行 > 配置文件 > 目标默认值；范围 1280~1500。"""
    mtu = (
        flag_value
        if flag_value is not None
        else (int(conf_mtu) if conf_mtu else default)
    )
    if not 1280 <= mtu <= 1500:
        die(f"MTU 取值范围为 1280~1500，当前为 {mtu}")
    return mtu


# ============================================================================
# 第四部分 数据源读取（优选IP：result.csv / ip.txt）
# ============================================================================

# csv 行的延迟列固定在第 3 列（索引 2）；这样表格末尾以后新增列也不会读错
CSV_DELAY_COLUMN = 2


def parse_source_line(line: str) -> tuple[str | None, int | None]:
    """按单行内容识别数据源，返回 (endpoint, delay)；无效行返回 (None, None)。

    - 含逗号 → 视为 csv：第 0 列是 endpoint（ip:port），第 3 列是延迟（如 "193 ms"）；
    - 不含逗号 → 视为纯 endpoint 行，无延迟。
    表头、列数不足、延迟列非数字的行都判为无效。
    """
    if "," in line:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) <= CSV_DELAY_COLUMN:
            return None, None
        try:
            delay = int(parts[CSV_DELAY_COLUMN].replace(" ", "").replace("ms", ""))
        except ValueError:
            return None, None
        return parts[0], delay
    return line, None


def load_endpoints(
    source_file: Path, max_delay: int = CSV_MAX_DELAY_MS
) -> list[Endpoint]:
    """统一数据源读取入口：逐行智能识别（csv / 纯 endpoint），**读取时即分离成 Endpoint**。

    * 不区分 txt / csv 文件——csv 数据放在 txt 里也按 csv 读，纯 endpoint 放在 csv 里也按 endpoint 读；
    * 丢弃：空行、表头、延迟列非数字、延迟 ≥ max_delay、非 ip:port 的行；按 host:port 去重保序。
    """
    ensure_readable_file(source_file)
    endpoints: list[Endpoint] = []
    seen = set()
    for raw in source_file.read_text(encoding="utf-8").splitlines():
        endpoint, delay = parse_source_line(raw.strip())
        if endpoint is None or parse_endpoint_strict(endpoint) is None:
            continue
        if delay is not None and delay >= max_delay:
            continue
        ep = split_endpoint(endpoint)
        key = (ep.host, ep.port)
        if key in seen:
            continue
        seen.add(key)
        endpoints.append(ep)
    return endpoints


def resolve_source_path(args: argparse.Namespace) -> Path:
    """--file 优先；否则按 --source 映射到 result.csv / ip.txt。"""
    if getattr(args, "file", None):
        return Path(args.file)
    return DIR_RESULT_CSV if args.source == "csv" else DIR_IP_TXT


# ============================================================================
# 第五部分 MASQUE 配置读取（masque-config.json）
# ============================================================================


@dataclass
class MasqueConfig:
    private_key: str
    public_key: str  # 去掉 PEM 头尾的节点公钥
    ipv4: str
    ipv6: str


def load_masque_config(path: Path = DIR_USQUE_CONF) -> MasqueConfig:
    ensure_readable_file(path)
    try:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except json.JSONDecodeError:
        die(f"文件 {path} JSON 格式错误")
    pub_key = (
        config["endpoint_pub_key"]
        .replace("-----BEGIN PUBLIC KEY-----\n", "")
        .replace("\n", "")
        .replace("-----END PUBLIC KEY-----", "")
    )
    return MasqueConfig(
        private_key=config["private_key"],
        public_key=pub_key,
        ipv4=config["ipv4"],
        ipv6=config["ipv6"],
    )


# ============================================================================
# 第六部分 SN 链接序列化（Android NekoBox 专用）
# 类名/字段名与 NekoBoxForAndroid 源码一一对应（MatsuriDayo/NekoBoxForAndroid）：
#   fmt/Serializable.kt               → KryoSerializable
#   fmt/AbstractBean.java             → AbstractBean
#   fmt/wireguard/WireGuardBean.java  → WireGuardBean
#   fmt/UniversalFmt.kt parseUniversal（TypeMap.kt 注册名 "wg"）→ to_sn_uri
# 链接格式：sn://wg?<urlsafe-base64(zlib(kryo 字节))>
# 注意：SN Link 的配置名称不能使用中文与部分特殊字符，不要乱改序列化逻辑
# ============================================================================


def kryo_write_string(s: str) -> bytes:
    """等价于 Kryo ByteBufferOutput.writeString（ASCII 路径，末字节置高位作结束标记）。"""
    if not s:
        return b"\x81"
    if len(s) == 1:
        return b"\x82" + s.encode()
    ret = s.encode()
    return ret[:-1] + (ret[-1] | 0x80).to_bytes(1, "little")


def kryo_write_int(n: int) -> bytes:
    """等价于 Kryo writeInt（App 端为固定 4 字节小端）。"""
    return n.to_bytes(4, "little")


def kryo_write_byte(n: int) -> bytes:
    """等价于 Kryo writeByte。"""
    return n.to_bytes(1, "little")


class KryoSerializable:
    """对应 nb4a fmt/Serializable.kt 的 Kryo 序列化基类。"""

    def serialize(self) -> bytes:
        ret = b""
        for v in self.__dict__.values():
            match type(v):
                case builtins.str:
                    ret += kryo_write_string(v)
                case builtins.bool:
                    ret += kryo_write_byte(int(v))
                case builtins.int:
                    ret += kryo_write_int(v)
                case _:
                    if isinstance(v, KryoSerializable):
                        ret += v.serialize()
        return ret


@dataclass(init=True, repr=True)
class AbstractBean(KryoSerializable):
    """对应 nb4a fmt/AbstractBean.java：服务器地址/端口 + 名称等元数据。"""

    serverAddress: str = "127.0.0.1"
    serverPort: int = 1080
    name: str = ""
    customOutboundJson: str = ""
    customConfigJson: str = ""

    def serialize(self) -> bytes:  # AbstractBean.serialize()
        return kryo_write_string(self.serverAddress) + kryo_write_int(self.serverPort)

    def serialize_to_buffer(self) -> bytes:  # AbstractBean.serializeToBuffer()
        # 源码此处写 writeInt(1)，App 反序列化只读取不使用该值；此处写 2 以保证
        # 与既有的 SN 链接逐字节一致。
        return (
            self.serialize()
            + kryo_write_int(2)
            + kryo_write_string(self.name)
            + kryo_write_string(self.customOutboundJson)
            + kryo_write_string(self.customConfigJson)
        )


@dataclass(init=True, repr=True)
class WireGuardBean(AbstractBean):
    """对应 nb4a fmt/wireguard/WireGuardBean.java，字段顺序即序列化顺序。"""

    serverAddress: str = "162.159.192.2"
    serverPort: int = 2408
    localAddress: str = "172.16.0.2/32"
    privateKey: str = ""
    peerPublicKey: str = WG_FALLBACK_PUBLIC_KEY
    peerPreSharedKey: str = ""
    mtu: int = 1280
    reserved: str = ""

    def serialize(
        self,
    ) -> bytes:  # WireGuardBean.serialize()：version(2) + 父类 + 本类字段
        return (
            kryo_write_int(2)
            + super().serialize()
            + kryo_write_string(self.localAddress)
            + kryo_write_string(self.privateKey)
            + kryo_write_string(self.peerPublicKey)
            + kryo_write_string(self.peerPreSharedKey)
            + kryo_write_int(self.mtu)
            + kryo_write_string(self.reserved)
        )


def to_sn_uri(bean: AbstractBean, sn_type: str = "wg") -> str:
    """parseUniversal 的逆操作：sn://<type>?<urlsafe-base64(zlib(kryo 字节))>。"""
    payload = base64.urlsafe_b64encode(
        zlib.compress(bean.serialize_to_buffer())
    ).decode()
    return f"sn://{sn_type}?{payload}"


# ============================================================================
# 第七部分 转换器
# 扩展点：新增一种转换目标时，写一个 BaseConverter 子类并加
# @register_converter(...) 装饰器，命令行会自动出现对应的子命令，例如：
#
#   @register_converter("xxx", "wg → XXX（说明）", default_output="sub.txt")
#   class XxxConverter(BaseConverter):
#       def fill_parser(self, parser):
#           add_source_args(parser, "txt")
#           add_output_arg(parser, self.default_output)
#       def run(self, args):
#           endpoints = load_endpoints(resolve_source_path(args))
#           ...
# ============================================================================

CONVERTERS: dict[str, type[BaseConverter]] = {}


def register_converter(
    name: str,
    help_text: str = "",
    default_output: str = "",
    default_source: str = "csv",
) -> Callable[[type[BaseConverter]], type[BaseConverter]]:
    """把转换器类注册为 CLI 子命令。"""

    def decorator(cls: type[BaseConverter]) -> type[BaseConverter]:
        cls.name = name
        cls.help_text = help_text or (cls.__doc__ or name).strip().splitlines()[0]
        cls.default_output = default_output
        cls.default_source = default_source
        CONVERTERS[name] = cls
        return cls

    return decorator


class BaseConverter:
    """所有转换器的基类：子类实现 fill_parser（声明参数）与 run（执行转换）。"""

    name: str = ""
    help_text: str = ""
    default_output: str = ""
    default_source: str = "csv"

    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        """声明该子命令的专属参数（公共参数由 build_parser 统一添加）。"""

    def run(self, args: argparse.Namespace) -> None:
        raise NotImplementedError


# ---- 公共参数声明辅助 -------------------------------------------------------

# --protocol 取值别名：支持两位简写与全称；mix 为 wg+masque 对半混合
PROTOCOL_ALIASES = {
    "wg": "wg",
    "wireguard": "wg",
    "mq": "masque",
    "masque": "masque",
    "mix": "mix",
    "wg+masque": "mix",
    "masque+wg": "mix",
}


def protocol_type(value: str) -> str:
    """把 --protocol 取值归一化为内部名（wg / masque / mix）。"""
    key = value.strip().lower()
    if key in PROTOCOL_ALIASES:
        return PROTOCOL_ALIASES[key]
    raise argparse.ArgumentTypeError(
        f"未知协议 {value!r}，可选：wg / wireguard / mq / masque / mix"
    )


def add_source_args(parser: argparse.ArgumentParser, default_source: str) -> None:
    parser.add_argument(
        "--source",
        choices=["csv", "txt"],
        default=default_source,
        help="优选 IP 数据源文件：csv=result.csv、txt=ip.txt"
        f"（默认：{default_source}）；只切换文件，行格式由内容自动识别",
    )
    parser.add_argument(
        "--file", default=None, help="直接指定数据文件路径（覆盖 --source 的默认路径）"
    )
    parser.add_argument(
        "--no-ipv6",
        action="store_true",
        help="剔除 IPv6 优选节点（默认保留；csv / txt 数据源同样生效）",
    )


def add_protocol_source_args(
    parser: argparse.ArgumentParser, with_wg: bool = True
) -> None:
    """mihomo/sing-box/hiddify 专用：wg 与 masque 默认读取不同数据源。"""
    parser.add_argument(
        "--source",
        choices=["csv", "txt"],
        default=None,
        help="统一覆盖两类节点的数据源；留空时按协议默认（wg=result.csv、masque=ip.txt）",
    )
    parser.add_argument(
        "--file", default=None, help="直接指定数据文件路径（覆盖 --source 的默认路径）"
    )
    if with_wg:
        parser.add_argument(
            "--with-wg",
            type=int,
            default=0,
            help="masque 模式下额外追加的 WireGuard 节点数（默认：0）",
        )
    parser.add_argument(
        "--no-ipv6",
        action="store_true",
        help="剔除 IPv6 优选节点（默认保留；csv / txt 数据源同样生效）",
    )


def resolve_protocol_source(args: argparse.Namespace, kind: str) -> Path:
    """按节点类型取数据源：显式 --file/--source 优先，否则 wg=result.csv、masque=ip.txt。"""
    if getattr(args, "file", None):
        return Path(args.file)
    source = getattr(args, "source", None)
    if source == "csv":
        return DIR_RESULT_CSV
    if source == "txt":
        return DIR_IP_TXT
    return DIR_RESULT_CSV if kind == "wg" else DIR_IP_TXT


def add_output_arg(parser: argparse.ArgumentParser, default_output: str) -> None:
    parser.add_argument(
        "--output", default=None, help=f"输出文件路径（默认：{default_output}）"
    )


def add_protocol_arg(parser: argparse.ArgumentParser, default: str = "wg") -> None:
    parser.add_argument(
        "--protocol",
        type=protocol_type,
        default=default,
        metavar="{wg|wireguard|mq|masque|mix}",
        help=f"节点协议：wg/wireguard=WireGuard，mq/masque=MASQUE，"
        f"mix=wg+masque 对半混合（默认：{default}）",
    )


def add_mtu_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--mtu",
        type=int,
        default=None,
        help="MTU，取值 1280~1500（不填则用配置文件值或协议默认值 wg=1340 / masque=1361）",
    )


def add_limit_arg(parser: argparse.ArgumentParser, default: int | None = None) -> None:
    help_default = "全部" if default is None else default
    parser.add_argument(
        "--limit",
        type=int,
        default=default,
        help=f"最多生成的节点数（默认：{help_default}）",
    )


def add_openvpn_args(parser: argparse.ArgumentParser) -> None:
    """声明 OpenVPN(VPN Gate) 注入参数；默认全部关闭，不影响原有输出。"""
    parser.add_argument(
        "--with-openvpn",
        action="store_true",
        help="追加 VPN Gate OpenVPN 节点（默认关闭）",
    )
    parser.add_argument(
        "--api-url",
        default=openvpn.DEFAULT_API_URL,
        help=f"VPN Gate API 地址（默认：{openvpn.DEFAULT_API_URL}）",
    )
    parser.add_argument(
        "--countries",
        default="",
        help="只保留指定国家代码，逗号分隔，例如 JP,KR,US；为空表示全部",
    )
    parser.add_argument(
        "--openvpn-limit",
        type=int,
        default=10,
        help=f"写入的 OpenVPN 节点数（默认：10，上限：{openvpn.MAX_OPENVPN_NODES}）",
    )
    parser.add_argument(
        "--openvpn-sort",
        choices=["api", "score", "ping", "speed"],
        default="api",
        help="OpenVPN 节点排序方式（默认：api 保持接口顺序）",
    )
    parser.add_argument(
        "--openvpn-proxy",
        default=None,
        help="抓取 VPN Gate API 的 HTTP 代理；默认自动探测本机代理，失败再直连",
    )
    parser.add_argument(
        "--openvpn-group",
        default=OPENVPN_AI_GROUP,
        help=f"OpenVPN 手动选择组名（默认：{OPENVPN_AI_GROUP}）",
    )
    parser.add_argument(
        "--openvpn-timeout",
        type=float,
        default=60.0,
        help="抓取 VPN Gate 的 HTTP 超时秒数（默认：60）",
    )
    parser.add_argument(
        "--openvpn-retries",
        type=int,
        default=3,
        help="抓取 VPN Gate 的重试次数（默认：3）",
    )


def pick_endpoints(
    endpoints: list[Endpoint], take: int, no_ipv6: bool
) -> list[Endpoint]:
    """按顺序取满 take 个；no_ipv6 时跳过 IPv6 继续向后补足，避免数量不足。"""
    if not no_ipv6:
        return endpoints[:take]
    picked: list[Endpoint] = []
    for ep in endpoints:
        if ip_version(ep.host_bare) == "IPv6":
            continue
        picked.append(ep)
        if len(picked) >= take:
            break
    return picked


def check_node_budget(total: int) -> None:
    """限制单份配置的节点总数，避免订阅体积与内核负担失控。"""
    if total > MAX_TOTAL_NODES:
        die(
            f"节点总数 {total} 超过上限 {MAX_TOTAL_NODES}，"
            "请调小 --limit / --with-wg / --openvpn-limit"
        )


def node_kind_label(args: argparse.Namespace, with_openvpn: bool) -> str:
    """生成结果提示里的节点类型描述。"""
    kind = {"masque": "masque", "mix": "wg+masque"}.get(args.protocol, "wg")
    if args.protocol == "masque" and args.with_wg > 0:
        kind = "masque+wg"
    return f"{kind}+openvpn" if with_openvpn else kind


def output_path_of(args: argparse.Namespace) -> Path:
    """未显式指定 --output 时，输出到脚本所在目录的默认文件。"""
    return (
        Path(args.output) if args.output else BASE_DIR / args.converter.default_output
    )


def output_path_for(args: argparse.Namespace, default_name: str) -> Path:
    """未显式指定 --output 时用给定默认名（同一子命令的不同协议用不同默认文件名）。"""
    return Path(args.output) if args.output else BASE_DIR / default_name


def load_wg_profile() -> WgProfile:
    """读取并校验 wg-config.conf。"""
    ensure_readable_file(DIR_WG_CONF)
    return parse_wg_conf(DIR_WG_CONF)


def load_wg_bundle() -> tuple[WgProfile, str, str, list[str]]:
    """读取 wg-config.conf，返回 (profile, 私钥, 公钥, 地址列表)，缺失项回退默认值。"""
    profile = load_wg_profile()
    private_key, public_key, addresses = read_conf_with_fallback(profile)
    return profile, private_key, public_key, addresses


def save_links(
    args: argparse.Namespace,
    lines: list[str],
    kind: str,
    default_name: str | None = None,
    trailing_newline: bool = True,
) -> None:
    """写出分享链接列表并打印结果。"""
    output = (
        output_path_for(args, default_name) if default_name else output_path_of(args)
    )
    write_lines(output, lines, trailing_newline)
    print(f"[OK] 已生成 {len(lines)} 个 {kind} 节点 → {output}")


def save_config(
    args: argparse.Namespace,
    config_text: str,
    count: int,
    kind: str,
    default_name: str | None = None,
) -> None:
    """写出完整配置文件并打印结果。"""
    output = (
        output_path_for(args, default_name) if default_name else output_path_of(args)
    )
    write_text_file(output, config_text)
    print(f"[OK] 已生成 {count} 个 {kind} 节点 → {output}")


def read_conf_with_fallback(profile: WgProfile) -> tuple[str, str, list[str]]:
    """取私钥/公钥/地址，缺失时回退到默认值。"""
    private_key = profile.private_key or WG_FALLBACK_PRIVATE_KEY
    public_key = profile.public_key or WG_FALLBACK_PUBLIC_KEY
    addresses = profile.addresses or [WG_FALLBACK_ADDRESS]
    return private_key, public_key, addresses


# ---- 中性节点收集与渲染（mihomo / sing-box 共用） ---------------------------


def collect_wg_nodes(
    args: argparse.Namespace,
    index_offset: int = 0,
    limit: int | None = None,
    picked: list[Endpoint] | None = None,
    source_total: int | None = None,
) -> list[dict[str, Any]]:
    """收集中性 WireGuard 节点（序号/位宽先记入 no/src_total，别名延后统一回填）。

    picked / source_total 供混合模式复用已筛选的数据源切片；默认自行加载数据源。
    """
    profile = load_wg_profile()
    private_key, public_key, addresses = read_conf_with_fallback(profile)
    mtu = resolve_mtu(args.mtu, profile.mtu, DEFAULT_MTU_WG)
    amnezia_random, amnezia_fixed = amnezia_mode(args.amnezia)

    if picked is None:
        endpoints = load_endpoints(resolve_protocol_source(args, "wg"))
        take = args.limit if limit is None else limit
        picked = pick_endpoints(endpoints, take, args.no_ipv6)
        source_total = len(endpoints)

    nodes = []
    for i, ep in enumerate(picked):
        nodes.append(
            {
                "kind": "wg",
                "no": index_offset + i + 1,
                "src_total": source_total,
                "server": ep.host_bare,
                "port": int(ep.port),
                "addresses": addresses,
                "private_key": private_key,
                "public_key": public_key,
                "mtu": mtu,
                # 随机模式下每个节点独享一套参数；禁用时为 None
                "amnezia": (
                    generate_amnezia_params() if amnezia_random else amnezia_fixed
                )
                or None,
            }
        )
    return nodes


def collect_masque_nodes(
    args: argparse.Namespace,
    index_offset: int = 0,
    limit: int | None = None,
    picked: list[Endpoint] | None = None,
    source_total: int | None = None,
) -> list[dict[str, Any]]:
    """收集中性 MASQUE 节点（序号/位宽先记入 no/src_total，别名延后统一回填）。"""
    config = load_masque_config()
    mtu = resolve_mtu(args.mtu, None, DEFAULT_MTU_MASQUE)

    if picked is None:
        endpoints = load_endpoints(resolve_protocol_source(args, "masque"))
        take = args.limit if limit is None else limit
        picked = pick_endpoints(endpoints, take, args.no_ipv6)
        source_total = len(endpoints)

    nodes = []
    for i, ep in enumerate(picked, start=1):
        nodes.append(
            {
                "kind": "masque",
                "no": index_offset + i,
                "src_total": source_total,
                "server": ep.host_bare,
                "port": int(ep.port),
                "private_key": config.private_key,
                "public_key": config.public_key,
                "ipv4": config.ipv4,
                "ipv6": config.ipv6,
                "mtu": mtu,
            }
        )
    return nodes


def mixed_quotas(
    total: int, wg_available: int, masque_available: int
) -> tuple[int, int]:
    """wg+masque 对半配额：各协议最多占上限一半，一方短缺时另一方补足到上限。"""
    half = total // 2
    wg_count = min(half, wg_available)
    masque_count = min(total - wg_count, masque_available)
    wg_count = min(total - masque_count, wg_available)  # masque 短缺时回补给 wg
    return wg_count, masque_count


def collect_mixed_nodes(args: argparse.Namespace) -> list[dict[str, Any]]:
    """wg + masque 对半混合：同一数据源时按前后对半切分（避免同 IP 重复两种节点）；
    不同数据源时各占上限一半、一方短缺时另一方补足，直到上限。
    输出 masque 在前、wg 在后，别名连续编号。"""
    total = args.limit
    wg_path = resolve_protocol_source(args, "wg")
    if wg_path == resolve_protocol_source(args, "masque"):
        pool = load_endpoints(wg_path)
        picked = pick_endpoints(pool, total, args.no_ipv6)
        split = len(picked) // 2
        masque_nodes = collect_masque_nodes(
            args, limit=split, picked=picked[:split], source_total=len(pool)
        )
        wg_nodes = collect_wg_nodes(
            args,
            index_offset=split,
            limit=len(picked) - split,
            picked=picked[split:],
            source_total=len(pool),
        )
        nodes = masque_nodes + wg_nodes
    else:
        wg_nodes = collect_wg_nodes(args, limit=total)
        masque_nodes = collect_masque_nodes(args, limit=total)
        wg_count, masque_count = mixed_quotas(total, len(wg_nodes), len(masque_nodes))
        nodes = masque_nodes[:masque_count] + wg_nodes[:wg_count]
        for i, node in enumerate(nodes, start=1):
            node["no"] = i
    return nodes


def collect_nodes_by_protocol(args: argparse.Namespace) -> list[dict[str, Any]]:
    """按协议收集中性节点；masque + --with-wg 时 wg 节点追加在 masque 之后。"""
    if args.protocol == "mix":
        if args.with_wg > 0:
            die("--with-wg 只能在 --protocol masque 下使用")
        nodes = collect_mixed_nodes(args)
    elif args.protocol == "masque":
        nodes = collect_masque_nodes(args)
        if args.with_wg > 0:
            nodes.extend(
                collect_wg_nodes(args, index_offset=len(nodes), limit=args.with_wg)
            )
    else:
        if args.with_wg > 0:
            die("--with-wg 只能在 --protocol masque 下使用")
        nodes = collect_wg_nodes(args)
    # 别名统一回填：【序号】ip(port)，位宽由各自数据源总数决定
    for node in nodes:
        node["name"] = node_name(
            node.pop("no"), node.pop("src_total"), node["server"], node["port"]
        )
    return nodes


def fetch_openvpn_neutral(
    args: argparse.Namespace, taken_names: set[str]
) -> list[dict[str, Any]]:
    """抓取 VPN Gate 中性节点；失败直接终止（CLI 报错退出，网页端转 400）。"""
    try:
        return openvpn.fetch_openvpn_proxies(
            api_url=args.api_url,
            countries=args.countries,
            limit=args.openvpn_limit,
            sort_mode=args.openvpn_sort,
            proxy=args.openvpn_proxy,
            timeout=args.openvpn_timeout,
            retries=args.openvpn_retries,
            taken_names=taken_names,
        )
    except (ValueError, RuntimeError) as error:
        die(str(error))


def wg_node_to_mihomo(node: dict[str, Any]) -> dict[str, Any]:
    """中性 WireGuard 节点 → mihomo type=wireguard。"""
    addresses = node["addresses"]
    ipv4_str, ipv6_str = "", ""
    if addresses:
        ipv4_addr = addresses[0].split("/")[0]
        ipv4_str = ipv4_addr if ip_version(ipv4_addr) == "IPv4" else "172.16.0.2"
        if len(addresses) > 1:
            ipv6_addr = addresses[1].split("/")[0]
            ipv6_str = ipv6_addr if ip_version(ipv6_addr) == "IPv6" else ""
    proxy: dict[str, Any] = {
        "name": node["name"],
        "type": "wireguard",
        "server": node["server"],
        "port": node["port"],
        "ip": ipv4_str,
        "ipv6": ipv6_str,
        "private-key": node["private_key"],
        "public-key": node["public_key"],
        "udp": True,
        "mtu": node["mtu"],
        "remote-dns-resolve": True,
        "dns": list(WG_DNS_SERVERS),
    }
    if node["amnezia"]:
        proxy["amnezia-wg-option"] = amnezia_config_fields(node["amnezia"])
    return proxy


def masque_node_to_mihomo(node: dict[str, Any]) -> dict[str, Any]:
    """中性 MASQUE 节点 → mihomo type=masque。"""
    return {
        "name": node["name"],
        "type": "masque",
        "server": node["server"],
        "port": node["port"],
        "private-key": node["private_key"],
        "public-key": node["public_key"],
        "ip": node["ipv4"],
        "ipv6": node["ipv6"],
        "mtu": node["mtu"],
        "udp": True,
        "remote-dns-resolve": True,
        "dns": list(WG_DNS_SERVERS),
    }


def wg_node_to_singbox(node: dict[str, Any]) -> dict[str, Any]:
    """中性 WireGuard 节点 → sing-box wireguard endpoint。"""
    endpoint: dict[str, Any] = {
        "type": "wireguard",
        "tag": node["name"],
        "mtu": node["mtu"],
        "address": node["addresses"],
        "private_key": node["private_key"],
        "peers": [
            {
                "address": node["server"],
                "port": node["port"],
                "public_key": node["public_key"],
                "allowed_ips": ["0.0.0.0/0", "::/0"],
            }
        ],
    }
    if node["amnezia"]:
        endpoint.update(amnezia_config_fields(node["amnezia"], snake_case=True))
    return endpoint


def masque_node_to_singbox(node: dict[str, Any]) -> dict[str, Any]:
    """中性 MASQUE 节点 → sing-box masque outbound。"""
    return {
        "type": "masque",
        "tag": node["name"],
        "server": node["server"],
        "server_port": node["port"],
        "profile": "cloudflare",
        "vhttp": "auto",
        "private_key": node["private_key"],
        "public_key": node["public_key"],
        "ip": node["ipv4"],
        "ipv6": node["ipv6"],
        "mtu": node["mtu"],
        "tls": {"enabled": True, "server_name": MASQUE_SERVER_NAME},
    }


# ---- 批量链接类转换器 -------------------------------------------------------


@register_converter(
    "nekoray", "wg → nekoray://custom# 节点链接", default_output="sub.txt"
)
class NekorayConverter(BaseConverter):
    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        add_source_args(parser, self.default_source)
        add_output_arg(parser, self.default_output)
        add_mtu_arg(parser)
        add_limit_arg(parser, 500)

    def run(self, args: argparse.Namespace) -> None:
        profile = load_wg_profile()
        mtu = resolve_mtu(args.mtu, profile.mtu, DEFAULT_MTU_WG)
        addresses = profile.addresses or [WG_FALLBACK_ADDRESS]
        reserved = profile.reserved_list

        endpoints = load_endpoints(resolve_source_path(args))
        total = len(endpoints)
        lines = []
        for i, ep in enumerate(pick_endpoints(endpoints, args.limit, args.no_ipv6)):
            # 写入 JSON 的 server 需去掉 IPv6 中括号
            remarks = node_name(i + 1, total, ep.host_bare, ep.port)
            bean = {
                "_v": 0,
                "addr": "127.0.0.1",
                "cmd": [""],
                "core": "internal",
                # cs 为内嵌 sing-box wireguard outbound 的 JSON 文本（缩进 2 格）
                "cs": json.dumps(
                    {
                        "interface_name": "WARP",
                        # Address 有多个值（一般 IPv4 CIDR + IPv6 CIDR）与单个值的格式不同
                        "local_address": (
                            addresses[0] if len(addresses) == 1 else list(addresses)
                        ),
                        "mtu": int(mtu),
                        "peer_public_key": (profile.public_key or "").strip(),
                        "private_key": (profile.private_key or "").strip(),
                        "reserved": reserved,
                        "server": ep.host_bare,
                        "server_port": int(ep.port),
                        "system_interface": False,
                        "tag": "proxy",
                        "type": "wireguard",
                    },
                    ensure_ascii=False,
                    indent=2,
                    sort_keys=True,
                ),
                "mapping_port": 0,
                "name": remarks,
                "port": 1080,
                "socks_port": 0,
            }
            lines.append(
                "nekoray://custom#"
                + base64.b64encode(
                    json.dumps(
                        bean,
                        ensure_ascii=False,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode(),
                    altchars=b"-_",
                ).decode()
            )
        save_links(args, lines, "nekoray")


@register_converter(
    "sn", "wg → sn://wg? 链接（Android NekoBox）", default_output="sub.txt"
)
class SnLinkConverter(BaseConverter):
    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        add_source_args(parser, self.default_source)
        add_output_arg(parser, self.default_output)
        add_mtu_arg(parser)
        add_limit_arg(parser, 100)

    def run(self, args: argparse.Namespace) -> None:
        profile, private_key, public_key, addresses = load_wg_bundle()
        local_address = ",".join(addresses)
        mtu = resolve_mtu(args.mtu, profile.mtu, DEFAULT_MTU_WG)
        reserved = profile.reserved_raw  # SN 链接里 reserved 按原始字符串序列化

        endpoints = load_endpoints(resolve_source_path(args))
        total = len(endpoints)
        results = []
        for i, ep in enumerate(pick_endpoints(endpoints, args.limit, args.no_ipv6)):
            try:
                # SN 链接的名称不支持中文，用 [01] 隔离序号
                name = node_name(i + 1, total, ep.host_bare, ep.port, ascii_only=True)
                bean = WireGuardBean(
                    serverAddress=ep.host_bare,
                    serverPort=int(ep.port),
                    localAddress=local_address,
                    privateKey=private_key,
                    peerPublicKey=public_key,
                    mtu=int(mtu),
                    reserved=reserved,
                    name=name,
                )
                results.append(to_sn_uri(bean))
            except Exception:  # noqa: BLE001, S112
                continue

        if results:
            save_links(args, results, "sn", trailing_newline=False)


@register_converter("throne", "wg/masque → Throne 分享链接", default_output="sub.txt")
class ThroneConverter(BaseConverter):
    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        add_source_args(parser, self.default_source)
        add_output_arg(parser, self.default_output)
        add_protocol_arg(parser)
        add_mtu_arg(parser)
        add_limit_arg(parser, 500)
        add_amnezia_arg(parser)

    def run(self, args: argparse.Namespace) -> None:
        if args.protocol == "mix":
            self._run_mix(args)
        elif args.protocol == "masque":
            self._run_masque(args)
        else:
            self._run_wg(args)

    def _run_wg(self, args: argparse.Namespace) -> None:
        save_links(args, self._wg_lines(args), "Throne(wg)")

    def _wg_lines(
        self,
        args: argparse.Namespace,
        picked: list[Endpoint] | None = None,
        source_total: int | None = None,
        name_offset: int = 0,
    ) -> list[str]:
        """生成 wg:// 分享链接；picked/source_total 供混合模式复用数据源切片。

        注意：序号用 i+1（从【02】开始），混合模式用 name_offset 校正衔接。
        """
        profile = load_wg_profile()
        private_key = profile.private_key
        public_key = profile.public_key or WG_FALLBACK_PUBLIC_KEY
        addresses = profile.addresses or [WG_FALLBACK_ADDRESS]
        mtu = resolve_mtu(args.mtu, profile.mtu, DEFAULT_MTU_WG)
        reserved = "-".join(map(str, profile.reserved_list))
        amnezia_random, amnezia_fixed = amnezia_mode(args.amnezia)

        if picked is None:
            endpoints = load_endpoints(resolve_source_path(args))
            picked = pick_endpoints(endpoints, args.limit, args.no_ipv6)
            source_total = len(endpoints)
        lines = []
        for i, ep in enumerate(picked, start=1):
            remarks = node_name(
                i + 1 + name_offset, source_total, ep.host_bare, ep.port
            )
            # 每写一个节点就随机一次：随机模式下该节点独享一套参数
            params = generate_amnezia_params() if amnezia_random else amnezia_fixed
            amnezia = ""
            if params:
                # i1/i2 是 AmneziaWG 标签语法（含 <、空格、>），wg:// 里需 URL 编码
                amnezia = "&enable_amnezia=true" + "".join(
                    f"&{key}={quote(str(val), safe='')}" for key, val in params.items()
                )
            lines.append(
                f"wg://{ep.host}:{ep.port}?private_key={private_key}"
                f"&public_key={public_key}&reserved={reserved}"
                f"&persistent_keepalive_interval=30&mtu={mtu}"
                f"&local_address={'-'.join(addresses)}{amnezia}"
                f"#{quote(remarks)}"
            )
        return lines

    def _run_masque(self, args: argparse.Namespace) -> None:
        save_links(
            args, self._masque_lines(args), "Throne(masque)", trailing_newline=False
        )

    def _masque_lines(
        self,
        args: argparse.Namespace,
        picked: list[Endpoint] | None = None,
        source_total: int | None = None,
    ) -> list[str]:
        """生成 masque 的 throne://add 分享链接；picked 供混合模式复用数据源切片。"""
        config = load_masque_config()
        mtu = resolve_mtu(args.mtu, None, DEFAULT_MTU_MASQUE)
        if picked is None:
            endpoints = load_endpoints(resolve_source_path(args))
            picked = pick_endpoints(endpoints, args.limit, args.no_ipv6)
            source_total = len(endpoints)
        links = []
        for i, ep in enumerate(picked, start=1):
            ip, port = ep.host_bare, int(ep.port)
            name = node_name(i, source_total, ip, port)
            data = {
                "address": [f"{config.ipv4}/32", f"{config.ipv6}/128"],
                "mtu": mtu,
                "peer_public_key": config.public_key,
                "private_key": config.private_key,
                "server": ip,
                "server_port": port,
                "tag": name,
                "tls": {"enabled": True, "server_name": MASQUE_SERVER_NAME},
                "type": "masque",
            }
            links.append(
                "throne://add/"
                + base64.b64encode(
                    json.dumps(data, ensure_ascii=False).encode(), altchars=b"-_"
                ).decode()
            )
        return links

    def _run_mix(self, args: argparse.Namespace) -> None:
        """wg + masque 对半混合：同一数据源按前后对半切分，masque 在前、wg 在后。"""
        endpoints = load_endpoints(resolve_source_path(args))
        picked = pick_endpoints(endpoints, args.limit, args.no_ipv6)
        split = len(picked) // 2
        lines = self._masque_lines(
            args, picked=picked[:split], source_total=len(endpoints)
        ) + self._wg_lines(
            args,
            picked=picked[split:],
            source_total=len(endpoints),
            name_offset=split - 1,
        )
        save_links(args, lines, "Throne(wg+masque)")


@register_converter(
    "hiddify",
    "wg/masque → Hiddify 分享链接（wg + --amnezia 输出 awg://）",
    default_output="sub.txt",
)
class HiddifyConverter(BaseConverter):
    """Hiddify（hiddify/ray2sing 解析器）链接：

    - wg → wg://，地址用 ip= 逗号分隔（IPv4 + 额外 IPv6 都是列表）
    - wg + --amnezia → awg:// + AmneziaWG 混淆（不带值=每节点随机）
    - masque → masque://，addr/addr6 分别对应设备 IPv4/IPv6，端点用 endpoint/endpoint6
    - mix → masque 前半 + 后半按 --amnezia 选 wg 或 awg，各取上限一半，短缺互补
    """

    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        add_protocol_source_args(parser, with_wg=False)
        add_output_arg(parser, self.default_output)
        add_protocol_arg(parser)
        add_mtu_arg(parser)
        add_limit_arg(parser, 50)
        add_amnezia_arg(parser)

    def run(self, args: argparse.Namespace) -> None:
        if args.protocol == "mix":
            self._run_mix(args)
        elif args.protocol == "masque":
            save_links(args, self._masque_lines(args), "Hiddify(masque)")
        else:
            amnezia_random, amnezia_fixed = amnezia_mode(args.amnezia)
            scheme = "awg" if (amnezia_random or amnezia_fixed) else "wg"
            save_links(args, self._wg_lines(args), f"Hiddify({scheme})")

    def _wg_lines(
        self,
        args: argparse.Namespace,
        picked: list[Endpoint] | None = None,
        source_total: int | None = None,
        name_offset: int = 0,
    ) -> list[str]:
        """生成 wg:// 链接；--amnezia 启用时改为 awg:// + 混淆参数。"""
        profile, private_key, public_key, addresses = load_wg_bundle()
        mtu = resolve_mtu(args.mtu, profile.mtu, DEFAULT_MTU_WG)
        reserved = profile.reserved_list
        # hiddify 对 reserved 逐项 ParseUint，空值或非 3 字节会让整条链接解析失败
        reserved_param = (
            f"&reserved={','.join(map(str, reserved))}"
            if len(reserved) == 3 and all(0 <= value <= 255 for value in reserved)
            else ""
        )
        local_address = quote(",".join(addresses), safe=",:")
        amnezia_random, amnezia_fixed = amnezia_mode(args.amnezia)
        scheme = "awg" if (amnezia_random or amnezia_fixed) else "wg"

        if picked is None:
            endpoints = load_endpoints(resolve_protocol_source(args, "wg"))
            picked = pick_endpoints(endpoints, args.limit, args.no_ipv6)
            source_total = len(endpoints)
        lines = []
        for i, ep in enumerate(picked, start=1):
            remarks = node_name(i + name_offset, source_total, ep.host_bare, ep.port)
            params = generate_amnezia_params() if amnezia_random else amnezia_fixed
            # i1/i2 是 AmneziaWG 标签语法（含 <、空格、>），必须 URL 编码
            amnezia = "".join(
                f"&{key}={quote(str(val), safe='')}" for key, val in params.items()
            )
            """ 该链接是 endpoints: type=wireguard + noise.fake_packet 写法"""
            lines.append(
                f"{scheme}://{ep.host}:{ep.port}?private_key={quote(private_key, safe='')}"
                f"&peer_public_key={quote(public_key, safe='')}&ip={local_address}"
                f"{reserved_param}&mtu={mtu}&keepalive=25{amnezia}"
                f"#{quote(remarks)}"
            )
            """ 该链接是 endpoints: type=awg + awg.jc/jmin 写法 """
            # ---- 可选：AWG 3.x 写法（整段取消注释即可切换，上方写法保持不动） ----
            # awg3_extra = ""
            # if amnezia:
            #     awg3_extra = (
            #         "&header_protection_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D"
            #         "&content_padding_addition=1-10"
            #         "&rekey_after_time=60-120"
            #         "&rekey_timeout=5-10"
            #         "&max_handshake_attempts=10"
            #     )
            # lines.append(
            #     f"{scheme}://{ep.host}:{ep.port}?private_key={quote(private_key, safe='')}"
            #     f"&peer_public_key={quote(public_key, safe='')}&ip={local_address}"
            #     f"{reserved_param}&mtu={mtu}&keepalive=25{amnezia}{awg3_extra}"
            #     f"#AWG3-{quote(remarks)}"
            # )
        return lines

    def _masque_lines(
        self,
        args: argparse.Namespace,
        picked: list[Endpoint] | None = None,
        source_total: int | None = None,
        name_offset: int = 0,
    ) -> list[str]:
        """生成 masque:// 链接：addr 只放 IPv4，额外 IPv6 走 addr6（单值，裸地址）。"""
        config = load_masque_config()
        mtu = resolve_mtu(args.mtu, None, DEFAULT_MTU_MASQUE)
        # masque 的 key/peer 不走 linkKey() 还原，未编码的 "+" 会被解成空格而损坏密钥
        key = quote(config.private_key, safe="/=")
        peer = quote(config.public_key, safe="/=")
        addr6 = f"&addr6={config.ipv6}" if config.ipv6 else ""

        if picked is None:
            endpoints = load_endpoints(resolve_protocol_source(args, "masque"))
            picked = pick_endpoints(endpoints, args.limit, args.no_ipv6)
            source_total = len(endpoints)
        lines = []
        for i, ep in enumerate(picked, start=1):
            remarks = node_name(i + name_offset, source_total, ep.host_bare, ep.port)
            endpoint_key = (
                "endpoint6" if ip_version(ep.host_bare) == "IPv6" else "endpoint"
            )
            lines.append(
                f"masque://?key={key}&peer={peer}&addr={config.ipv4}{addr6}"
                f"&{endpoint_key}={ep.host}:{ep.port}&transport=auto"
                f"&sni={MASQUE_SERVER_NAME}&mtu={mtu}#{quote(remarks)}"
            )
        return lines

    def _run_mix(self, args: argparse.Namespace) -> None:
        """masque 用 ip.txt、后半用 result.csv：各占上限一半，短缺时另一方补足；
        后半是 wg 还是 awg 由 --amnezia 决定。"""
        total = args.limit
        masque_endpoints = load_endpoints(resolve_protocol_source(args, "masque"))
        masque_picked = pick_endpoints(masque_endpoints, total // 2, args.no_ipv6)
        wg_endpoints = load_endpoints(resolve_protocol_source(args, "wg"))
        wg_picked = pick_endpoints(
            wg_endpoints, total - len(masque_picked), args.no_ipv6
        )
        lines = self._masque_lines(
            args, picked=masque_picked, source_total=total
        ) + self._wg_lines(
            args,
            picked=wg_picked,
            source_total=total,
            name_offset=len(masque_picked),
        )
        amnezia_random, amnezia_fixed = amnezia_mode(args.amnezia)
        kind = "awg+masque" if (amnezia_random or amnezia_fixed) else "wg+masque"
        save_links(args, lines, f"Hiddify({kind})")


# NymBox wg:// 链接的 Amnezia 参数键：内部短键 → 链接长键名
_NYMBOX_AMNEZIA_FIELDS = (
    ("jc", "junk_packet_count", None),
    ("jmin", "junk_packet_min_size", None),
    ("jmax", "junk_packet_max_size", None),
    ("s1", "init_packet_junk_size", "0"),
    ("s2", "response_packet_junk_size", "0"),
    ("s3", "underload_packet_junk_size", "0"),
    ("s4", "transport_packet_junk_size", "0"),
    ("h1", "init_packet_magic_header", None),
    ("h2", "response_packet_magic_header", None),
    ("h3", "cookie_reply_magic_header", None),
    ("h4", "transport_packet_magic_header", None),
    ("i1", "i1", None),
    ("i2", "i2", None),
)


@register_converter(
    "nyamebox",
    "wg → nekoray://wireguard# 分享链接（NyameBox；--amnezia 时输出 wg:// 链接）",
    default_output="sub.txt",
)
class NyameBoxConverter(BaseConverter):
    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        add_source_args(parser, self.default_source)
        add_output_arg(parser, self.default_output)
        add_mtu_arg(parser)
        add_limit_arg(parser, 500)
        add_amnezia_arg(parser)

    def run(self, args: argparse.Namespace) -> None:
        profile = load_wg_profile()
        private_key = profile.private_key
        public_key = profile.public_key or WG_FALLBACK_PUBLIC_KEY
        addresses = profile.addresses or [WG_FALLBACK_ADDRESS]
        mtu = resolve_mtu(args.mtu, profile.mtu, DEFAULT_MTU_WG)
        reserved = "-".join(map(str, profile.reserved_list))
        amnezia_random, amnezia_fixed = amnezia_mode(args.amnezia)

        endpoints = load_endpoints(resolve_source_path(args))
        total = len(endpoints)
        lines = []
        for i, ep in enumerate(pick_endpoints(endpoints, args.limit, args.no_ipv6)):
            remarks = node_name(i + 1, total, ep.host_bare, ep.port)
            # 每写一个节点就随机一次：随机模式下该节点独享一套参数
            params = generate_amnezia_params() if amnezia_random else amnezia_fixed
            if params:
                # --amnezia 分支：wg:// 长键名格式（保持不变）。S 参数缺失时硬编码 0；
                # i1/i2 是 AmneziaWG 标签语法（含 <、空格、>），wg:// 里需 URL 编码
                fields = []
                for short, name, fill in _NYMBOX_AMNEZIA_FIELDS:
                    val = params.get(short, fill)
                    if val is not None:
                        fields.append(f"&{name}={quote(str(val), safe='')}")
                amnezia = "&enable_amnezia=true" + "".join(fields)
                # NymBox 导出格式里 base64 的 +// 、节点名的 (): 均不转码（仅 = 等转码）
                lines.append(
                    f"wg://{ep.host}:{ep.port}?private_key={quote(private_key, safe='+/')}"
                    f"&peer_public_key={quote(public_key, safe='+/')}"
                    f"&reserved={reserved}"
                    f"&persistent_keepalive=0&mtu={quote(str(mtu))}"
                    f"&use_system_interface={'true' if amnezia else 'false'}"
                    f"&local_address={'-'.join(addresses)}{amnezia}"
                    f"#{quote(remarks, safe='():')}"
                )
            else:
                # 不启用混淆：NyameBox（NekoBox for PC）原生分享格式
                # nekoray://wireguard#<base64(bean JSON)>，按 App 导出的示例 bean 构造：
                # 紧凑无空格、键名字母序、非 ASCII 原样 UTF-8、标准 base64 带 = padding
                bean = {
                    "_v": 0,
                    "addr": ep.host_bare,
                    "brutal_speed": 0,
                    "c_cfg": "",
                    "c_out": "",
                    "enable_amnezia": False,
                    "enable_brutal": False,
                    "h1": "",
                    "h2": "",
                    "h3": "",
                    "h4": "",
                    "i1": "",
                    "i2": "",
                    "i3": "",
                    "i4": "",
                    "i5": "",
                    "jc": 0,
                    "jmax": 0,
                    "jmin": 0,
                    "local_address": list(addresses),
                    "mtu": int(mtu),
                    "mux": 0,
                    "name": remarks,
                    "persistent_keepalive": 0,
                    "port": int(ep.port),
                    "pre_shared_key": "",
                    "private_key": private_key,
                    "public_key": public_key,
                    "reserved": profile.reserved_list,
                    "s1": 0,
                    "s2": 0,
                    "s3": 0,
                    "s4": 0,
                    "use_system_proxy": False,
                }
                lines.append(
                    "nekoray://wireguard#"
                    + base64.b64encode(
                        json.dumps(
                            bean,
                            ensure_ascii=False,
                            separators=(",", ":"),
                            sort_keys=True,
                        ).encode()
                    ).decode()
                )
        save_links(args, lines, "NyameBox")


@register_converter(
    "v2rayn",
    "wg → wireguard:// 分享链接（v2rayN / v2rayNG）",
    default_output="sub.txt",
)
class V2rayNConverter(BaseConverter):
    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        add_source_args(parser, self.default_source)
        add_output_arg(parser, self.default_output)
        add_mtu_arg(parser)
        add_limit_arg(parser, 500)

    def run(self, args: argparse.Namespace) -> None:
        profile = load_wg_profile()
        private_key = profile.private_key
        public_key = profile.public_key or WG_FALLBACK_PUBLIC_KEY
        addresses = profile.addresses or [WG_FALLBACK_ADDRESS]
        mtu = resolve_mtu(args.mtu, profile.mtu, DEFAULT_MTU_WG)
        reserved = ",".join(map(str, profile.reserved_list))
        # 不带 CIDR 掩码
        # addr = re.sub(r"/\d+", "", ",".join(addresses).replace(" ", ""))
        # 带 CIDR 掩码
        addr = ",".join(addresses).replace(" ", "")

        endpoints = load_endpoints(resolve_source_path(args))
        total = len(endpoints)
        lines = []
        for i, ep in enumerate(pick_endpoints(endpoints, args.limit, args.no_ipv6)):
            remarks = node_name(i + 1, total, ep.host_bare, ep.port)
            lines.append(
                f"wireguard://{quote(private_key, safe='')}@{ep.host}:{ep.port}?"
                f"address={quote(addr, safe='')}&presharedkey="
                f"&reserved={quote(reserved, safe='')}"
                f"&publickey={quote(public_key, safe='')}"
                f"&dns={quote(','.join(WG_DNS_SERVERS), safe='')}"
                f"&mtu={mtu}"
                f"#{quote(remarks, safe='')}"
            )
        save_links(args, lines, "v2rayN")


# ---- mihomo 配置类转换器 ---------------------------------------


def build_clash_config(proxy_lines: list[str]) -> str:
    """把模板中的空 proxies 占位替换为生成的节点，返回 mihomo 配置文本。"""
    ensure_readable_file(DIR_CLASH_TEMPLATE)
    template = DIR_CLASH_TEMPLATE.read_text(encoding="utf-8")
    if not template.strip():
        raise ValueError("配置模板文件为空")
    replacement = "proxies:\n" + "\n".join(proxy_lines)
    return CLASH_TEMPLATE_NODE_PLACEHOLDER.sub(lambda _: replacement, template, count=1)


def _split_eol(text: str) -> tuple[list[str], str]:
    eol = "\r\n" if "\r\n" in text else "\n"
    return text.split(eol), eol


def _top_section(lines: list[str], header: str) -> tuple[int, int]:
    """返回顶层 header 块的 [start, end)，end 是下一个顶层 key。"""
    start = -1
    for i, line in enumerate(lines):
        if re.match(rf"^{re.escape(header)}\s*:", line):
            start = i
            break
    if start < 0:
        raise RuntimeError(f"配置里找不到顶层块：{header}")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        line = lines[i]
        if not line.strip() or line.startswith("#"):
            continue
        if not line[0].isspace():
            end = i
            break
    return start, end


def _proxy_group_blocks(lines: list[str], start: int, end: int) -> dict[str, dict]:
    """把 proxy-groups 拆成 name -> {start, end}。"""
    starts: list[tuple[int, str]] = []
    for i in range(start + 1, end):
        match = re.match(r"^  - name\s*:\s*(.+?)\s*$", lines[i])
        if match:
            starts.append((i, match.group(1).strip().strip("\"'")))
    blocks: dict[str, dict] = {}
    for index, (line_no, name) in enumerate(starts):
        stop = starts[index + 1][0] if index + 1 < len(starts) else end
        blocks[name] = {"start": line_no, "end": stop}
    return blocks


def _append_member_to_block(block_lines: list[str], member: str) -> list[str]:
    """在单个组块内把成员追加到 proxies 列表末尾。"""
    out = list(block_lines)
    for i, line in enumerate(out):
        if not re.match(r"^\s+proxies\s*:\s*$", line):
            continue
        indent = len(line) - len(line.lstrip())
        prefix = " " * (indent + 2) + "- "
        last = i
        for j in range(i + 1, len(out)):
            if out[j].startswith(prefix):
                last = j
            elif out[j].strip():
                break
        out.insert(last + 1, prefix + member)
        break
    return out


def _ensure_group_field(block_lines: list[str], key: str, value: str) -> list[str]:
    """确保组块带指定字段（如 exclude-type / exclude-filter）。"""
    out = list(block_lines)
    for i, line in enumerate(out):
        if re.match(rf"^\s+{re.escape(key)}\s*:", line):
            indent = line[: len(line) - len(line.lstrip())]
            out[i] = f"{indent}{key}: {value}"
            return out
    for i, line in enumerate(out):
        if re.match(r"^\s+type\s*:", line):
            indent = line[: len(line) - len(line.lstrip())]
            out.insert(i + 1, f"{indent}{key}: {value}")
            return out
    return out


def inject_mihomo_openvpn(
    config_text: str,
    openvpn_names: list[str],
    group: str = OPENVPN_AI_GROUP,
    dial_group: str = MIHOMO_AUTO_GROUP,
    auto_group: str = MIHOMO_AUTO_GROUP,
    main_group: str = "🚀 节点选择",
    final_group: str = "🐟 漏网之鱼",
    direct_group: str = "🎯 全球直连",
) -> str:
    """插入 AI 手动组，并让自动选择组排除 openvpn 与 AI 组自身。"""
    if not openvpn_names:
        return config_text
    lines, eol = _split_eol(config_text)
    start, end = _top_section(lines, "proxy-groups")
    blocks = _proxy_group_blocks(lines, start, end)

    rebuilt: list[str] = []
    for name, block in blocks.items():
        group_lines = lines[block["start"] : block["end"]]
        if name == auto_group:
            group_lines = _ensure_group_field(group_lines, "exclude-type", '"openvpn"')
            group_lines = _ensure_group_field(
                group_lines, "exclude-filter", f'"{group}"'
            )
        elif name in (main_group, final_group):
            group_lines = _append_member_to_block(group_lines, group)
        rebuilt.extend(group_lines)

    rebuilt.extend(
        [
            "",
            f"  - name: {group}",
            "    type: select",
            "    proxies:",
            *[f"      - {name}" for name in openvpn_names],
            f"      - {dial_group}",
            f"      - {direct_group}",
        ]
    )

    new_lines = lines[: start + 1] + rebuilt + lines[end:]
    return inject_mihomo_ai_rules(eol.join(new_lines), group)


def inject_mihomo_ai_rules(config_text: str, group: str) -> str:
    """插入 AI 规则集 provider 与 RULE-SET 规则，命中走 OpenVPN 手动组。"""
    lines, eol = _split_eol(config_text)

    start, end = _top_section(lines, "rule-providers")
    has_provider = any(
        re.match(rf"^\s+{re.escape(MIHOMO_AI_RULE_TAG)}\s*:", line)
        for line in lines[start:end]
    )
    if not has_provider:
        provider = [
            f"  {MIHOMO_AI_RULE_TAG}:",
            "    type: http",
            "    behavior: classical",
            "    format: yaml",
            f'    url: "{MIHOMO_AI_RULE_URL}"',
            f"    path: ./ruleset/{MIHOMO_AI_RULE_TAG}.yaml",
            "    interval: 86400",
        ]
        lines[end:end] = provider

    start, end = _top_section(lines, "rules")
    rule_text = f"RULE-SET,{MIHOMO_AI_RULE_TAG},{group}"
    if not any(line.strip() == f"- {rule_text}" for line in lines[start:end]):
        insert_at = start + 1
        for i in range(start + 1, end):
            if "bm7ads" in lines[i]:
                insert_at = i + 1
        lines.insert(insert_at, f"  - {rule_text}")

    return eol.join(lines)


def inject_singbox_openvpn(
    config: dict,
    openvpn_endpoints: list[dict],
    group: str = OPENVPN_AI_GROUP,
    dial_group: str = SINGBOX_DIAL_GROUP,
    main_group: str = "🚀代理",
) -> None:
    """在 sing-box 配置里追加 openvpn-client endpoint 与手动选择组。"""
    if not openvpn_endpoints:
        return
    endpoints = config.setdefault("endpoints", [])
    endpoints.extend(openvpn_endpoints)

    outbounds = config.setdefault("outbounds", [])
    tags = {item.get("tag") for item in outbounds} | {
        item.get("tag") for item in endpoints
    }
    if group not in tags:
        outbounds.append(
            {
                "type": "selector",
                "tag": group,
                "outbounds": [item["tag"] for item in openvpn_endpoints]
                + [dial_group, "DIRECT"],
                "default": openvpn_endpoints[0]["tag"],
            }
        )

    for item in outbounds:
        if item.get("tag") != main_group:
            continue
        children = item.setdefault("outbounds", [])
        if group not in children:
            children.append(group)
        break

    route = config.setdefault("route", {})
    rule_sets = route.setdefault("rule_set", [])
    if not any(item.get("tag") == SINGBOX_AI_RULE_TAG for item in rule_sets):
        rule_sets.append(
            {
                "type": "remote",
                "tag": SINGBOX_AI_RULE_TAG,
                "url": SINGBOX_AI_RULE_URL,
                "http_client": "ruleset-download",
                "update_interval": "24h",
            }
        )

    rules = route.setdefault("rules", [])
    if not any(
        isinstance(item, dict) and item.get("rule_set") == SINGBOX_AI_RULE_TAG
        for item in rules
    ):
        insert_at = len(rules)
        for i, item in enumerate(rules):
            if isinstance(item, dict) and item.get("rule_set") == "geosite-cn":
                insert_at = i
                break
        rules.insert(insert_at, {"rule_set": SINGBOX_AI_RULE_TAG, "outbound": group})


@register_converter(
    "mihomo",
    "wg/masque → mihomo(clash.meta) 完整配置",
    default_output="sub.yaml",
)
class MihomoConverter(BaseConverter):
    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        add_protocol_source_args(parser)
        add_output_arg(parser, self.default_output)
        add_protocol_arg(parser)
        add_mtu_arg(parser)
        add_limit_arg(parser, 80)
        add_amnezia_arg(parser)
        add_openvpn_args(parser)

    def run(self, args: argparse.Namespace) -> None:
        neutral = collect_nodes_by_protocol(args)
        nodes = [
            wg_node_to_mihomo(node)
            if node["kind"] == "wg"
            else masque_node_to_mihomo(node)
            for node in neutral
        ]
        names = [str(node["name"]) for node in nodes]

        openvpn_nodes: list[dict] = []
        if args.with_openvpn:
            openvpn_nodes = [
                openvpn.to_mihomo_proxy(node)
                for node in fetch_openvpn_neutral(args, set(names))
            ]
            for node in openvpn_nodes:
                node["dialer-proxy"] = MIHOMO_AUTO_GROUP
            nodes.extend(openvpn_nodes)

        check_node_budget(len(nodes))
        proxy_lines = [f"  - {json.dumps(node, ensure_ascii=False)}" for node in nodes]
        config_text = build_clash_config(proxy_lines)
        if openvpn_nodes:
            config_text = inject_mihomo_openvpn(
                config_text,
                [str(node["name"]) for node in openvpn_nodes],
                group=args.openvpn_group,
            )
        save_config(
            args,
            config_text,
            len(nodes),
            node_kind_label(args, bool(openvpn_nodes)),
        )


# ---- clash-rs 配置类转换器 ---------------------------------------------------


def wg_node_to_clashrs(node: dict[str, Any]) -> dict[str, Any]:
    """中性 WireGuard 节点 → clash-rs type=wireguard。

    clash-rs 的 ip/ipv6 要求 CIDR 格式（与 mihomo 的裸地址不同），因此保留
    wg-config.conf 地址自带的 /32、/128 位宽。
    """
    ipv4_str = ipv6_str = ""
    for addr in node["addresses"]:
        if ip_version(addr.split("/")[0]) == "IPv4":
            ipv4_str = addr
            break
    for addr in node["addresses"]:
        if ip_version(addr.split("/")[0]) == "IPv6":
            ipv6_str = addr
            break
    proxy: dict[str, Any] = {
        "name": node["name"],
        "type": "wireguard",
        "server": node["server"],
        "port": node["port"],
        "ip": ipv4_str or WG_FALLBACK_ADDRESS,
        "private-key": node["private_key"],
        "public-key": node["public_key"],
        "udp": True,
        "mtu": node["mtu"],
        "remote-dns-resolve": True,
        "dns": list(WG_DNS_SERVERS),
    }
    if ipv6_str:
        proxy["ipv6"] = ipv6_str
    return proxy


def _replace_group_proxies_placeholder(
    block_lines: list[str], names: list[str]
) -> list[str]:
    """把组块内的 proxies: [] 占位替换为实际节点名列表。"""
    out = list(block_lines)
    for i, line in enumerate(out):
        if not re.match(r"^\s+proxies\s*:\s*\[\s*\]\s*$", line):
            continue
        indent = " " * (len(line) - len(line.lstrip()))
        out[i : i + 1] = [f"{indent}proxies:"] + [
            f"{indent}  - {name}" for name in names
        ]
        return out
    return out


def build_clashrs_config(proxy_lines: list[str], names: list[str]) -> str:
    """clash-rs 模板注入：clash-rs 不支持 include-all，除顶层 proxies 占位外，
    还需把节点写入 ♻️ 自动选择 组的 proxies:[] 占位，并追加到 🚀 节点选择 组。"""
    ensure_readable_file(DIR_CLASHRS_TEMPLATE)
    template = DIR_CLASHRS_TEMPLATE.read_text(encoding="utf-8")
    if not template.strip():
        raise ValueError("配置模板文件为空")
    replacement = "proxies:\n" + "\n".join(proxy_lines)
    text = CLASH_TEMPLATE_NODE_PLACEHOLDER.sub(lambda _: replacement, template, count=1)
    lines, eol = _split_eol(text)
    start, end = _top_section(lines, "proxy-groups")
    blocks = _proxy_group_blocks(lines, start, end)
    if MIHOMO_AUTO_GROUP not in blocks or "🚀 节点选择" not in blocks:
        raise RuntimeError(
            "clash-rs 模板缺少 🚀 节点选择 / ♻️ 自动选择 组，无法注入节点"
        )
    rebuilt: list[str] = []
    for name, block in blocks.items():
        group_lines = lines[block["start"] : block["end"]]
        if name == MIHOMO_AUTO_GROUP:
            group_lines = _replace_group_proxies_placeholder(group_lines, names)
        elif name == "🚀 节点选择":
            for member in names:
                group_lines = _append_member_to_block(group_lines, member)
        rebuilt.extend(group_lines)
    return eol.join(lines[: start + 1] + rebuilt + lines[end:])


@register_converter(
    "clashrs",
    "wg → clash-rs 完整配置（不支持 masque/AmneziaWG）",
    default_output="sub.yaml",
)
class ClashRsConverter(BaseConverter):
    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        add_source_args(parser, self.default_source)
        add_output_arg(parser, self.default_output)
        add_mtu_arg(parser)
        add_limit_arg(parser, 80)
        # 有意不声明 --protocol / --amnezia：clash-rs 仅支持 wg 且无 AmneziaWG
        # 混淆，订阅表单据此自动冻结协议与混淆选项

    def run(self, args: argparse.Namespace) -> None:
        # collect_wg_nodes 读取 args.amnezia；clash-rs 不支持混淆，固定禁用
        args.amnezia = None
        nodes = collect_wg_nodes(args)
        for node in nodes:
            node["name"] = node_name(
                node.pop("no"), node.pop("src_total"), node["server"], node["port"]
            )
        check_node_budget(len(nodes))
        nodes = [wg_node_to_clashrs(node) for node in nodes]
        names = [str(node["name"]) for node in nodes]
        proxy_lines = [f"  - {json.dumps(node, ensure_ascii=False)}" for node in nodes]
        config_text = build_clashrs_config(proxy_lines, names)
        save_config(args, config_text, len(names), "wg")


# ---- sing-box 配置类转换器 --------------------------------------------------


def fill_singbox_selector_names(config: dict, names: list[str]) -> None:
    """把模板中 selector/urltest 的 {all} 占位替换为实际节点名。"""
    for item in config.get("outbounds", []):
        if (
            isinstance(item, dict)
            and SINGBOX_SELECTOR_PLACEHOLDER in item.get("outbounds", [])
            and item.get("type") in ("selector", "urltest")
        ):
            item["outbounds"].remove(SINGBOX_SELECTOR_PLACEHOLDER)
            item["outbounds"].extend(names)


def load_singbox_template() -> dict:
    """读取并解析 sing-box 模板配置文件。"""
    ensure_readable_file(DIR_SINGBOX_TEMPLATE)
    with open(DIR_SINGBOX_TEMPLATE, mode="r", encoding="utf-8") as rf:
        return json.load(rf)


@register_converter(
    "singbox", "wg/masque → sing-box 完整配置", default_output="sub.json"
)
class SingBoxConverter(BaseConverter):
    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        add_protocol_source_args(parser)
        add_output_arg(parser, self.default_output)
        add_protocol_arg(parser)
        add_mtu_arg(parser)
        add_limit_arg(parser, 50)
        add_amnezia_arg(parser)
        add_openvpn_args(parser)

    def run(self, args: argparse.Namespace) -> None:
        neutral = collect_nodes_by_protocol(args)
        endpoints = [
            wg_node_to_singbox(node) for node in neutral if node["kind"] == "wg"
        ]
        outbounds_nodes = [
            masque_node_to_singbox(node) for node in neutral if node["kind"] == "masque"
        ]
        names = [str(item["tag"]) for item in endpoints] + [
            str(item["tag"]) for item in outbounds_nodes
        ]

        openvpn_endpoints: list[dict] = []
        if args.with_openvpn:
            openvpn_endpoints = [
                openvpn.to_singbox_endpoint(node, str(node["name"]), SINGBOX_DIAL_GROUP)
                for node in fetch_openvpn_neutral(args, set(names))
            ]

        check_node_budget(len(names) + len(openvpn_endpoints))

        config = load_singbox_template()
        config.setdefault("endpoints", []).extend(endpoints)
        config.setdefault("outbounds", []).extend(outbounds_nodes)
        fill_singbox_selector_names(config, names)
        if openvpn_endpoints:
            inject_singbox_openvpn(config, openvpn_endpoints, group=args.openvpn_group)
        save_config(
            args,
            json.dumps(config, ensure_ascii=False, indent=2),
            len(names) + len(openvpn_endpoints),
            node_kind_label(args, bool(openvpn_endpoints)),
        )


import web_ui  # 展示层独立模块：订阅页面 + 网页实时转换


def add_serve_args(parser: argparse.ArgumentParser, with_serve: bool) -> None:
    """注册订阅页面参数；转换子命令带 --server 开关，独立 server 子命令不带。"""
    if with_serve:
        parser.add_argument(
            "--server",
            action="store_true",
            help="转换完成后启动本地订阅页面（默认关闭）",
        )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="订阅页面监听地址（默认 127.0.0.1 仅本机；0.0.0.0 会暴露到局域网，sub 内容含私钥，慎用）",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=web_ui.SUB_PAGE_PORT,
        help=f"订阅页面端口（默认 {web_ui.SUB_PAGE_PORT}）",
    )


# ============================================================================
# 第九部分 命令行入口
# ============================================================================


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG_NAME,
        description="cfwarp-converter：把 Cloudflare WARP（WireGuard/MASQUE）配置转换成第三方代理软件的节点链接或完整配置。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "- WireGuard 协议\n"
            f"  {PROG_NAME} nekoray --source csv\n"
            f"  {PROG_NAME} v2rayn  --source csv\n"
            f"  {PROG_NAME} nyamebox  --source csv\n"
            f"  {PROG_NAME} nyamebox  --source csv --amnezia\n"
            f"  {PROG_NAME} throne  --source csv\n"
            f"  {PROG_NAME} throne  --source csv --amnezia\n"
            f"  {PROG_NAME} hiddify --source csv --amnezia\n"
            f"  {PROG_NAME} singbox --source csv\n"
            f"  {PROG_NAME} singbox --source csv --amnezia\n"
            f"  {PROG_NAME} mihomo  --source csv\n"
            f"  {PROG_NAME} mihomo  --source csv --amnezia\n"
            f"  {PROG_NAME} clashrs --source csv\n"
            f"  {PROG_NAME} sn     --source csv --limit 50\n"
            "- MASQUE 协议\n"
            f"  {PROG_NAME} mihomo  --protocol masque --source txt\n"
            f"  {PROG_NAME} singbox --protocol masque --source txt\n"
            f"  {PROG_NAME} hiddify --protocol masque\n"
            "- wg+masque 对半混合\n"
            f"  {PROG_NAME} mihomo  --protocol mix --limit 20\n"
            f"  {PROG_NAME} throne  --source csv --protocol mix\n"
            f"  {PROG_NAME} hiddify --protocol mix --limit 20\n"
            "- OpenVPN(VPN Gate) 注入（默认关闭；openvpn 手动组不自动测速）\n"
            f"  {PROG_NAME} mihomo  --source csv --with-openvpn --openvpn-limit 10\n"
            f"  {PROG_NAME} singbox --protocol masque --with-wg 5 --with-openvpn --no-ipv6\n"
            "- 本地订阅页面 (网页展示 sub.txt/sub.yaml/sub.json 内容)\n"
            f"  {PROG_NAME} server\n"
            f"  {PROG_NAME} server --host 0.0.0.0\n"
            f"  {PROG_NAME} throne --source csv --server\n"
            f"  {PROG_NAME} (不带参数等同 server)\n"
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True, metavar="子命令")
    for name, converter_cls in CONVERTERS.items():
        sub = subparsers.add_parser(
            name, help=converter_cls.help_text, description=converter_cls.help_text
        )
        sub.set_defaults(converter=converter_cls)
        converter_cls().fill_parser(sub)
        add_serve_args(sub, with_serve=True)
    server_parser = subparsers.add_parser(
        "server",
        help="启动本地订阅页面，网页展示 sub.txt/sub.yaml/sub.json 内容",
        description="启动本地 HTTP 服务，在网页上实时展示 exe 同目录的 sub.txt/sub.yaml/sub.json 内容。重新执行转换命令更新文件后，刷新网页即最新内容。",
    )
    add_serve_args(server_parser, with_serve=False)
    return parser


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if not argv:
        # 不带参数运行（如双击 exe）时，默认启动本地订阅页面服务
        argv = ["server"]
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "server":
            web_ui.server_sub_page(args.host, args.port)
        else:
            args.converter().run(args)
            if args.server:
                web_ui.server_sub_page(args.host, args.port)
    except KeyboardInterrupt:
        print("\n已取消。")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
