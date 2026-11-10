#!/usr/bin/env python3
"""cfwarp-converter 命令行工具。

把 Cloudflare WARP 的两种传输 (WireGuard / MASQUE) 配置，转换成第三方代理软件
可用的节点分享链接或完整配置文件。每个子命令都支持 csv/txt 两种优选 IP 数据源。

子命令与协议：
    nekoray    wg → nekoray://custom# 分享链接，NekoBox (原4.0.1 - Throne 4.2.7 2024年历史版本)
    sn         wg → sn://wg? 分享链接（Android NekoBox）
    v2rayn     wg → wireguard:// 链接（v2rayN / v2rayNG），有bug，导不入v2rayNG
    nyamebox   wg → wg:// 链接（NyameBox / ⌈lblis NekoBox⌋ ）
    throne     wg/masque → Throne 分享链接，Throne新版本
    mihomo     wg/masque → mihomo 完整配置
    singbox    wg/masque → sing-box(-lx) 完整配置
    server     启动本地订阅页面，网页展示 sub.txt/sub.yaml/sub.json 内容

--protocol 支持两位简写与全称: wg|wireguard、mq|masque。

统一约定：
    * MTU 通过 --mtu 指定（省略则用配置文件值或协议默认值 wg=1340 / masque=1361），取值 1280~1500；
    * 节点/分组别名统一为「【01】ip(port)」，SN 链接因不支持中文改用「[01]」；
    * CLI命令执行的输出文件默认生成在脚本所在目录。

用法示例：
    python main.py --help
    python main.py throne --source csv --amnezia
    python main.py mihomo --protocol mq --source csv --limit 30
    python main.py singbox --protocol masque --source txt
    python main.py nekoray --source csv --server
    python main.py server
    python main.py            （不带参数 = 同 server，启动本地订阅页面）
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
from urllib.parse import quote

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
DIR_SINGBOX_TEMPLATE = BASE_DIR / "配置文件" / "sing-box.json"
DIR_RESULT_CSV = BASE_DIR / "result.csv"
DIR_IP_TXT = BASE_DIR / "ip.txt"

WG_FALLBACK_PUBLIC_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
WG_FALLBACK_PRIVATE_KEY = "+HfkMSyh7obEkX4J8Qa7Xk77CLVn45AW4CdBbnFNaGc="
WG_FALLBACK_ADDRESS = "172.16.0.2/32"

# CSV（result.csv）延迟筛选阈值（ms）
CSV_MAX_DELAY_MS = 500

# 统一的协议默认 MTU：wg=1340、masque=1361
# （仅在配置文件里没有 MTU 且未用 --mtu 指定时生效）
DEFAULT_MTU_WG = 1340
DEFAULT_MTU_MASQUE = 1361

# AmneziaWG 常量与工具在 amnezia.py（见顶部 import）。

# MASQUE 节点统一的 TLS SNI
MASQUE_SERVER_NAME = "consumer-masque.cloudflareclient.com"

# mihomo / sing-box 模板里的占位节点（与 配置文件/clash.yaml、sing-box.json 对应）
# 正则容忍冒号后与方括号内的 0 个或多个空格
# （proxies:[]、proxies: []、proxies:    []、proxies: [ ]、proxies:[   ]）
CLASH_TEMPLATE_NODE_PLACEHOLDER = re.compile(
    r"^proxies:[ \t]*\[[ \t]*\][ \t]*\r?$", re.MULTILINE
)
SINGBOX_SELECTOR_PLACEHOLDER = "{all}"

# nekoray v4.0.1 自定义节点 JSON 模板（占位符：#local_address、#MUT值、#peer_public_key、#private_key、别名、IP地址、端口）
NEKORAY_CUSTOM_JSON_TEMPLATE = (
    '{"_v":0,"addr":"127.0.0.1","cmd":[""],"core":"internal","cs":"{\\n  \\"interface_name\\": '
    '\\"WARP\\",\\n  \\"local_address\\": #local_address,\\n'
    '  \\"mtu\\": #MUT值,\\n  \\"peer_public_key\\": \\"#peer_public_key\\",\\n  \\"private_key\\":'
    ' \\"#private_key\\",\\n  \\"server\\": \\"IP地址\\",\\n  \\"server_port\\": 端口,\\n  '
    '\\"system_interface\\": false,\\n  \\"tag\\": \\"proxy\\",\\n  \\"type\\": \\"wireguard'
    '\\"\\n}","mapping_port":0,"name":"别名","port":1080,"socks_port":0}'
)


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

# --protocol 取值别名：支持两位简写与全称
PROTOCOL_ALIASES = {"wg": "wg", "wireguard": "wg", "mq": "masque", "masque": "masque"}


def protocol_type(value: str) -> str:
    """把 --protocol 取值归一化为内部名（wg / masque）。"""
    key = value.strip().lower()
    if key in PROTOCOL_ALIASES:
        return PROTOCOL_ALIASES[key]
    raise argparse.ArgumentTypeError(
        f"未知协议 {value!r}，可选：wg / wireguard / mq / masque"
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


def add_output_arg(parser: argparse.ArgumentParser, default_output: str) -> None:
    parser.add_argument(
        "--output", default=None, help=f"输出文件路径（默认：{default_output}）"
    )


def add_protocol_arg(parser: argparse.ArgumentParser, default: str = "wg") -> None:
    parser.add_argument(
        "--protocol",
        type=protocol_type,
        default=default,
        metavar="{wg|wireguard|mq|masque}",
        help=f"节点协议：wg/wireguard=WireGuard，mq/masque=MASQUE（默认：{default}）",
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
        base_str = self._build_base_template(profile, mtu)

        endpoints = load_endpoints(resolve_source_path(args))
        total = len(endpoints)
        lines = []
        for i, ep in enumerate(endpoints[: args.limit]):
            # 写入 JSON 的 server 需去掉 IPv6 中括号
            remarks = node_name(i + 1, total, ep.host_bare, ep.port)
            node = (
                base_str.replace("别名", remarks)
                .replace("IP地址", ep.host_bare)
                .replace("端口", ep.port)
            )
            lines.append(
                "nekoray://custom#"
                + base64.b64encode(node.encode(), altchars=b"-_").decode()
            )
        save_links(args, lines, "nekoray")

    @staticmethod
    def _build_base_template(profile: WgProfile, mtu: int) -> str:
        addresses = profile.addresses or [WG_FALLBACK_ADDRESS]
        # Address 有多个值（一般 IPv4 CIDR + IPv6 CIDR）与单个值的格式不同
        if len(addresses) > 1:
            local_address = (
                r"[\n" + ",".join(rf"    \"{item}\"" for item in addresses) + r"\n  ]"
            )
        else:
            local_address = rf"\"{addresses[0]}\""
        peer_public_key = (profile.public_key or "").strip()
        private_key = (profile.private_key or "").strip()
        return (
            NEKORAY_CUSTOM_JSON_TEMPLATE.replace("#peer_public_key", peer_public_key)
            .replace("#private_key", private_key)
            .replace("#local_address", local_address)
            .replace("#MUT值", str(mtu))
        )


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
        for i, ep in enumerate(endpoints[: args.limit]):
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
        if args.protocol == "masque":
            self._run_masque(args)
        else:
            self._run_wg(args)

    def _run_wg(self, args: argparse.Namespace) -> None:
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
        for i, ep in enumerate(endpoints[: args.limit], start=1):
            remarks = node_name(i + 1, total, ep.host_bare, ep.port)
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
        save_links(args, lines, "Throne(wg)")

    def _run_masque(self, args: argparse.Namespace) -> None:
        config = load_masque_config()
        mtu = resolve_mtu(args.mtu, None, DEFAULT_MTU_MASQUE)
        endpoints = load_endpoints(resolve_source_path(args))
        links = []
        for i, ep in enumerate(endpoints[: args.limit], start=1):
            ip, port = ep.host_bare, int(ep.port)
            name = node_name(i, len(endpoints), ip, port)
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
        save_links(args, links, "Throne(masque)", trailing_newline=False)


@register_converter(
    "nyamebox",
    "wg → wg:// 分享链接（NyameBox / NekoBox）",
    default_output="sub.txt",
)
class NyameBoxConverter(BaseConverter):
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

        endpoints = load_endpoints(resolve_source_path(args))
        total = len(endpoints)
        lines = []
        for i, ep in enumerate(endpoints[: args.limit]):
            remarks = node_name(i + 1, total, ep.host_bare, ep.port)
            lines.append(
                f"wg://{ep.host}:{ep.port}?private_key={quote(private_key)}"
                f"&peer_public_key={quote(public_key)}"
                f"&persistent_keepalive=0&mtu={quote(str(mtu))}"
                f"&use_system_interface=false"
                f"&local_address={'-'.join(addresses)}#{quote(remarks)}"
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
        for i, ep in enumerate(endpoints[: args.limit]):
            remarks = node_name(i + 1, total, ep.host_bare, ep.port)
            lines.append(
                f"wireguard://{quote(private_key, safe='')}@{ep.host}:{ep.port}?"
                f"&address={quote(addr, safe='')}&presharedkey="
                f"&reserved={quote(reserved, safe='')}"
                f"&publickey={quote(public_key, safe='')}"
                f"&dns={quote('1.1.1.1,1.0.0.1,2606:4700:4700::1111,2606:4700:4700::1001', safe='')}"
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


@register_converter(
    "mihomo",
    "wg/masque → mihomo(clash.meta) 完整配置",
    default_output="sub.yaml",
)
class MihomoConverter(BaseConverter):
    def fill_parser(self, parser: argparse.ArgumentParser) -> None:
        add_source_args(parser, self.default_source)
        add_output_arg(parser, self.default_output)
        add_protocol_arg(parser)
        add_mtu_arg(parser)
        add_limit_arg(parser, 80)
        add_amnezia_arg(parser)

    def run(self, args: argparse.Namespace) -> None:
        if args.protocol == "masque":
            self._run_masque(args)
        else:
            self._run_wg(args)

    def _run_wg(self, args: argparse.Namespace) -> None:
        profile = load_wg_profile()
        private_key, public_key, addresses = read_conf_with_fallback(profile)
        mtu = resolve_mtu(args.mtu, profile.mtu, DEFAULT_MTU_WG)
        amnezia_random, amnezia_fixed = amnezia_mode(args.amnezia)

        # mihomo 的 wireguard 节点需拆分 IPv4 / IPv6 地址
        ipv4_str, ipv6_str = "", ""
        if addresses:
            ipv4_addr = addresses[0].split("/")[0]
            ipv4_str = ipv4_addr if ip_version(ipv4_addr) == "IPv4" else "172.16.0.2"
            if len(addresses) > 1:
                ipv6_addr = addresses[1].split("/")[0]
                ipv6_str = ipv6_addr if ip_version(ipv6_addr) == "IPv6" else ""

        endpoints = load_endpoints(resolve_source_path(args))

        proxy_lines = []
        for i, ep in enumerate(endpoints[: args.limit]):
            proxy_name = node_name(i + 1, len(endpoints), ep.host_bare, ep.port)
            node = {
                "name": proxy_name,
                "type": "wireguard",
                "server": ep.host_bare,
                "port": int(ep.port),
                "ip": ipv4_str,
                "ipv6": ipv6_str,
                "private-key": private_key,
                "public-key": public_key,
                # "reserved": "",
                "udp": True,
                "mtu": mtu,
                "remote-dns-resolve": True,
                "dns": [
                    "1.1.1.1",
                    "1.0.0.1",
                    "2606:4700:4700::1111",
                    "2606:4700:4700::1001",
                ],
            }
            params = generate_amnezia_params() if amnezia_random else amnezia_fixed
            if params:
                node["amnezia-wg-option"] = amnezia_config_fields(params)
            proxy_lines.append(f"  - {json.dumps(node, ensure_ascii=False)}")


        save_config(
            args,
            build_clash_config(proxy_lines),
            len(proxy_lines),
            "wg",
            default_name="sub.yaml",
        )

    def _run_masque(self, args: argparse.Namespace) -> None:
        config = load_masque_config()
        mtu = resolve_mtu(args.mtu, None, DEFAULT_MTU_MASQUE)
        endpoints = load_endpoints(resolve_source_path(args))
        proxy_lines = []
        for i, ep in enumerate(endpoints[: args.limit], start=1):
            ip, port = ep.host_bare, int(ep.port)
            name = node_name(i, len(endpoints), ip, port)
            node = {
                "name": name,
                "type": "masque",
                "server": ip,
                "port": port,
                "private-key": config.private_key,
                "public-key": config.public_key,
                "ip": config.ipv4,
                "ipv6": config.ipv6,
                "mtu": mtu,
                "udp": True,
                "remote-dns-resolve": True,
                "dns": [
                    "1.1.1.1",
                    "1.0.0.1",
                    "2606:4700:4700::1111",
                    "2606:4700:4700::1001",
                ],
            }
            proxy_lines.append(f"  - {json.dumps(node, ensure_ascii=False)}")

        save_config(
            args,
            build_clash_config(proxy_lines),
            len(proxy_lines),
            "masque",
            default_name="sub.yaml",
        )


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
        add_source_args(parser, self.default_source)
        add_output_arg(parser, self.default_output)
        add_protocol_arg(parser)
        add_mtu_arg(parser)
        add_limit_arg(parser, 50)
        add_amnezia_arg(parser)

    def run(self, args: argparse.Namespace) -> None:
        if args.protocol == "masque":
            self._run_masque(args)
        else:
            self._run_wg(args)

    def _run_wg(self, args: argparse.Namespace) -> None:
        profile = load_wg_profile()
        private_key = profile.private_key or WG_FALLBACK_PRIVATE_KEY
        public_key = profile.public_key or WG_FALLBACK_PUBLIC_KEY
        addresses = profile.addresses or [WG_FALLBACK_ADDRESS]
        mtu = resolve_mtu(args.mtu, profile.mtu, DEFAULT_MTU_WG)
        # reserved = profile.reserved_list
        amnezia_random, amnezia_fixed = amnezia_mode(args.amnezia)
        endpoints = load_endpoints(resolve_source_path(args))

        nodes, names = [], []
        for i, ep in enumerate(endpoints[: args.limit]):
            proxy_name = node_name(i + 1, len(endpoints), ep.host_bare, ep.port)
            node = {
                "type": "wireguard",
                "tag": proxy_name,
                "mtu": mtu,
                "address": addresses,
                "private_key": private_key,
                "peers": [
                    {
                        "address": ep.host_bare,
                        "port": int(ep.port),
                        "public_key": public_key,
                        "allowed_ips": ["0.0.0.0/0", "::/0"],
                        # "reserved": reserved,
                    }
                ],
            }
            params = generate_amnezia_params() if amnezia_random else amnezia_fixed
            if params:
                node.update(amnezia_config_fields(params, snake_case=True))
            names.append(proxy_name)
            nodes.append(node)

        config = load_singbox_template()
        fill_singbox_selector_names(config, names)
        config.setdefault("endpoints", []).extend(nodes)
        save_config(
            args,
            json.dumps(config, ensure_ascii=False, indent=2),
            len(nodes),
            "wg",
            default_name="sub.json",
        )

    def _run_masque(self, args: argparse.Namespace) -> None:
        masque = load_masque_config()
        mtu = resolve_mtu(args.mtu, None, DEFAULT_MTU_MASQUE)
        endpoints = load_endpoints(resolve_source_path(args))
        nodes, names = [], []
        for i, ep in enumerate(endpoints[: args.limit], start=1):
            ip, port = ep.host_bare, int(ep.port)
            name = node_name(i, len(endpoints), ip, port)
            nodes.append(
                {
                    "type": "masque",
                    "tag": name,
                    "server": ip,
                    "server_port": port,
                    "profile": "cloudflare",
                    "vhttp": "auto",
                    "private_key": masque.private_key,
                    "public_key": masque.public_key,
                    "ip": masque.ipv4,
                    "ipv6": masque.ipv6,
                    "mtu": mtu,
                    "tls": {"enabled": True, "server_name": MASQUE_SERVER_NAME},
                }
            )
            names.append(name)

        config = load_singbox_template()
        fill_singbox_selector_names(config, names)
        config.setdefault("outbounds", []).extend(nodes)
        save_config(
            args,
            json.dumps(config, ensure_ascii=False, indent=2),
            len(nodes),
            "masque",
            default_name="sub.json",
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
        description="cfwarp-converter：把 Cloudflare WARP（WireGuard / MASQUE）配置转换成第三方代理软件的节点链接或完整配置。",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "示例：\n"
            "- WireGuard 协议\n"
            f"  {PROG_NAME} nekoray --source csv\n"
            f"  {PROG_NAME} v2rayn  --source csv\n"
            f"  {PROG_NAME} throne  --source csv\n"
            f"  {PROG_NAME} throne  --source csv --amnezia\n"
            f"  {PROG_NAME} singbox --source csv\n"
            f"  {PROG_NAME} singbox --source csv --amnezia\n"
            f"  {PROG_NAME} mihomo  --source csv\n"
            f"  {PROG_NAME} mihomo  --source csv --amnezia\n"
            f"  {PROG_NAME} sn     --source csv --limit 50\n"
            "- MASQUE 协议\n"
            f"  {PROG_NAME} mihomo  --protocol masque --source txt\n"
            f"  {PROG_NAME} singbox --protocol masque --source txt\n"
            "- 本地订阅页面 (网页展示 sub.txt/sub.yaml/sub.json 内容)\n"
            f"  {PROG_NAME} server\n"
            f"  {PROG_NAME} server --host 0.0.0.0\n"
            f"  {PROG_NAME} nekoray --source csv --server\n"
            f"  {PROG_NAME}    (不带参数等同 server)\n"
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
