#!/usr/bin/env python3.11

# 注意：刚注册，可能的不生效，要等一会才账户才生效！
import argparse
import base64
import json
import secrets
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

# PyInstaller 打包后 __file__ 指向 _internal 临时目录，需改用 exe 所在目录
IS_FROZEN = getattr(sys, "frozen", False)
BASE_DIR = (
    Path(sys.executable).resolve().parent
    if IS_FROZEN
    else Path(__file__).resolve().parent
)

DEFAULT_MASQUE_OUTPUT = BASE_DIR / "配置文件" / "masque-config.json"
DEFAULT_WG_OUTPUT = BASE_DIR / "配置文件" / "wg-config.conf"


class CloudflareRegistrationBase:
    def __init__(self):
        self.api_url = "https://api.cloudflareclient.com/v0a4471"
        self.headers = {
            "User-Agent": "WARP for Android",
            "CF-Client-Version": "a-6.35-4471",
            "Content-Type": "application/json; charset=UTF-8",
            "Accept": "application/json",
        }
        self.timeout = 15

    @staticmethod
    def generate_wg_keypair():
        """一次生成 WireGuard 密钥对，避免私钥 Base64 后再解码回对象算公钥。"""
        private_obj = x25519.X25519PrivateKey.generate()
        private_key = base64.b64encode(
            private_obj.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ).decode()
        public_key = base64.b64encode(
            private_obj.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode()
        return private_key, public_key

    def _request(self, method, path, headers=None, **kwargs):
        response = requests.request(
            method,
            f"{self.api_url}{path}",
            headers=headers or self.headers,
            timeout=self.timeout,
            **kwargs,
        )
        if not response.ok:
            raise requests.HTTPError(
                f"HTTP {response.status_code}: {response.text}", response=response
            )
        return response

    def enable_warp(self, device_id, token):
        """新注册设备默认 warp_enabled=false，必须显式启用才能建立隧道。"""
        headers = {**self.headers, "Authorization": f"Bearer {token}"}
        data = self._request(
            "PATCH", f"/reg/{device_id}", headers=headers, json={"warp_enabled": True}
        ).json()
        if not data.get("warp_enabled"):
            raise ValueError("设备未能启用 WARP（warp_enabled 仍为 false）")
        return data

    @staticmethod
    def _parse_ttl(account):
        ttl = (account or {}).get("ttl")
        if not ttl:
            return None
        try:
            return datetime.strptime(str(ttl)[:19], "%Y-%m-%dT%H:%M:%S").replace(
                tzinfo=UTC
            )
        except ValueError:
            return None

    @classmethod
    def ttl_local(cls, account):
        """把 account.ttl 转成本地时间字符串，供写入配置文件。"""
        ttl = (account or {}).get("ttl")
        expire = cls._parse_ttl(account)
        if expire is None:
            return str(ttl) if ttl else ""
        return expire.astimezone().strftime("%Y-%m-%d %H:%M:%S")

    @classmethod
    def describe_ttl(cls, account):
        """account.ttl 只在 POST /reg 响应下发，GET/PATCH 不回显，属服务端只读字段。"""
        ttl = (account or {}).get("ttl")
        if not ttl:
            return "未知（接口未返回 ttl）"
        expire = cls._parse_ttl(account)
        if expire is None:
            return str(ttl)
        days = (expire - datetime.now(UTC)).days
        return f"{ttl}（本地 {cls.ttl_local(account)}，剩余约 {days} 天）"

    def write_output(self, text):
        """写入配置前创建父目录，并备份同名旧文件，避免设备 ID/私钥被静默覆盖。"""
        path = Path(self.output_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            backup = path.with_name(path.name + ".bak")
            backup.write_bytes(path.read_bytes())
            print(f"[!] 检测到已有配置文件，已备份到 {backup}")
        path.write_text(text, encoding="utf-8")

    def register_device(self, public_key, tunnel_type="wireguard"):
        tos = (
            datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        )
        registration = {
            "key": public_key,
            "install_id": str(uuid.uuid4()),
            "fcm_token": "",
            "tos": tos,
            "model": "PC",
            "serial_number": secrets.token_hex(8),
            "os_version": "",
            "key_type": "curve25519",
            "tunnel_type": tunnel_type,
        }
        return self._request("POST", "/reg", json=registration).json()


class MasqueConfigGenerator(CloudflareRegistrationBase):
    def __init__(self, output_file=DEFAULT_MASQUE_OUTPUT):
        super().__init__()
        # Cloudflare 默认的 MASQUE 节点公钥 (固定值)
        self.CF_ENDPOINT_PUB_KEY = (
            "-----BEGIN PUBLIC KEY-----\n"
            "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIaU7MToJm9NKp8YfGxR6r+/h4mcG\n"
            "7SxI8tsW8OR1A5tv/zCzVbCRRh2t87/kxnP6lAy0lkr7qYwu+ox+k3dr6w==\n"
            "-----END PUBLIC KEY-----\n"
        )
        self.output_file = output_file

    def generate_keys(self):
        """生成 WireGuard 注册用的 WG 密钥和 MASQUE 用的 P-256 密钥"""
        # WireGuard Key（仅取公钥用于基础注册，私钥 MASQUE 流程不需要）
        _, wg_pub = self.generate_wg_keypair()

        # P-256 Key (MASQUE)
        ec_priv_obj = ec.generate_private_key(ec.SECP256R1())
        # usque sends the public key as ASN.1 PKIX/SubjectPublicKeyInfo DER.
        ec_pub = base64.b64encode(
            ec_priv_obj.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).decode()
        # 导出为 SEC1/传统 EC 私钥
        ec_priv = base64.b64encode(
            ec_priv_obj.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        ).decode()

        return wg_pub, ec_pub, ec_priv

    def run(self, verbose=True):
        """verbose=False 时不打印完整配置（含私钥/Token），仅提示保存路径。"""
        wg_pub, ec_pub, ec_priv = self.generate_keys()

        # 1. 基础注册
        print("[*] 正在向 Cloudflare 注册新设备...")
        try:
            res1 = self.register_device(wg_pub)
        except (requests.RequestException, ValueError) as e:
            print(f"[-] 注册请求失败: {e}")
            return False

        try:
            device_id = res1["id"]
            token = res1["token"]
        except (ValueError, KeyError, TypeError) as e:
            print(f"[-] 注册响应格式无效: {e}")
            return False

        # 2. 升级到 MASQUE
        auth_headers = {**self.headers, "Authorization": f"Bearer {token}"}
        enroll_data = {
            "key": ec_pub,
            "key_type": "secp256r1",
            "tunnel_type": "masque",
            "name": f"MASQUE-{secrets.token_hex(4)}",
            "warp_enabled": True,
        }

        print("[*] 正在开启 MASQUE 协议并获取 IP 分配...")
        try:
            res2 = self._request(
                "PATCH", f"/reg/{device_id}", headers=auth_headers, json=enroll_data
            ).json()
            if not res2.get("warp_enabled"):
                res2 = self.enable_warp(device_id, token)
        except (requests.RequestException, ValueError) as e:
            print(f"[-] MASQUE 升级失败: {e}")
            return False

        account = res2.get("account", {})
        warp_plus = account.get("warp_plus", False)
        quota = account.get("quota", 0)
        print(
            f"[OK] WARP 已启用: {res2.get('warp_enabled')}, "
            f"Warp+ 账户: {warp_plus}, quota(配额): {quota}"
        )
        print(f"[OK] 账户有效期(ttl): {self.describe_ttl(res1.get('account', {}) or account)}")

        try:
            peer = res2["config"]["peers"][0]
            endpoint = peer["endpoint"]
            endpoint_v4 = endpoint["v4"].rsplit(":", 1)[0]
            endpoint_v6 = endpoint["v6"]
            if endpoint_v6.startswith("[") and "]" in endpoint_v6:
                endpoint_v6 = endpoint_v6[1 : endpoint_v6.index("]")]
            elif endpoint_v6.endswith(":0"):
                endpoint_v6 = endpoint_v6[:-2]
        except (KeyError, IndexError, TypeError, AttributeError) as e:
            print(f"[-] 注册响应缺少有效的 MASQUE 端点: {e}")
            return False

        # 3. 构造输出的格式
        # 节点公钥优先取接口返回值（CF 轮换密钥时不会失效），硬编码值仅作兜底
        endpoint_pub_key = peer.get("public_key") or self.CF_ENDPOINT_PUB_KEY
        config_output = {
            "private_key": ec_priv,
            "endpoint_v4": endpoint_v4,
            "endpoint_v6": endpoint_v6,
            "endpoint_h2_v4": endpoint_v4,
            "endpoint_h2_v6": endpoint_v6,
            "endpoint_pub_key": endpoint_pub_key,
            "license": account.get("license", ""),
            "ttl": self.ttl_local(res1.get("account", {}) or account),
            "id": device_id,
            "access_token": token,
            "ipv4": res2.get("config", {})
            .get("interface", {})
            .get("addresses", {})
            .get("v4", ""),
            "ipv6": res2.get("config", {})
            .get("interface", {})
            .get("addresses", {})
            .get("v6", ""),
        }

        config_text = json.dumps(config_output, indent=2)
        try:
            self.write_output(config_text)
        except OSError as error:
            print(f"[-] 写入配置失败: {error}")
            return False

        print("[OK] 注册成功！")
        if verbose:
            print("以下是生成的配置：\n")
            print(config_text)
        print(f"\n[!] masque 配置已保存到 {self.output_file}")
        return True


class WireGuardConfigGenerator(CloudflareRegistrationBase):
    """注册 Cloudflare WireGuard 设备并生成标准 WireGuard 配置。"""

    def __init__(self, output_file=DEFAULT_WG_OUTPUT):
        super().__init__()
        self.output_file = output_file

    @staticmethod
    def _with_prefix(address, prefix):
        address = str(address).strip()
        if not address:
            return ""
        return address if "/" in address else f"{address}/{prefix}"

    @staticmethod
    def _format_endpoint(endpoint):
        endpoint = str(endpoint).strip()
        if not endpoint:
            raise ValueError("注册响应中没有有效的 peer.endpoint")
        if endpoint.startswith("[") or ":" not in endpoint:
            return endpoint
        # IPv6 端点在 WireGuard 配置文件中需要使用方括号
        host, port = endpoint.rsplit(":", 1)
        if ":" not in host:
            return endpoint
        if "]" not in host:
            return f"[{host}]:{port}"
        return endpoint

    @staticmethod
    def _get_endpoint(endpoint_data):
        if isinstance(endpoint_data, dict):
            for field in ("host", "v4", "v6"):
                endpoint = endpoint_data.get(field)
                if endpoint:
                    return endpoint
        elif endpoint_data:
            return endpoint_data
        raise ValueError("注册响应中没有有效的 peer.endpoint")

    @classmethod
    def render_config(cls, response, private_key):
        config = response.get("config", {})
        interface = config.get("interface", {})
        addresses = interface.get("addresses", {})
        peers = config.get("peers", [])
        if not peers:
            raise ValueError("注册响应中没有 WireGuard peer")

        peer = peers[0]
        peer_key = peer.get("public_key") or peer.get("publicKey") or peer.get("key")
        if not peer_key:
            raise ValueError("注册响应中没有 peer 公钥")
        endpoint_data = peer.get("endpoint", {})
        endpoint = cls._format_endpoint(cls._get_endpoint(endpoint_data))
        client_id = config.get("client_id")
        if not client_id:
            raise ValueError("注册响应中没有 config.client_id")

        ipv4 = cls._with_prefix(addresses.get("v4", ""), 32)
        ipv6 = cls._with_prefix(addresses.get("v6", ""), 128)
        interface_addresses = ", ".join(item for item in (ipv4, ipv6) if item)
        allowed_ips = (
            peer.get("allowed_ips") or peer.get("allowedIPs") or ["0.0.0.0/0", "::/0"]
        )
        allowed_ips = ", ".join(str(item) for item in allowed_ips)
        dns = (
            interface.get("dns")
            or config.get("dns")
            or ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"]
        )
        dns = (
            ", ".join(str(item) for item in dns) if isinstance(dns, list) else str(dns)
        )
        mtu = interface.get("mtu") or config.get("mtu") or 1340
        try:
            reserved = list(base64.b64decode(client_id, validate=True))
        except (ValueError, TypeError) as error:
            raise ValueError("config.client_id 不是有效的 Base64") from error
        if not reserved:
            raise ValueError("config.client_id 解码后为空")

        return "\n".join(
            [
                "[Interface]",
                f"PrivateKey = {private_key}",
                f"Address = {interface_addresses}",
                f"DNS = {dns}",
                f"MTU = {mtu}",
                "[Peer]",
                f"PublicKey = {peer_key}",
                f"AllowedIPs = {allowed_ips}",
                f"Endpoint = {endpoint}",
                f"Reserved = {json.dumps(reserved, separators=(', ', ':'))}",
            ]
        )

    def run(self, verbose=True):
        """verbose=False 时不打印完整配置（含私钥），仅提示保存路径。"""
        private_key, public_key = self.generate_wg_keypair()
        print("[*] 正在向 Cloudflare 注册 WireGuard 设备...")
        try:
            response_data = self.register_device(public_key)
            account = response_data.get("account", {})
            self.enable_warp(response_data["id"], response_data["token"])
            print(
                f"[OK] WARP 已启用: True, "
                f"Warp+ 账户: {account.get('warp_plus', False)}, "
                f"Quota(配额): {account.get('quota', 0)}"
            )
            print(f"[OK] 账户有效期(ttl): {self.describe_ttl(account)}")
            config_text = self.render_config(response_data, private_key)
            ttl_local = self.ttl_local(account)
            if ttl_local:
                config_text = config_text.replace(
                    "[Interface]",
                    f"[Interface]\n# 账户有效期(ttl): {ttl_local}（本地时间）",
                    1,
                )
        except (requests.RequestException, ValueError, KeyError, TypeError) as error:
            print(f"[-] WireGuard 注册失败: {error}")
            return False

        print("[OK] WireGuard 注册成功！")
        if verbose:
            print("以下是生成的配置：\n")
            print(config_text)

        try:
            self.write_output(config_text)
        except OSError as error:
            print(f"[-] 写入配置失败: {error}")
            return False
        print(f"\n[!] WireGuard 配置已保存到 {self.output_file}")
        return True


def select_generator(input_func=input):
    """读取并校验协议选择，返回对应的生成器实例。"""
    options = {
        "1": MasqueConfigGenerator,
        "masque": MasqueConfigGenerator,
        "2": WireGuardConfigGenerator,
        "wireguard": WireGuardConfigGenerator,
        "wg": WireGuardConfigGenerator,
    }

    while True:
        try:
            choice = (
                input_func(
                    "请选择注册的协议类型 (1: masque, 2: wireguard，q: 退出，"
                    "-h 查看命令行用法): "
                )
                .strip()
                .lower()
            )
        except (EOFError, KeyboardInterrupt):
            print("\n已取消注册。")
            return None

        if choice in ("q", "quit", "exit"):
            print("已取消注册。")
            return None

        generator_class = options.get(choice)
        if generator_class is not None:
            return generator_class()

        print("输入无效，请输入 1、2、masque、wireguard 或 q。")


CANONICAL_TYPES = {
    "masque": "masque",
    "mq": "masque",
    "wireguard": "wireguard",
    "wg": "wireguard",
}

TYPE_ALIASES = {
    "masque": (MasqueConfigGenerator, DEFAULT_MASQUE_OUTPUT),
    "wireguard": (WireGuardConfigGenerator, DEFAULT_WG_OUTPUT),
}


def parse_type(value):
    key = str(value).strip().lower()
    if key not in CANONICAL_TYPES:
        raise argparse.ArgumentTypeError(
            f"不支持的协议类型 {value!r}，可选 masque、mq、wireguard、wg"
        )
    return CANONICAL_TYPES[key]


def build_parser():
    parser = argparse.ArgumentParser(
        prog=Path(sys.argv[0]).name,
        description="注册 Cloudflare WARP 设备并生成 masque / WireGuard 配置。",
        epilog=(
            "不传 --type 时进入交互菜单；传 --type 时直接注册并写入文件，"
            "适合脚本或计划任务调用。返回码 0=成功，1=失败。"
        ),
    )
    parser.add_argument(
        "--type",
        "-t",
        type=parse_type,
        metavar="masque|wireguard",
        help="协议类型（masque/mq 或 wireguard/wg），省略则进入交互菜单",
    )
    parser.add_argument(
        "--output",
        "-o",
        metavar="PATH",
        help="输出文件路径，默认 配置文件/masque-config.json 或 wg-config.conf",
    )
    parser.add_argument(
        "--show",
        action="store_true",
        help="命令行模式下同时打印完整配置（默认只提示保存路径）",
    )
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.type is None:
        generator = select_generator()
        if generator is None:
            return 0
        if args.output:
            generator.output_file = Path(args.output)
        return 0 if generator.run() else 1

    generator_class, default_output = TYPE_ALIASES[args.type]
    generator = generator_class(
        output_file=Path(args.output) if args.output else default_output
    )
    return 0 if generator.run(verbose=args.show) else 1


if __name__ == "__main__":
    sys.exit(main())
