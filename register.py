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
(BASE_DIR / "配置文件").mkdir(exist_ok=True)


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
        response = requests.post(
            f"{self.api_url}/reg",
            headers=self.headers,
            json=registration,
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()


class MasqueConfigGenerator(CloudflareRegistrationBase):
    def __init__(self, output_file=BASE_DIR / "配置文件" / "masque-config.json"):
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
        # WireGuard Key
        wg_priv_obj = x25519.X25519PrivateKey.generate()
        wg_pub = base64.b64encode(
            wg_priv_obj.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode()

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

    def run(self):
        wg_pub, ec_pub, ec_priv = self.generate_keys()

        # 1. 基础注册
        print("[*] 正在向 Cloudflare 注册新设备...")
        try:
            res1 = self.register_device(wg_pub)
        except requests.RequestException as e:
            print(f"[-] 注册请求失败: {e}")
            return

        try:
            device_id = res1["id"]
            token = res1["token"]
        except (ValueError, KeyError, TypeError) as e:
            print(f"[-] 注册响应格式无效: {e}")
            return

        # 2. 升级到 MASQUE
        auth_headers = {**self.headers, "Authorization": f"Bearer {token}"}
        enroll_data = {
            "key": ec_pub,
            "key_type": "secp256r1",
            "tunnel_type": "masque",
            "name": f"MASQUE-{secrets.token_hex(4)}",
        }

        print("[*] 正在开启 MASQUE 协议并获取 IP 分配...")
        try:
            r2 = requests.patch(
                f"{self.api_url}/reg/{device_id}",
                headers=auth_headers,
                json=enroll_data,
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            print(f"[-] MASQUE 升级请求失败: {e}")
            return
        if r2.status_code != 200:
            print(f"[-] 升级失败: {r2.text}")
            return

        try:
            res2 = r2.json()
            # print(res2)
            warp_plus = res2.get("account", {}).get("warp_plus", False)
            print(f"[OK] Warp+ 账户: {warp_plus}, quota(配额): 0")
        except ValueError as e:
            print(f"[-] 升级响应格式无效: {e}")
            return

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
            return

        # 3. 构造输出的格式
        config_output = {
            "private_key": ec_priv,
            "endpoint_v4": endpoint_v4,
            "endpoint_v6": endpoint_v6,
            "endpoint_h2_v4": endpoint_v4,
            "endpoint_h2_v6": endpoint_v6,
            "endpoint_pub_key": self.CF_ENDPOINT_PUB_KEY,
            "license": res2.get("account", {}).get("license", ""),
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

        print("[OK] 注册成功！以下是生成的配置：\n")
        print(json.dumps(config_output, indent=2))

        with open(self.output_file, "w", encoding="utf-8") as f:
            json.dump(config_output, f, indent=2)
        print(f"\n[!] masque 配置已保存到 {self.output_file}")


class WireGuardConfigGenerator(CloudflareRegistrationBase):
    """注册 Cloudflare WireGuard 设备并生成标准 WireGuard 配置。"""

    def __init__(self, output_file=BASE_DIR / "配置文件" / "wg-config.conf"):
        super().__init__()
        self.output_file = output_file

    @staticmethod
    def generate_private_key():
        private_key = x25519.X25519PrivateKey.generate()
        return base64.b64encode(
            private_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ).decode()

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

    def run(self):
        private_key = self.generate_private_key()
        private_key_obj = x25519.X25519PrivateKey.from_private_bytes(
            base64.b64decode(private_key)
        )
        public_key = base64.b64encode(
            private_key_obj.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ).decode()
        print("[*] 正在向 Cloudflare 注册 WireGuard 设备...")
        try:
            response_data = self.register_device(public_key)
            # print(response_data)
            warp_plus = response_data.get("account", {}).get("warp_plus", False)
            print(f"[OK] Warp+ 账户: {warp_plus}, Quota(配额): 0")
            config_text = self.render_config(response_data, private_key)
        except (requests.RequestException, ValueError, KeyError, TypeError) as error:
            print(f"[-] WireGuard 注册失败: {error}")
            return
        print("[OK] 注册成功！以下是生成的配置：\n")
        print(config_text)
        with open(self.output_file, "w", encoding="utf-8") as config_file:
            config_file.write(config_text)
        print(f"\n[!] WireGuard 配置已保存到 {self.output_file}")


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
                input_func("请选择注册的协议类型 (1: masque, 2: wireguard，q: 退出): ")
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


if __name__ == "__main__":
    generator = select_generator()
    if generator is not None:
        generator.run()
