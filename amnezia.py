#!/usr/bin/env python3
"""amnezia.py —— warp_convert.py 专用的 AmneziaWG 参数模块

包含：
  - 常量：AMNEZIA_DEFAULT / AMNEZIA_RANDOM / AMNEZIA_INT_KEYS
  - CLI 开关注册：add_amnezia_arg
  - 解析 / 下发：amnezia_mode / amnezia_config_fields
  - 每节点随机生成：generate_amnezia_params（含真实加密的 QUIC v1 Initial 构造）

QUIC 加密用 RFC 9001（HKDF + AES-128-GCM AEAD + AES-ECB header protection），
依赖第三方库 cryptography；HKDF 用标准库 hashlib/hmac。
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import random
import re

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _HAVE_CRYPTO = True
except ImportError:  # 未安装 cryptography 时无法生成 QUIC 形态参数
    _HAVE_CRYPTO = False

__all__ = [
    "AMNEZIA_DEFAULT",
    "AMNEZIA_INT_KEYS",
    "AMNEZIA_RANDOM",
    "add_amnezia_arg",
    "amnezia_config_fields",
    "amnezia_mode",
    "generate_amnezia_params",
    "parse_amnezia_params",
    "resolve_amnezia_params",
]

# ============================================================================
# 常量
# ============================================================================

# --amnezia 带值时，先在此默认值上叠加命令行传入的同名键；i1 用下方位模板
AMNEZIA_DEFAULT = (
    "jc=120&jmin=23&jmax=911&h1=1&h2=2&h3=3&h4=4&i1=<b 0x"
    "c2000000011419fa4bb3599f336777de79f81ca9a8d80d91eeec000044c635cef024a885dcb66d1420"
    "a91a8c427e87d6cf8e08b563932f449412cddf77d3e2594ea1c7a183c238a89e9adb7ffa57c133e55"
    "c59bec101634db90afb83f75b19fe703179e26a31902324c73f82d9354e1ed8da39af610afcb27e659"
    "0a44341a0828e5a3d2f0e0f7b0945d7bf3402feea0ee6332e19bdf48ffc387a97227aa97b205a485d282"
    "cd66d1c384bafd63dc42f822c4df2109db5b5646c458236ddcc01ae1c493482128bc0830c9e1233f0027"
    "a0d262f92b49d9d8abd9a9e0341f6e1214761043c021d7aa8c464b9d865f5fbe234e49626e007120317"
    "03a3e23ef82975f014ee1e1dc428521dc23ce7c6c13663b19906240b3efe403cf30559d798871557e4e6"
    "0e86c29ea4504ed4d9bb8b549d0e8acd6c334c39bb8fb42ede68fb2aadf00cfc8bcc12df03602bbd4fe7"
    "01d64a39f7ced112951a83b1dbbe6cd696dd3f15985c1b9fef72fa8d0319708b633cc4681910843ce753"
    "fac596ed9945d8b839aeff8d3bf0449197bd0bb22ab8efd5d63eb4a95db8d3ffc796ed5bcf2f4a136a8a"
    "36c7a0c65270d511aebac733e61d414050088a1c3d868fb52bc7e57d3d9fd132d78b740a6ecdc6c24936"
    "e92c28672dbe00928d89b891865f885aeb4c4996d50c2bbbb7a99ab5de02ac89b3308e57bcecf13f2da0"
    "333d1420e18b66b4c23d625d836b538fc0c221d6bd7f566a31fa292b85be96041d8e0bfe655d5dc1afed"
    "23eb8f2b3446561bbee7644325cc98d31cea38b865bdcc507e48c6ebdc7553be7bd6ab963d5a14615c4b8"
    "1da7081c127c791224853e2d19bafdc0d9f3f3a6de898d14abb0e2bc849917e0a599ed4a541268ad0e60"
    "ea4d147dc33d17fa82f22aa505ccb53803a31d10a7ca2fea0b290a52ee92c7bf4aab7cea4e3c07b19893"
    "64eed87a3c6ba65188cd349d37ce4eefde9ec43bab4b4dc79e03469c2ad6b902e28e0bbbbf696781ad4e"
    "df424ffb35ce0236d373629008f142d04b5e08a124237e03e3149f4cdde92d7fae581a1ac332e26b2c9c"
    "1a6bdec5b3a9c7a2a870f7a0c25fc6ce245e029b686e346c6d862ad8df6d9b62474fbc31dbb914711f78"
    "074d4441f4e6e9edca3c52315a5c0653856e23f681558d669f4a4e6915bcf42b56ce36cb7dd3983b0b1"
    "d6fdf0f8efddb68e7ca0ae9dd4570fe6978fbb524109f6ec957ca61f1767ef74eb803b0f16abd0087cf2"
    "d01bc1db1c01d97ac81b3196c934586963fe7cf2d310e0739621e8bd00dc23fded18576d8c8f285d7bb5"
    "f43b547af3c76235de8b6f757f817683b2151600b11721219212bf27558edd439e73fce951f61d582320e"
    "5f4d6c315c71129b719277fc144bbe8ded25ab6d29b6e189c9bd9b16538faf60cc2aab3c3bb81fc22136"
    "57f2dd0ceb9b3b871e1423d8d3e8cc008721ef03b28e0ee7bb66b8f2a2ac01ef88df1f21ed49bf1ce435"
    "df31ac34485936172567488812429c269b49ee9e3d99652b51a7a614b7c460bf0d2d64d8349ded7345be"
    "dab1ea0a766a8470b1242f38d09f7855a32db39516c2bd4bcc538c52fa3a90c8714d4b006a15d9c7a7d0"
    "4919a1cab48da7cce0d5de1f9e5f8936cffe469132991c6eb84c5191d1bcf69f70c58d9a7b66846440a9"
    "f0eef25ee6ab62715b50ca7bef0bc3013d4b62e1639b5028bdf757454356e9326a4c76dabfb497d451a3"
    "a1d2dbd46ec283d255799f72dfe878ae25892e25a2542d3ca9018394d8ca35b53ccd94947a8>"
)
# --amnezia 不带值时的哨兵：表示「每个节点各随机一套参数」
AMNEZIA_RANDOM = "\x00random\x00"
# 需要按整数写入配置文件（mihomo/sing-box）的键；i1~i5 等保持字符串
AMNEZIA_INT_KEYS = frozenset(
    {"jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "version"}
)


# ============================================================================
# QUIC v1 Initial（真实加密，RFC 9001）
# ============================================================================

# Initial 用固定 salt 从 DCID 派生密钥（RFC 9001 §5.2）
_QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _quic_varint(value: int) -> bytes:
    """QUIC 可变长度整数编码（RFC 9000 §16）。"""
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return (value | 0x4000).to_bytes(2, "big")
    if value < 0x40000000:
        return (value | 0x80000000).to_bytes(4, "big")
    return (value | 0xC000000000000000).to_bytes(8, "big")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, block, counter = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        out += block
        counter += 1
    return out[:length]


def _hkdf_expand_label(
    secret: bytes, label: bytes, context: bytes, length: int
) -> bytes:
    """RFC 8446 §7.1 的 HKDF-Expand-Label（label 前加 "tls13 "）。"""
    full_label = b"tls13 " + label
    info = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return _hkdf_expand(secret, info, length)


def _aes_ecb_encrypt(key: bytes, data: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def build_quic_initial(
    rng: random.Random, version: int = 0x00000001, size: int = 1200, jitter: int = 32
) -> str:
    """构造一个真实加密的 QUIC v1 Initial 长头包，返回 HEX 字节串（RFC 9001）。

    固定身份：首字节（长头 + Initial + pn_len）、version；随机：DCID/SCID、
    packet number、加密 padding、长度（size ± jitter）。payload 为全 PADDING（合法 frames），
    可被标准 QUIC 解析器解密校验通过。
    """
    if not _HAVE_CRYPTO:
        raise RuntimeError(
            "生成 QUIC 形态参数需要 cryptography 库：pip install cryptography"
        )

    total = size + (rng.randint(0, jitter) if jitter else 0)
    dcid = bytes(
        rng.randrange(256) for _ in range(8)
    )  # v1 客户端 Initial DCID ≥ 8 字节
    scid = bytes(rng.randrange(256) for _ in range(8))
    pn_len = 4
    pn = rng.randrange(1, 1 << (8 * pn_len))
    pn_bytes = pn.to_bytes(pn_len, "big")
    first = 0xC0 | (0 << 4) | (pn_len - 1)  # long header + Initial

    header = bytearray([first])
    header += version.to_bytes(4, "big")
    header.append(len(dcid))
    header += dcid
    header.append(len(scid))
    header += scid
    header += _quic_varint(0)  # Token Length = 0
    base = bytes(header)

    tag_len = 16
    length_bytes = _quic_varint(pn_len + 1 + tag_len)
    plaintext_len = 1
    for _ in range(4):  # 迭代使 Length varint 稳定
        cipher_len = total - len(base) - len(length_bytes) - pn_len
        plaintext_len = max(cipher_len - tag_len, 1)
        new_length = _quic_varint(pn_len + plaintext_len + tag_len)
        if new_length == length_bytes:
            break
        length_bytes = new_length

    header_no_pn = base + length_bytes
    aad = header_no_pn + pn_bytes  # AAD = 未受保护的头部

    initial_secret = _hkdf_extract(_QUIC_V1_SALT, dcid)
    client_secret = _hkdf_expand_label(initial_secret, b"client in", b"", 32)
    key = _hkdf_expand_label(client_secret, b"quic key", b"", 16)
    iv = _hkdf_expand_label(client_secret, b"quic iv", b"", 12)
    hp = _hkdf_expand_label(client_secret, b"quic hp", b"", 16)

    plaintext = b"\x00" * plaintext_len  # 全 PADDING：合法 QUIC frames
    nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

    sample = ciphertext[:16]  # sample 取 pn_offset+4 起 16 字节
    hp_mask = _aes_ecb_encrypt(hp, sample)
    protected_first = header_no_pn[0] ^ (hp_mask[0] & 0x0F)
    protected_pn = bytes(b ^ hp_mask[1 + i] for i, b in enumerate(pn_bytes))
    return (
        bytes([protected_first]) + header_no_pn[1:] + protected_pn + ciphertext
    ).hex()


def generate_amnezia_params(
    *,
    jc_range: tuple[int, int] = (4, 12),
    jmin_range: tuple[int, int] = (1, 64),
    jmax_range: tuple[int, int] = (128, 1200),
    quic_version: int = 0x00000001,
    quic_size: int = 1200,
    quic_jitter: int = 32,
    rng: random.Random | None = None,
) -> dict[str, str]:
    """随机生成一套 WARP 可用的 AmneziaWG 参数，返回有序 dict。

    默认 H1~H4=1/2/3/4（WARP 兼容）、无 S；随机 Jc/Jmin/Jmax；i1、i2 为真实加密的
    QUIC v1 Initial（标签语法 `<b 0x..>`）。每次调用都产生不同结果，适合给**每个节点**各生成一套。
    """
    rng = rng or random.SystemRandom()
    params: dict[str, str] = {}

    params["jc"] = str(rng.randint(*jc_range))
    jmin = rng.randint(*jmin_range)
    params["jmin"] = str(jmin)
    params["jmax"] = str(rng.randint(max(jmax_range[0], jmin), jmax_range[1]))
    params.update({"h1": "1", "h2": "2", "h3": "3", "h4": "4"})

    params["i1"] = (
        f"<b 0x{build_quic_initial(rng, quic_version, quic_size, quic_jitter)}>"
    )
    params["i2"] = (
        f"<b 0x{build_quic_initial(rng, quic_version, quic_size, quic_jitter)}>"
    )
    return params


# ============================================================================
# CLI 开关 / 解析 / 下发
# ============================================================================


def add_amnezia_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--amnezia",
        nargs="?",
        const=AMNEZIA_RANDOM,
        default=None,
        metavar="KEY=VALUE&...",
        help="启用 AmneziaWG 混淆（仅 wg 协议）：省略=禁用；不带值=每个节点"
        '各随机生成一套参数；带值形如 "jc=120&jmin=23&i1=..."=所有节点'
        "共用这套固定参数",
    )


def parse_amnezia_params(value: str) -> dict[str, str]:
    """把 'jc=120&jmin=23&i1=...' 解析为字典（& 或 , 分隔）。"""
    params: dict[str, str] = {}
    for item in re.split(r"[&,]", value):
        key, sep, val = item.partition("=")
        key = key.strip()
        if sep and key:
            params[key] = val.strip()
    return params


def resolve_amnezia_params(value: str | None) -> dict[str, str]:
    """省略 --amnezia 时返回 {}；否则用默认参数打底，再叠加命令行传入的同名键。"""
    if value is None:
        return {}
    params = parse_amnezia_params(AMNEZIA_DEFAULT)
    params.update(parse_amnezia_params(value))
    params.pop("enable_amnezia", None)  # 仅 wg:// 链接使用的标记，不写入各端配置
    return params


def amnezia_mode(value: str | None) -> tuple[bool, dict[str, str]]:
    """解析 --amnezia 取值：返回 (是否每节点随机, 固定参数字典)。

    None → (False, {}) 禁用；AMNEZIA_RANDOM → (True, {}) 每个节点各随机一套；
    其它字符串 → (False, 解析后的固定参数)。
    """
    if value is None:
        return False, {}
    if value == AMNEZIA_RANDOM:
        return True, {}
    return False, resolve_amnezia_params(value)


def amnezia_config_fields(
    params: dict[str, str], snake_case: bool = False
) -> dict[str, object]:
    """按目标端键名风格与类型，转成可直接写入 wg 节点的字段字典。"""
    fields: dict[str, object] = {}
    for key, val in params.items():
        base = key.replace("_", "-")
        name = base.replace("-", "_") if snake_case else base
        if base in AMNEZIA_INT_KEYS:
            try:
                fields[name] = int(val)
                continue
            except ValueError:
                pass
        fields[name] = val
    return fields
