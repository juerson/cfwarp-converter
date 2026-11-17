#!/usr/bin/env python3.11

"""本地订阅页面 + 网页订阅链接生成（独立展示层模块）。

main.py 只 import 本模块并调用 server_sub_page()；CLI 转换命令不经过本模块。

设计要点：
- 首页（/）内嵌两个订阅链接生成表单（订阅链接生成 + OpenVPN）：选择客户端与参数，
  点击生成后页面下方显示可复制的订阅 URL（左侧二维码、右侧链接，纯前端拼参数，不跳转）。
- 两个表单行为一致：切换客户端即恢复默认（默认值统一放在控件的 data-default 属性，
  JS 一键还原）；参数改动后已生成的链接标记为过期。
- 该 URL 是订阅链接：客户端或浏览器打开它时，服务端实时转换一次，以纯文本
  （text/plain）返回结果——与 /sub.txt 的内容展示格式完全一致，无任何 HTML 包装。
- 转换结果不写任何文件：server_sub_page 启动时把 main.write_text_file 替换为
  线程内收集器（threading.local，按请求线程隔离，响应完即弃），CLI 进程不受影响——
  --server 组合时 CLI 转换发生在补丁生效之前，照常写 sub 文件。
- 服务端无共享状态，每个打开者各自触发各自的转换，互不影响，无锁。
"""

from __future__ import annotations

import argparse
import io
import json
import socket
import sys
import threading
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

try:
    import segno
except ModuleNotFoundError:  # 二维码为可选能力：未安装时订阅页面与转换仍可用
    segno = None

import main
from main import BASE_DIR, CONVERTERS, OPENVPN_AI_GROUP
from openvpn import MAX_OPENVPN_NODES

SUB_PAGE_FILES = ("sub.txt", "sub.yaml", "sub.json")
SUB_PAGE_PATHS = {f"/{name}": name for name in SUB_PAGE_FILES}
SUB_PAGE_PORT = 8790
CONVERT_PAGE = "/convert"
OPENVPN_CONVERT_PAGE = "/convert-openvpn"
OPENVPN_CLIENTS = ("mihomo", "singbox")
QR_MAX_DATA = 1000  # 二维码数据长度上限（QR byte 模式容量的保守值）
QR_SCALE = 4
QR_BORDER = 2
QR_DARK = "#1f2937"


def _qr_svg_bytes(data: str) -> bytes:
    """把文本编码为 SVG 二维码（统一缩放、边框与配色）。"""
    if segno is None:
        raise RuntimeError("二维码功能需要 segno：pip install segno")
    buf = io.BytesIO()
    segno.make(data).save(
        buf, kind="svg", scale=QR_SCALE, border=QR_BORDER, dark=QR_DARK
    )
    return buf.getvalue()


@lru_cache(maxsize=8)
def _qr_data_uri(url: str) -> str:
    """首页内联二维码 data URI：按 URL 缓存，刷新页面不重复编码。"""
    if segno is None:
        raise RuntimeError("二维码功能需要 segno：pip install segno")
    return segno.make(url).svg_data_uri(scale=QR_SCALE, border=QR_BORDER, dark=QR_DARK)


class _FormParser(argparse.ArgumentParser):
    """表单参数解析器：参数错误抛 ValueError，由 HTTP 层返回 400。"""

    def error(self, message: str) -> None:
        raise ValueError(message)


def _build_parsers() -> tuple[dict[str, _FormParser], dict[str, frozenset[str]]]:
    """为每个客户端构建一次参数解析器，并汇总各客户端支持的参数 dest。"""
    parsers: dict[str, _FormParser] = {}
    support: dict[str, frozenset[str]] = {}
    for name, cls in CONVERTERS.items():
        parser = _FormParser(prog=name)
        cls().fill_parser(parser)
        parsers[name] = parser
        support[name] = frozenset(action.dest for action in parser._actions)
    return parsers, support


PARSERS, SUPPORT = _build_parsers()
# dest → 支持该参数的客户端逗号串：渲染为 data-clients 属性，JS 据此切换启用/禁用
FIELD_CLIENTS: dict[str, str] = {}
for _client, _dests in SUPPORT.items():
    for _dest in _dests:
        FIELD_CLIENTS.setdefault(_dest, []).append(_client)
FIELD_CLIENTS = {dest: ",".join(clients) for dest, clients in FIELD_CLIENTS.items()}


def _client_attr(dest: str) -> str:
    clients = FIELD_CLIENTS.get(dest)
    return f' data-clients="{clients}"' if clients else ""


# 约定：控件的默认值统一渲染在 data-default 属性里，切换客户端时 JS 据此还原；
# select 的第一个 option 与 data-default 保持一致，页面初始状态即默认状态。
SUB_PAGE_STYLE = (
    # ---- 设计变量：亮色默认，跟随系统暗色模式 ----
    ":root{--bg:#f4f6fb;--card:#ffffff;--border:#e5e7eb;--text:#1f2937;--muted:#6b7280;"
    "--accent:#2563eb;--accent-hover:#1d4ed8;--accent-soft:#eff6ff;"
    "--field:#ffffff;--field-border:#d1d5db;--shadow:0 1px 3px rgba(15,23,42,.07);"
    "--focus-ring:0 0 0 3px rgba(37,99,235,.18)}"
    "@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--card:#151e31;--border:#2a3650;"
    "--text:#e5eaf3;--muted:#94a3b8;--accent:#3b82f6;--accent-hover:#60a5fa;--accent-soft:#1e2a44;"
    "--field:#0f1830;--field-border:#334155;--shadow:0 1px 3px rgba(0,0,0,.4);"
    "--focus-ring:0 0 0 3px rgba(59,130,246,.25)}}"
    "*{box-sizing:border-box;margin:0}"
    "html{scrollbar-gutter:stable}"
    "body{font-family:system-ui,-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;"
    "background:var(--bg);color:var(--text);padding:32px 16px;-webkit-font-smoothing:antialiased}"
    ".wrap{max-width:860px;margin:0 auto}"
    "h1{font-size:22px;margin-bottom:4px}"
    "h2{font-size:16px;margin:24px 0 10px;display:flex;align-items:center;gap:8px}"
    "h2::before{content:'';width:4px;height:16px;border-radius:2px;background:var(--accent)}"
    ".sub{color:var(--muted);font-size:13px;margin-bottom:16px;line-height:1.6}"
    ".grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:16px}"
    ".card{background:var(--card);border:1px solid var(--border);border-radius:14px;"
    "padding:16px;text-align:center;box-shadow:var(--shadow)}"
    ".card img{width:150px;height:150px;border-radius:10px}"
    ".qrmiss{width:150px;height:150px;display:flex;align-items:center;justify-content:center;"
    "margin:0 auto;background:var(--accent-soft);border-radius:10px;color:var(--muted);font-size:13px}"
    ".qname{font-size:13px;font-weight:600;margin-top:10px}"
    ".qsize{font-size:11px;font-weight:400;color:var(--muted)}"
    "a.qurl{display:block;font-size:11px;color:var(--muted);word-break:break-all;"
    "margin-top:2px;text-decoration:none;transition:color .15s}"
    "a.qurl:hover{color:var(--accent)}"
    ".tip{font-size:12px;color:var(--text);background:var(--accent-soft);"
    "border:1px solid var(--border);border-radius:10px;padding:10px 14px;"
    "margin-bottom:16px;line-height:1.7}"
    ".tip code{background:var(--field);border:1px solid var(--border);border-radius:4px;padding:1px 5px}"
    ".form{background:var(--card);border:1px solid var(--border);border-radius:14px;"
    "padding:18px 20px;display:grid;grid-template-columns:1fr 1fr;gap:12px 16px;"
    "margin-bottom:16px;box-shadow:var(--shadow)}"
    ".form label{font-size:12px;color:var(--muted);display:flex;flex-direction:column;gap:5px}"
    ".form select,.form input{padding:8px 11px;border:1px solid var(--field-border);"
    "border-radius:9px;font-size:14px;color:var(--text);background:var(--field);"
    "transition:border-color .15s,box-shadow .15s;width:100%}"
    ".form select:hover,.form input:hover{border-color:var(--accent)}"
    ".form select:focus,.form input:focus{outline:none;border-color:var(--accent);"
    "box-shadow:var(--focus-ring)}"
    ".form button{grid-column:1/-1;justify-self:center;width:fit-content;"
    "padding:9px 30px;background:var(--accent);color:#fff;border:none;border-radius:10px;"
    "font-size:14px;font-weight:600;cursor:pointer;margin-top:4px;"
    "transition:background .15s,transform .1s,box-shadow .15s}"
    ".form button:hover{background:var(--accent-hover);box-shadow:0 3px 10px rgba(37,99,235,.3)}"
    ".form button:active{transform:translateY(1px)}"
    ".form .chk{flex-direction:row;align-items:center;gap:8px;font-size:13px;"
    "color:var(--text);padding-top:18px}"
    ".form .chk input{width:auto;accent-color:var(--accent)}"
    ".subgen{background:var(--card);border:1px solid var(--border);border-radius:14px;"
    "padding:16px;margin-bottom:16px;box-shadow:var(--shadow)}"
    ".qrerr{color:#ef4444;font-size:12px;margin-top:6px;display:none}"
    ".substale{min-height:130px;display:none;align-items:center;justify-content:center;"
    "text-align:center;color:var(--muted);font-size:13px}"
    ".subrow{display:flex;gap:14px;align-items:center}"
    ".subqr{width:130px;height:130px;flex:none;border-radius:10px}"
    ".suburl{flex:1;word-break:break-all;font-size:12px;font-family:Consolas,monospace;"
    "background:var(--accent-soft);border:1px solid var(--border);border-radius:8px;"
    "padding:10px 12px;cursor:pointer;transition:border-color .15s}"
    ".suburl:hover{border-color:var(--accent)}"
    ".off{opacity:.45}"
    # ---- 小屏自适应：卡片与表单改单列，二维码结果纵向堆叠 ----
    "@media (max-width:640px){.grid{grid-template-columns:1fr}"
    ".form{grid-template-columns:1fr}.subrow{flex-direction:column}}"
)


def sub_page_html(title: str, body: str) -> str:
    """拼接页面完整 HTML（UTF-8 + 手机 viewport + 样式；body 可含 script）。"""
    return (
        '<!DOCTYPE html><html lang="zh"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{title}</title><style>{SUB_PAGE_STYLE}</style></head>"
        f'<body><div class="wrap">{body}</div></body></html>'
    )


def get_lan_ip() -> str | None:
    """取局域网 IP：先探测默认路由出口，失败再枚举本机内网地址（纯本地，不发数据）。"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("223.5.5.5", 80))
        ip = sock.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    finally:
        sock.close()
    try:
        for ip in socket.gethostbyname_ex(socket.gethostname())[2]:
            parts = ip.split(".")
            is_private = ip.startswith(("192.168.", "10.")) or (
                parts[0] == "172" and len(parts) == 4 and 16 <= int(parts[1]) <= 31
            )
            if is_private:
                return ip
    except OSError:
        pass
    return None


# ============================================================================
# 内存输出：server 模式下接管 main.write_text_file，转换结果不落盘
# ============================================================================

_local = threading.local()
_original_write_text_file = main.write_text_file


def _memory_write_text_file(path, text: str) -> None:
    """替换 main.write_text_file：写入当前请求线程的收集器而非磁盘。"""
    sink = getattr(_local, "sink", None)
    if sink is None:
        # 非请求线程（理论上不会发生）：保持原行为，避免静默丢数据
        _original_write_text_file(path, text)
        return
    sink.append(text)


# ============================================================================
# 订阅链接生成表单（首页内嵌；字段从 fill_parser 动态生成，CLI 加参数自动跟随）
# ============================================================================


# 客户端下拉框的显示别名 (value 仍是程序 ID)
CLIENT_ALIASES = {
    "nekoray": "nekoray v4.0.1",
    "sn": "Android NekoBox",
    "throne": "Throne PC/Android",
    "nyamebox": "NyameBox/NekoBox",
    "v2rayn": "v2rayN(G)",
    "mihomo": "mihomo 内核",
    "clashrs": "clash-rs 内核",
    "singbox": "sing-box/sing-box-lx 内核",
    "hiddify": "Hiddify",
}

# 这些客户端的 --source 支持"按协议默认"：留空时 wg=result.csv、masque=ip.txt
PROTOCOL_SOURCE_CLIENTS = {"mihomo", "singbox", "hiddify"}


def _form_fields() -> str:
    """渲染固定字段集；data-clients 声明各参数的可用客户端，JS 按 client 启用/禁用。"""
    options = "".join(
        f'<option value="{name}" data-source="'
        f'{"" if name in PROTOCOL_SOURCE_CLIENTS else CONVERTERS[name].default_source}">'
        f"{name} ({CLIENT_ALIASES.get(name, name)})</option>"
        for name in CONVERTERS
    )
    fields = [
        f'<label>客户端（转换目标）<select name="client" onchange="changeClient()">{options}</select></label>',
        (
            f"<label>协议（按客户端支持）"
            f'<select name="protocol" data-default="wg" onchange="applySupport()"{_client_attr("protocol")}>'
            '<option value="wg">wg</option>'
            '<option value="masque">masque</option>'

            '<option value="mix">wg + masque 混合（对半分配上限）</option></select></label>'
        ),
        (
            f'<label>数据源 <select name="source" data-default=""{_client_attr("source")}>'
            '<option value="">按协议默认（wg=result.csv / masque=ip.txt）</option>'
            '<option value="csv">csv (result.csv)</option>'
            '<option value="txt">txt (ip.txt)</option></select></label>'
        ),
        (
            f'<label class="chk"><input type="checkbox" name="no_ipv6" data-default="0"'
            f"{_client_attr('no_ipv6')}> 剔除 IPv6 数据（csv/txt 通用）</label>"
        ),
        (
            f"<label>AmneziaWG 混淆（wg/awg/mix 协议 + 支持的客户端）"
            f'<select name="amnezia_mode" data-default="off"{_client_attr("amnezia")} data-needs-wg="1">'
            '<option value="off">禁用</option>'
            '<option value="random">每节点随机</option>'
            '<option value="custom">自定义</option></select></label>'
        ),
        (
            f'<label>AmneziaWG 自定义参数 <input type="text" name="amnezia_custom" '
            f'data-default="" placeholder="jc=6&amp;jmin=36&amp;jmax=398（选择自定义时生效）"{_client_attr("amnezia")} '
            f'data-needs-wg="1"></label>'
        ),
        (
            f'<label>节点数上限（留空=各客户端默认）<input type="number" name="limit" '
            f'data-default="" placeholder="默认：全部 / 500 / 80 / 50"{_client_attr("limit")}></label>'
        ),
        (
            f'<label>MTU（1280~1500，留空=配置文件值或协议默认）<input type="number" name="mtu" '
            f'data-default="" placeholder="默认：wg=1340 / masque=1361"{_client_attr("mtu")}></label>'
        ),
    ]
    return "".join(fields)


def _openvpn_form_fields() -> str:
    """OpenVPN 独立区块的字段集；默认值统一放在 data-default，切客户端一键还原。"""
    client_options = "".join(
        f'<option value="{name}">{name} ({CLIENT_ALIASES.get(name, name)})</option>'
        for name in OPENVPN_CLIENTS
    )
    fields = [
        f'<label>客户端（转换目标）<select name="client" onchange="openvpnChangeClient()">{client_options}</select></label>',
        (
            '<label>主协议<select name="mix" data-default="wg" onchange="openvpnMix()">'
            '<option value="wg">全 wg</option>'
            '<option value="masque">全 masque</option>'
            '<option value="mix">wg + masque 混合（对半分配上限）</option></select></label>'
        ),
        (
            '<label>数据源<select name="source" data-default="">'
            '<option value="">按协议默认（wg=result.csv / masque=ip.txt）</option>'
            '<option value="csv">csv (result.csv)</option>'
            '<option value="txt">txt (ip.txt)</option></select></label>'
        ),
        (
            '<label class="chk"><input type="checkbox" name="no_ipv6" data-default="0"> '
            "剔除 IPv6 数据（csv/txt 通用）</label>"
        ),
        (
            '<label>AmneziaWG 混淆（wg 参与时生效）<select name="amnezia_mode" '
            'data-default="off" data-needs-wg="1">'
            '<option value="off">禁用</option>'
            '<option value="random">每节点随机</option>'
            '<option value="custom">自定义</option></select></label>'
        ),
        (
            '<label>混淆自定义参数（选择自定义时生效）<input type="text" name="amnezia_custom" '
            'data-default="" placeholder="jc=6&amp;jmin=36&amp;jmax=398" data-needs-wg="1"></label>'
        ),
        (
            '<label>主协议节点数<input type="number" name="limit" '
            'data-default="30" value="30" min="1" max="150"></label>'
        ),
        (
            f'<label>副协议 OpenVPN 数量（1~{MAX_OPENVPN_NODES}）<input type="number" '
            f'name="openvpn_limit" data-default="10" value="10" min="1" max="{MAX_OPENVPN_NODES}"></label>'
        ),
        (
            '<label>国家代码筛选（逗号分隔）<input type="text" name="countries" '
            'data-default="" placeholder="JP,KR,US（留空=全部）"></label>'
        ),
        (
            f'<label>自定义 OpenVPN 代理组名<input type="text" name="openvpn_group" '
            f'data-default="{OPENVPN_AI_GROUP}" value="{OPENVPN_AI_GROUP}"></label>'
        ),
        (
            '<label>VPN Gate API 地址<input type="text" name="api_url" '
            'data-default="" placeholder="留空=官方接口"></label>'
        ),
        (
            '<label>节点排序<select name="openvpn_sort" data-default="api">'
            '<option value="api">api（接口原序）</option>'
            '<option value="score">score（综合评分）</option>'
            '<option value="ping">ping（延迟优先）</option>'
            '<option value="speed">speed（带宽优先）</option></select></label>'
        ),
        (
            '<label>设置本机代理（用于抓取 VPN Gate 的 openVPN 数据）<input type="text" name="openvpn_proxy" '
            'data-default="" placeholder="http://127.0.0.1:7897（留空=自动探测本机常见端口，无则直连抓取数据）" '
            'title="只支持 HTTP 代理；Clash / v2rayN 的混合端口同一端口同时收 '
            'HTTP 与 socks5，直接填 http://127.0.0.1:端口 即可"></label>'
        ),
    ]
    return "".join(fields)


def _openvpn_form_section() -> str:
    """首页独立的 OpenVPN(VPN Gate) 订阅链接生成区。"""
    return (
        "<h2>【进阶玩法】OpenVPN（VPN Gate）</h2>"
        '<p class="sub">在 wg/masque/wg+masque 订阅配置里面插入 OpenVPN 副协议的节点，流量走指定的网站才启用 OpenVPN</p>'
        '<form class="form" id="ovpnform" oninput="staleForm(\'ovpnform\')" '
        "onchange=\"staleForm('ovpnform')\">"
        f"{_openvpn_form_fields()}"
        '<button type="button" onclick="genOpenvpnLink()">生成订阅链接</button>'
        "</form>"
        '<div class="subgen" id="ovpngen" style="display:none">'
        '<div id="ovpnresult">'
        '<div class="subrow"><img id="ovpnqr" class="subqr" alt="订阅链接二维码">'
        '<code id="ovpnurl" class="suburl" onclick="copySubUrl(\'ovpnurl\')" '
        'title="点击复制订阅链接"></code></div>'
        '<div class="qrerr" id="ovpnqrerr">二维码生成失败（未安装 segno 或链接过长），链接本身仍可使用</div>'
        "</div>"
        '<div class="substale" id="ovpnstale">参数已变更，请点击“生成订阅链接”'
        "重新生成</div>"
        "</div>" + _OPENVPN_FORM_SCRIPT
    )


# 共用脚本：两个表单的结果区结构一致（FORMS 注册表），重置/过期提示通用
_FORM_SCRIPT = """<script>
var QR_BASE=LAN_BASE||window.location.origin;
var FORMS={
  cform:{gen:'subgen',result:'subresult',stale:'substale',qr:'subqr',url:'suburl',err:'qrerr'},
  ovpnform:{gen:'ovpngen',result:'ovpnresult',stale:'ovpnstale',qr:'ovpnqr',url:'ovpnurl',err:'ovpnqrerr'}
};
function staleForm(id){
  var cfg=FORMS[id],gen=document.getElementById(cfg.gen);
  if(!gen||gen.style.display==='none')return;
  document.getElementById(cfg.result).style.display='none';
  document.getElementById(cfg.stale).style.display='flex';
}
function resetForm(id){
  var f=document.getElementById(id);
  f.querySelectorAll('[data-default]').forEach(function(el){
    if(el.name==='client')return;                    // 切换的发起者保持新选择
    if(el.type==='checkbox'){el.checked=el.getAttribute('data-default')==='1';}
    else{el.value=el.getAttribute('data-default');}
  });
  var sel=f.querySelector('[name=client]');
  var src=f.querySelector('[name=source]');
  if(sel&&src&&sel.selectedOptions[0]){              // 数据源默认值跟随客户端
    var ds=sel.selectedOptions[0].getAttribute('data-source');
    if(ds!==null)src.value=ds;
  }
  staleForm(id);                                     // 生成过才提示重新生成，未生成不留空白
}
function collectParams(f,skip){
  var p=new URLSearchParams();
  new FormData(f).forEach(function(v,k){
    if(typeof v!=='string')return;
    if(k==='no_ipv6'){p.append(k,'1');return;}       // checkbox 统一传 1
    v=v.trim();
    if(!v)return;                                    // 空值不写进链接（服务端默认值等价）
    if(skip&&skip(k,v))return;
    p.append(k,v);
  });
  return p;
}
function applySupport(){
  var f=document.getElementById('cform');
  var c=f.querySelector('[name=client]').value;
  var pv=f.querySelector('[name=protocol]').value;
  var wg=(pv==='wg'||pv==='mix');            // 混合模式含 wg 节点，混淆同样生效
  f.querySelectorAll('[data-clients]').forEach(function(el){
    var ok=el.getAttribute('data-clients').split(',').indexOf(c)>=0;
    if(ok&&el.hasAttribute('data-needs-wg')) ok=wg;
    el.disabled=!ok;
    var lb=el.closest('label'); if(lb) lb.classList.toggle('off',!ok);
  });
}
function changeClient(){
  resetForm('cform');
  applySupport();
}
function revealGen(id){
  // 结果块就在生成按钮下方：已在视口内就不滚动；被遮挡时才最小幅度平滑滚入
  var g=document.getElementById(id);
  var r=g.getBoundingClientRect();
  var vh=window.innerHeight||document.documentElement.clientHeight;
  if(r.top<0||r.top>=vh||r.bottom>vh) g.scrollIntoView({behavior:'smooth',block:'nearest'});
}
function genLink(){
  var f=document.getElementById('cform');
  var p=collectParams(f,function(k,v){
    if(k==='amnezia_mode'&&v==='off')return true;    // off 是服务端默认值，省略
    return k==='amnezia_custom'&&f.querySelector('[name=amnezia_mode]').value!=='custom';
  });
  var url=window.location.origin+'/convert?'+p.toString();
  document.getElementById('suburl').textContent=url;
  var img=document.getElementById('subqr');
  var hint=document.getElementById('qrerr');
  img.onload=function(){img.style.visibility='visible';hint.style.display='none';};
  img.onerror=function(){img.style.visibility='hidden';hint.style.display='block';};
  img.style.visibility='hidden';
  img.src='/qr?data='+encodeURIComponent(QR_BASE+'/convert?'+p.toString());
  document.getElementById('subresult').style.display='block';
  document.getElementById('substale').style.display='none';
  document.getElementById('subgen').style.display='block';
  revealGen('subgen');
}
function copySubUrl(id){
  var u=document.getElementById(id||'suburl');
  var t=u.textContent;
  if(!t) return;
  function ok(){u.style.color='#16a34a';setTimeout(function(){u.style.color='';},1200);}
  function fail(){
    u.style.color='#b91c1c';u.title='复制失败，请手动选中链接复制';
    setTimeout(function(){u.style.color='';u.title='点击复制订阅链接';},2000);
  }
  function legacy(){
    var ta=document.createElement('textarea');
    ta.value=t;ta.setAttribute('readonly','');
    ta.style.position='fixed';ta.style.top='-1000px';
    document.body.appendChild(ta);
    ta.focus();
    ta.select();
    ta.setSelectionRange(0,t.length);
    var done=false;
    try{done=document.execCommand('copy');}catch(e){done=false;}
    document.body.removeChild(ta);
    if(done) ok(); else fail();
  }
  // 局域网 http:// 不是安全上下文，navigator.clipboard 不可用，回退 execCommand
  if(window.isSecureContext&&navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(ok,legacy);
  }else{
    legacy();
  }
}
applySupport();
</script>"""


_OPENVPN_FORM_SCRIPT = """<script>
var QR_BASE=LAN_BASE||window.location.origin;
function openvpnMix(){
  var f=document.getElementById('ovpnform');
  if(!f) return;
  var mix=f.querySelector('[name=mix]').value;
  var hasWg=(mix!=='masque');          // AmneziaWG 只要有 wg 参与（全 wg 或混合）就生效
  // 全 masque 时没有 wg 节点，混淆无从谈起，直接禁用
  f.querySelectorAll('[data-needs-wg]').forEach(function(el){
    el.disabled=!hasWg;
    var lb=el.closest('label'); if(lb) lb.classList.toggle('off',!hasWg);
  });
  staleForm('ovpnform');
}
function openvpnChangeClient(){
  resetForm('ovpnform');
  openvpnMix();
}
function genOpenvpnLink(){
  var f=document.getElementById('ovpnform');
  var p=collectParams(f,function(k,v){
    if(k==='amnezia_mode'&&v==='off')return true;    // off 是服务端默认值，省略
    return k==='amnezia_custom'&&f.querySelector('[name=amnezia_mode]').value!=='custom';
  });
  var url=window.location.origin+'/convert-openvpn?'+p.toString();
  document.getElementById('ovpnurl').textContent=url;
  var img=document.getElementById('ovpnqr');
  var hint=document.getElementById('ovpnqrerr');
  img.onload=function(){img.style.visibility='visible';hint.style.display='none';};
  img.onerror=function(){img.style.visibility='hidden';hint.style.display='block';};
  img.style.visibility='hidden';
  img.src='/qr?data='+encodeURIComponent(QR_BASE+'/convert-openvpn?'+p.toString());
  document.getElementById('ovpnresult').style.display='block';
  document.getElementById('ovpnstale').style.display='none';
  document.getElementById('ovpngen').style.display='block';
  revealGen('ovpngen');
}
openvpnMix();
</script>"""


# ============================================================================
# 实时转换（内存直出，零落盘）
# ============================================================================


def _form_argv(client: str, form: dict[str, str]) -> list[str]:
    """把表单字段翻译成 CLI 参数，归一化与类型校验交给 argparse。"""
    supported = SUPPORT[client]
    argv: list[str] = []
    if "protocol" in supported:
        raw_protocol = form.get("protocol", "").strip()
        if raw_protocol:
            argv += ["--protocol", raw_protocol]
    if "source" in supported:
        source = form.get("source", "").strip()
        if source in ("csv", "txt"):
            argv += ["--source", source]
    for name in ("limit", "mtu"):
        if name in supported:
            value = form.get(name, "").strip()
            if value:
                argv += [f"--{name}", value]
    if "no_ipv6" in supported and form.get("no_ipv6"):
        argv.append("--no-ipv6")
    if "amnezia" in supported:
        mode = form.get("amnezia_mode", "off")
        custom = form.get("amnezia_custom", "").strip()
        protocol = form.get("protocol", "").strip() or "wg"
        try:
            has_wg = main.protocol_type(protocol) in ("wg", "mix")
        except argparse.ArgumentTypeError as error:
            raise ValueError(str(error)) from error
        if has_wg:
            if mode == "random":
                argv.append("--amnezia")
            elif mode == "custom" and custom:
                argv += ["--amnezia", custom]
    return argv


def _run_client_in_memory(client: str, argv: list[str]) -> str:
    """按客户端解析 argv 并实时转换一次，结果写内存收集器。"""
    converter_cls = CONVERTERS.get(client)
    if converter_cls is None:
        raise ValueError(
            f"未知客户端：{client or '(未指定)'}，可选：{' / '.join(CONVERTERS)}"
        )
    conv = converter_cls()
    args = PARSERS[client].parse_args(argv)
    args.converter = conv
    # 仅用于日志展示：输出已被内存收集器接管，不会落盘
    args.output = "<内存>"

    _local.sink = []
    try:
        conv.run(args)
    except SystemExit as error:  # die() 用 sys.exit 报错，转为 400 纯文本
        raise ValueError(f"转换参数或配置文件有误（退出码 {error.code}）") from error
    finally:
        chunks = _local.sink
        _local.sink = None
    if not chunks:
        raise RuntimeError("该转换器没有产生任何输出")
    return chunks[-1]


def run_in_memory(form: dict[str, str]) -> str:
    """按现有客户端表单参数实时转换一次，返回结果文本；全程内存，零落盘。"""
    client = form.get("client", "")
    return _run_client_in_memory(client, _form_argv(client, form))


def _openvpn_argv(client: str, form: dict[str, str]) -> list[str]:
    """把 OpenVPN 区块字段翻译成 mihomo / sing-box 的 CLI 参数。"""
    mix = form.get("mix", "wg")
    protocol = {"wg": "wg", "masque": "masque", "mix": "mix"}.get(mix, "wg")
    argv = ["--with-openvpn", "--protocol", protocol]

    source = form.get("source", "")
    if source in ("csv", "txt"):
        argv += ["--source", source]

    limit = form.get("limit", "").strip()
    if limit:
        argv += ["--limit", limit]
    if form.get("no_ipv6"):
        argv.append("--no-ipv6")

    argv += ["--openvpn-limit", form.get("openvpn_limit", "").strip() or "10"]
    for dest in ("countries", "api_url", "openvpn_group", "openvpn_proxy"):
        value = form.get(dest, "").strip()
        if value:
            argv += [f"--{dest.replace('_', '-')}", value]
    sort_mode = form.get("openvpn_sort", "").strip()
    if sort_mode:
        argv += ["--openvpn-sort", sort_mode]

    if mix in ("wg", "mix"):
        mode = form.get("amnezia_mode", "off")
        custom = form.get("amnezia_custom", "").strip()
        if mode == "random":
            argv.append("--amnezia")
        elif mode == "custom" and custom:
            argv += ["--amnezia", custom]

    # 网页请求必须有界：客户端订阅超时远小于 CLI 默认值
    argv += ["--openvpn-timeout", "15", "--openvpn-retries", "2"]
    return argv


def run_openvpn_in_memory(form: dict[str, str]) -> str:
    """OpenVPN 独立区块：实时抓取 VPN Gate 并生成订阅内容。"""
    client = form.get("client", "")
    if client not in OPENVPN_CLIENTS:
        raise ValueError(
            f"OpenVPN 只支持 {' / '.join(OPENVPN_CLIENTS)}，"
            f"当前为：{client or '(未指定)'}"
        )
    return _run_client_in_memory(client, _openvpn_argv(client, form))


# ============================================================================
# HTTP 处理器与启动
# ============================================================================


class SubPageHandler(BaseHTTPRequestHandler):
    """订阅展示 + 订阅链接内容端点的请求处理器。

    路由白名单：/（订阅首页 + 表单）、/convert（订阅链接内容，纯文本）、
    /convert-openvpn（OpenVPN 订阅内容，纯文本）、/qr（按需生成二维码）、
    三个 sub 文件路径；每次请求都重新读文件。
    """

    base_url: str | None = (
        None  # server_sub_page 启动时设置：局域网地址，用于生成二维码
    )

    def do_GET(self) -> None:
        split = urlsplit(self.path)
        path = split.path.rstrip("/") or "/"
        form = dict(parse_qsl(split.query, keep_blank_values=True))
        try:
            if path == "/":
                page = sub_page_html("cfwarp-converter 订阅", self._index_body())
                self._send(page.encode("utf-8"), 200, "text/html; charset=utf-8")
            elif path == CONVERT_PAGE:
                # 订阅链接的内容端点：纯文本直出，与 sub 文件展示格式一致
                try:
                    content = run_in_memory(form)
                except ValueError as error:
                    self._send_text(str(error), 400)
                    return
                except Exception as error:  # noqa: BLE001 - 转换失败也以纯文本返回
                    print(f"[!] 网页转换异常：{error}", flush=True)
                    self._send_text(f"转换失败：{error}", 500)
                    return
                self._send_text(content)
            elif path == OPENVPN_CONVERT_PAGE:
                try:
                    content = run_openvpn_in_memory(form)
                except ValueError as error:
                    self._send_text(str(error), 400)
                    return
                except Exception as error:  # noqa: BLE001 - 转换失败也以纯文本返回
                    print(f"[!] OpenVPN 网页转换异常：{error}", flush=True)
                    self._send_text(f"转换失败：{error}", 500)
                    return
                self._send_text(content)
            elif path == "/qr":
                data = form.get("data", "")
                if not data:
                    self._send_text("missing data", 400)
                    return
                if len(data) > QR_MAX_DATA:
                    self._send_text("data too long", 400)
                    return
                if segno is None:
                    self._send_text("二维码功能需要 segno：pip install segno", 500)
                    return
                self._send(_qr_svg_bytes(data), 200, "image/svg+xml")
            elif path in SUB_PAGE_PATHS:
                name = SUB_PAGE_PATHS[path]
                file_path = BASE_DIR / name
                if file_path.exists():
                    self._send(file_path.read_bytes(), 200, "text/plain; charset=utf-8")
                else:
                    self._send_text(f"{name} 文件不存在，请先执行对应转换命令生成。")
            else:
                self._send_text("404 页面不存在", 404)
        except Exception as error:  # noqa: BLE001 - 页面异常直接回 500，避免连接被硬断
            print(f"[!] 页面生成异常（{path}）：{error}", flush=True)
            self._send_text(f"500 页面生成异常：{error}", 500)

    def _index_body(self) -> str:
        cards = []
        for name in SUB_PAGE_FILES:
            path = BASE_DIR / name
            exists = path.exists()
            if exists and self.base_url and segno is not None:
                qr = _qr_data_uri(f"{self.base_url}/{name}")
                size = path.stat().st_size
                cards.append(
                    f'<div class="card"><img class="qr" src="{qr}" alt="{name} 二维码">'
                    f'<div class="qname">{name}<span class="qsize">（{size:,} 字节）</span></div>'
                    f'<a class="qurl" href="/{name}" target="_blank" rel="noopener" '
                    f'title="点击在新标签页打开">{self.base_url}/{name}</a></div>'
                )
            else:
                if segno is None:
                    hint = "未安装 segno"
                else:
                    hint = "文件未生成" if not exists else "无局域网地址"
                cards.append(
                    f'<div class="card"><div class="qrmiss">{hint}</div>'
                    f'<div class="qname">{name}</div></div>'
                )
        if segno is None:
            tip = '<p class="tip">未安装 segno，二维码不可用：pip install segno</p>'
        elif self.base_url:
            tip = (
                f'<p class="tip">二维码为局域网地址 <code>{self.base_url}</code>，供手机扫码打开；'
                "手机访问需要额外加 CLI 参数 <code>--host 0.0.0.0</code> 启动服务（推荐在可信网络使用）</p>"
            )
        else:
            tip = '<p class="tip">未检测到局域网地址，二维码不可用（手机与电脑需在同一网络）。</p>'
        return (
            f"<script>var LAN_BASE={json.dumps(self.base_url)}</script>"
            "<h1>cfwarp-converter</h1>"
            '<p class="sub">下面三个二维码和对应的链接，即sub文件的订阅内容，如果没有显示，需执行CLI命令生成sub文件再刷新本页</p>'
            f'<div class="grid">{"".join(cards)}</div>{tip}'
            + self._form_section()
            + _openvpn_form_section()
        )

    def _form_section(self) -> str:
        """首页内嵌的订阅链接生成区：表单 + 生成结果（初始隐藏，JS 填充）。"""
        return (
            "<h2>【基础玩法】订阅链接生成</h2>"
            '<p class="sub">选择对应的客户端与参数生成一个订阅链接，复制打开或扫码该链接对应的二维码即可</p>'
            '<form class="form" id="cform" oninput="staleForm(\'cform\')" '
            "onchange=\"staleForm('cform')\">"
            f"{_form_fields()}"
            '<button type="button" onclick="genLink()">生成订阅链接</button></form>'
            '<div class="subgen" id="subgen" style="display:none">'
            '<div id="subresult">'
            '<div class="subrow"><img id="subqr" class="subqr" alt="订阅链接二维码">'
            '<code id="suburl" class="suburl" onclick="copySubUrl()" '
            'title="点击复制订阅链接"></code></div>'
            '<div class="qrerr" id="qrerr">二维码生成失败（未安装 segno 或链接过长），链接本身仍可使用</div>'
            "</div>"
            '<div class="substale" id="substale">参数已变更，请点击“生成订阅链接”重新生成</div>'
            "</div>" + _FORM_SCRIPT
        )

    def _send_text(self, text: str, status: int = 200) -> None:
        """以纯文本 UTF-8 响应（无法编码的字符替换，避免二次异常）。"""
        self._send(text.encode("utf-8", "replace"), status, "text/plain; charset=utf-8")

    def _send(self, data: bytes, status: int, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")  # 禁止缓存
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args) -> None:
        pass  # 静默访问日志，避免刷屏


class SubPageServer(ThreadingHTTPServer):
    """订阅服务：客户端探测/断开造成的连接中断只提示一行，不刷 traceback。"""

    def handle_error(self, request, client_address) -> None:
        error = sys.exc_info()[1]
        # ConnectionResetError(10054)/ConnectionAbortedError(10053)/BrokenPipeError
        # 的共同基类是 ConnectionError；TimeoutError 为套接字超时，同属预期中断
        if isinstance(error, (ConnectionError, TimeoutError)):
            address = (
                f"{client_address[0]}:{client_address[1]}" if client_address else "?"
            )
            print(
                f"[!] 客户端 {address} 连接中断！",
                flush=True,
            )
            return
        super().handle_error(request, client_address)


def server_sub_page(host: str, port: int) -> None:
    """启动本地订阅与网页转换服务（Ctrl+C 停止）。"""
    # server 模式接管输出：转换结果进内存不落盘（CLI 的 --server 组合中，
    # 转换先于本调用执行完毕，照常写 sub 文件，不受影响）
    main.write_text_file = _memory_write_text_file
    try:
        server = SubPageServer((host, port), SubPageHandler)
    except OSError as error:
        print(f"[!] 无法监听 {host}:{port}：{error}（端口可能被占用）")
        return
    lan_ip = get_lan_ip()
    SubPageHandler.base_url = f"http://{lan_ip}:{port}" if lan_ip else None
    print("[OK] 订阅页面已开启（Ctrl+C 停止）：", flush=True)
    print(f"  本机访问   http://127.0.0.1:{port}/", flush=True)
    if lan_ip:
        print(f"  局域网访问 http://{lan_ip}:{port}/", flush=True)
        if host != "0.0.0.0":
            print(
                "  （手机扫码访问需 --host 0.0.0.0 启动；sub 内容含私钥，仅限可信网络）",
                flush=True,
            )
    else:
        print("  未检测到局域网地址（可能未联网），二维码不可用", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止订阅服务。")
    finally:
        server.server_close()
