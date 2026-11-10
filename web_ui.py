"""本地订阅页面 + 网页订阅链接生成（独立展示层模块）。

main.py 只 import 本模块并调用 server_sub_page()；CLI 转换命令不经过本模块。

设计要点：
- 首页（/）内嵌订阅链接生成表单：选择客户端与参数，点击生成后页面下方显示
  可复制的订阅 URL（左侧二维码、右侧链接，纯前端拼参数，不跳转页面）。
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
import socket
import threading
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qsl, urlsplit

try:
    import segno
except ModuleNotFoundError:  # 二维码为可选能力：未安装时订阅页面与转换仍可用
    segno = None

import main
from main import BASE_DIR, CONVERTERS

SUB_PAGE_FILES = ("sub.txt", "sub.yaml", "sub.json")
SUB_PAGE_PATHS = {f"/{name}": name for name in SUB_PAGE_FILES}
SUB_PAGE_PORT = 8790
CONVERT_PAGE = "/convert"
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


SUB_PAGE_STYLE = (
    "*{box-sizing:border-box;margin:0}"
    "html{scrollbar-gutter:stable}"
    "body{font-family:system-ui,-apple-system,'Segoe UI','Microsoft YaHei',sans-serif;"
    "background:#f5f7fa;color:#1f2937;padding:32px 16px}"
    ".wrap{max-width:860px;margin:0 auto}"
    "h1{font-size:22px;margin-bottom:4px}"
    "h2{font-size:16px;margin:20px 0 10px}"
    ".sub{color:#6b7280;font-size:13px;margin-bottom:24px}"
    ".grid{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:16px}"
    ".card{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;text-align:center}"
    ".card img{width:150px;height:150px}"
    ".qrmiss{width:150px;height:150px;display:flex;align-items:center;justify-content:center;"
    "margin:0 auto;background:#f3f4f6;border-radius:8px;color:#9ca3af;font-size:13px}"
    ".qname{font-size:13px;font-weight:600;margin-top:10px}"
    ".qurl{font-size:11px;color:#6b7280;word-break:break-all;margin-top:2px}"
    ".tip{font-size:12px;color:#4b5563;background:#eef2ff;border:1px solid #e0e7ff;"
    "border-radius:8px;padding:10px 14px;margin-bottom:16px}"
    ".tip code{background:#e0e7ff;border-radius:4px;padding:1px 5px}"
    ".list{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:4px 16px;margin-bottom:16px}"
    ".row{display:flex;justify-content:space-between;align-items:center;padding:13px 4px;"
    "border-bottom:1px solid #f3f4f6;text-decoration:none;color:inherit}"
    ".row:last-child{border-bottom:none}"
    ".row b{font-size:15px}.row span{font-size:12px;color:#6b7280}"
    ".miss{color:#9ca3af}"
    ".form{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:16px 20px;"
    "display:grid;grid-template-columns:1fr 1fr;gap:12px 16px;margin-bottom:16px}"
    ".form label{font-size:12px;color:#6b7280;display:flex;flex-direction:column;gap:4px}"
    ".form select,.form input{padding:7px 10px;border:1px solid #d1d5db;border-radius:8px;"
    "font-size:14px;color:#1f2937}"
    ".form button{align-self:end;padding:9px 10px;background:#2563eb;color:#fff;border:none;"
    "border-radius:8px;font-size:15px;cursor:pointer}"
    ".subgen{background:#fff;border:1px solid #e5e7eb;border-radius:12px;padding:16px;margin-bottom:16px}"
    ".qrerr{color:#b91c1c;font-size:12px;margin-top:6px;display:none}"
    ".substale{min-height:130px;display:none;align-items:center;justify-content:center;"
    "text-align:center;color:#6b7280;font-size:13px}"
    ".subrow{display:flex;gap:14px;align-items:center}"
    ".subqr{width:130px;height:130px;flex:none}"
    ".suburl{flex:1;word-break:break-all;font-size:12px;font-family:Consolas,monospace;"
    "background:#f3f4f6;border-radius:6px;padding:10px 12px;cursor:pointer}"
    ".off{opacity:.45}"
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
    "singbox": "sing-box/sing-box-lx 内核",
}


def _form_fields(form: dict[str, str]) -> str:
    """渲染固定字段集；data-clients 声明各参数的可用客户端，JS 按 client 启用/禁用。"""
    selected = form.get("client", "")
    options = "".join(
        f'<option value="{name}" data-source="{CONVERTERS[name].default_source}"'
        f'{" selected" if name == selected else ""}>'
        f"{name} ({CLIENT_ALIASES.get(name, name)})</option>"
        for name in CONVERTERS
    )
    fields = [
        f'<label>客户端（转换目标）<select name="client" onchange="changeClient()">{options}</select></label>',
        (
            f"<label>协议（仅 Throne / mihomo / sing-box 使用）"
            f'<select name="protocol" onchange="applySupport()"{_client_attr("protocol")}>'
            '<option value="wg">wg</option>'
            '<option value="masque">masque</option></select></label>'
        ),
        (
            f'<label>数据源 <select name="source"{_client_attr("source")}>'
            '<option value="csv">csv (result.csv)</option>'
            '<option value="txt">txt (ip.txt)</option></select></label>'
        ),
        (
            f"<label>AmneziaWG 混淆（仅 wg 协议 + 支持的客户端）"
            f'<select name="amnezia_mode"{_client_attr("amnezia")} data-needs-wg="1">'
            '<option value="off">禁用</option>'
            '<option value="random">每节点随机</option>'
            '<option value="custom">自定义</option></select></label>'
        ),
        (
            f'<label>AmneziaWG 自定义参数 <input type="text" name="amnezia_custom" '
            f'placeholder="jc=6&jmin=36&jmax=398（选择自定义时生效）"{_client_attr("amnezia")} '
            f'data-needs-wg="1"></label>'
        ),
        (
            f'<label>节点数上限（留空=各客户端默认）<input type="number" name="limit" '
            f'placeholder="默认：全部 / 500 / 80 / 50"{_client_attr("limit")}></label>'
        ),
        (
            f'<label>MTU（1280~1500，留空=配置文件值或协议默认）<input type="number" name="mtu" '
            f'placeholder="默认：wg=1340 / masque=1361"{_client_attr("mtu")}></label>'
        ),
    ]
    return "".join(fields)


_FORM_SCRIPT = """<script>
function applySupport(){
  var f=document.getElementById('cform');
  var c=f.querySelector('[name=client]').value;
  var wg=f.querySelector('[name=protocol]').value==='wg';
  f.querySelectorAll('[data-clients]').forEach(function(el){
    var ok=el.getAttribute('data-clients').split(',').indexOf(c)>=0;
    if(ok&&el.hasAttribute('data-needs-wg')) ok=wg;
    el.disabled=!ok;
    var lb=el.closest('label'); if(lb) lb.classList.toggle('off',!ok);
  });
}
function changeClient(){
  resetForm();
  applySupport();
}
function resetForm(){
  var f=document.getElementById('cform');
  var sel=f.querySelector('[name=client]');
  var srcDefault=sel.selectedOptions[0].getAttribute('data-source')||'csv';
  f.querySelectorAll('input').forEach(function(el){el.value='';});
  f.querySelector('[name=protocol]').value='wg';
  f.querySelector('[name=source]').value=srcDefault;
  f.querySelector('[name=amnezia_mode]').value='off';
  var img=document.getElementById('subqr');
  img.onload=null;img.onerror=null;
  img.removeAttribute('src');img.style.visibility='hidden';
  document.getElementById('suburl').textContent='';
  document.getElementById('qrerr').style.display='none';
  var gen=document.getElementById('subgen');
  if(gen.style.display!=='none'){          // 生成过才保留提示区，未生成时不留空白
    document.getElementById('subresult').style.display='none';
    document.getElementById('substale').style.display='flex';
  }
}
function genLink(){
  var f=document.getElementById('cform');
  var p=new URLSearchParams();
  new FormData(f).forEach(function(v,k){
    if(typeof v!=='string') return;
    v=v.trim();
    if(!v) return;                                   // 空值不写进链接（服务端默认值等价）
    if(k==='amnezia_mode'&&v==='off') return;        // off 是服务端默认值，省略
    if(k==='amnezia_custom'&&f.querySelector('[name=amnezia_mode]').value!=='custom') return;
    p.append(k,v);
  });
  var url=window.location.origin+'/convert?'+p.toString();
  document.getElementById('suburl').textContent=url;
  var img=document.getElementById('subqr');
  var hint=document.getElementById('qrerr');
  img.onload=function(){img.style.visibility='visible';hint.style.display='none';};
  img.onerror=function(){img.style.visibility='hidden';hint.style.display='block';};
  img.style.visibility='hidden';
  img.src='/qr?data='+encodeURIComponent(url);
  document.getElementById('subresult').style.display='block';
  document.getElementById('substale').style.display='none';
  document.getElementById('subgen').style.display='block';
  document.getElementById('subgen').scrollIntoView({behavior:'smooth'});
}
function copySubUrl(){
  var u=document.getElementById('suburl');
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
    if "amnezia" in supported:
        mode = form.get("amnezia_mode", "off")
        custom = form.get("amnezia_custom", "").strip()
        protocol = form.get("protocol", "").strip() or "wg"
        try:
            is_wg = main.protocol_type(protocol) == "wg"
        except argparse.ArgumentTypeError as error:
            raise ValueError(str(error)) from error
        if is_wg:
            if mode == "random":
                argv.append("--amnezia")
            elif mode == "custom" and custom:
                argv += ["--amnezia", custom]
    return argv


def run_in_memory(form: dict[str, str]) -> str:
    """按表单参数实时转换一次，返回结果文本；全程内存，零落盘。"""
    client = form.get("client", "")
    converter_cls = CONVERTERS.get(client)
    if converter_cls is None:
        raise ValueError(
            f"未知客户端：{client or '(未指定)'}，可选：{' / '.join(CONVERTERS)}"
        )
    conv = converter_cls()
    args = PARSERS[client].parse_args(_form_argv(client, form))
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


# ============================================================================
# HTTP 处理器与启动
# ============================================================================


class SubPageHandler(BaseHTTPRequestHandler):
    """订阅展示 + 订阅链接内容端点的请求处理器。

    路由白名单：/（订阅首页 + 表单）、/convert（订阅链接内容，纯文本）、
    /qr（按需生成二维码）、三个 sub 文件路径；每次请求都重新读文件。
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
                page = sub_page_html("cfwarp-converter 订阅", self._index_body(form))
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

    def _index_body(self, form: dict[str, str]) -> str:
        cards, rows = [], []
        for name in SUB_PAGE_FILES:
            path = BASE_DIR / name
            if path.exists():
                rows.append(
                    f'<a class="row" href="/{name}" target="_blank"><b>{name}</b>'
                    f"<span>{path.stat().st_size:,} 字节 · 点击查看内容</span></a>"
                )
            else:
                rows.append(
                    f'<div class="row"><b class="miss">{name}</b>'
                    '<span class="miss">（未生成，执行对应转换命令后出现）</span></div>'
                )
            if path.exists() and self.base_url and segno is not None:
                qr = _qr_data_uri(f"{self.base_url}/{name}")
                cards.append(
                    f'<div class="card"><img class="qr" src="{qr}" alt="{name} 二维码">'
                    f'<div class="qname">{name}</div>'
                    f'<div class="qurl">{self.base_url}/{name}</div></div>'
                )
            else:
                if segno is None:
                    hint = "未安装 segno"
                else:
                    hint = "文件未生成" if not path.exists() else "无局域网地址"
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
            "<h1>cfwarp-converter</h1>"
            '<p class="sub">订阅内容实时读取 exe 同目录文件，重新转换后刷新本页即最新</p>'
            f'<div class="grid">{"".join(cards)}</div>{tip}'
            f'<div class="list">{"".join(rows)}</div>' + self._form_section(form)
        )

    def _form_section(self, form: dict[str, str]) -> str:
        """首页内嵌的订阅链接生成区：表单 + 生成结果（初始隐藏，JS 填充）。"""
        return (
            "<h2>订阅链接生成</h2>"
            '<p class="sub">选择客户端与参数生成一个订阅链接；打开或扫码该链接都会'
            "<b>实时重新转换</b>，内容与 sub 文件格式一致，直接显示在浏览器中，"
            "不写入任何文件，多用户互不影响。</p>"
            f'<form class="form" id="cform">{_form_fields(form)}'
            '<button type="button" onclick="genLink()">生成订阅链接</button></form>'
            '<div class="subgen" id="subgen" style="display:none">'
            '<div id="subresult">'
            '<div class="subrow"><img id="subqr" class="subqr" alt="订阅链接二维码">'
            '<code id="suburl" class="suburl" onclick="copySubUrl()" '
            'title="点击复制订阅链接"></code></div>'
            '<div class="qrerr" id="qrerr">订阅链接过长，无法生成二维码</div>'
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
        # no-store：禁止浏览器缓存，保证重新生成文件后刷新即最新内容
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args) -> None:
        pass  # 静默访问日志，避免刷屏


def server_sub_page(host: str, port: int) -> None:
    """启动本地订阅与网页转换服务（Ctrl+C 停止）。"""
    # server 模式接管输出：转换结果进内存不落盘（CLI 的 --server 组合中，
    # 转换先于本调用执行完毕，照常写 sub 文件，不受影响）
    main.write_text_file = _memory_write_text_file
    try:
        server = ThreadingHTTPServer((host, port), SubPageHandler)
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
