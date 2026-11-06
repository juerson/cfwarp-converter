import json
import re
import sys
from itertools import islice


def load_ips(path=r"ip.txt"):
    """读取ip.txt文件，解析ip:port格式数据，返回字典（保持顺序且去重）"""
    result = {}
    seen = set()
    idx = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line in seen:
                    continue
                seen.add(line)
                match_v6 = re.match(r'^\[(.+)\]:(\d+)$', line)
                if match_v6:
                    ip, port = match_v6.groups()
                    idx += 1
                    result[idx] = {"ip": ip, "port": int(port)}
                    continue
                match_v4 = re.match(r'^(\d+\.\d+\.\d+\.\d+):(\d+)$', line)
                if match_v4:
                    ip, port = match_v4.groups()
                    idx += 1
                    result[idx] = {"ip": ip, "port": int(port)}
    except FileNotFoundError:
        print(f"文件 {path} 不存在")
        sys.exit(1)
    if not result:
        print(f"文件 {path} 中未解析到有效的ip:port数据")
        sys.exit(1)
    return result


def load_config(path=r"配置文件\usque_config.json"):
    try:
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"文件 {path} 不存在")
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"文件 {path} JSON格式错误")
        sys.exit(1)

    pub_key = config["endpoint_pub_key"]
    pub_key = pub_key.replace("-----BEGIN PUBLIC KEY-----\n", "")
    pub_key = pub_key.replace("\n", "")
    pub_key = pub_key.replace("-----END PUBLIC KEY-----", "")
    config["pub_key"] = pub_key
    return config


if __name__ == "__main__":
    config = load_config()
    ips = load_ips()
    total = len(ips)
    names = []
    prxies = []
    for i, item in islice(ips.items(), 50):  # 限制只取前50个节点
        name = f"【{str(i).zfill(len(str(total)))}】{item['ip']}({item['port']})"
        node_data = {
            "type": "masque",
            "tag": name,
            "server": item['ip'],
            "server_port": item['port'],
            "profile": "cloudflare",
            "vhttp": "auto",
            "private_key": config["private_key"],
            "public_key": config["pub_key"],
            "ip": config["ipv4"],
            "ipv6": config["ipv6"],
            "mtu": 1280,
            "tls": {
                "enabled": True,
                "server_name": "consumer-masque.cloudflareclient.com"
            },
        }
        names.append(name)
        prxies.append(node_data)
    with open('配置文件/sing-box.json', mode='r', encoding='utf-8') as rf, open("output-masque.json", 'w', encoding='utf-8') as wf:
        config = json.load(rf)
        outbounds = config["outbounds"]
        for i, item in enumerate(outbounds):
            if r"{all}" in item.get('outbounds', []) and (item["type"] == "selector" or item["type"] == "urltest"):
                config["outbounds"][i]["outbounds"].remove(r"{all}")
                config["outbounds"][i]["outbounds"].extend(names)
        config["outbounds"].extend(prxies)
        json.dump(config, wf, ensure_ascii=False, indent=2)