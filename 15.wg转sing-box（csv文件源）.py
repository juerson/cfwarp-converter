# 新版本sing-box桌面端，无法使用，很慢，只能打开https://connectivity.cloudflareclient.com/cdn-cgi/trace。
# 测试软件：SFW-1.14.2-x64.exe

import json
import os
import sys
from collections import OrderedDict


def check_file_exist_or_zero_size(file):
    if not os.path.exists(file) or os.stat(file).st_size == 0:
        sys.exit()


def read_wireguard_key_parameters(conf_file):
    with open(file=conf_file, mode='r', encoding='utf-8') as f:
        wireguard_param = dict()
        for line in f:
            if line:
                if line.startswith("PrivateKey"):
                    wireguard_param["PrivateKey"] = line.strip().replace(' ', '').replace("PrivateKey=", '')
                if line.startswith("PublicKey"):
                    wireguard_param["PublicKey"] = line.strip().replace(' ', '').replace("PublicKey=", '')
                if line.startswith("Address"):
                    wireguard_param["Address"] = line.strip().replace(' ', '').replace("Address=", '').split(',')
                if line.startswith("MTU"):
                    wireguard_param["MTU"] = line.strip().replace(' ', '').replace("MTU=", '')
                if line.startswith("Reserved"):
                    wireguard_param["Reserved"] = parse_value(line.strip().replace(' ', '').replace("Reserved=", ''))
        return wireguard_param


def read_ip_endpoints(csv_file):
    endpoints = []
    seen = set()
    with open(file=csv_file, mode='r', encoding='utf-8') as rf:
        next(rf)
        for line in rf:
            trim_line = line.strip()
            delay = trim_line.split(',')[2].replace(' ', '').replace('ms', '')
            if int(delay) < 500:
                endpoint = trim_line.split(',')[0]
                endpoint = str(endpoint).strip('[').strip(']')
                if endpoint not in seen:
                    seen.add(endpoint)
                    endpoints.append(endpoint)
        return endpoints


def parse_value(s):
    try:
        result = json.loads(s)
        return result if isinstance(result, list) else s
    except (json.JSONDecodeError, TypeError):
        return s


if __name__ == '__main__':
    files = ["配置文件/wg-config.conf", "result.csv"]
    for file in files:
        check_file_exist_or_zero_size(file)
    param = read_wireguard_key_parameters(files[0])

    private_key = param.get("PrivateKey", "+HfkMSyh7obEkX4J8Qa7Xk77CLVn45AW4CdBbnFNaGc=")
    public_key = param.get("PublicKey", "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")

    reserved = param.get("Reserved")
    
    mtu = param.get("MTU", 1280)
    Address = param.get("Address", ["172.16.0.2/32"])
   
    endpoints: list[str] = read_ip_endpoints(files[1])

    wireguard_nodes: list = []
    wireguard_names: list = []

    deduplicated_list = OrderedDict.fromkeys(endpoints)
    data_list = list(deduplicated_list)[:50]
    
    for i, ip_with_port in enumerate(data_list):
        [server, port] = ip_with_port.rsplit(":", 1)
        index = str(i + 1).zfill(len(str(len(deduplicated_list))))
        proxy_name: str = f"warp{index}-{str(server).strip('[').strip(']')}"
        
        wireguard_dict = {
        "type": "wireguard",
        "tag": proxy_name,
        # "system": False,
        # "name": "system-warp",
        "mtu": int(mtu),
        "address": Address,
        "private_key": private_key,
        # "listen_port": 10000 + i,
        "peers": [
            {
            "address": server,
            "port": int(port),
            "public_key": public_key,
            # "pre_shared_key": "",
            "allowed_ips": ["0.0.0.0/0", "::/0"],
            # "persistent_keepalive_interval": 0,
            "reserved": reserved if isinstance(reserved, list) else []
            }
        ],
        # "workers": 0,
        # "on_demand": False
        }
        wireguard_names.append(proxy_name)
        wireguard_nodes.append(wireguard_dict)
    with open('配置文件/sing-box.json', mode='r', encoding='utf-8') as rf, open("output-wireguard.json", 'w', encoding='utf-8') as wf:
        config = json.load(rf)
        outbounds = config["outbounds"]
        for i, item in enumerate(outbounds):
            if r"{all}" in item.get('outbounds', []) and (item["type"] == "selector" or item["type"] == "urltest"):
                config["outbounds"][i]["outbounds"].remove(r"{all}")
                config["outbounds"][i]["outbounds"].extend(wireguard_names)
        config["endpoints"].extend(wireguard_nodes)
        wf.write(json.dumps(config, ensure_ascii=False, indent=2))
