import json
import re
import base64
import sys
from itertools import islice


def load_ips(path=r"result.csv"):
    """读取CSV文件，解析endpoint和delay数据，筛选delay<500ms的节点，返回字典（保持顺序且去重）"""
    result = {}
    seen = set()
    idx = 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            next(f)  # 跳过表头
            for line in f:
                line = line.strip()
                if not line:
                    continue
                parts = line.split(',')
                endpoint = parts[0]
                delay_str = parts[-1].replace(' ', '').replace('ms', '')
                try:
                    delay = int(delay_str)
                except ValueError:
                    continue
                if delay >= 500: # 筛选延迟小于500ms
                    continue
                if endpoint in seen:
                    continue
                seen.add(endpoint)
                match_v6 = re.match(r'^\[(.+)\]:(\d+)$', endpoint)
                if match_v6:
                    ip, port = match_v6.groups()
                    idx += 1
                    result[idx] = {"ip": ip, "port": int(port)}
                    continue
                match_v4 = re.match(r'^(\d+\.\d+\.\d+\.\d+):(\d+)$', endpoint)
                if match_v4:
                    ip, port = match_v4.groups()
                    idx += 1
                    result[idx] = {"ip": ip, "port": int(port)}
    except FileNotFoundError:
        print(f"文件 {path} 不存在")
        sys.exit(1)
    if not result:
        print(f"文件 {path} 中未解析到有效的节点数据（或所有节点延迟>=500ms）")
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
    for i, item in islice(ips.items(), 50): # 限制只取前50个节点
        name = f"【{str(i).zfill(len(str(total)))}】{item['ip']}({item['port']})"
        node_data = {"name": name,"type":"masque","server":item['ip'],"port":item['port'],"private-key":config["private_key"],"public-key":config["pub_key"],"ip":config["ipv4"],"ipv6":config["ipv6"],"mtu":1281,"udp":True,"remote-dns-resolve":True,"dns":["8.8.8.8","2001:4860:4860::8844"]}
        node_masque = json.dumps(node_data, ensure_ascii=False)
        names.append(f"      - {name}")
        prxies.append(f"  - {node_masque}")
    
    output_file = "output-masque.yaml"
    with open('配置文件/clash.yaml', mode='r', encoding='utf-8') as rf, open(output_file, 'w', encoding='utf-8') as wf:
        clash = rf.read()

        node_info = base64.b64decode("ICAtIHtuYW1lOiAxMjcuMC4wLjE6MTA4MCwgc2VydmVyOiAxMjcuMC4wLjEsIHBvcnQ6IDEwODAsIHR5cGU6IHNzLCBjaXBoZXI6IGFlcy0xMjgtZ2NtLCBwYXNzd29yZDogYWJjMTIzNDU2fQ==").decode("utf-8")
        node_name = base64.b64decode("ICAgICAgLSAxMjcuMC4wLjE6MTA4MA==").decode("utf-8")

        masque_mihomo = clash.replace(node_info, "\n".join(prxies)).replace(node_name, "\n".join(names))
        wf.write(masque_mihomo)
    print(f"制作的mihomo配置已经写入文件 {output_file}，有 {len(prxies)} 个节点信息")