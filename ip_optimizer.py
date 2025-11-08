#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare IP扫描简化版
确保连接正常和地理信息一致
"""

import os
import requests
import random
import time
import socket
import ssl
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from tqdm import tqdm
import urllib3
import ipaddress

# 禁用不安全请求警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

####################################################
# 配置参数
####################################################
CONFIG = {
    "MODE": "URL_TEST",
    "URL_TEST_TARGET": "http://www.gstatic.com/generate_204",
    "URL_TEST_TIMEOUT": 3,
    "URL_TEST_RETRY": 2,
    "PORT": 443,
    "RTT_RANGE": "0~800",
    "LOSS_MAX": 2.0,
    "THREADS": 200,
    "IP_POOL_SIZE": 50000,
    "TEST_IP_COUNT": 1000,
    "TOP_IPS_LIMIT": 50,
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    
    # 地区配置
    "REGION_MAPPING": {
        'US': ['🇺🇸 美国', 'US', 'United States'],
        'SG': ['🇸🇬 新加坡', 'SG', 'Singapore'],
        'JP': ['🇯🇵 日本', 'JP', 'Japan'],
        'HK': ['🇭🇰 香港', 'HK', 'Hong Kong'],
        'KR': ['🇰🇷 韩国', 'KR', 'South Korea'],
        'DE': ['🇩🇪 德国', 'DE', 'Germany'],
        'GB': ['🇬🇧 英国', 'GB', 'United Kingdom']
    }
}

####################################################
# 核心测试函数
####################################################

def url_test(ip, url=None, timeout=None, retry=None):
    """URL测试函数"""
    if url is None:
        url = CONFIG["URL_TEST_TARGET"]
    if timeout is None:
        timeout = CONFIG["URL_TEST_TIMEOUT"]
    if retry is None:
        retry = CONFIG["URL_TEST_RETRY"]
    
    success_count = 0
    total_rtt = 0
    
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme.lower()
    hostname = parsed_url.hostname
    port = parsed_url.port or (443 if scheme == 'https' else 80)
    path = parsed_url.path or '/'
    
    for attempt in range(retry):
        try:
            start_time = time.time()
            
            if scheme == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(ip, port=port, timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)
            
            headers = {
                'Host': hostname,
                'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Tester/1.0)',
                'Accept': '*/*',
                'Connection': 'close'
            }
            
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            response.read()
            
            rtt = (time.time() - start_time) * 1000
            
            if response.status < 500:
                success_count += 1
                total_rtt += rtt
            
            conn.close()
            
        except Exception:
            continue
        
        if attempt < retry - 1:
            time.sleep(0.1)
    
    if success_count > 0:
        avg_rtt = total_rtt / success_count
        loss_rate = ((retry - success_count) / retry) * 100
    else:
        avg_rtt = float('inf')
        loss_rate = 100.0
    
    return avg_rtt, loss_rate

def get_ip_region(ip):
    """获取IP地区信息 - 简化版本"""
    try:
        # 使用可靠的IP API
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=status,countryCode', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                country_code = data.get('countryCode')
                # 简单映射
                region_map = {
                    'US': 'US', 'CA': 'US', 'MX': 'US',
                    'SG': 'SG', 'JP': 'JP', 'KR': 'KR',
                    'TW': 'HK', 'MO': 'HK', 'CN': 'HK',
                    'GB': 'GB', 'DE': 'DE', 'FR': 'DE'
                }
                return region_map.get(country_code, 'US')
    except:
        pass
    
    # 如果API失败，根据IP段推测
    if ip.startswith(('8.8.', '8.9.', '8.10.')):
        return 'US'
    elif ip.startswith(('103.21.', '103.22.', '104.16.')):
        return 'SG'
    elif ip.startswith(('108.162.', '162.158.')):
        return 'JP'
    else:
        return 'US'

####################################################
# 输出格式化函数
####################################################

def format_ip_with_region(ip_data, port=None):
    """格式化IP输出"""
    if port is None:
        port = CONFIG["PORT"]
    
    region_code = ip_data.get('regionCode', 'US')
    region_info = CONFIG["REGION_MAPPING"].get(region_code, ['🇺🇸 美国'])
    flag_and_name = region_info[0]
    
    return f"{ip_data['ip']}:{port}#{flag_and_name}"

def format_ip_list_for_display(ip_list):
    """格式化IP列表用于显示"""
    formatted_ips = []
    for ip_data in ip_list:
        formatted_ips.append(format_ip_with_region(ip_data))
    return formatted_ips

####################################################
# 核心逻辑函数
####################################################

def init_env():
    """初始化环境"""
    for key, value in CONFIG.items():
        os.environ[key] = str(value)

def fetch_ip_ranges():
    """获取Cloudflare IP段"""
    try:
        res = requests.get(CONFIG["CLOUDFLARE_IPS_URL"], timeout=10, verify=False)
        return res.text.splitlines()
    except Exception as e:
        print(f"获取IP段失败: {e}")
        return []

def generate_random_ip(subnet):
    """生成随机IP"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        network_addr = int(network.network_address)
        broadcast_addr = int(network.broadcast_address)
        first_ip = network_addr + 1
        last_ip = broadcast_addr - 1
        random_ip_int = random.randint(first_ip, last_ip)
        return str(ipaddress.IPv4Address(random_ip_int))
    except:
        base_ip = subnet.split('/')[0]
        parts = base_ip.split('.')
        parts = parts[:3] + [str(random.randint(1, 254))]
        return ".".join(parts)

def test_ip(ip):
    """测试单个IP"""
    try:
        rtt, loss = url_test(ip)
        return (ip, rtt, loss)
    except:
        return (ip, float('inf'), 100.0)

def enhance_ip_info(ip_data):
    """为IP添加地区信息"""
    ip, rtt, loss = ip_data
    region_code = get_ip_region(ip)
    region_name = CONFIG["REGION_MAPPING"].get(region_code, ['🇺🇸 美国'])[0]
    
    return {
        'ip': ip,
        'rtt': rtt,
        'loss': loss,
        'regionCode': region_code,
        'regionName': region_name
    }

####################################################
# 主程序
####################################################
if __name__ == "__main__":
    # 初始化
    init_env()
    
    print("=" * 50)
    print(f"{'Cloudflare IP扫描器':^50}")
    print("=" * 50)
    
    # 获取IP段
    subnets = fetch_ip_ranges()
    if not subnets:
        print("❌ 无法获取IP段")
        exit(1)
    
    print(f"✅ 获取到 {len(subnets)} 个IP段")
    
    # 生成IP池
    ip_pool_size = CONFIG["IP_POOL_SIZE"]
    test_ip_count = CONFIG["TEST_IP_COUNT"]
    
    full_ip_pool = set()
    print(f"生成 {ip_pool_size} 个随机IP...")
    
    with tqdm(total=ip_pool_size, desc="生成IP池") as pbar:
        while len(full_ip_pool) < ip_pool_size:
            subnet = random.choice(subnets)
            ip = generate_random_ip(subnet)
            if ip not in full_ip_pool:
                full_ip_pool.add(ip)
                pbar.update(1)
    
    test_ip_pool = random.sample(list(full_ip_pool), min(test_ip_count, len(full_ip_pool)))
    print(f"测试 {len(test_ip_pool)} 个IP")
    
    # 延迟测试
    ping_results = []
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_ip = {executor.submit(test_ip, ip): ip for ip in test_ip_pool}
        with tqdm(total=len(test_ip_pool), desc="延迟测试") as pbar:
            for future in as_completed(future_to_ip):
                try:
                    ping_results.append(future.result())
                except:
                    pass
                finally:
                    pbar.update(1)
    
    # 筛选合格IP
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    
    passed_ips = [
        ip_data for ip_data in ping_results
        if rtt_min <= ip_data[1] <= rtt_max and ip_data[2] <= loss_max
    ]
    
    print(f"✅ 通过测试: {len(passed_ips)}/{len(ping_results)}")
    
    if not passed_ips:
        print("❌ 没有合格的IP")
        exit(1)
    
    # 添加地区信息
    print("检测地理位置...")
    enhanced_ips = []
    for ip_data in tqdm(passed_ips, desc="地理位置"):
        enhanced_ips.append(enhance_ip_info(ip_data))
    
    # 排序和选择
    sorted_ips = sorted(enhanced_ips, key=lambda x: x['rtt'])[:CONFIG["TOP_IPS_LIMIT"]]
    
    # 保存结果
    os.makedirs('results', exist_ok=True)
    
    with open('results/top_ips.txt', 'w', encoding='utf-8') as f:
        for ip_data in sorted_ips:
            line = format_ip_with_region(ip_data)
            f.write(line + '\n')
    
    with open('results/top_ips_plain.txt', 'w', encoding='utf-8') as f:
        for ip_data in sorted_ips:
            f.write(f"{ip_data['ip']}:{CONFIG['PORT']}\n")
    
    # 显示结果
    print("\n" + "=" * 50)
    print(f"{'最佳IP结果':^50}")
    print("=" * 50)
    
    print("🏆 【TOP 10 IP (带地区)】")
    formatted_ips = format_ip_list_for_display(sorted_ips[:10])
    for i, ip in enumerate(formatted_ips, 1):
        print(f"{i:2d}. {ip}")
    
    print(f"\n🏆 【TOP 10 IP (纯IP)】")
    for i, ip_data in enumerate(sorted_ips[:10], 1):
        print(f"{i:2d}. {ip_data['ip']}:{CONFIG['PORT']}")
    
    print(f"\n📋 【全部 {len(sorted_ips)} 个IP】")
    all_formatted = format_ip_list_for_display(sorted_ips)
    for i in range(0, len(all_formatted), 2):
        line_ips = all_formatted[i:i+2]
        print("  " + "  ".join(line_ips))
    
    print("=" * 50)
    print("✅ 结果已保存至 results/ 目录")
    print("📁 top_ips.txt - 带地区信息的IP列表")
    print("📁 top_ips_plain.txt - 纯IP列表")
    print("=" * 50)
