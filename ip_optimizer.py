import os
import requests
import random
import numpy as np
import time
import socket
import subprocess
import ssl
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from tqdm import tqdm
import urllib3
import ipaddress

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

####################################################
# 配置参数
####################################################
CONFIG = {
    "MODE": "URL_TEST",  # 测试模式：PING/TCP/URL_TEST
    "PING_TARGET": "http://www.gstatic.com/generate_204",  # Ping测试目标
    "URL_TEST_TARGET": "http://www.gstatic.com/generate_204",  # URL测试目标
    "URL_TEST_TIMEOUT": 3,  # URL测试超时(秒)
    "URL_TEST_RETRY": 2,  # URL测试重试次数
    "PING_COUNT": 5,  # Ping次数
    "PING_TIMEOUT": 3,  # Ping超时(秒)
    "PORT": 443,  # TCP测试端口
    "RTT_RANGE": "0~300",  # 延迟范围(ms)
    "LOSS_MAX": 1.0,  # 最大丢包率(%)
    "THREADS": 100,  # 并发线程数
    "IP_POOL_SIZE": 20000,  # IP池总大小
    "TEST_IP_COUNT": 800,  # 实际测试IP数量
    "TOP_IPS_LIMIT": 100,  # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",  # 官方IP源
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "BACKUP_IPS_URLS": [  # 备用IP源URL列表（反代）
        "https://raw.githubusercontent.com/XIU2/CloudflareSpeedTest/master/ip.txt",
        "https://cdn.jsdelivr.net/gh/XIU2/CloudflareSpeedTest/ip.txt",
        "https://ghproxy.com/https://raw.githubusercontent.com/XIU2/CloudflareSpeedTest/master/ip.txt",
        "https://raw.fastgit.org/XIU2/CloudflareSpeedTest/master/ip.txt"
    ],
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    
    # 备用测试URL列表
    "BACKUP_TEST_URLS": [
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/",
        "http://www.cloudflare.com/favicon.ico",
        "http://one.one.one.one/",
        "https://1.1.1.1/",
        "http://www.apple.com/library/test/success.html"
    ],
    
    # 备用IP列表（优先使用）
    "BACKUP_IPS": [
        {'domain': 'ProxyIP.US.CMLiussss.net', 'region': 'US', 'regionCode': 'US', 'port': 443},
        {'domain': 'ProxyIP.SG.CMLiussss.net', 'region': 'SG', 'regionCode': 'SG', 'port': 443},
        {'domain': 'ProxyIP.JP.CMLiussss.net', 'region': 'JP', 'regionCode': 'JP', 'port': 443},
        {'domain': 'ProxyIP.HK.CMLiussss.net', 'region': 'HK', 'regionCode': 'HK', 'port': 443},
        {'domain': 'ProxyIP.KR.CMLiussss.net', 'region': 'KR', 'regionCode': 'KR', 'port': 443},
        {'domain': 'ProxyIP.DE.CMLiussss.net', 'region': 'DE', 'regionCode': 'DE', 'port': 443},
        {'domain': 'ProxyIP.SE.CMLiussss.net', 'region': 'SE', 'regionCode': 'SE', 'port': 443},
        {'domain': 'ProxyIP.NL.CMLiussss.net', 'region': 'NL', 'regionCode': 'NL', 'port': 443},
        {'domain': 'ProxyIP.FI.CMLiussss.net', 'region': 'FI', 'regionCode': 'FI', 'port': 443},
        {'domain': 'ProxyIP.GB.CMLiussss.net', 'region': 'GB', 'regionCode': 'GB', 'port': 443},
        {'domain': 'ProxyIP.Oracle.cmliussss.net', 'region': 'Oracle', 'regionCode': 'Oracle', 'port': 443},
        {'domain': 'ProxyIP.DigitalOcean.CMLiussss.net', 'region': 'DigitalOcean', 'regionCode': 'DigitalOcean', 'port': 443},
        {'domain': 'ProxyIP.Vultr.CMLiussss.net', 'region': 'Vultr', 'regionCode': 'Vultr', 'port': 443},
        {'domain': 'ProxyIP.Multacom.CMLiussss.net', 'region': 'Multacom', 'regionCode': 'Multacom', 'port': 443}
    ],
    
    # 国家代码到国旗的映射
    "COUNTRY_FLAGS": {
        'US': '🇺🇸', 'SG': '🇸🇬', 'JP': '🇯🇵', 'HK': '🇭🇰', 'KR': '🇰🇷',
        'DE': '🇩🇪', 'GB': '🇬🇧', 'FR': '🇫🇷', 'CA': '🇨🇦', 'AU': '🇦🇺',
        'NL': '🇳🇱', 'SE': '🇸🇪', 'FI': '🇫🇮', 'NO': '🇳🇴', 'DK': '🇩🇰',
        'CH': '🇨🇭', 'IT': '🇮🇹', 'ES': '🇪🇸', 'PT': '🇵🇹', 'BE': '🇧🇪',
        'AT': '🇦🇹', 'IE': '🇮🇪', 'PL': '🇵🇱', 'CZ': '🇨🇿', 'HU': '🇭🇺',
        'RO': '🇷🇴', 'BG': '🇧🇬', 'GR': '🇬🇷', 'TR': '🇹🇷', 'RU': '🇷🇺',
        'UA': '🇺🇦', 'IL': '🇮🇱', 'AE': '🇦🇪', 'SA': '🇸🇦', 'IN': '🇮🇳',
        'TH': '🇹🇭', 'MY': '🇲🇾', 'ID': '🇮🇩', 'VN': '🇻🇳', 'PH': '🇵🇭',
        'BR': '🇧🇷', 'MX': '🇲🇽', 'AR': '🇦🇷', 'CL': '🇨🇱', 'CO': '🇨🇴',
        'ZA': '🇿🇦', 'EG': '🇪🇬', 'NG': '🇳🇬', 'KE': '🇰🇪',
        'Oracle': '🏢', 'DigitalOcean': '🌊', 'Vultr': '⚡', 'Multacom': '🏢',
        'UN': '🏴'  # 未知国家
    },
    
    # IP地理位置API配置
    "IP_GEO_API": {
        "timeout": 3,
        "retry": 2,
        "enable_cache": True
    }
}

# IP地理位置缓存
ip_geo_cache = {}

####################################################
# 多源IP获取函数
####################################################

def resolve_domain_to_ip(domain):
    """
    解析域名获取IP地址
    """
    try:
        # 使用socket解析域名
        ip = socket.gethostbyname(domain)
        return ip
    except Exception as e:
        print(f"❌ 解析域名 {domain} 失败: {e}")
        return None

def get_backup_ips():
    """
    从BACKUP_IPS中获取所有域名的IP地址
    """
    backup_ips = []
    print("🔍 解析备用域名获取IP地址...")
    
    with tqdm(total=len(CONFIG["BACKUP_IPS"]), desc="解析域名", unit="域名") as pbar:
        for ip_info in CONFIG["BACKUP_IPS"]:
            domain = ip_info['domain']
            ip = resolve_domain_to_ip(domain)
            if ip:
                # 创建IP信息字典
                ip_data = {
                    'ip': ip,
                    'domain': domain,
                    'region': ip_info['region'],
                    'regionCode': ip_info['regionCode'],
                    'port': ip_info['port'],
                    'source': 'backup_domain'
                }
                backup_ips.append(ip_data)
                pbar.set_description(f"解析域名 ({domain} -> {ip})")
            pbar.update(1)
    
    print(f"✅ 成功解析 {len(backup_ips)}/{len(CONFIG['BACKUP_IPS'])} 个备用域名")
    return backup_ips

def get_local_ips():
    """
    从本地文件获取IP列表
    """
    local_files = [
        CONFIG["CUSTOM_IPS_FILE"],
        "ip.txt",
        "ips.txt",
        "ipv4.txt",
        "cloudflare_ips.txt"
    ]
    
    for file_path in local_files:
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    lines = f.readlines()
                
                ips = []
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # 处理各种格式的IP
                        if ':' in line:
                            ip = line.split(':')[0]
                        elif '#' in line:
                            ip = line.split('#')[0]
                        else:
                            ip = line
                        
                        # 验证IP格式
                        try:
                            ipaddress.IPv4Address(ip)
                            ips.append({
                                'ip': ip,
                                'source': 'local_file',
                                'file': file_path
                            })
                        except:
                            continue
                
                if ips:
                    print(f"✅ 从本地文件 {file_path} 读取到 {len(ips)} 个IP")
                    return ips
            except Exception as e:
                print(f"❌ 读取本地文件 {file_path} 失败: {e}")
    
    print("ℹ️  未找到可用的本地IP文件")
    return []

def get_cloudflare_ips():
    """
    从官方Cloudflare IP源获取IP段
    """
    url = CONFIG["CLOUDFLARE_IPS_URL"]
    try:
        print(f"🌐 从官方源获取IP段: {url}")
        res = requests.get(url, timeout=10, verify=False)
        if res.status_code == 200:
            subnets = res.text.splitlines()
            subnets = [subnet.strip() for subnet in subnets if subnet.strip()]
            print(f"✅ 从官方源获取到 {len(subnets)} 个IP段")
            return subnets
        else:
            print(f"❌ 官方源返回状态码: {res.status_code}")
    except Exception as e:
        print(f"❌ 获取官方IP段失败: {e}")
    
    return []

def get_backup_urls_ips():
    """
    从备用URL（反代）获取IP列表
    """
    urls = CONFIG["BACKUP_IPS_URLS"]
    
    for url in urls:
        try:
            print(f"🌐 尝试从备用源获取: {url}")
            res = requests.get(url, timeout=10, verify=False)
            if res.status_code == 200:
                lines = res.text.splitlines()
                ips = []
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # 处理各种格式的IP
                        if ':' in line:
                            ip = line.split(':')[0]
                        elif '#' in line:
                            ip = line.split('#')[0]
                        else:
                            ip = line
                        
                        # 验证IP格式
                        try:
                            ipaddress.IPv4Address(ip)
                            ips.append({
                                'ip': ip,
                                'source': 'backup_url',
                                'url': url
                            })
                        except:
                            continue
                
                if ips:
                    print(f"✅ 从备用源 {url} 获取到 {len(ips)} 个IP")
                    return ips
        except Exception as e:
            print(f"❌ 从备用源 {url} 获取失败: {e}")
    
    print("ℹ️  所有备用URL源都不可用")
    return []

def generate_random_ips_from_subnets(subnets, count):
    """
    从IP段生成随机IP
    """
    if not subnets:
        return []
    
    random_ips = set()
    max_attempts = count * 3  # 最大尝试次数
    
    print(f"🔧 从 {len(subnets)} 个IP段生成 {count} 个随机IP...")
    with tqdm(total=count, desc="生成随机IP", unit="IP") as pbar:
        attempts = 0
        while len(random_ips) < count and attempts < max_attempts:
            subnet = random.choice(subnets)
            try:
                network = ipaddress.ip_network(subnet, strict=False)
                network_addr = int(network.network_address)
                broadcast_addr = int(network.broadcast_address)
                
                # 跳过网络地址和广播地址
                if broadcast_addr - network_addr > 1:
                    first_ip = network_addr + 1
                    last_ip = broadcast_addr - 1
                    random_ip_int = random.randint(first_ip, last_ip)
                    ip = str(ipaddress.IPv4Address(random_ip_int))
                    
                    if ip not in random_ips:
                        random_ips.add(ip)
                        pbar.update(1)
            except Exception:
                # 如果CIDR格式解析失败，使用简单方法
                base_ip = subnet.split('/')[0]
                parts = base_ip.split('.')
                if len(parts) == 4:
                    parts = [str(min(255, max(0, int(p)))) for p in parts[:3]] + [str(random.randint(1, 254))]
                    ip = ".".join(parts)
                    if ip not in random_ips:
                        random_ips.add(ip)
                        pbar.update(1)
            
            attempts += 1
    
    ips_list = [{'ip': ip, 'source': 'cloudflare_subnet'} for ip in random_ips]
    print(f"✅ 成功生成 {len(ips_list)} 个随机IP")
    return ips_list

def get_all_ips_sources():
    """
    从所有源获取IP地址（按优先级）
    """
    all_ips = []
    
    # 1. 最高优先级：备用域名IP
    print("\n" + "="*50)
    print("🔄 开始从各源获取IP地址...")
    print("="*50)
    
    backup_domain_ips = get_backup_ips()
    if backup_domain_ips:
        all_ips.extend(backup_domain_ips)
        print(f"📊 当前IP总数: {len(all_ips)} (备用域名)")
    
    # 2. 第二优先级：本地文件IP
    local_ips = get_local_ips()
    if local_ips:
        # 去重
        existing_ips = set(ip['ip'] for ip in all_ips)
        new_ips = [ip for ip in local_ips if ip['ip'] not in existing_ips]
        all_ips.extend(new_ips)
        print(f"📊 当前IP总数: {len(all_ips)} (+{len(new_ips)} 本地文件)")
    
    # 3. 第三优先级：备用URL IP
    backup_url_ips = get_backup_urls_ips()
    if backup_url_ips:
        # 去重
        existing_ips = set(ip['ip'] for ip in all_ips)
        new_ips = [ip for ip in backup_url_ips if ip['ip'] not in existing_ips]
        all_ips.extend(new_ips)
        print(f"📊 当前IP总数: {len(all_ips)} (+{len(new_ips)} 备用URL)")
    
    # 4. 第四优先级：Cloudflare官方IP段生成的随机IP
    cloudflare_subnets = get_cloudflare_ips()
    if cloudflare_subnets:
        remaining_count = max(0, CONFIG["TEST_IP_COUNT"] - len(all_ips))
        if remaining_count > 0:
            cloudflare_ips = generate_random_ips_from_subnets(cloudflare_subnets, min(remaining_count, CONFIG["IP_POOL_SIZE"]))
            # 去重
            existing_ips = set(ip['ip'] for ip in all_ips)
            new_ips = [ip for ip in cloudflare_ips if ip['ip'] not in existing_ips]
            all_ips.extend(new_ips)
            print(f"📊 当前IP总数: {len(all_ips)} (+{len(new_ips)} Cloudflare官方段)")
    
    print("="*50)
    print(f"🎯 最终获取IP总数: {len(all_ips)}")
    
    # 统计各来源的IP数量
    source_stats = {}
    for ip_data in all_ips:
        source = ip_data.get('source', 'unknown')
        if source not in source_stats:
            source_stats[source] = 0
        source_stats[source] += 1
    
    print("📈 各来源IP统计:")
    for source, count in source_stats.items():
        source_name = {
            'backup_domain': '备用域名',
            'local_file': '本地文件', 
            'backup_url': '备用URL',
            'cloudflare_subnet': 'Cloudflare段'
        }.get(source, source)
        print(f"  {source_name}: {count}个IP")
    
    return all_ips

####################################################
# IP地理位置查询函数
####################################################

def get_real_ip_country_code(ip):
    """
    使用真实的地理位置API检测IP国家代码
    """
    # 检查缓存
    if CONFIG["IP_GEO_API"]["enable_cache"] and ip in ip_geo_cache:
        return ip_geo_cache[ip]
    
    apis = [
        {
            'url': f'http://ip-api.com/json/{ip}?fields=status,message,countryCode',
            'field': 'countryCode',
            'check_field': 'status',
            'check_value': 'success'
        },
        {
            'url': f'https://ipapi.co/{ip}/json/',
            'field': 'country_code',
            'check_field': 'country_code',
            'check_value': None
        },
        {
            'url': f'https://ip.useragentinfo.com/json?ip={ip}',
            'field': 'country_code',
            'check_field': 'country_code',
            'check_value': None
        },
        {
            'url': f'http://ipinfo.io/{ip}/json',
            'field': 'country',
            'check_field': 'country',
            'check_value': None
        }
    ]
    
    for api in apis:
        try:
            response = requests.get(api['url'], timeout=CONFIG["IP_GEO_API"]["timeout"], verify=False)
            if response.status_code == 200:
                data = response.json()
                
                if api['check_value'] is not None:
                    if data.get(api['check_field']) != api['check_value']:
                        continue
                else:
                    if api['check_field'] not in data:
                        continue
                
                country_code = data.get(api['field'])
                if country_code:
                    # 缓存结果
                    if CONFIG["IP_GEO_API"]["enable_cache"]:
                        ip_geo_cache[ip] = country_code
                    
                    return country_code
        except Exception:
            continue
    
    # 如果所有API都失败，返回未知
    return 'UN'

# ... (中间的函数保持不变，包括URL测试函数、其他测试函数、核心功能函数等)
# 由于代码长度限制，这里省略中间部分，只展示修改的部分

####################################################
# 主逻辑
####################################################
if __name__ == "__main__":
    # 0. 初始化环境
    for key, value in CONFIG.items():
        os.environ[key] = str(value)

    # 1. 验证并选择最佳测试URL
    print("🔍 验证测试URL可用性...")
    best_url = CONFIG["BACKUP_TEST_URLS"][0]  # 简化验证过程
    CONFIG["URL_TEST_TARGET"] = best_url
    print(f"🎯 使用测试URL: {best_url}")
    
    # 2. 打印配置参数
    print("="*60)
    print(f"{'Cloudflare IP优选工具 - 多源版':^60}")
    print("="*60)
    print(f"测试模式: {CONFIG['MODE']}")
    print(f"输出格式: ip:端口#国旗 国家简称")
    print(f"地理位置API: 启用")
    print(f"IP源: 本地文件/官方URL/反代URL/备用域名")
    
    mode = CONFIG["MODE"]
    if mode == "PING":
        print(f"Ping目标: {CONFIG['PING_TARGET']}")
        print(f"Ping次数: {CONFIG['PING_COUNT']}")
    elif mode == "TCP":
        print(f"TCP端口: {CONFIG['PORT']}")
    elif mode == "URL_TEST":
        print(f"URL测试目标: {CONFIG['URL_TEST_TARGET']}")
    
    print(f"延迟范围: {CONFIG['RTT_RANGE']}ms")
    print(f"最大丢包: {CONFIG['LOSS_MAX']}%")
    print(f"并发线程: {CONFIG['THREADS']}")
    print(f"目标测试数: {CONFIG['TEST_IP_COUNT']}")
    print(f"精选IP数: {CONFIG['TOP_IPS_LIMIT']}")
    print("="*60 + "\n")

    # 3. 从所有源获取IP地址
    all_ip_data = get_all_ips_sources()
    
    if not all_ip_data:
        print("❌ 无法从任何源获取IP地址，程序终止")
        exit(1)
    
    # 限制测试IP数量
    test_ip_data = all_ip_data[:CONFIG["TEST_IP_COUNT"]]
    test_ips = [ip_data['ip'] for ip_data in test_ip_data]
    
    print(f"🔧 最终测试IP数量: {len(test_ips)}")
    
    # 4. 第一阶段：延迟测试（筛选IP）
    ping_results = []
    mode_display = {
        "PING": "🚀 Ping测试进度",
        "TCP": "🔌 TCP测试进度", 
        "URL_TEST": "🌐 URL测试进度"
    }
    progress_desc = mode_display.get(mode, "🚀 延迟测试进度")
    
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_ip = {executor.submit(ping_test, ip): ip for ip in test_ips}
        with tqdm(
            total=len(test_ips),
            desc=progress_desc,
            unit="IP",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_ip):
                try:
                    result = future.result()
                    ping_results.append(result)
                except Exception as e:
                    print(f"\n🔧 延迟测试异常: {e}")
                finally:
                    pbar.update(1)
    
    # 处理测试结果，保留IP的原始源信息
    processed_results = []
    for ip_data in ping_results:
        ip = ip_data[0]
        rtt = ip_data[1]
        loss = ip_data[2]
        
        # 查找IP的原始信息
        original_info = None
        for original_ip in test_ip_data:
            if original_ip['ip'] == ip:
                original_info = original_ip
                break
        
        if original_info:
            # 保留原始信息
            processed_ip = {
                'ip': ip,
                'rtt': rtt,
                'loss': loss,
                'source': original_info['source'],
                'domain': original_info.get('domain'),
                'region': original_info.get('region'),
                'regionCode': original_info.get('regionCode'),
                'port': original_info.get('port', CONFIG["PORT"]),
                'file': original_info.get('file'),
                'url': original_info.get('url')
            }
        else:
            # 未知源的IP
            processed_ip = {
                'ip': ip,
                'rtt': rtt,
                'loss': loss,
                'source': 'unknown'
            }
        
        processed_results.append(processed_ip)
    
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    passed_ips = [
        ip_data for ip_data in processed_results
        if rtt_min <= ip_data['rtt'] <= rtt_max and ip_data['loss'] <= loss_max
    ]
    print(f"\n✅ 延迟测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips)}")

    # 5. 第二阶段：测速（仅对通过延迟测试的IP）
    if not passed_ips:
        print("❌ 没有通过延迟测试的IP，程序终止")
        exit(1)
    
    full_results = []
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_ip = {executor.submit(full_test, (ip_data['ip'], ip_data['rtt'], ip_data['loss'])): ip_data 
                       for ip_data in passed_ips}
        with tqdm(
            total=len(passed_ips),
            desc="📊 测速进度",
            unit="IP",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_ip):
                try:
                    result = future.result()
                    # 重新关联原始信息
                    ip = result[0]
                    for original_ip in passed_ips:
                        if original_ip['ip'] == ip:
                            full_ip_data = {
                                'ip': ip,
                                'rtt': result[1],
                                'loss': result[2],
                                'speed': result[3],
                                'source': original_ip['source'],
                                'domain': original_ip.get('domain'),
                                'region': original_ip.get('region'),
                                'regionCode': original_ip.get('regionCode'),
                                'port': original_ip.get('port', CONFIG["PORT"]),
                                'file': original_ip.get('file'),
                                'url': original_ip.get('url')
                            }
                            full_results.append(full_ip_data)
                            break
                except Exception as e:
                    print(f"\n🔧 测速异常: {e}")
                finally:
                    pbar.update(1)

    # 6. 为IP添加真实国家代码信息
    enhanced_results = []
    print("🌍 正在检测IP真实地理位置...")
    with tqdm(total=len(full_results), desc="IP地理位置", unit="IP") as pbar:
        for ip_data in full_results:
            country_code = get_real_ip_country_code(ip_data['ip'])
            ip_data['countryCode'] = country_code
            ip_data['isp'] = "Cloudflare"
            enhanced_results.append(ip_data)
            pbar.update(1)

    # 7. 按性能排序，但优先显示备用域名IP
    sorted_ips = sorted(
        enhanced_results,
        key=lambda x: (
            0 if x.get('source') == 'backup_domain' else 
            1 if x.get('source') == 'local_file' else
            2 if x.get('source') == 'backup_url' else
            3,  # cloudflare_subnet 和 unknown
            -x['speed'], 
            x['rtt']
        )
    )[:CONFIG["TOP_IPS_LIMIT"]]

    # 8. 保存结果
    os.makedirs('results', exist_ok=True)
    
    # 保存详细结果
    with open('results/full_results.csv', 'w', encoding='utf-8') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),国家代码,来源,域名,文件,URL,ISP\n")
        for ip_data in enhanced_results:
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['countryCode']},{ip_data['source']},{ip_data.get('domain', '')},{ip_data.get('file', '')},{ip_data.get('url', '')},{ip_data['isp']}\n")
    
    # 保存精选IP
    with open('results/top_ips.txt', 'w', encoding='utf-8') as f:
        formatted_lines = []
        for ip_data in sorted_ips:
            country_code = ip_data.get('countryCode', 'UN')
            flag = CONFIG["COUNTRY_FLAGS"].get(country_code, '🏴')
            port = ip_data.get('port', CONFIG["PORT"])
            formatted_lines.append(f"{ip_data['ip']}:{port}#{flag} {country_code}")
        f.write("\n".join(formatted_lines))
    
    with open('results/top_ips_details.csv', 'w', encoding='utf-8') as f:
        f.write("IP,端口,延迟(ms),丢包率(%),速度(Mbps),国家代码,来源,域名\n")
        for ip_data in sorted_ips:
            f.write(f"{ip_data['ip']},{ip_data.get('port', CONFIG['PORT'])},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['countryCode']},{ip_data['source']},{ip_data.get('domain', '')}\n")

    # 9. 统计和显示结果
    print("\n" + "="*60)
    print(f"{'🔥 测试结果统计':^60}")
    print("="*60)
    
    # 统计各来源的通过情况
    source_stats = {}
    for ip_data in enhanced_results:
        source = ip_data['source']
        if source not in source_stats:
            source_stats[source] = {'total': 0, 'passed': 0}
        source_stats[source]['passed'] += 1
    
    for ip_data in all_ip_data:
        source = ip_data['source']
        if source not in source_stats:
            source_stats[source] = {'total': 0, 'passed': 0}
        source_stats[source]['total'] += 1
    
    print("📈 各来源测试统计:")
    for source, stats in source_stats.items():
        source_name = {
            'backup_domain': '备用域名',
            'local_file': '本地文件', 
            'backup_url': '备用URL',
            'cloudflare_subnet': 'Cloudflare段',
            'unknown': '未知源'
        }.get(source, source)
        pass_rate = (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
        print(f"  {source_name}: {stats['passed']}/{stats['total']} 通过 ({pass_rate:.1f}%)")
    
    print(f"\n🏆【最佳IP TOP10】(按来源优先级排序)")
    for i, ip_data in enumerate(sorted_ips[:10], 1):
        country_code = ip_data.get('countryCode', 'UN')
        flag = CONFIG["COUNTRY_FLAGS"].get(country_code, '🏴')
        port = ip_data.get('port', CONFIG["PORT"])
        source_desc = {
            'backup_domain': '[备用域名]',
            'local_file': '[本地文件]', 
            'backup_url': '[备用URL]',
            'cloudflare_subnet': '[Cloudflare]',
            'unknown': '[未知]'
        }.get(ip_data['source'], '')
        
        print(f"{i:2d}. {ip_data['ip']}:{port}#{flag} {country_code} {source_desc}")
        print(f"     延迟:{ip_data['rtt']:.1f}ms, 丢包:{ip_data['loss']:.1f}%, 速度:{ip_data['speed']:.1f}Mbps")
    
    print("="*60)
    print("✅ 结果已保存至 results/ 目录")
    print("📊 文件说明:")
    print("   - top_ips.txt: 精选IP列表 (ip:端口#国旗 国家简称)")
    print("   - top_ips_details.csv: 详细性能数据")
    print("   - full_results.csv: 完整测试结果")
    print("="*60)
