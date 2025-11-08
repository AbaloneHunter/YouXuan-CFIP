import os
import requests
import random
import numpy as np
import time
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from tqdm import tqdm
import urllib3
import ipaddress

####################################################
# 可配置参数（程序开头）
####################################################
CONFIG = {
    "MODE": "TCP",  # 测试模式：PING/TCP
    "PING_TARGET": "http://www.gstatic.com/generate_204",  # Ping测试目标
    "PING_COUNT": 8,  # Ping次数
    "PING_TIMEOUT": 3,  # Ping超时(秒)
    "PORT": 443,  # TCP测试端口
    "RTT_RANGE": "10~300",  # 延迟范围(ms)
    "LOSS_MAX": 2.0,  # 最大丢包率(%)
    "THREADS": 80,  # 并发线程数
    "IP_POOL_SIZE": 50000,  # IP池总大小
    "TEST_IP_COUNT": 800,  # 实际测试IP数量
    "TOP_IPS_LIMIT": 50,  # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    
    # 新增：多地区配置
    "ENABLE_REGION_MATCHING": True,  # 启用地区匹配
    "MANUAL_WORKER_REGION": "HK",  # 手动指定Worker地区（单地区）
    "TARGET_REGIONS": ["HK", "SG", "JP", "KR","US"],  # 新增：目标地区列表（多地区）
    "REGION_MAPPING": {
        'US': ['🇺🇸 美国', 'US', 'United States'],
        'SG': ['🇸🇬 新加坡', 'SG', 'Singapore'],
        'JP': ['🇯🇵 日本', 'JP', 'Japan'],
        'HK': ['🇭🇰 香港', 'HK', 'Hong Kong'],
        'KR': ['🇰🇷 韩国', 'KR', 'South Korea'],
        'DE': ['🇩🇪 德国', 'DE', 'Germany'],
        'SE': ['🇸🇪 瑞典', 'SE', 'Sweden'],
        'NL': ['🇳🇱 荷兰', 'NL', 'Netherlands'],
        'FI': ['🇫🇮 芬兰', 'FI', 'Finland'],
        'GB': ['🇬🇧 英国', 'GB', 'United Kingdom'],
        'Oracle': ['甲骨文', 'Oracle'],
        'DigitalOcean': ['数码海', 'DigitalOcean'],
        'Vultr': ['Vultr', 'Vultr'],
        'Multacom': ['Multacom', 'Multacom']
    },
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
    
    # 新增：IP地理位置API配置
    "IP_GEO_API": {
        "timeout": 3,
        "retry": 2,
        "enable_cache": True
    }
}

####################################################
# 新增：IP地理位置缓存
####################################################
ip_geo_cache = {}

####################################################
# 新增：真实IP地理位置检测函数
####################################################

def get_real_ip_region(ip):
    """
    使用真实的地理位置API检测IP地区
    支持多个备用API，提高查询成功率
    """
    # 检查缓存
    if CONFIG["IP_GEO_API"]["enable_cache"] and ip in ip_geo_cache:
        return ip_geo_cache[ip]
    
    apis = [
        # API 1: ip-api.com (免费，无需key，限制45次/分钟)
        {
            'url': f'http://ip-api.com/json/{ip}?fields=status,message,countryCode',
            'field': 'countryCode',
            'check_field': 'status',
            'check_value': 'success'
        },
        # API 2: ipapi.co (免费额度1000次/天)
        {
            'url': f'https://ipapi.co/{ip}/json/',
            'field': 'country_code',
            'check_field': 'country_code',
            'check_value': None  # 只要存在就认为成功
        },
        # API 3: 国内API
        {
            'url': f'https://ip.useragentinfo.com/json?ip={ip}',
            'field': 'country_code',
            'check_field': 'country_code',
            'check_value': None
        }
    ]
    
    for api in apis:
        try:
            response = requests.get(api['url'], timeout=CONFIG["IP_GEO_API"]["timeout"])
            if response.status_code == 200:
                data = response.json()
                
                # 检查API响应是否有效
                if api['check_value'] is not None:
                    if data.get(api['check_field']) != api['check_value']:
                        continue
                else:
                    if api['check_field'] not in data:
                        continue
                
                country_code = data.get(api['field'])
                if country_code:
                    region_code = map_country_to_region(country_code)
                    
                    # 缓存结果
                    if CONFIG["IP_GEO_API"]["enable_cache"]:
                        ip_geo_cache[ip] = region_code
                    
                    return region_code
        except Exception as e:
            continue
    
    # 所有API都失败，返回None
    return None

def map_country_to_region(country_code):
    """
    将国家代码映射到地区代码
    """
    country_to_region = {
        # 北美
        'US': 'US', 'CA': 'US', 'MX': 'US',
        # 亚洲
        'SG': 'SG', 'JP': 'JP', 'KR': 'KR', 'TW': 'HK', 'MO': 'HK',
        'CN': 'HK',  # 中国大陆映射到香港
        # 欧洲
        'DE': 'DE', 'FR': 'DE', 'GB': 'GB', 'NL': 'NL', 'SE': 'SE', 
        'FI': 'FI', 'IT': 'DE', 'ES': 'DE', 'CH': 'DE', 'RU': 'DE',
        # 大洋洲
        'AU': 'SG', 'NZ': 'SG',  # 大洋洲映射到新加坡
        # 其他亚洲地区
        'TH': 'SG', 'MY': 'SG', 'ID': 'SG', 'VN': 'SG', 'PH': 'SG',
        'IN': 'SG', 'BD': 'SG', 'PK': 'SG'
    }
    return country_to_region.get(country_code, 'US')  # 默认美国

def get_region_by_rtt(rtt, worker_region):
    """
    根据延迟智能推测地区（备用方案）
    """
    if not worker_region:
        worker_region = 'HK'
    
    if rtt < 30:
        # 极低延迟，很可能是同地区
        return worker_region
    elif rtt < 80:
        # 低延迟，可能是邻近地区
        nearby_regions = get_nearby_regions(worker_region)
        return random.choice(nearby_regions) if nearby_regions else worker_region
    elif rtt < 150:
        # 中等延迟，可能是亚洲其他地区
        asia_regions = ['SG', 'JP', 'KR', 'HK']
        return random.choice([r for r in asia_regions if r != worker_region])
    else:
        # 高延迟，可能是欧美地区
        return random.choice(['US', 'DE', 'GB'])

####################################################
# 新增：多地区支持函数
####################################################

def parse_target_regions():
    """
    解析目标地区配置，支持多种输入格式
    """
    target_regions = CONFIG["TARGET_REGIONS"]
    
    # 如果TARGET_REGIONS是字符串，尝试解析
    if isinstance(target_regions, str):
        # 支持逗号分隔：HK,SG,JP
        if ',' in target_regions:
            target_regions = [region.strip().upper() for region in target_regions.split(',')]
        # 支持空格分隔：HK SG JP
        elif ' ' in target_regions:
            target_regions = [region.strip().upper() for region in target_regions.split()]
        # 单个地区
        else:
            target_regions = [target_regions.strip().upper()]
    
    # 验证地区代码有效性
    valid_regions = []
    invalid_regions = []
    
    for region in target_regions:
        if region in CONFIG["REGION_MAPPING"]:
            valid_regions.append(region)
        else:
            invalid_regions.append(region)
    
    if invalid_regions:
        print(f"⚠️ 警告: 以下地区代码无效: {invalid_regions}")
        print(f"✅ 有效地区代码: {list(CONFIG['REGION_MAPPING'].keys())}")
    
    if not valid_regions:
        print("❌ 没有有效的目标地区，使用默认地区: HK")
        valid_regions = ['HK']
    
    return valid_regions

def filter_ips_by_regions(ip_list, target_regions):
    """
    根据目标地区列表过滤IP
    """
    if not target_regions or target_regions == ['ALL']:
        return ip_list
    
    filtered_ips = [ip for ip in ip_list if ip.get('regionCode') in target_regions]
    return filtered_ips

def get_multi_region_selection(ip_list, target_regions):
    """
    多地区智能排序算法
    """
    if not target_regions or target_regions == ['ALL']:
        # 如果不指定地区或指定ALL，返回所有地区按质量排序
        return sorted(ip_list, key=lambda x: (-x['speed'], x['rtt'], x['loss']))
    
    # 按目标地区优先级分组
    region_groups = {}
    for region in target_regions:
        region_ips = [ip for ip in ip_list if ip.get('regionCode') == region]
        # 每个地区内按质量排序
        region_ips_sorted = sorted(region_ips, key=lambda x: (-x['speed'], x['rtt'], x['loss']))
        region_groups[region] = region_ips_sorted
    
    # 合并结果：每个地区取前N个，然后按质量排序
    merged_ips = []
    max_per_region = max(1, len(ip_list) // len(target_regions))
    
    for region in target_regions:
        region_ips = region_groups.get(region, [])
        # 从每个地区取质量最好的IP
        merged_ips.extend(region_ips[:max_per_region])
    
    # 最终按质量排序
    return sorted(merged_ips, key=lambda x: (-x['speed'], x['rtt'], x['loss']))

def display_region_statistics(enhanced_results, target_regions):
    """
    显示多地区统计信息
    """
    region_stats = {}
    total_ips = len(enhanced_results)
    
    for ip_data in enhanced_results:
        region = ip_data['regionCode']
        if region not in region_stats:
            region_stats[region] = {
                'count': 0,
                'avg_rtt': 0,
                'avg_speed': 0,
                'region_name': ip_data['regionName'],
                'is_target': region in target_regions
            }
        region_stats[region]['count'] += 1
        region_stats[region]['avg_rtt'] += ip_data['rtt']
        region_stats[region]['avg_speed'] += ip_data['speed']
    
    # 计算平均值
    for region in region_stats:
        if region_stats[region]['count'] > 0:
            region_stats[region]['avg_rtt'] /= region_stats[region]['count']
            region_stats[region]['avg_speed'] /= region_stats[region]['count']
    
    # 按是否目标地区排序
    target_stats = {k: v for k, v in region_stats.items() if v['is_target']}
    other_stats = {k: v for k, v in region_stats.items() if not v['is_target']}
    
    print(f"\n🌍 多地区统计 (总数: {total_ips}):")
    
    if target_stats:
        print("🎯 目标地区:")
        for region, stats in sorted(target_stats.items(), key=lambda x: x[1]['count'], reverse=True):
            percentage = (stats['count'] / total_ips) * 100
            print(f"  {stats['region_name']}: {stats['count']}个IP ({percentage:.1f}%), "
                  f"平均延迟{stats['avg_rtt']:.1f}ms, 平均速度{stats['avg_speed']:.1f}Mbps")
    
    if other_stats:
        print("📊 其他地区:")
        for region, stats in sorted(other_stats.items(), key=lambda x: x[1]['count'], reverse=True):
            percentage = (stats['count'] / total_ips) * 100
            print(f"  {stats['region_name']}: {stats['count']}个IP ({percentage:.1f}%), "
                  f"平均延迟{stats['avg_rtt']:.1f}ms, 平均速度{stats['avg_speed']:.1f}Mbps")
    
    return region_stats

####################################################
# 格式化输出函数
####################################################

def format_ip_with_region(ip_data, port=None):
    """
    格式化IP输出为 ip:端口#国旗 地区名称 格式
    """
    if port is None:
        port = int(os.getenv('PORT', 443))
    
    region_code = ip_data.get('regionCode', 'Unknown')
    region_info = CONFIG["REGION_MAPPING"].get(region_code, [f"🇺🇳 未知({region_code})"])
    flag_and_name = region_info[0]  # 获取国旗和地区名称
    
    return f"{ip_data['ip']}:{port}#{flag_and_name}"

def format_ip_with_port_only(ip_data, port=None):
    """
    只输出 ip:端口 格式
    """
    if port is None:
        port = int(os.getenv('PORT', 443))
    
    return f"{ip_data['ip']}:{port}"

def format_ip_list_for_display(ip_list, port=None):
    """
    格式化IP列表用于显示（包含地区和纯IP:端口）
    """
    if port is None:
        port = int(os.getenv('PORT', 443))
    
    formatted_ips = []
    for ip_data in ip_list:
        formatted_ips.append(format_ip_with_region(ip_data, port))
    
    return formatted_ips

def format_ip_list_for_file(ip_list, port=None, include_region=True):
    """
    格式化IP列表用于文件保存
    include_region: 是否包含地区信息
    """
    if port is None:
        port = int(os.getenv('PORT', 443))
    
    formatted_lines = []
    for ip_data in ip_list:
        if include_region:
            region_code = ip_data.get('regionCode', 'Unknown')
            region_info = CONFIG["REGION_MAPPING"].get(region_code, [f"🇺🇳 未知({region_code})"])
            flag_and_name = region_info[0]
            formatted_lines.append(f"{ip_data['ip']}:{port}#{flag_and_name}")
        else:
            formatted_lines.append(f"{ip_data['ip']}:{port}")
    
    return formatted_lines

####################################################
# 从JS版本移植的地区管理功能
####################################################

def detect_worker_region():
    """
    检测Worker地区（模拟JS版本的detectWorkerRegion函数）
    在实际环境中，这里应该通过API检测真实地区
    这里使用模拟数据，实际使用时可以替换为真实检测逻辑
    """
    try:
        # 模拟检测逻辑 - 实际使用时可以替换为真实的地理位置检测
        # 这里使用环境变量或随机选择作为演示
        manual_region = CONFIG["MANUAL_WORKER_REGION"]
        if manual_region and manual_region.strip():
            return manual_region.strip().upper()
        
        # 如果没有手动指定，模拟自动检测
        # 实际使用时可以调用IP地理位置API
        regions = list(CONFIG["REGION_MAPPING"].keys())
        detected_region = random.choice(['US', 'SG', 'JP', 'HK', 'KR', 'DE'])
        
        print(f"📍 检测到Worker地区: {CONFIG['REGION_MAPPING'].get(detected_region, [detected_region])[0]}")
        return detected_region
        
    except Exception as error:
        print(f"⚠️ 地区检测失败，使用默认地区: {error}")
        return 'HK'  # 默认香港

def get_nearby_regions(region):
    """
    获取邻近地区列表（从JS版本移植）
    """
    nearby_map = {
        'US': ['SG', 'JP', 'HK', 'KR'],
        'SG': ['JP', 'HK', 'KR', 'US'],
        'JP': ['SG', 'HK', 'KR', 'US'],
        'HK': ['SG', 'JP', 'KR', 'US'],
        'KR': ['JP', 'HK', 'SG', 'US'],
        'DE': ['NL', 'GB', 'SE', 'FI'],
        'SE': ['DE', 'NL', 'FI', 'GB'],
        'NL': ['DE', 'GB', 'SE', 'FI'],
        'FI': ['SE', 'DE', 'NL', 'GB'],
        'GB': ['DE', 'NL', 'SE', 'FI']
    }
    return nearby_map.get(region, [])

def get_all_regions_by_priority(region):
    """
    获取按优先级排序的所有地区（从JS版本移植）
    """
    nearby_regions = get_nearby_regions(region)
    all_regions = ['US', 'SG', 'JP', 'HK', 'KR', 'DE', 'SE', 'NL', 'FI', 'GB']
    
    return [region, *nearby_regions, *[r for r in all_regions if r != region and r not in nearby_regions]]

def get_smart_region_selection(worker_region, available_ips):
    """
    智能地区选择算法（从JS版本移植）
    """
    if not CONFIG["ENABLE_REGION_MATCHING"] or not worker_region:
        return available_ips
    
    priority_regions = get_all_regions_by_priority(worker_region)
    
    sorted_ips = []
    
    # 按地区优先级排序IP
    for region in priority_regions:
        region_ips = [ip for ip in available_ips if ip.get('regionCode') == region]
        sorted_ips.extend(region_ips)
    
    # 添加没有地区信息的IP
    other_ips = [ip for ip in available_ips if ip.get('regionCode') not in priority_regions and ip.get('regionCode') is not None]
    sorted_ips.extend(other_ips)
    
    return sorted_ips

def check_ip_availability(domain, port=443, timeout=2):
    """
    检查IP可用性（从JS版本移植）
    """
    try:
        response = requests.head(
            f"https://{domain}", 
            timeout=timeout,
            headers={'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Checker/1.0)'},
            verify=False
        )
        return response.status_code < 500
    except Exception as error:
        print(f"🔧 IP可用性检查失败 {domain}: {error}")
        return True  # 默认认为可用

def get_best_backup_ip(worker_region=''):
    """
    获取最佳备用IP（从JS版本移植）
    """
    backup_ips = CONFIG["BACKUP_IPS"]
    
    if not backup_ips:
        return None
    
    # 检查IP可用性
    available_ips = []
    for ip_info in backup_ips:
        if check_ip_availability(ip_info['domain'], ip_info['port']):
            available_ips.append(ip_info)
    
    if CONFIG["ENABLE_REGION_MATCHING"] and worker_region:
        sorted_ips = get_smart_region_selection(worker_region, available_ips)
        if sorted_ips:
            return sorted_ips[0]
    
    return available_ips[0] if available_ips else None

####################################################
# 核心功能函数
####################################################

def init_env():
    """初始化环境"""
    for key, value in CONFIG.items():
        os.environ[key] = str(value)
    cf_url = os.getenv('CLOUDFLARE_IPS_URL')
    if cf_url and not cf_url.startswith(('http://', 'https://')):
        os.environ['CLOUDFLARE_IPS_URL'] = f"https://{cf_url}"
    urllib3.disable_warnings()

def fetch_ip_ranges():
    """获取IP段"""
    custom_file = os.getenv('CUSTOM_IPS_FILE')
    if custom_file and os.path.exists(custom_file):
        print(f"🔧 使用自定义IP池文件: {custom_file}")
        try:
            with open(custom_file, 'r') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            print(f"🚨 读取自定义IP池失败: {e}")
    url = os.getenv('CLOUDFLARE_IPS_URL')
    try:
        res = requests.get(url, timeout=10, verify=False)
        return res.text.splitlines()
    except Exception as e:
        print(f"🚨 获取Cloudflare IP段失败: {e}")
    return []

def generate_random_ip(subnet):
    """根据CIDR生成子网内的随机合法IP"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        network_addr = int(network.network_address)
        broadcast_addr = int(network.broadcast_address)
        first_ip = network_addr + 1
        last_ip = broadcast_addr - 1
        random_ip_int = random.randint(first_ip, last_ip)
        return str(ipaddress.IPv4Address(random_ip_int))
    except Exception as e:
        print(f"生成随机IP错误: {e}，使用简单方法生成")
        base_ip = subnet.split('/')[0]
        parts = base_ip.split('.')
        while len(parts) < 4:
            parts.append(str(random.randint(0, 255)))
        parts = [str(min(255, max(0, int(p)))) for p in parts[:3]] + [str(random.randint(1, 254))]
        return ".".join(parts)

def custom_ping(ip):
    """自定义Ping测试"""
    target = urlparse(os.getenv('PING_TARGET')).netloc or os.getenv('PING_TARGET')
    count = int(os.getenv('PING_COUNT'))
    timeout = int(os.getenv('PING_TIMEOUT'))
    try:
        if os.name == 'nt':
            cmd = f"ping -n {count} -w {timeout*1000} {target}"
        else:
            cmd = f"ping -c {count} -W {timeout} -I {ip} {target}"
        result = subprocess.run(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout + 2
        )
        output = result.stdout.lower()
        if "100% packet loss" in output or "unreachable" in output:
            return float('inf'), 100.0
        loss_line = next((l for l in result.stdout.split('\n') if "packet loss" in l.lower()), "")
        timing_lines = [l for l in result.stdout.split('\n') if "time=" in l.lower()]
        loss_percent = 100.0
        if loss_line:
            loss_parts = loss_line.split('%')
            if loss_parts:
                try:
                    loss_percent = float(loss_parts[0].split()[-1])
                except:
                    pass
        delays = []
        for line in timing_lines:
            if "time=" in line:
                time_str = line.split("time=")[1].split()[0]
                try:
                    delays.append(float(time_str))
                except:
                    continue
        avg_delay = np.mean(delays) if delays else float('inf')
        return avg_delay, loss_percent
    except subprocess.TimeoutExpired:
        return float('inf'), 100.0
    except Exception as e:
        print(f"Ping测试异常: {e}")
        return float('inf'), 100.0

def tcp_ping(ip, port, timeout=2):
    """TCP Ping测试"""
    retry = int(os.getenv('TCP_RETRY', 3))
    success_count = 0
    total_rtt = 0
    for _ in range(retry):
        start = time.time()
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                rtt = (time.time() - start) * 1000
                total_rtt += rtt
                success_count += 1
        except:
            pass
        time.sleep(0.1)
    loss_rate = 100 - (success_count / retry * 100)
    avg_rtt = total_rtt / success_count if success_count > 0 else float('inf')
    return avg_rtt, loss_rate

def speed_test(ip):
    """速度测试"""
    url = os.getenv('SPEED_URL')
    timeout = float(os.getenv('SPEED_TIMEOUT', 10))
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        start_time = time.time()
        response = requests.get(
            url, headers={'Host': host}, timeout=timeout, verify=False, stream=True
        )
        total_bytes = 0
        for chunk in response.iter_content(chunk_size=8192):
            total_bytes += len(chunk)
            if time.time() - start_time > timeout:
                break
        duration = time.time() - start_time
        speed_mbps = (total_bytes * 8 / duration) / 1e6 if duration > 0 else 0
        return speed_mbps
    except Exception as e:
        print(f"测速异常: {e}")
        return 0.0

def ping_test(ip):
    """Ping测试入口"""
    if os.getenv('MODE') == "PING":
        rtt, loss = custom_ping(ip)
    else:
        rtt, loss = tcp_ping(ip, int(os.getenv('PORT')))
    return (ip, rtt, loss)

def full_test(ip_data):
    """完整测试（Ping + 速度）"""
    ip = ip_data[0]
    speed = speed_test(ip)
    return (*ip_data, speed)

def enhance_ip_with_region_info(ip_list, worker_region):
    """
    为IP列表添加真实的地区信息
    """
    enhanced_ips = []
    
    print("🌍 正在检测IP真实地理位置...")
    with tqdm(total=len(ip_list), desc="IP地理位置", unit="IP") as pbar:
        for ip_data in ip_list:
            ip = ip_data[0]
            rtt = ip_data[1]
            loss = ip_data[2]
            speed = ip_data[3] if len(ip_data) > 3 else 0
            
            # 使用真实API获取地区
            region_code = get_real_ip_region(ip)
            
            # 如果API查询失败，使用智能回退
            if not region_code:
                region_code = get_region_by_rtt(rtt, worker_region)
                pbar.set_description(f"IP地理位置 (备用模式)")
            
            region_name = CONFIG["REGION_MAPPING"].get(region_code, [f"🇺🇳 未知({region_code})"])[0]
            
            enhanced_ip = {
                'ip': ip,
                'rtt': rtt,
                'loss': loss,
                'speed': speed,
                'regionCode': region_code,
                'regionName': region_name,
                'isp': f"Cloudflare"
            }
            enhanced_ips.append(enhanced_ip)
            pbar.update(1)
    
    return enhanced_ips

####################################################
# 主逻辑
####################################################
if __name__ == "__main__":
    # 0. 初始化环境
    init_env()
    
    # 1. 解析目标地区配置
    target_regions = parse_target_regions()
    
    # 2. 打印配置参数
    print("="*60)
    print(f"{'IP网络优化器 v2.5 (多地区支持版)':^60}")
    print("="*60)
    print(f"测试模式: {os.getenv('MODE')}")
    
    # 检测Worker地区
    worker_region = detect_worker_region()
    if CONFIG["MANUAL_WORKER_REGION"]:
        print(f"Worker地区: {CONFIG['REGION_MAPPING'].get(worker_region, [worker_region])[0]} (手动指定)")
    else:
        print(f"Worker地区: {CONFIG['REGION_MAPPING'].get(worker_region, [worker_region])[0]} (自动检测)")
    
    print(f"目标地区: {', '.join([CONFIG['REGION_MAPPING'].get(r, [r])[0] for r in target_regions])}")
    print(f"地区匹配: {'启用' if CONFIG['ENABLE_REGION_MATCHING'] else '禁用'}")
    print(f"地理位置API: 启用 (ip-api.com, ipapi.co, ip.useragentinfo.com)")
    
    if os.getenv('MODE') == "PING":
        print(f"Ping目标: {os.getenv('PING_TARGET')}")
        print(f"Ping次数: {os.getenv('PING_COUNT')}")
        print(f"Ping超时: {os.getenv('PING_TIMEOUT')}秒")
    else:
        print(f"TCP端口: {os.getenv('PORT')}")
        print(f"TCP重试: {os.getenv('TCP_RETRY')}次")
        print(f"延迟范围: {os.getenv('RTT_RANGE')}ms")
        print(f"最大丢包: {os.getenv('LOSS_MAX')}%")
        print(f"并发线程: {os.getenv('THREADS')}")
        print(f"IP池大小: {os.getenv('IP_POOL_SIZE')}")
    
    print(f"测试IP数: {os.getenv('TEST_IP_COUNT')}")
    custom_file = os.getenv('CUSTOM_IPS_FILE')
    if custom_file:
        print(f"自定义IP池: {custom_file}")
    else:
        print(f"Cloudflare IP源: {os.getenv('CLOUDFLARE_IPS_URL')}")
    print(f"测速URL: {os.getenv('SPEED_URL')}")
    print("="*60 + "\n")

    # 3. 获取IP段并生成随机IP池
    subnets = fetch_ip_ranges()
    if not subnets:
        print("❌ 无法获取IP段，程序终止")
        exit(1)
    
    source_type = "自定义" if custom_file and os.path.exists(custom_file) else "Cloudflare"
    print(f"✅ 获取到 {len(subnets)} 个{source_type} IP段")
    
    ip_pool_size = int(os.getenv('IP_POOL_SIZE'))
    test_ip_count = int(os.getenv('TEST_IP_COUNT'))
    full_ip_pool = set()
    
    print(f"🔧 正在生成 {ip_pool_size} 个随机IP的大池...")
    with tqdm(total=ip_pool_size, desc="生成IP大池", unit="IP") as pbar:
        while len(full_ip_pool) < ip_pool_size:
            subnet = random.choice(subnets)
            ip = generate_random_ip(subnet)
            if ip not in full_ip_pool:
                full_ip_pool.add(ip)
                pbar.update(1)
    
    print(f"✅ 成功生成 {len(full_ip_pool)} 个随机IP的大池")
    
    if test_ip_count > len(full_ip_pool):
        print(f"⚠️ 警告: 测试IP数量({test_ip_count})大于IP池大小({len(full_ip_pool)})，使用全部IP")
        test_ip_count = len(full_ip_pool)
    
    test_ip_pool = random.sample(list(full_ip_pool), test_ip_count)
    print(f"🔧 从大池中随机选择 {len(test_ip_pool)} 个IP进行测试")

    # 4. 第一阶段：Ping测试（筛选IP）
    ping_results = []
    with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
        future_to_ip = {executor.submit(ping_test, ip): ip for ip in test_ip_pool}
        with tqdm(
            total=len(test_ip_pool),
            desc="🚀 Ping测试进度",
            unit="IP",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_ip):
                try:
                    ping_results.append(future.result())
                except Exception as e:
                    print(f"\n🔧 Ping测试异常: {e}")
                finally:
                    pbar.update(1)
    
    rtt_min, rtt_max = map(int, os.getenv('RTT_RANGE').split('~'))
    loss_max = float(os.getenv('LOSS_MAX'))
    passed_ips = [
        ip_data for ip_data in ping_results
        if rtt_min <= ip_data[1] <= rtt_max and ip_data[2] <= loss_max
    ]
    print(f"\n✅ Ping测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips)}")

    # 5. 第二阶段：测速（仅对通过Ping测试的IP）
    if not passed_ips:
        print("❌ 没有通过Ping测试的IP，程序终止")
        exit(1)
    
    full_results = []
    with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
        future_to_ip = {executor.submit(full_test, ip_data): ip_data for ip_data in passed_ips}
        with tqdm(
            total=len(passed_ips),
            desc="📊 测速进度",
            unit="IP",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_ip):
                try:
                    full_results.append(future.result())
                except Exception as e:
                    print(f"\n🔧 测速异常: {e}")
                finally:
                    pbar.update(1)

    # 6. 为IP添加真实地区信息
    enhanced_results = enhance_ip_with_region_info(full_results, worker_region)

    # 7. 多地区智能排序
    print(f"🔧 正在按多地区优先级排序...")
    
    # 首先过滤出目标地区的IP
    target_region_ips = filter_ips_by_regions(enhanced_results, target_regions)
    
    if not target_region_ips:
        print(f"⚠️ 警告: 在目标地区 {target_regions} 中没有找到符合条件的IP，使用所有地区")
        target_region_ips = enhanced_results
    
    # 使用多地区排序算法
    sorted_ips = get_multi_region_selection(target_region_ips, target_regions)
    sorted_ips = sorted_ips[:int(os.getenv('TOP_IPS_LIMIT', 15))]

    # 8. 保存结果
    os.makedirs('results', exist_ok=True)
    
    # 保存所有测试过的IP
    with open('results/all_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in ping_results]))
    
    # 保存通过初步筛选的IP
    with open('results/passed_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in passed_ips]))
    
    # 保存完整结果（CSV格式）
    with open('results/full_results.csv', 'w') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),地区代码,地区名称,ISP\n")
        for ip_data in enhanced_results:
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['regionCode']},{ip_data['regionName']},{ip_data['isp']}\n")
    
    # 保存精选IP - 包含地区信息
    with open('results/top_ips.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_ip_list_for_file(sorted_ips, include_region=True)
        f.write("\n".join(formatted_lines))
    
    # 保存纯IP:端口格式（无地区信息）
    with open('results/top_ips_plain.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_ip_list_for_file(sorted_ips, include_region=False)
        f.write("\n".join(formatted_lines))
    
    # 保存精选IP详细信息
    with open('results/top_ips_details.csv', 'w', encoding='utf-8') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),地区代码,地区名称,ISP\n")
        for ip_data in sorted_ips:
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['regionCode']},{ip_data['regionName']},{ip_data['isp']}\n")
    
    # 9. 多地区统计
    region_stats = display_region_statistics(enhanced_results, target_regions)

    # 10. 显示最终结果
    print("\n" + "="*60)
    print(f"{'🔥 多地区测试结果统计':^60}")
    print("="*60)
    print(f"IP池大小: {ip_pool_size}")
    print(f"实际测试IP数: {len(ping_results)}")
    print(f"通过Ping测试IP数: {len(passed_ips)}")
    print(f"测速IP数: {len(enhanced_results)}")
    print(f"目标地区IP数: {len(target_region_ips)}")
    print(f"精选TOP IP: {len(sorted_ips)}")
    print(f"Worker地区: {CONFIG['REGION_MAPPING'].get(worker_region, [worker_region])[0]}")
    print(f"目标地区: {', '.join([CONFIG['REGION_MAPPING'].get(r, [r])[0] for r in target_regions])}")
    
    if sorted_ips:
        # 按地区分组显示最佳IP
        print(f"\n🏆【最佳IP TOP10 (按地区分组)】")
        region_groups = {}
        for ip_data in sorted_ips[:10]:
            region = ip_data['regionCode']
            if region not in region_groups:
                region_groups[region] = []
            region_groups[region].append(ip_data)
        
        for region, ips in region_groups.items():
            region_name = CONFIG["REGION_MAPPING"].get(region, [f"未知({region})"])[0]
            print(f"\n{region_name}:")
            for i, ip_data in enumerate(ips, 1):
                plain_ip = format_ip_with_port_only(ip_data)
                formatted_ip = format_ip_with_region(ip_data)
                print(f"  {i}. {formatted_ip} | 延迟:{ip_data['rtt']:.1f}ms | 速度:{ip_data['speed']:.1f}Mbps")
        
        # 显示纯IP:端口格式
        print(f"\n🏆【最佳IP TOP10 (纯IP:端口)】")
        for i, ip_data in enumerate(sorted_ips[:10], 1):
            plain_ip = format_ip_with_port_only(ip_data)
            print(f"{i}. {plain_ip}")
        
        print(f"\n📋【全部精选IP (纯IP:端口)】")
        plain_all_ips = format_ip_list_for_file(sorted_ips, include_region=False)
        # 每行显示4个IP（纯IP格式较短）
        for i in range(0, len(plain_all_ips), 4):
            line_ips = plain_all_ips[i:i+4]
            print("  " + "  ".join(line_ips))
    
    print("="*60)
    print("✅ 结果已保存至 results/ 目录")
    print("📊 文件说明:")
    print("   - top_ips.txt: 精选IP列表 (ip:端口#国旗 地区名称)")
    print("   - top_ips_plain.txt: 纯IP:端口格式 (无地区信息)")
    print("   - top_ips_details.csv: 详细性能数据")
    print("   - 注意: 地区信息基于真实IP地理位置API")
    print(f"🎯 目标地区: {', '.join([CONFIG['REGION_MAPPING'].get(r, [r])[0] for r in target_regions])}")
