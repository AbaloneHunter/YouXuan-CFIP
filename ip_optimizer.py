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
import re

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

####################################################
# 配置参数
####################################################
CONFIG = {
    "MODE": "URL_TEST",  # 测试模式：TCP/URL_TEST
    "URL_TEST_TARGET": "http://www.gstatic.com/generate_204",  # URL测试目标
    "URL_TEST_TIMEOUT": 3,  # URL测试超时(秒)
    "URL_TEST_RETRY": 2,  # URL测试重试次数
    "PORT": 443,  # TCP测试端口
    "RTT_RANGE": "0~400",  # 延迟范围(ms)
    "LOSS_MAX": 2.0,  # 最大丢包率(%)
    "THREADS": 300,  # 并发线程数
    "IP_POOL_SIZE": 100000,  # IP池总大小
    "TEST_IP_COUNT": 1000,  # 实际测试IP数量
    "TOP_IPS_LIMIT": 100,  # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://raw.githubusercontent.com/XIU2/CloudflareSpeedTest/master/ip.txt",  # 网络IP池地址
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    "IP_POOL_SOURCE": "1,2,3",  # IP池来源: 1(自定义域名+IP)/2(自定义IP段)/3(网络IP池)，可多选使用','隔开
    
    # 备用测试URL列表
    "BACKUP_TEST_URLS": [
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/",
        "http://www.cloudflare.com/favicon.ico"
    ],
    
    # 国家代码到国旗和名称的映射
    "COUNTRY_MAPPING": {
        'US': {'flag': '🇺🇸', 'name': '美国'},
        'SG': {'flag': '🇸🇬', 'name': '新加坡'},
        'JP': {'flag': '🇯🇵', 'name': '日本'},
        'HK': {'flag': '🇭🇰', 'name': '香港'},
        'KR': {'flag': '🇰🇷', 'name': '韩国'},
        'DE': {'flag': '🇩🇪', 'name': '德国'},
        'GB': {'flag': '🇬🇧', 'name': '英国'},
        'FR': {'flag': '🇫🇷', 'name': '法国'},
        'CA': {'flag': '🇨🇦', 'name': '加拿大'},
        'AU': {'flag': '🇦🇺', 'name': '澳大利亚'},
        'NL': {'flag': '🇳🇱', 'name': '荷兰'},
        'SE': {'flag': '🇸🇪', 'name': '瑞典'},
        'FI': {'flag': '🇫🇮', 'name': '芬兰'},
        'NO': {'flag': '🇳🇴', 'name': '挪威'},
        'DK': {'flag': '🇩🇰', 'name': '丹麦'},
        'CH': {'flag': '🇨🇭', 'name': '瑞士'},
        'IT': {'flag': '🇮🇹', 'name': '意大利'},
        'ES': {'flag': '🇪🇸', 'name': '西班牙'},
        'PT': {'flag': '🇵🇹', 'name': '葡萄牙'},
        'BE': {'flag': '🇧🇪', 'name': '比利时'},
        'AT': {'flag': '🇦🇹', 'name': '奥地利'},
        'IE': {'flag': '🇮🇪', 'name': '爱尔兰'},
        'PL': {'flag': '🇵🇱', 'name': '波兰'},
        'CZ': {'flag': '🇨🇿', 'name': '捷克'},
        'HU': {'flag': '🇭🇺', 'name': '匈牙利'},
        'RO': {'flag': '🇷🇴', 'name': '罗马尼亚'},
        'BG': {'flag': '🇧🇬', 'name': '保加利亚'},
        'GR': {'flag': '🇬🇷', 'name': '希腊'},
        'TR': {'flag': '🇹🇷', 'name': '土耳其'},
        'RU': {'flag': '🇷🇺', 'name': '俄罗斯'},
        'UA': {'flag': '🇺🇦', 'name': '乌克兰'},
        'IL': {'flag': '🇮🇱', 'name': '以色列'},
        'AE': {'flag': '🇦🇪', 'name': '阿联酋'},
        'SA': {'flag': '🇸🇦', 'name': '沙特'},
        'IN': {'flag': '🇮🇳', 'name': '印度'},
        'TH': {'flag': '🇹🇭', 'name': '泰国'},
        'MY': {'flag': '🇲🇾', 'name': '马来西亚'},
        'ID': {'flag': '🇮🇩', 'name': '印度尼西亚'},
        'VN': {'flag': '🇻🇳', 'name': '越南'},
        'PH': {'flag': '🇵🇭', 'name': '菲律宾'},
        'BR': {'flag': '🇧🇷', 'name': '巴西'},
        'MX': {'flag': '🇲🇽', 'name': '墨西哥'},
        'AR': {'flag': '🇦🇷', 'name': '阿根廷'},
        'CL': {'flag': '🇨🇱', 'name': '智利'},
        'CO': {'flag': '🇨🇴', 'name': '哥伦比亚'},
        'ZA': {'flag': '🇿🇦', 'name': '南非'},
        'EG': {'flag': '🇪🇬', 'name': '埃及'},
        'NG': {'flag': '🇳🇬', 'name': '尼日利亚'},
        'KE': {'flag': '🇰🇪', 'name': '肯尼亚'},
        'CN': {'flag': '⭐', 'name': '中国'},
        'TW': {'flag': '🌶️', 'name': '台湾'},
        'UN': {'flag': '🏴', 'name': '未知'}
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

# 自定义IP标记跟踪
custom_ip_sources = {}  # 记录每个IP的来源：'custom_domain', 'custom_subnet', 'network_pool'

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

def get_country_info(country_code):
    """
    根据国家代码获取国旗和名称信息
    """
    country_mapping = CONFIG["COUNTRY_MAPPING"]
    if country_code in country_mapping:
        return country_mapping[country_code]
    else:
        return country_mapping['UN']

####################################################
# URL测试函数
####################################################

def url_test(ip, url=None, timeout=None, retry=None):
    """
    URL Test模式延迟检测
    """
    if url is None:
        url = CONFIG["URL_TEST_TARGET"]
    if timeout is None:
        timeout = CONFIG["URL_TEST_TIMEOUT"]
    if retry is None:
        retry = CONFIG["URL_TEST_RETRY"]
    
    success_count = 0
    total_rtt = 0
    delays = []
    
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
                
                conn = http.client.HTTPSConnection(
                    ip, 
                    port=port, 
                    timeout=timeout,
                    context=context
                )
            else:
                conn = http.client.HTTPConnection(
                    ip,
                    port=port,
                    timeout=timeout
                )
            
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
                delays.append(rtt)
            
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
    
    return avg_rtt, loss_rate, delays

def smart_url_test(ip, url=None, timeout=None, retry=None):
    """
    智能URL测试
    """
    try:
        return url_test(ip, url, timeout, retry)
    except Exception:
        # 简化版本，直接返回超时
        return float('inf'), 100.0, []

####################################################
# 其他测试函数
####################################################

def tcp_ping(ip, port, timeout=2):
    """TCP Ping测试"""
    retry = CONFIG["TCP_RETRY"]
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
    url = CONFIG["SPEED_URL"]
    timeout = CONFIG["SPEED_TIMEOUT"]
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
    except Exception:
        return 0.0

####################################################
# 核心功能函数
####################################################

def init_env():
    """初始化环境"""
    for key, value in CONFIG.items():
        os.environ[key] = str(value)

def parse_custom_ips_file():
    """
    解析自定义IP文件，支持域名、单个IP和IP段
    注意：域名不会被解析，直接作为域名处理
    返回: (domains, individual_ips, ip_subnets)
    """
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    domains = set()
    individual_ips = set()
    ip_subnets = set()
    
    if not custom_file or not os.path.exists(custom_file):
        return domains, individual_ips, ip_subnets
    
    print(f"🔧 读取自定义IP池文件: {custom_file}")
    try:
        with open(custom_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # 检查是否是域名（不进行解析）
                if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', line) and not re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                    domains.add(line)
                    continue
                
                # 尝试解析为IP地址
                try:
                    ip_obj = ipaddress.ip_address(line)
                    individual_ips.add(line)
                    continue
                except ValueError:
                    pass
                
                # 尝试解析为IP段
                try:
                    network = ipaddress.ip_network(line, strict=False)
                    ip_subnets.add(str(network))
                except ValueError:
                    print(f"⚠️ 第{line_num}行格式错误: {line}")
        
        print(f"✅ 自定义IP池解析完成: {len(domains)}个域名, {len(individual_ips)}个独立IP, {len(ip_subnets)}个IP段")
        
    except Exception as e:
        print(f"🚨 读取自定义IP池失败: {e}")
    
    return domains, individual_ips, ip_subnets

def fetch_ip_ranges():
    """获取网络IP池"""
    url = CONFIG["CLOUDFLARE_IPS_URL"]
    try:
        res = requests.get(url, timeout=10, verify=False)
        # 按行分割并过滤空行
        ips = [line.strip() for line in res.text.splitlines() if line.strip()]
        return ips
    except Exception as e:
        print(f"🚨 获取网络IP池失败: {e}")
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
    except Exception:
        # 如果不是CIDR格式，直接返回原IP（用于处理单个IP）
        return subnet

def generate_ip_pool():
    """
    根据配置的IP_POOL_SOURCE生成IP池
    """
    ip_pool_sources = [s.strip() for s in CONFIG["IP_POOL_SOURCE"].split(',')]
    total_ip_pool_size = CONFIG["IP_POOL_SIZE"]
    test_ip_count = CONFIG["TEST_IP_COUNT"]
    
    print(f"🔧 IP池来源模式: {ip_pool_sources}")
    
    all_ips = []
    
    # 根据选择的来源生成IP
    for source in ip_pool_sources:
        if source == '1':
            print("\n📝 生成自定义域名+IP池...")
            ips = generate_custom_domain_ip_pool(total_ip_pool_size)
            all_ips.extend(ips)
        elif source == '2':
            print("\n📝 生成自定义IP段池...")
            ips = generate_custom_subnet_pool(total_ip_pool_size)
            all_ips.extend(ips)
        elif source == '3':
            print("\n📝 生成网络IP池...")
            ips = generate_network_pool(total_ip_pool_size)
            all_ips.extend(ips)
    
    if not all_ips:
        print("❌ 没有生成任何IP，程序终止")
        exit(1)
    
    # 去重并随机打乱
    unique_ips = list(set(all_ips))
    random.shuffle(unique_ips)
    
    print(f"✅ IP池生成完成: 总计 {len(unique_ips)} 个唯一IP")
    
    # 抽样测试IP
    if test_ip_count > len(unique_ips):
        test_ip_count = len(unique_ips)
    
    test_ip_pool = unique_ips[:test_ip_count]
    print(f"🔧 选择 {len(test_ip_pool)} 个IP进行测试")
    
    return test_ip_pool

def generate_custom_domain_ip_pool(max_size):
    """生成自定义域名+IP池（域名不解析，直接使用）"""
    domains, individual_ips, _ = parse_custom_ips_file()
    
    domain_ips = set()
    
    # 直接使用域名，不进行解析
    for domain in domains:
        domain_ips.add(domain)
        custom_ip_sources[domain] = 'custom_domain'
    
    # 添加独立IP
    for ip in individual_ips:
        domain_ips.add(ip)
        custom_ip_sources[ip] = 'custom_domain'
    
    result = list(domain_ips)[:max_size]
    print(f"✅ 自定义域名+IP池: {len(result)} 个域名/IP")
    return result

def generate_custom_subnet_pool(max_size):
    """生成自定义IP段池"""
    _, _, custom_subnets = parse_custom_ips_file()
    
    if not custom_subnets:
        print("⚠️ 没有可用的自定义IP段")
        return []
    
    print(f"🔧 从 {len(custom_subnets)} 个自定义IP段生成IP...")
    custom_ip_pool = set()
    
    with tqdm(total=max_size, desc="生成自定义IP", unit="IP") as pbar:
        while len(custom_ip_pool) < max_size and custom_subnets:
            subnet = random.choice(list(custom_subnets))
            ip = generate_random_ip(subnet)
            if ip not in custom_ip_pool:
                custom_ip_pool.add(ip)
                custom_ip_sources[ip] = 'custom_subnet'
                pbar.update(1)
    
    result = list(custom_ip_pool)
    print(f"✅ 自定义IP段池: {len(result)} 个IP")
    return result

def generate_network_pool(max_size):
    """生成网络IP池"""
    network_ips = fetch_ip_ranges()
    if not network_ips:
        print("❌ 无法获取网络IP池")
        return []
    
    print(f"🔧 从网络IP池获取 {len(network_ips)} 个IP...")
    
    # 随机选择IP，但不超过最大限制
    selected_ips = []
    available_ips = network_ips.copy()
    random.shuffle(available_ips)
    
    for ip in available_ips[:max_size]:
        selected_ips.append(ip)
        custom_ip_sources[ip] = 'network_pool'
    
    result = selected_ips
    print(f"✅ 网络IP池: {len(result)} 个IP")
    return result

def ping_test(ip):
    """延迟测试"""
    mode = CONFIG["MODE"]
    
    if mode == "TCP":
        rtt, loss = tcp_ping(ip, CONFIG["PORT"])
    else:  # URL_TEST
        rtt, loss, _ = smart_url_test(ip)
    
    return (ip, rtt, loss)

def full_test(ip_data):
    """完整测试（延迟 + 速度）"""
    ip = ip_data[0]
    speed = speed_test(ip)
    return (*ip_data, speed)

def enhance_ip_with_country_info(ip_list):
    """
    为IP列表添加真实的国家代码信息
    """
    enhanced_ips = []
    
    print("🌍 正在检测IP真实地理位置...")
    with tqdm(total=len(ip_list), desc="IP地理位置", unit="IP") as pbar:
        for ip_data in ip_list:
            ip = ip_data[0]
            rtt = ip_data[1]
            loss = ip_data[2]
            speed = ip_data[3] if len(ip_data) > 3 else 0
            
            # 如果是域名，跳过地理位置检测
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', ip) and not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
                country_code = 'UN'
            else:
                country_code = get_real_ip_country_code(ip)
            
            country_info = get_country_info(country_code)
            
            enhanced_ip = {
                'ip': ip,
                'rtt': rtt,
                'loss': loss,
                'speed': speed,
                'countryCode': country_code,
                'countryName': country_info['name'],
                'countryFlag': country_info['flag'],
                'source': custom_ip_sources.get(ip, 'unknown')
            }
            enhanced_ips.append(enhanced_ip)
            pbar.update(1)
    
    return enhanced_ips

####################################################
# 格式化输出函数
####################################################

def format_ip_output(ip_data, port=None):
    """
    输出 ip:端口#国旗 国家名称·国家简称✓ 格式
    """
    if port is None:
        port = CONFIG["PORT"]
    
    country_code = ip_data.get('countryCode', 'UN')
    country_name = ip_data.get('countryName', '未知')
    flag = ip_data.get('countryFlag', '🏴')
    
    # 添加自定义IP标志
    source = ip_data.get('source', '')
    custom_flag = '✓' if source.startswith('custom') else ''
    
    return f"{ip_data['ip']}:{port}#{flag} {country_name}·{country_code}{custom_flag}"

def format_ip_list_for_display(ip_list, port=None):
    """格式化IP列表用于显示"""
    if port is None:
        port = CONFIG["PORT"]
    
    formatted_ips = []
    for ip_data in ip_list:
        formatted_ips.append(format_ip_output(ip_data, port))
    
    return formatted_ips

def format_ip_list_for_file(ip_list, port=None):
    """格式化IP列表用于文件保存"""
    if port is None:
        port = CONFIG["PORT"]
    
    formatted_lines = []
    for ip_data in ip_list:
        formatted_lines.append(format_ip_output(ip_data, port))
    
    return formatted_lines

def validate_test_urls():
    """验证测试URL的可用性"""
    print("🔍 验证测试URL可用性...")
    
    for test_url in CONFIG["BACKUP_TEST_URLS"]:
        try:
            start_time = time.time()
            response = requests.get(test_url, timeout=5, verify=False)
            rtt = (time.time() - start_time) * 1000
            
            if response.status_code < 500:
                print(f"✅ {test_url} - 可用 (延迟: {rtt:.1f}ms)")
                return test_url
        except Exception:
            continue
    
    print("🚨 所有测试URL都不可用，使用默认URL")
    return CONFIG["BACKUP_TEST_URLS"][0]

def calculate_score(ip_data):
    """
    计算IP的综合得分
    延迟越低、速度越快，得分越高
    """
    rtt = ip_data['rtt']
    speed = ip_data['speed']
    
    # 延迟权重（越低越好）
    rtt_score = max(0, 1000 - rtt) / 10  # 延迟在0-1000ms范围内
    
    # 速度权重（越高越好）
    speed_score = min(speed, 100)  # 速度在0-100Mbps范围内
    
    # 综合得分：延迟权重60%，速度权重40%
    total_score = rtt_score * 0.6 + speed_score * 0.4
    
    return total_score

####################################################
# 主逻辑
####################################################
if __name__ == "__main__":
    # 初始化环境
    init_env()
    
    # 验证并选择最佳测试URL
    best_url = validate_test_urls()
    CONFIG["URL_TEST_TARGET"] = best_url
    print(f"🎯 使用测试URL: {best_url}")
    
    # 打印配置参数
    print("="*60)
    print(f"{'Cloudflare IP优选工具':^60}")
    print("="*60)
    print(f"测试模式: {CONFIG['MODE']}")
    print(f"IP池来源: {CONFIG['IP_POOL_SOURCE']}")
    print(f"输出格式: ip:端口#国旗 国家名称·国家简称✓ (✓表示自定义IP)")
    
    mode = CONFIG["MODE"]
    if mode == "TCP":
        print(f"TCP端口: {CONFIG['PORT']}")
    elif mode == "URL_TEST":
        print(f"URL测试目标: {CONFIG['URL_TEST_TARGET']}")
    
    print(f"延迟范围: {CONFIG['RTT_RANGE']}ms")
    print(f"最大丢包: {CONFIG['LOSS_MAX']}%")
    print(f"并发线程: {CONFIG['THREADS']}")
    print(f"IP池大小: {CONFIG['IP_POOL_SIZE']}")
    print(f"测试IP数: {CONFIG['TEST_IP_COUNT']}")
    print(f"精选IP数: {CONFIG['TOP_IPS_LIMIT']}")
    print("="*60 + "\n")

    # 生成IP池
    test_ip_pool = generate_ip_pool()
    if not test_ip_pool:
        print("❌ 无法生成IP池，程序终止")
        exit(1)

    # 第一阶段：延迟测试
    ping_results = []
    mode_display = {
        "TCP": "🔌 TCP测试进度", 
        "URL_TEST": "🌐 URL测试进度"
    }
    progress_desc = mode_display.get(mode, "🚀 延迟测试进度")
    
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_ip = {executor.submit(ping_test, ip): ip for ip in test_ip_pool}
        with tqdm(
            total=len(test_ip_pool),
            desc=progress_desc,
            unit="IP",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_ip):
                try:
                    ping_results.append(future.result())
                except Exception:
                    pass
                finally:
                    pbar.update(1)
    
    # 筛选通过的IP（按延迟升序排列）
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    passed_ips = [
        ip_data for ip_data in ping_results
        if rtt_min <= ip_data[1] <= rtt_max and ip_data[2] <= loss_max
    ]
    
    # 按延迟升序排列
    passed_ips.sort(key=lambda x: x[1])
    
    print(f"\n✅ 延迟测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips)}")

    # 第二阶段：测速
    if not passed_ips:
        print("❌ 没有通过延迟测试的IP，程序终止")
        exit(1)
    
    full_results = []
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
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
                except Exception:
                    pass
                finally:
                    pbar.update(1)

    # 为IP添加真实国家代码信息
    enhanced_results = enhance_ip_with_country_info(full_results)
    
    # 按综合得分排序（延迟低、速度快）
    for ip_data in enhanced_results:
        ip_data['score'] = calculate_score(ip_data)
    
    # 按综合得分降序排列
    sorted_ips = sorted(enhanced_results, key=lambda x: x['score'], reverse=True)[:CONFIG["TOP_IPS_LIMIT"]]

    # 保存结果
    os.makedirs('results', exist_ok=True)
    
    # 保存所有IP
    with open('results/all_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in ping_results]))
    
    # 保存通过的IP
    with open('results/passed_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in passed_ips]))
    
    # 保存详细结果CSV（按综合得分降序）
    with open('results/full_results.csv', 'w') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),国家代码,国家名称,来源,综合得分\n")
        for ip_data in sorted(enhanced_results, key=lambda x: x['score'], reverse=True):
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['countryCode']},{ip_data['countryName']},{ip_data.get('source', 'unknown')},{ip_data['score']:.2f}\n")
    
    # 保存精选IP（按综合得分降序）
    with open('results/top_ips.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_ip_list_for_file(sorted_ips)
        f.write("\n".join(formatted_lines))
    
    with open('results/top_ips_details.csv', 'w', encoding='utf-8') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),国家代码,国家名称,来源,综合得分\n")
        for ip_data in sorted_ips:
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['countryCode']},{ip_data['countryName']},{ip_data.get('source', 'unknown')},{ip_data['score']:.2f}\n")

    # 显示统计结果
    print("\n" + "="*60)
    print(f"{'🔥 测试结果统计':^60}")
    print("="*60)
    print(f"IP池大小: {CONFIG['IP_POOL_SIZE']}")
    print(f"实际测试IP数: {len(ping_results)}")
    print(f"通过延迟测试IP数: {len(passed_ips)}")
    print(f"测速IP数: {len(enhanced_results)}")
    print(f"精选TOP IP: {len(sorted_ips)}")
    
    # 统计各来源IP表现
    source_stats = {}
    for ip_data in enhanced_results:
        source = ip_data.get('source', 'unknown')
        if source not in source_stats:
            source_stats[source] = {'count': 0, 'passed': 0}
        source_stats[source]['count'] += 1
    
    for ip_data in ping_results:
        source = custom_ip_sources.get(ip_data[0], 'unknown')
        if source in source_stats:
            source_stats[source]['passed'] += 1
    
    print(f"\n📊 各来源IP统计:")
    for source, stats in source_stats.items():
        if stats['count'] > 0:
            pass_rate = (stats['passed'] / stats['count']) * 100
            print(f"  {source}: {stats['passed']}/{stats['count']} (通过率: {pass_rate:.1f}%)")
    
    if sorted_ips:
        print(f"\n🏆【最佳IP TOP10】(按综合得分排序，✓表示自定义IP)")
        for i, ip_data in enumerate(sorted_ips[:10], 1):
            formatted_ip = format_ip_output(ip_data)
            source_info = " [自定义]" if ip_data.get('source', '').startswith('custom') else ""
            print(f"{i:2d}. {formatted_ip} (延迟:{ip_data['rtt']:.1f}ms, 速度:{ip_data['speed']:.1f}Mbps, 得分:{ip_data['score']:.1f}{source_info})")
        
        print(f"\n📋【全部精选IP】(按综合得分排序，✓表示自定义IP)")
        formatted_all_ips = format_ip_list_for_display(sorted_ips)
        for i in range(0, len(formatted_all_ips), 2):
            line_ips = formatted_all_ips[i:i+2]
            print("  " + "  ".join(line_ips))
    
    print("="*60)
    print("✅ 结果已保存至 results/ 目录")
    print("📊 文件说明:")
    print("   - top_ips.txt: 精选IP列表 (ip:端口#国旗 国家名称·国家简称✓)")
    print("   - top_ips_details.csv: 详细性能数据")
    print("   - full_results.csv: 完整测试结果")
    print("="*60)
