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
    "VERSION": "1.1",  # 版本号更新
    "MODE": "URL_TEST",  # 测试模式：TCP/URL_TEST
    "URL_TEST_TARGET": "http://www.gstatic.com/generate_204",  # URL测试目标
    "URL_TEST_TIMEOUT": 3,  # URL测试超时(秒)
    "URL_TEST_RETRY": 3,  # URL测试重试次数
    "PORT": 8443,  # TCP测试端口
    "RTT_RANGE": "0~100",  # 延迟范围(ms)
    "LOSS_MAX": 1.0,  # 最大丢包率(%)
    "THREADS": 500,  # 并发线程数
    "IP_POOL_SIZE": 50000,  # IP池总大小
    "TEST_IP_COUNT": 5000,  # 实际测试IP数量
    "TOP_IPS_LIMIT": 100,  # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    "IP_POOL_SOURCES": "2",  # IP池来源：1=自定义域名和IP, 2=自定义IP段, 3=CLOUDFLARE_IPS_URL
    "GEO_TEST_LIMIT": 200,  # 地理位置测试数量限制
    
    # 备用测试URL列表
    "BACKUP_TEST_URLS": [
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/",
        "http://www.cloudflare.com/favicon.ico"
    ],
    
    # 国家代码到国旗的映射
    "COUNTRY_FLAGS": {
        'CN': '❣️', 'TW': '❣️',
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
        'UN': '🏴'
    },
    
    # 国家代码到中文名称的映射
    "COUNTRY_NAMES": {
        'CN': '中·国',
        'TW': '台·湾',
        'US': '美国',
        'SG': '新加坡',
        'JP': '日本',
        'HK': '香港',
        'KR': '韩国',
        'DE': '德国',
        'GB': '英国',
        'FR': '法国',
        'CA': '加拿大',
        'AU': '澳大利亚',
        'NL': '荷兰',
        'SE': '瑞典',
        'FI': '芬兰',
        'NO': '挪威',
        'DK': '丹麦',
        'CH': '瑞士',
        'IT': '意大利',
        'ES': '西班牙',
        'PT': '葡萄牙',
        'BE': '比利时',
        'AT': '奥地利',
        'IE': '爱尔兰',
        'PL': '波兰',
        'CZ': '捷克',
        'HU': '匈牙利',
        'RO': '罗马尼亚',
        'BG': '保加利亚',
        'GR': '希腊',
        'TR': '土耳其',
        'RU': '俄罗斯',
        'UA': '乌克兰',
        'IL': '以色列',
        'AE': '阿联酋',
        'SA': '沙特',
        'IN': '印度',
        'TH': '泰国',
        'MY': '马来西亚',
        'ID': '印度尼西亚',
        'VN': '越南',
        'PH': '菲律宾',
        'BR': '巴西',
        'MX': '墨西哥',
        'AR': '阿根廷',
        'CL': '智利',
        'CO': '哥伦比亚',
        'ZA': '南非',
        'EG': '埃及',
        'NG': '尼日利亚',
        'KE': '肯尼亚',
        'UN': '未知'
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

# 自定义IP标记跟踪和注释信息
custom_ip_comments = {}  # 记录每个IP/域名的注释信息
preformatted_targets = {}  # 记录已格式化的目标信息

####################################################
# 辅助函数
####################################################

def parse_target_with_port(target_str, default_port=None):
    """解析目标字符串，支持自定义端口"""
    if default_port is None:
        default_port = CONFIG["PORT"]
    
    # 检查是否包含端口
    if ':' in target_str:
        parts = target_str.rsplit(':', 1)
        if len(parts) == 2:
            # 格式: ip:port 或 domain:port
            host = parts[0]
            try:
                port = int(parts[1])
                return host, port, f"{host}:{port}"
            except ValueError:
                # 端口不是数字，使用默认端口
                pass
    
    # 没有端口或端口无效，使用默认端口
    return target_str, default_port, f"{target_str}:{default_port}"

def is_preformatted_target(line):
    """检测是否为已格式化的目标（包含#和国旗）"""
    return '#' in line and any(flag in line for flag in CONFIG["COUNTRY_FLAGS"].values())

def parse_preformatted_target(line):
    """解析已格式化的目标"""
    try:
        # 分离目标和国家信息
        target_part, country_part = line.split('#', 1)
        
        # 检查是否已包含端口
        if ':' in target_part:
            # 如果已经包含端口，直接使用
            target = target_part
            host, port, _ = parse_target_with_port(target_part)
        else:
            # 如果不包含端口，添加默认端口
            host = target_part
            port = CONFIG["PORT"]
            target = f"{target_part}:{port}"
        
        # 提取国家代码
        country_code = 'UN'
        for code, flag in CONFIG["COUNTRY_FLAGS"].items():
            if flag in country_part:
                country_code = code
                break
        
        # 提取注释
        comment = ''
        for code, name in CONFIG["COUNTRY_NAMES"].items():
            if name in country_part:
                # 移除国家信息部分，剩下的就是注释
                comment = country_part.replace(flag, '').replace(name, '').replace('·' + code, '').strip()
                break
        
        return target, country_code, comment, line
    except Exception as e:
        print(f"解析格式化目标失败: {line}, 错误: {e}")
        return None, 'UN', '', line

def parse_simple_target(line):
    """解析简单目标（IP/域名 + 可选注释）"""
    try:
        if '#' in line:
            content, comment = line.split('#', 1)
            content = content.strip()
            comment = comment.strip()
        else:
            content = line.strip()
            comment = ''
        
        # 检查是否包含端口
        if ':' in content:
            target = content
            host, port, _ = parse_target_with_port(content)
        else:
            host = content
            port = CONFIG["PORT"]
            target = f"{content}:{port}"
        
        return target, comment
    except Exception as e:
        print(f"解析简单目标失败: {line}, 错误: {e}")
        return None, ''

####################################################
# IP地理位置查询函数
####################################################

def get_real_ip_country_code(ip):
    """使用真实的地理位置API检测IP国家代码"""
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

####################################################
# URL测试函数
####################################################

def url_test(target, url=None, timeout=None, retry=None):
    """URL Test模式延迟检测，支持自定义端口"""
    if url is None:
        url = CONFIG["URL_TEST_TARGET"]
    if timeout is None:
        timeout = CONFIG["URL_TEST_TIMEOUT"]
    if retry is None:
        retry = CONFIG["URL_TEST_RETRY"]
    
    success_count = 0
    total_rtt = 0
    delays = []
    
    # 解析目标，提取主机和端口
    host, port, _ = parse_target_with_port(target)
    
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme.lower()
    hostname = parsed_url.hostname
    path = parsed_url.path or '/'
    
    for attempt in range(retry):
        try:
            start_time = time.time()
            
            if scheme == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                conn = http.client.HTTPSConnection(
                    host, 
                    port=port,  # 使用解析出的端口
                    timeout=timeout,
                    context=context
                )
            else:
                conn = http.client.HTTPConnection(
                    host,
                    port=port,  # 使用解析出的端口
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

def smart_url_test(target, url=None, timeout=None, retry=None):
    """智能URL测试"""
    try:
        return url_test(target, url, timeout, retry)
    except Exception:
        return float('inf'), 100.0, []

####################################################
# 其他测试函数
####################################################

def tcp_ping(target, default_port=443, timeout=2):
    """TCP Ping测试，支持自定义端口"""
    retry = CONFIG["TCP_RETRY"]
    success_count = 0
    total_rtt = 0
    
    # 解析目标，提取主机和端口
    host, port, _ = parse_target_with_port(target, default_port)
    
    for _ in range(retry):
        start = time.time()
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                rtt = (time.time() - start) * 1000
                total_rtt += rtt
                success_count += 1
        except:
            pass
        time.sleep(0.1)
    
    loss_rate = 100 - (success_count / retry * 100)
    avg_rtt = total_rtt / success_count if success_count > 0 else float('inf')
    return avg_rtt, loss_rate

def speed_test(target):
    """速度测试，支持自定义端口"""
    url = CONFIG["SPEED_URL"]
    timeout = CONFIG["SPEED_TIMEOUT"]
    try:
        # 解析目标，提取主机和端口
        host, port, _ = parse_target_with_port(target)
            
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        start_time = time.time()
        
        # 构建代理配置或直接使用目标主机和端口
        proxies = {
            'http': f'http://{host}:{port}',
            'https': f'https://{host}:{port}'
        }
        
        response = requests.get(
            url, 
            headers={'Host': hostname}, 
            timeout=timeout, 
            verify=False, 
            stream=True,
            proxies=proxies
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
    """解析自定义IP文件"""
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    domains = set()
    individual_ips = set()
    ip_subnets = set()
    preformatted = set()
    
    if not os.path.exists(custom_file):
        print(f"自定义IP文件 {custom_file} 不存在")
        return domains, individual_ips, ip_subnets, preformatted
    
    print(f"读取自定义IP池文件: {custom_file}")
    try:
        with open(custom_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # 检测是否为已格式化的目标
                if is_preformatted_target(line):
                    target, country_code, comment, original_line = parse_preformatted_target(line)
                    if target:
                        preformatted.add(target)
                        preformatted_targets[target] = {
                            'countryCode': country_code,
                            'comment': comment,
                            'original_line': original_line
                        }
                    continue
                
                # 解析简单目标（IP/域名 + 可选注释）
                target, comment = parse_simple_target(line)
                if target:
                    # 检测是否为域名
                    if any(c.isalpha() for c in target.split(':')[0]) and '.' in target.split(':')[0]:
                        domains.add(target)
                        if comment:
                            custom_ip_comments[target] = comment
                        continue
                    
                    # 尝试解析为IP地址
                    try:
                        host = target.split(':')[0]
                        ip_obj = ipaddress.ip_address(host)
                        individual_ips.add(target)
                        if comment:
                            custom_ip_comments[target] = comment
                        continue
                    except ValueError:
                        pass
                    
                    # 尝试解析为IP段
                    try:
                        host = target.split(':')[0]
                        network = ipaddress.ip_network(host, strict=False)
                        ip_subnets.add(str(network))
                    except ValueError:
                        print(f"第{line_num}行格式错误: {line}")
        
        print(f"自定义IP池解析完成: {len(domains)}个域名, {len(individual_ips)}个独立IP, {len(ip_subnets)}个IP段, {len(preformatted)}个已格式化目标")
        
    except Exception as e:
        print(f"读取自定义IP池失败: {e}")
    
    return domains, individual_ips, ip_subnets, preformatted

def fetch_ip_ranges():
    """获取Cloudflare官方IP段"""
    url = CONFIG["CLOUDFLARE_IPS_URL"]
    try:
        res = requests.get(url, timeout=10, verify=False)
        return res.text.splitlines()
    except Exception as e:
        print(f"获取Cloudflare官方IP段失败: {e}")
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
        base_ip = subnet.split('/')[0]
        parts = base_ip.split('.')
        while len(parts) < 4:
            parts.append(str(random.randint(0, 255)))
        parts = [str(min(255, max(0, int(p)))) for p in parts[:3]] + [str(random.randint(1, 254))]
        return ".".join(parts)

def generate_ip_pool():
    """根据配置的IP池来源生成IP池，按顺序补齐所需数量"""
    sources_config = CONFIG["IP_POOL_SOURCES"]
    sources = [s.strip() for s in sources_config.split(',')]
    
    print(f"IP池来源配置: {sources_config}")
    
    total_target_pool = set()
    target_pool_size = CONFIG["IP_POOL_SIZE"]
    
    # 预先解析自定义IP文件，确保变量在所有分支中都可用
    domains, individual_ips, custom_subnets, preformatted = parse_custom_ips_file()
    
    # 1. 自定义域名和IP
    if '1' in sources:
        # 收集来源1的所有目标
        source1_targets = set()
        source1_targets.update(domains)
        source1_targets.update(individual_ips)
        source1_targets.update(preformatted)
        
        # 添加到总池子
        total_target_pool.update(source1_targets)
        
        print(f"来源1 - 自定义目标: {len(domains)}个域名, {len(individual_ips)}个IP, {len(preformatted)}个已格式化目标")
        print(f"来源1贡献: {len(source1_targets)} 个目标")
        
        # 如果来源1已经满足大池数量，直接使用
        if len(total_target_pool) >= target_pool_size:
            full_target_pool = list(total_target_pool)[:target_pool_size]
            print(f"来源1已满足大池需求，使用前 {len(full_target_pool)} 个目标")
            
            # 从大池中随机选择测试目标
            test_target_count = min(CONFIG["TEST_IP_COUNT"], len(full_target_pool))
            test_target_pool = random.sample(full_target_pool, test_target_count)
            print(f"从大池中随机选择 {len(test_target_pool)} 个目标进行测试")
            return test_target_pool
    
    # 2. 自定义IP段 - 补齐到目标数量
    if '2' in sources and len(total_target_pool) < target_pool_size:
        needed_count = target_pool_size - len(total_target_pool)
        
        custom_ip_pool = set()
        if custom_subnets:
            print(f"从 {len(custom_subnets)} 个自定义IP段生成 {needed_count} 个IP补齐大池...")
            max_attempts = needed_count * 3  # 最大尝试次数
            attempts = 0
            
            with tqdm(total=needed_count, desc="生成自定义IP段", unit="IP") as pbar:
                while len(custom_ip_pool) < needed_count and custom_subnets and attempts < max_attempts:
                    subnet = random.choice(list(custom_subnets))
                    ip = generate_random_ip(subnet)
                    # 为生成的IP添加默认端口
                    ip_with_port = f"{ip}:{CONFIG['PORT']}"
                    if ip_with_port not in custom_ip_pool and ip_with_port not in total_target_pool:
                        custom_ip_pool.add(ip_with_port)
                        pbar.update(1)
                    attempts += 1
        
        total_target_pool.update(custom_ip_pool)
        print(f"来源2 - 自定义IP段: 添加了 {len(custom_ip_pool)} 个IP")
        
        # 如果来源1+2已经满足大池数量，直接使用
        if len(total_target_pool) >= target_pool_size:
            full_target_pool = list(total_target_pool)[:target_pool_size]
            print(f"来源1+2已满足大池需求，使用前 {len(full_target_pool)} 个目标")
            
            # 从大池中随机选择测试目标
            test_target_count = min(CONFIG["TEST_IP_COUNT"], len(full_target_pool))
            test_target_pool = random.sample(full_target_pool, test_target_count)
            print(f"从大池中随机选择 {len(test_target_pool)} 个目标进行测试")
            return test_target_pool
    
    # 3. 官方Cloudflare IP池 - 补齐到目标数量
    if '3' in sources and len(total_target_pool) < target_pool_size:
        cf_subnets = fetch_ip_ranges()
        if not cf_subnets:
            print("无法获取Cloudflare官方IP段")
        else:
            needed_count = target_pool_size - len(total_target_pool)
            
            cf_ip_pool = set()
            print(f"从 {len(cf_subnets)} 个Cloudflare官方IP段生成 {needed_count} 个IP补齐大池...")
            max_attempts = needed_count * 3  # 最大尝试次数
            attempts = 0
            
            with tqdm(total=needed_count, desc="生成官方IP", unit="IP") as pbar:
                while len(cf_ip_pool) < needed_count and attempts < max_attempts:
                    subnet = random.choice(list(cf_subnets))
                    ip = generate_random_ip(subnet)
                    # 为生成的IP添加默认端口
                    ip_with_port = f"{ip}:{CONFIG['PORT']}"
                    if ip_with_port not in cf_ip_pool and ip_with_port not in total_target_pool:
                        cf_ip_pool.add(ip_with_port)
                        pbar.update(1)
                    attempts += 1
            
            total_target_pool.update(cf_ip_pool)
            print(f"来源3 - 官方Cloudflare IP池: 添加了 {len(cf_ip_pool)} 个IP")
    
    # 最终处理 - 确保不超过目标大小
    full_target_pool = list(total_target_pool)
    random.shuffle(full_target_pool)
    
    actual_pool_size = min(target_pool_size, len(full_target_pool))
    final_full_pool = full_target_pool[:actual_pool_size]
    
    print(f"\nIP大池构建完成: 总计 {len(full_target_pool)} 个目标，使用前 {actual_pool_size} 个")
    
    # 从大池中随机选择实际测试的目标
    test_target_count = min(CONFIG["TEST_IP_COUNT"], len(final_full_pool))
    test_target_pool = random.sample(final_full_pool, test_target_count)
    print(f"从大池中随机选择 {len(test_target_pool)} 个目标进行测试")
    
    return test_target_pool

def ping_test(target):
    """延迟测试入口"""
    mode = CONFIG["MODE"]
    
    if mode == "TCP":
        rtt, loss = tcp_ping(target, CONFIG["PORT"])
    elif mode == "URL_TEST":
        rtt, loss, _ = smart_url_test(target)
    else:
        rtt, loss = tcp_ping(target, CONFIG["PORT"])
    
    return (target, rtt, loss)

def full_test(target_data):
    """完整测试（延迟 + 速度）"""
    target = target_data[0]
    speed = speed_test(target)
    return (*target_data, speed)

def enhance_target_with_country_info(target_list):
    """为目标列表添加国家代码信息"""
    enhanced_targets = []
    
    print(f"正在处理目标地理位置信息...")
    with tqdm(total=len(target_list), desc="目标地理位置", unit="目标") as pbar:
        for target_data in target_list:
            target = target_data[0]
            rtt = target_data[1]
            loss = target_data[2]
            speed = target_data[3] if len(target_data) > 3 else 0
            
            # 检查是否为已格式化目标
            if target in preformatted_targets:
                country_code = preformatted_targets[target]['countryCode']
                comment = preformatted_targets[target]['comment']
            else:
                # 只有未格式化的IP地址才进行地理位置查询
                country_code = 'UN'
                comment = custom_ip_comments.get(target, '')
                
                # 提取纯IP地址进行查询
                try:
                    host = target.split(':')[0]
                    ipaddress.ip_address(host)
                    # 只对前GEO_TEST_LIMIT个目标进行真实地理位置查询
                    if len(enhanced_targets) < CONFIG["GEO_TEST_LIMIT"]:
                        country_code = get_real_ip_country_code(host)
                except ValueError:
                    # 域名不进行地理位置查询
                    pass
            
            enhanced_target = {
                'target': target,
                'rtt': rtt,
                'loss': loss,
                'speed': speed,
                'countryCode': country_code,
                'isp': "Cloudflare",
                'comment': comment
            }
            enhanced_targets.append(enhanced_target)
            pbar.update(1)
    
    return enhanced_targets

####################################################
# 格式化输出函数
####################################################

def get_country_display_name(country_code):
    """获取国家显示名称"""
    country_name = CONFIG["COUNTRY_NAMES"].get(country_code, country_code)
    return f"{country_name}·{country_code}"

def format_target_output(target_data):
    """输出格式化目标，保持原有端口和地区信息"""
    # 直接从target_data中获取完整的目标（可能已包含端口）
    full_target = target_data['target']
    
    country_code = target_data.get('countryCode', 'UN')
    flag = CONFIG["COUNTRY_FLAGS"].get(country_code, '🏴')
    country_display = get_country_display_name(country_code)
    
    # 对于已格式化目标，直接使用原始行
    if target_data['target'] in preformatted_targets:
        return preformatted_targets[target_data['target']]['original_line']
    
    # 添加注释
    comment = target_data.get('comment', '')
    comment_str = f" {comment}" if comment else ''
    
    return f"{full_target}#{flag}{country_display}{comment_str}"

def format_target_list_for_display(target_list):
    """格式化目标列表用于显示"""
    formatted_targets = []
    for target_data in target_list:
        formatted_targets.append(format_target_output(target_data))
    
    return formatted_targets

def format_target_list_for_file(target_list):
    """格式化目标列表用于文件保存"""
    formatted_lines = []
    for target_data in target_list:
        formatted_lines.append(format_target_output(target_data))
    
    return formatted_lines

####################################################
# 主逻辑
####################################################
if __name__ == "__main__":
    init_env()
    
    print("="*60)
    print(f"{'Cloudflare IP优选工具 v' + CONFIG['VERSION']:^60}")
    print("="*60)
    print(f"测试模式: {CONFIG['MODE']}")
    print(f"输出格式: 目标:端口#国旗国家名称·国家代码注释")
    print(f"目标池来源: {CONFIG['IP_POOL_SOURCES']}")
    
    mode = CONFIG["MODE"]
    if mode == "TCP":
        print(f"TCP端口: {CONFIG['PORT']}")
    elif mode == "URL_TEST":
        print(f"URL测试目标: {CONFIG['URL_TEST_TARGET']}")
    
    print(f"延迟范围: {CONFIG['RTT_RANGE']}ms")
    print(f"最大丢包: {CONFIG['LOSS_MAX']}%")
    print(f"并发线程: {CONFIG['THREADS']}")
    print(f"IP大池大小: {CONFIG['IP_POOL_SIZE']}")
    print(f"实际测试数: {CONFIG['TEST_IP_COUNT']}")
    print(f"精选目标数: {CONFIG['TOP_IPS_LIMIT']}")
    print("="*60 + "\n")

    test_target_pool = generate_ip_pool()
    if not test_target_pool:
        print("无法生成目标池，程序终止")
        exit(1)

    ping_results = []
    mode_display = {
        "TCP": "TCP测试进度", 
        "URL_TEST": "URL测试进度"
    }
    progress_desc = mode_display.get(mode, "延迟测试进度")
    
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_target = {executor.submit(ping_test, target): target for target in test_target_pool}
        with tqdm(
            total=len(test_target_pool),
            desc=progress_desc,
            unit="目标",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_target):
                try:
                    ping_results.append(future.result())
                except Exception as e:
                    print(f"延迟测试异常: {e}")
                finally:
                    pbar.update(1)
    
    ping_results.sort(key=lambda x: x[1])
    
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    passed_targets = [
        target_data for target_data in ping_results
        if rtt_min <= target_data[1] <= rtt_max and target_data[2] <= loss_max
    ]
    print(f"延迟测试完成: 总数 {len(ping_results)}, 通过 {len(passed_targets)}")

    if not passed_targets:
        print("没有通过延迟测试的目标，程序终止")
        exit(1)
    
    full_results = []
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_target = {executor.submit(full_test, target_data): target_data for target_data in passed_targets}
        with tqdm(
            total=len(passed_targets),
            desc="测速进度",
            unit="目标",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_target):
                try:
                    full_results.append(future.result())
                except Exception as e:
                    print(f"测速异常: {e}")
                finally:
                    pbar.update(1)

    full_results.sort(key=lambda x: x[1])
    enhanced_results = enhance_target_with_country_info(full_results)
    sorted_targets = sorted(enhanced_results, key=lambda x: x['rtt'])[:CONFIG["TOP_IPS_LIMIT"]]

    os.makedirs('results', exist_ok=True)
    
    with open('results/top_targets.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_target_list_for_file(sorted_targets)
        f.write("\n".join(formatted_lines))
    
    with open('results/top_targets_details.csv', 'w', encoding='utf-8') as f:
        f.write("目标,延迟(ms),丢包率(%),速度(Mbps),国家代码,国家名称,ISP,注释\n")
        for target_data in sorted_targets:
            country_display = get_country_display_name(target_data['countryCode'])
            f.write(f"{target_data['target']},{target_data['rtt']:.2f},{target_data['loss']:.2f},{target_data['speed']:.2f},{target_data['countryCode']},{country_display},{target_data['isp']},{target_data.get('comment', '')}\n")

    print("\n" + "="*60)
    print(f"{'测试结果统计':^60}")
    print("="*60)
    print(f"实际测试目标数: {len(ping_results)}")
    print(f"通过延迟测试目标数: {len(passed_targets)}")
    print(f"精选TOP目标: {len(sorted_targets)}")
    
    if sorted_targets:
        print(f"【最佳目标 TOP10】(按延迟升序排列)")
        formatted_top_targets = format_target_list_for_display(sorted_targets[:10])
        for i, formatted_target in enumerate(formatted_top_targets, 1):
            target_data = sorted_targets[i-1]
            print(f"{i:2d}. {formatted_target} (延迟:{target_data['rtt']:.1f}ms, 速度:{target_data['speed']:.1f}Mbps)")
    
    print("="*60)
    print("结果已保存至 results/ 目录")
    print("文件说明:")
    print("   - top_targets.txt: 精选目标列表")
    print("   - top_targets_details.csv: 详细性能数据")
    print("="*60)
