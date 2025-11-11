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
    "VERSION": "1.0",  # 版本号
    "MODE": "URL_TEST",  # 测试模式：TCP/URL_TEST
    "URL_TEST_TARGET": "http://www.gstatic.com/generate_204",  # URL测试目标
    "URL_TEST_TIMEOUT": 3,  # URL测试超时(秒)
    "URL_TEST_RETRY": 3,  # URL测试重试次数
    "PORT": 8443,  # TCP测试端口
    "RTT_RANGE": "0~100",  # 延迟范围(ms)
    "LOSS_MAX": 1.0,  # 最大丢包率(%)
    "THREADS": 500,  # 并发线程数
    "IP_POOL_SIZE": 100000,  # IP池总大小
    "TEST_IP_COUNT": 5000,  # 实际测试IP数量
    "TOP_IPS_LIMIT": 100,  # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    "IP_POOL_SOURCES": "1,2,3",  # IP池来源：1=自定义域名和IP, 2=自定义IP段, 3=CLOUDFLARE_IPS_URL
    "GEO_TEST_LIMIT": 200,  # 地理位置测试数量限制
    
    # 备用测试URL列表
    "BACKUP_TEST_URLS": [
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/",
        "http://www.cloudflare.com/favicon.ico"
    ],
    
    # 国家代码到国旗的映射
    "COUNTRY_FLAGS": {
        'CN': '❤️', 'TW': '🌀',  # 中国和台湾
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
        'UN': '🏴'  # 未知
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
custom_ip_country_codes = {}  # 记录自定义的国家代码

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

####################################################
# URL测试函数
####################################################

def url_test(target, url=None, timeout=None, retry=None):
    """
    URL Test模式延迟检测
    支持HTTP和HTTPS，更好的错误处理和超时控制
    支持直接测试域名
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
                # HTTPS请求
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                conn = http.client.HTTPSConnection(
                    target, 
                    port=port, 
                    timeout=timeout,
                    context=context
                )
            else:
                # HTTP请求
                conn = http.client.HTTPConnection(
                    target,
                    port=port,
                    timeout=timeout
                )
            
            # 设置请求头
            headers = {
                'Host': hostname,
                'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Tester/1.0)',
                'Accept': '*/*',
                'Connection': 'close'
            }
            
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            
            # 读取响应内容
            response.read()
            
            rtt = (time.time() - start_time) * 1000
            
            # 成功条件：任何有效的HTTP响应都算成功
            if response.status < 500:  # 1xx, 2xx, 3xx, 4xx 都接受
                success_count += 1
                total_rtt += rtt
                delays.append(rtt)
            
            conn.close()
            
        except socket.timeout:
            continue
        except (socket.gaierror, ConnectionRefusedError, ConnectionResetError):
            continue
        except ssl.SSLError:
            continue
        except Exception:
            continue
        
        # 短暂间隔避免过于频繁
        if attempt < retry - 1:
            time.sleep(0.1)
    
    # 计算平均延迟和丢包率
    if success_count > 0:
        avg_rtt = total_rtt / success_count
        loss_rate = ((retry - success_count) / retry) * 100
    else:
        avg_rtt = float('inf')
        loss_rate = 100.0
    
    return avg_rtt, loss_rate, delays

def url_test_requests(target, url=None, timeout=None, retry=None):
    """
    备选的requests库版本URL测试
    支持直接测试域名
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
    
    for attempt in range(retry):
        try:
            start_time = time.time()
            
            # 构建使用目标直接访问的URL
            if parsed_url.port:
                actual_url = f"{parsed_url.scheme}://{target}:{parsed_url.port}{parsed_url.path}"
            else:
                actual_url = f"{parsed_url.scheme}://{target}{parsed_url.path}"
            
            headers = {
                'Host': parsed_url.hostname,
                'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Tester/1.0)',
                'Accept': '*/*'
            }
            
            response = requests.get(
                actual_url,
                headers=headers,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                stream=True
            )
            
            rtt = (time.time() - start_time) * 1000
            
            # 非常宽松的成功条件
            if response.status_code < 500:
                success_count += 1
                total_rtt += rtt
                delays.append(rtt)
            
            response.close()
            
        except requests.exceptions.Timeout:
            continue
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.SSLError:
            continue
        except Exception:
            continue
        
        if attempt < retry - 1:
            time.sleep(0.05)
    
    if success_count > 0:
        avg_rtt = total_rtt / success_count
        loss_rate = ((retry - success_count) / retry) * 100
    else:
        avg_rtt = float('inf')
        loss_rate = 100.0
    
    return avg_rtt, loss_rate, delays

def smart_url_test(target, url=None, timeout=None, retry=None):
    """
    智能URL测试 - 自动选择最佳测试方法
    支持直接测试域名
    """
    # 先尝试http.client版本（更快）
    try:
        return url_test(target, url, timeout, retry)
    except Exception:
        # 回退到requests版本
        return url_test_requests(target, url, timeout, retry)

####################################################
# 其他测试函数
####################################################

def tcp_ping(target, port, timeout=2):
    """TCP Ping测试 - 支持域名和IP"""
    retry = CONFIG["TCP_RETRY"]
    success_count = 0
    total_rtt = 0
    for _ in range(retry):
        start = time.time()
        try:
            with socket.create_connection((target, port), timeout=timeout) as sock:
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
    """速度测试 - 支持域名和IP"""
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
    except Exception as e:
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
    解析自定义IP文件，区分域名、单个IP和IP段
    返回: (domains, individual_ips, ip_subnets)
    """
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    domains = set()
    individual_ips = set()
    ip_subnets = set()
    
    if not os.path.exists(custom_file):
        print(f"自定义IP文件 {custom_file} 不存在")
        return domains, individual_ips, ip_subnets
    
    print(f"读取自定义IP池文件: {custom_file}")
    try:
        with open(custom_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # 分离注释
                if '#' in line:
                    content, comment = line.split('#', 1)
                    content = content.strip()
                    if not content:
                        continue
                else:
                    content = line
                    comment = None
                
                # 检测是否为域名（包含字母）
                if any(c.isalpha() for c in content) and '.' in content:
                    domains.add(content)
                    if comment:
                        custom_ip_comments[content] = comment
                    continue
                
                # 尝试解析为IP地址
                try:
                    ip_obj = ipaddress.ip_address(content)
                    individual_ips.add(content)
                    if comment:
                        # 检查注释是否为有效的国家代码
                        if comment.upper() in CONFIG["COUNTRY_FLAGS"]:
                            custom_ip_country_codes[content] = comment.upper()
                            custom_ip_comments[content] = ""  # 国家代码不作为注释显示
                        else:
                            custom_ip_comments[content] = comment
                    continue
                except ValueError:
                    pass
                
                # 尝试解析为IP段
                try:
                    network = ipaddress.ip_network(content, strict=False)
                    ip_subnets.add(str(network))
                except ValueError:
                    print(f"第{line_num}行格式错误: {line}")
        
        print(f"自定义IP池解析完成: {len(domains)}个域名, {len(individual_ips)}个独立IP, {len(ip_subnets)}个IP段")
        if custom_ip_country_codes:
            print(f"发现 {len(custom_ip_country_codes)} 个IP带有预定义国家代码")
        
    except Exception as e:
        print(f"读取自定义IP池失败: {e}")
    
    return domains, individual_ips, ip_subnets

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
    except Exception as e:
        base_ip = subnet.split('/')[0]
        parts = base_ip.split('.')
        while len(parts) < 4:
            parts.append(str(random.randint(0, 255)))
        parts = [str(min(255, max(0, int(p)))) for p in parts[:3]] + [str(random.randint(1, 254))]
        return ".".join(parts)

def generate_ip_pool():
    """
    根据配置的IP池来源生成IP池
    """
    sources_config = CONFIG["IP_POOL_SOURCES"]
    sources = [s.strip() for s in sources_config.split(',')]
    
    print(f"IP池来源配置: {sources_config}")
    
    total_target_pool = set()
    
    # 1. 自定义域名和IP
    if '1' in sources:
        domains, individual_ips, _ = parse_custom_ips_file()
        # 直接添加域名（不解析）
        total_target_pool.update(domains)
        # 添加独立IP
        total_target_pool.update(individual_ips)
        
        print(f"来源1 - 自定义域名和IP: {len(domains)}个域名, {len(individual_ips)}个IP")
    
    # 2. 自定义IP段
    if '2' in sources:
        _, _, custom_subnets = parse_custom_ips_file()
        custom_ip_count = CONFIG["IP_POOL_SIZE"] // 3  # 分配1/3给自定义IP段
        
        custom_ip_pool = set()
        if custom_subnets:
            print(f"从 {len(custom_subnets)} 个自定义IP段生成IP...")
            with tqdm(total=min(custom_ip_count, len(custom_subnets) * 10), 
                     desc="生成自定义IP段", unit="IP") as pbar:
                while len(custom_ip_pool) < custom_ip_count and custom_subnets:
                    subnet = random.choice(list(custom_subnets))
                    ip = generate_random_ip(subnet)
                    if ip not in custom_ip_pool:
                        custom_ip_pool.add(ip)
                        pbar.update(1)
        
        total_target_pool.update(custom_ip_pool)
        print(f"来源2 - 自定义IP段: {len(custom_ip_pool)} 个IP")
    
    # 3. 官方Cloudflare IP池
    if '3' in sources:
        cf_subnets = fetch_ip_ranges()
        if not cf_subnets:
            print("无法获取Cloudflare官方IP段")
        else:
            cf_ip_count = CONFIG["IP_POOL_SIZE"] // 3  # 分配1/3给官方IP
            
            cf_ip_pool = set()
            print(f"从 {len(cf_subnets)} 个Cloudflare官方IP段生成IP...")
            with tqdm(total=cf_ip_count, desc="生成官方IP", unit="IP") as pbar:
                while len(cf_ip_pool) < cf_ip_count:
                    subnet = random.choice(list(cf_subnets))
                    ip = generate_random_ip(subnet)
                    if ip not in cf_ip_pool and ip not in total_target_pool:
                        cf_ip_pool.add(ip)
                        pbar.update(1)
            
            total_target_pool.update(cf_ip_pool)
            print(f"来源3 - 官方Cloudflare IP池: {len(cf_ip_pool)} 个IP")
    
    full_target_pool = list(total_target_pool)
    random.shuffle(full_target_pool)
    
    print(f"目标池生成完成: 总计 {len(full_target_pool)} 个目标（包含域名和IP）")
    
    # 抽样测试目标
    test_target_count = min(CONFIG["TEST_IP_COUNT"], len(full_target_pool))
    test_target_pool = random.sample(full_target_pool, test_target_count)
    print(f"随机选择 {len(test_target_pool)} 个目标进行测试")
    
    return test_target_pool

def ping_test(target):
    """延迟测试入口 - 支持两种模式，支持域名和IP"""
    mode = CONFIG["MODE"]
    
    if mode == "TCP":
        rtt, loss = tcp_ping(target, CONFIG["PORT"])
    elif mode == "URL_TEST":
        # 使用智能URL测试
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
    """
    为目标列表添加真实的国家代码信息
    只对前200个目标进行地理位置测试（仅对IP地址）
    """
    enhanced_targets = []
    
    # 只对前200个目标进行地理位置测试
    geo_test_limit = min(CONFIG["GEO_TEST_LIMIT"], len(target_list))
    target_list_for_geo = target_list[:geo_test_limit]
    
    print(f"正在检测前{geo_test_limit}个目标的地理位置...")
    with tqdm(total=geo_test_limit, desc="目标地理位置", unit="目标") as pbar:
        for target_data in target_list_for_geo:
            target = target_data[0]
            rtt = target_data[1]
            loss = target_data[2]
            speed = target_data[3] if len(target_data) > 3 else 0
            
            # 检查是否有预定义的国家代码
            if target in custom_ip_country_codes:
                country_code = custom_ip_country_codes[target]
                print(f"使用预定义国家代码: {target} -> {country_code}")
            else:
                # 只有IP地址才进行地理位置查询，域名使用默认值
                try:
                    # 尝试解析为IP地址
                    ipaddress.ip_address(target)
                    country_code = get_real_ip_country_code(target)
                except ValueError:
                    # 如果是域名，使用默认值
                    country_code = 'UN'
            
            enhanced_target = {
                'target': target,
                'rtt': rtt,
                'loss': loss,
                'speed': speed,
                'countryCode': country_code,
                'isp': "Cloudflare",
                'comment': custom_ip_comments.get(target, '')  # 添加注释信息
            }
            enhanced_targets.append(enhanced_target)
            pbar.update(1)
    
    # 对于没有进行地理位置测试的目标，使用默认信息
    for target_data in target_list[geo_test_limit:]:
        target = target_data[0]
        rtt = target_data[1]
        loss = target_data[2]
        speed = target_data[3] if len(target_data) > 3 else 0
        
        # 检查是否有预定义的国家代码
        if target in custom_ip_country_codes:
            country_code = custom_ip_country_codes[target]
        else:
            country_code = 'UN'
        
        enhanced_target = {
            'target': target,
            'rtt': rtt,
            'loss': loss,
            'speed': speed,
            'countryCode': country_code,
            'isp': "Cloudflare",
            'comment': custom_ip_comments.get(target, '')
        }
        enhanced_targets.append(enhanced_target)
    
    return enhanced_targets

####################################################
# 格式化输出函数 - 优化输出格式，添加国家名称，无空格
####################################################

def get_country_display_name(country_code):
    """
    获取国家显示名称，包含特殊格式
    """
    country_name = CONFIG["COUNTRY_NAMES"].get(country_code, country_code)
    return f"{country_name}·{country_code}"

def format_target_output(target_data, port=None):
    """
    输出 目标:端口#国旗国家名称·国家代码注释 格式（无空格）
    """
    if port is None:
        port = CONFIG["PORT"]
    
    country_code = target_data.get('countryCode', 'UN')
    flag = CONFIG["COUNTRY_FLAGS"].get(country_code, '🏴')
    country_display = get_country_display_name(country_code)
    
    # 添加注释
    comment = target_data.get('comment', '')
    comment_str = f"{comment}" if comment else ''
    
    return f"{target_data['target']}:{port}#{flag}{country_display}{comment_str}"

def format_target_list_for_display(target_list, port=None):
    """
    格式化目标列表用于显示（统一格式）
    """
    if port is None:
        port = CONFIG["PORT"]
    
    formatted_targets = []
    for target_data in target_list:
        formatted_targets.append(format_target_output(target_data, port))
    
    return formatted_targets

def format_target_list_for_file(target_list, port=None):
    """
    格式化目标列表用于文件保存（统一格式）
    """
    if port is None:
        port = CONFIG["PORT"]
    
    formatted_lines = []
    for target_data in target_list:
        formatted_lines.append(format_target_output(target_data, port))
    
    return formatted_lines

####################################################
# 主逻辑
####################################################
if __name__ == "__main__":
    # 0. 初始化环境
    init_env()
    
    # 1. 打印配置参数
    print("="*60)
    print(f"{'Cloudflare IP优选工具 v' + CONFIG['VERSION']:^60}")
    print("="*60)
    print(f"测试模式: {CONFIG['MODE']}")
    print(f"输出格式: 目标:端口#国旗国家名称·国家代码注释")
    print(f"目标池来源: {CONFIG['IP_POOL_SOURCES']}")
    print(f"地理位置API: 仅对前{CONFIG['GEO_TEST_LIMIT']}个IP目标启用")
    
    mode = CONFIG["MODE"]
    if mode == "TCP":
        print(f"TCP端口: {CONFIG['PORT']}")
        print(f"TCP重试: {CONFIG['TCP_RETRY']}次")
    elif mode == "URL_TEST":
        print(f"URL测试目标: {CONFIG['URL_TEST_TARGET']}")
        print(f"URL测试超时: {CONFIG['URL_TEST_TIMEOUT']}秒")
        print(f"URL测试重试: {CONFIG['URL_TEST_RETRY']}次")
    
    print(f"延迟范围: {CONFIG['RTT_RANGE']}ms")
    print(f"最大丢包: {CONFIG['LOSS_MAX']}%")
    print(f"并发线程: {CONFIG['THREADS']}")
    print(f"目标池大小: {CONFIG['IP_POOL_SIZE']}")
    print(f"测试目标数: {CONFIG['TEST_IP_COUNT']}")
    print(f"精选目标数: {CONFIG['TOP_IPS_LIMIT']}")
    print(f"地理位置测试: 前{CONFIG['GEO_TEST_LIMIT']}个目标")
    print("="*60 + "\n")

    # 2. 生成目标池（包含域名和IP）
    test_target_pool = generate_ip_pool()
    if not test_target_pool:
        print("无法生成目标池，程序终止")
        exit(1)

    # 3. 第一阶段：延迟测试（筛选目标）
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
    
    # 按延迟升序排列
    ping_results.sort(key=lambda x: x[1])
    
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    passed_targets = [
        target_data for target_data in ping_results
        if rtt_min <= target_data[1] <= rtt_max and target_data[2] <= loss_max
    ]
    print(f"延迟测试完成: 总数 {len(ping_results)}, 通过 {len(passed_targets)}")

    # 4. 第二阶段：测速（仅对通过延迟测试的目标）
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

    # 按延迟升序排列
    full_results.sort(key=lambda x: x[1])

    # 5. 为前200个目标添加真实国家代码信息和注释标记
    enhanced_results = enhance_target_with_country_info(full_results)

    # 6. 按延迟升序排列，取前TOP_IPS_LIMIT个
    sorted_targets = sorted(
        enhanced_results,
        key=lambda x: x['rtt']
    )[:CONFIG["TOP_IPS_LIMIT"]]

    # 7. 保存结果（统一格式）
    os.makedirs('results', exist_ok=True)
    
    with open('results/all_targets.txt', 'w') as f:
        f.write("\n".join([target[0] for target in ping_results]))
    
    with open('results/passed_targets.txt', 'w') as f:
        f.write("\n".join([target[0] for target in passed_targets]))
    
    with open('results/full_results.csv', 'w') as f:
        f.write("目标,延迟(ms),丢包率(%),速度(Mbps),国家代码,国家名称,ISP,注释\n")
        for target_data in enhanced_results:
            country_display = get_country_display_name(target_data['countryCode'])
            f.write(f"{target_data['target']},{target_data['rtt']:.2f},{target_data['loss']:.2f},{target_data['speed']:.2f},{target_data['countryCode']},{country_display},{target_data['isp']},{target_data.get('comment', '')}\n")
    
    # 所有输出文件都使用统一格式
    with open('results/top_targets.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_target_list_for_file(sorted_targets)
        f.write("\n".join(formatted_lines))
    
    with open('results/top_targets_details.csv', 'w', encoding='utf-8') as f:
        f.write("目标,延迟(ms),丢包率(%),速度(Mbps),国家代码,国家名称,ISP,注释\n")
        for target_data in sorted_targets:
            country_display = get_country_display_name(target_data['countryCode'])
            f.write(f"{target_data['target']},{target_data['rtt']:.2f},{target_data['loss']:.2f},{target_data['speed']:.2f},{target_data['countryCode']},{country_display},{target_data['isp']},{target_data.get('comment', '')}\n")

    # 8. 显示统计结果
    print("\n" + "="*60)
    print(f"{'测试结果统计':^60}")
    print("="*60)
    print(f"目标池大小: {CONFIG['IP_POOL_SIZE']}")
    print(f"实际测试目标数: {len(ping_results)}")
    print(f"通过延迟测试目标数: {len(passed_targets)}")
    print(f"测速目标数: {len(enhanced_results)}")
    print(f"精选TOP目标: {len(sorted_targets)}")
    print(f"地理位置测试目标数: {min(CONFIG['GEO_TEST_LIMIT'], len(passed_targets))}")
    
    if sorted_targets:
        print(f"【最佳目标 TOP10】(按延迟升序排列)")
        formatted_top_targets = format_target_list_for_display(sorted_targets[:10])
        for i, formatted_target in enumerate(formatted_top_targets, 1):
            target_data = sorted_targets[i-1]
            print(f"{i:2d}. {formatted_target} (延迟:{target_data['rtt']:.1f}ms, 速度:{target_data['speed']:.1f}Mbps)")
        
        print(f"【全部精选目标】(按延迟升序排列)")
        formatted_all_targets = format_target_list_for_display(sorted_targets)
        for i in range(0, len(formatted_all_targets), 2):
            line_targets = formatted_all_targets[i:i+2]
            print("  " + "  ".join(line_targets))
    
    print("="*60)
    print("结果已保存至 results/ 目录")
    print("文件说明:")
    print("   - top_targets.txt: 精选目标列表 (目标:端口#国旗国家名称·国家代码注释)")
    print("   - top_targets_details.csv: 详细性能数据")
    print("结果已按延迟升序排列")
    print("="*60)
