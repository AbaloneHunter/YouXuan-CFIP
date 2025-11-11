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
    "MODE": "URL_TEST",  # 测试模式：TCP/URL_TEST
    "URL_TEST_TARGET": "http://www.gstatic.com/generate_204",  # URL测试目标
    "URL_TEST_TIMEOUT": 3,  # URL测试超时(秒)
    "URL_TEST_RETRY": 3,  # URL测试重试次数
    "PORT": 8443,  # TCP测试端口
    "RTT_RANGE": "0~100",  # 延迟范围(ms)
    "LOSS_MAX": 1.0,  # 最大丢包率(%)
    "THREADS": 500,  # 并发线程数
    "IP_POOL_SIZE": 100000,  # IP池总大小
    "TEST_IP_COUNT": 2000,  # 实际测试IP数量
    "TOP_IPS_LIMIT": 200,  # 精选IP数量（增加到200用于地理位置测试）
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    "IP_POOL_SOURCES": "1,2",  # IP池来源：1=自定义域名和IP, 2=自定义IP段, 3=官方IP池
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

# 自定义IP标记跟踪和注释信息
custom_ip_sources = {}  # 记录每个IP的来源：'custom' 或 'cloudflare'
custom_ip_comments = {}  # 记录每个IP的注释信息
domain_comments = {}  # 记录域名的注释信息

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

def url_test(ip, url=None, timeout=None, retry=None):
    """
    URL Test模式延迟检测
    支持HTTP和HTTPS，更好的错误处理和超时控制
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
                    ip, 
                    port=port, 
                    timeout=timeout,
                    context=context
                )
            else:
                # HTTP请求
                conn = http.client.HTTPConnection(
                    ip,
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

def url_test_requests(ip, url=None, timeout=None, retry=None):
    """
    备选的requests库版本URL测试
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
            
            # 构建使用IP直接访问的URL
            if parsed_url.port:
                actual_url = f"{parsed_url.scheme}://{ip}:{parsed_url.port}{parsed_url.path}"
            else:
                actual_url = f"{parsed_url.scheme}://{ip}{parsed_url.path}"
            
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

def smart_url_test(ip, url=None, timeout=None, retry=None):
    """
    智能URL测试 - 自动选择最佳测试方法
    """
    # 先尝试http.client版本（更快）
    try:
        return url_test(ip, url, timeout, retry)
    except Exception:
        # 回退到requests版本
        return url_test_requests(ip, url, timeout, retry)

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
    
    # 使用您提供的自定义IP数据
    custom_data = """cf.090227.xyz
ip2.242625.xyz
mfa.gov.ua#域名01
saas.sin.fan#域名02
store.ubi.com#域名03
cf.130519.xyz#域名04
cf.008500.xyz#域名05
cf.090227.xyz#域名06
cf.877774.xyz#域名07
cdns.doon.eu.org#域名08
sub.danfeng.eu.org#域名09
cf.zhetengsha.eu.org#域名10

104.16.0.0/20
104.17.0.0/20
104.18.0.0/20
104.19.0.0/20
104.21.224.0/20
104.24.192.0/20
104.25.0.0/20
104.27.0.0/20
172.65.0.0/16
172.66.0.0/16
188.114.0.0/16
198.41.192.0/18
162.159.0.0/16
173.245.48.0/20
190.93.240.0/20"""
    
    print(f"🔧 使用内置自定义IP池数据")
    try:
        for line_num, line in enumerate(custom_data.split('\n'), 1):
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
                    domain_comments[content] = comment
                continue
            
            # 尝试解析为IP地址
            try:
                ip_obj = ipaddress.ip_address(content)
                individual_ips.add(content)
                if comment:
                    custom_ip_comments[content] = comment
                continue
            except ValueError:
                pass
            
            # 尝试解析为IP段
            try:
                network = ipaddress.ip_network(content, strict=False)
                ip_subnets.add(str(network))
            except ValueError:
                print(f"⚠️ 第{line_num}行格式错误: {line}")
        
        print(f"✅ 自定义IP池解析完成: {len(domains)}个域名, {len(individual_ips)}个独立IP, {len(ip_subnets)}个IP段")
        
    except Exception as e:
        print(f"🚨 解析自定义IP池失败: {e}")
    
    return domains, individual_ips, ip_subnets

def resolve_domains_to_ips(domains):
    """
    将域名解析为IP地址
    """
    resolved_ips = set()
    
    if not domains:
        return resolved_ips
    
    print(f"🔧 解析 {len(domains)} 个域名...")
    with tqdm(total=len(domains), desc="域名解析", unit="域名") as pbar:
        for domain in domains:
            try:
                # 解析域名获取IP地址
                ips = socket.getaddrinfo(domain, None, socket.AF_INET)
                for ip_info in ips:
                    ip = ip_info[4][0]
                    resolved_ips.add(ip)
                    custom_ip_sources[ip] = 'custom'
                    # 传递域名注释到IP
                    if domain in domain_comments:
                        custom_ip_comments[ip] = domain_comments[domain]
            except Exception as e:
                print(f"⚠️ 域名解析失败 {domain}: {e}")
            finally:
                pbar.update(1)
    
    print(f"✅ 域名解析完成: 获得 {len(resolved_ips)} 个IP")
    return resolved_ips

def fetch_optimized_ip_ranges():
    """
    获取优选Cloudflare IP段
    使用已知的性能较好的IP段
    """
    optimized_ranges = [
        # 优选IP段 - 这些通常是性能较好的Cloudflare IP段
        "104.16.0.0/20",
        "104.17.0.0/20", 
        "104.18.0.0/20",
        "104.19.0.0/20",
        "104.21.224.0/20",
        "104.24.192.0/20",
        "104.25.0.0/20",
        "104.27.0.0/20",
        "172.65.0.0/16",
        "172.66.0.0/16",
        "188.114.0.0/16",
        "198.41.192.0/18",
        "162.159.0.0/16",
        "173.245.48.0/20",
        "190.93.240.0/20"
    ]
    
    print("✅ 使用优选Cloudflare IP段")
    return optimized_ranges

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
    
    print(f"📊 IP池来源配置: {sources_config}")
    
    total_ip_pool = set()
    
    # 1. 自定义域名和IP
    if '1' in sources:
        domains, individual_ips, _ = parse_custom_ips_file()
        # 解析域名
        resolved_ips = resolve_domains_to_ips(domains)
        # 添加独立IP
        for ip in individual_ips:
            resolved_ips.add(ip)
            custom_ip_sources[ip] = 'custom'
        
        total_ip_pool.update(resolved_ips)
        print(f"✅ 来源1 - 自定义域名和IP: {len(resolved_ips)} 个IP")
    
    # 2. 自定义IP段
    if '2' in sources:
        _, _, custom_subnets = parse_custom_ips_file()
        custom_ip_count = CONFIG["IP_POOL_SIZE"] // 3  # 分配1/3给自定义IP段
        
        custom_ip_pool = set()
        if custom_subnets:
            print(f"🔧 从 {len(custom_subnets)} 个自定义IP段生成IP...")
            with tqdm(total=min(custom_ip_count, len(custom_subnets) * 10), 
                     desc="生成自定义IP段", unit="IP") as pbar:
                while len(custom_ip_pool) < custom_ip_count and custom_subnets:
                    subnet = random.choice(list(custom_subnets))
                    ip = generate_random_ip(subnet)
                    if ip not in custom_ip_pool:
                        custom_ip_pool.add(ip)
                        custom_ip_sources[ip] = 'custom'
                        pbar.update(1)
        
        total_ip_pool.update(custom_ip_pool)
        print(f"✅ 来源2 - 自定义IP段: {len(custom_ip_pool)} 个IP")
    
    # 3. 官方优选IP池
    if '3' in sources:
        cf_subnets = fetch_optimized_ip_ranges()
        if not cf_subnets:
            print("❌ 无法获取Cloudflare优选IP段")
        else:
            cf_ip_count = CONFIG["IP_POOL_SIZE"] // 2  # 分配1/2给官方IP
            
            cf_ip_pool = set()
            print(f"🔧 从 {len(cf_subnets)} 个Cloudflare优选IP段生成IP...")
            with tqdm(total=cf_ip_count, desc="生成优选官方IP", unit="IP") as pbar:
                while len(cf_ip_pool) < cf_ip_count:
                    subnet = random.choice(cf_subnets)
                    ip = generate_random_ip(subnet)
                    if ip not in cf_ip_pool and ip not in total_ip_pool:
                        cf_ip_pool.add(ip)
                        custom_ip_sources[ip] = 'cloudflare'
                        pbar.update(1)
            
            total_ip_pool.update(cf_ip_pool)
            print(f"✅ 来源3 - 官方优选IP池: {len(cf_ip_pool)} 个IP")
    
    full_ip_pool = list(total_ip_pool)
    random.shuffle(full_ip_pool)
    
    print(f"✅ IP池生成完成: 总计 {len(full_ip_pool)} 个IP")
    
    # 抽样测试IP
    test_ip_count = min(CONFIG["TEST_IP_COUNT"], len(full_ip_pool))
    test_ip_pool = random.sample(full_ip_pool, test_ip_count)
    print(f"🔧 随机选择 {len(test_ip_pool)} 个IP进行测试")
    
    return test_ip_pool

def ping_test(ip):
    """延迟测试入口 - 支持两种模式"""
    mode = CONFIG["MODE"]
    
    if mode == "TCP":
        rtt, loss = tcp_ping(ip, CONFIG["PORT"])
    elif mode == "URL_TEST":
        # 使用智能URL测试
        rtt, loss, _ = smart_url_test(ip)
    else:
        rtt, loss = tcp_ping(ip, CONFIG["PORT"])
    
    return (ip, rtt, loss)

def full_test(ip_data):
    """完整测试（延迟 + 速度）"""
    ip = ip_data[0]
    speed = speed_test(ip)
    return (*ip_data, speed)

def enhance_ip_with_country_info(ip_list):
    """
    为IP列表添加真实的国家代码信息
    只对前200个IP进行地理位置测试
    """
    enhanced_ips = []
    
    # 只对前200个IP进行地理位置测试
    geo_test_limit = min(CONFIG["GEO_TEST_LIMIT"], len(ip_list))
    ip_list_for_geo = ip_list[:geo_test_limit]
    
    print(f"🌍 正在检测前{geo_test_limit}个IP的真实地理位置...")
    with tqdm(total=geo_test_limit, desc="IP地理位置", unit="IP") as pbar:
        for ip_data in ip_list_for_geo:
            ip = ip_data[0]
            rtt = ip_data[1]
            loss = ip_data[2]
            speed = ip_data[3] if len(ip_data) > 3 else 0
            
            country_code = get_real_ip_country_code(ip)
            
            enhanced_ip = {
                'ip': ip,
                'rtt': rtt,
                'loss': loss,
                'speed': speed,
                'countryCode': country_code,
                'isp': "Cloudflare",
                'source': custom_ip_sources.get(ip, 'cloudflare'),  # 添加来源信息
                'comment': custom_ip_comments.get(ip, '')  # 添加注释信息
            }
            enhanced_ips.append(enhanced_ip)
            pbar.update(1)
    
    # 对于没有进行地理位置测试的IP，使用默认信息
    for ip_data in ip_list[geo_test_limit:]:
        ip = ip_data[0]
        rtt = ip_data[1]
        loss = ip_data[2]
        speed = ip_data[3] if len(ip_data) > 3 else 0
        
        enhanced_ip = {
            'ip': ip,
            'rtt': rtt,
            'loss': loss,
            'speed': speed,
            'countryCode': 'UN',
            'isp': "Cloudflare",
            'source': custom_ip_sources.get(ip, 'cloudflare'),
            'comment': custom_ip_comments.get(ip, '')
        }
        enhanced_ips.append(enhanced_ip)
    
    return enhanced_ips

####################################################
# 格式化输出函数 - 添加自定义IP标志'✓'和注释
####################################################

def format_ip_output(ip_data, port=None):
    """
    输出 ip:端口#国旗 国家简称✓ 注释 格式
    """
    if port is None:
        port = CONFIG["PORT"]
    
    country_code = ip_data.get('countryCode', 'UN')
    flag = CONFIG["COUNTRY_FLAGS"].get(country_code, '🏴')
    
    # 添加自定义IP标志
    custom_flag = '✓' if ip_data.get('source') == 'custom' else ''
    
    # 添加注释
    comment = ip_data.get('comment', '')
    comment_str = f" #{comment}" if comment else ''
    
    return f"{ip_data['ip']}:{port}#{flag} {country_code}{custom_flag}{comment_str}"

def format_ip_list_for_display(ip_list, port=None):
    """
    格式化IP列表用于显示（统一格式）
    """
    if port is None:
        port = CONFIG["PORT"]
    
    formatted_ips = []
    for ip_data in ip_list:
        formatted_ips.append(format_ip_output(ip_data, port))
    
    return formatted_ips

def format_ip_list_for_file(ip_list, port=None):
    """
    格式化IP列表用于文件保存（统一格式）
    """
    if port is None:
        port = CONFIG["PORT"]
    
    formatted_lines = []
    for ip_data in ip_list:
        formatted_lines.append(format_ip_output(ip_data, port))
    
    return formatted_lines

####################################################
# 主逻辑
####################################################
if __name__ == "__main__":
    # 0. 初始化环境
    init_env()
    
    # 1. 打印配置参数
    print("="*60)
    print(f"{'Cloudflare IP优选工具':^60}")
    print("="*60)
    print(f"测试模式: {CONFIG['MODE']}")
    print(f"输出格式: ip:端口#国旗 国家简称✓ #注释 (✓表示自定义IP)")
    print(f"IP池来源: {CONFIG['IP_POOL_SOURCES']}")
    print(f"地理位置API: 仅对前{CONFIG['GEO_TEST_LIMIT']}个IP启用")
    
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
    print(f"IP池大小: {CONFIG['IP_POOL_SIZE']}")
    print(f"测试IP数: {CONFIG['TEST_IP_COUNT']}")
    print(f"精选IP数: {CONFIG['TOP_IPS_LIMIT']}")
    print(f"地理位置测试: 前{CONFIG['GEO_TEST_LIMIT']}个IP")
    print("="*60 + "\n")

    # 2. 生成IP池（根据配置的多种来源）
    test_ip_pool = generate_ip_pool()
    if not test_ip_pool:
        print("❌ 无法生成IP池，程序终止")
        exit(1)

    # 3. 第一阶段：延迟测试（筛选IP）
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
                except Exception as e:
                    print(f"\n🔧 延迟测试异常: {e}")
                finally:
                    pbar.update(1)
    
    # 按延迟升序排列
    ping_results.sort(key=lambda x: x[1])
    
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    passed_ips = [
        ip_data for ip_data in ping_results
        if rtt_min <= ip_data[1] <= rtt_max and ip_data[2] <= loss_max
    ]
    print(f"\n✅ 延迟测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips)}")

    # 4. 第二阶段：测速（仅对通过延迟测试的IP）
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
                except Exception as e:
                    print(f"\n🔧 测速异常: {e}")
                finally:
                    pbar.update(1)

    # 按延迟升序排列
    full_results.sort(key=lambda x: x[1])

    # 5. 为前200个IP添加真实国家代码信息和来源标记
    enhanced_results = enhance_ip_with_country_info(full_results)

    # 6. 按延迟升序排列，取前TOP_IPS_LIMIT个
    sorted_ips = sorted(
        enhanced_results,
        key=lambda x: x['rtt']
    )[:CONFIG["TOP_IPS_LIMIT"]]

    # 7. 保存结果（统一格式）
    os.makedirs('results', exist_ok=True)
    
    with open('results/all_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in ping_results]))
    
    with open('results/passed_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in passed_ips]))
    
    with open('results/full_results.csv', 'w') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),国家代码,ISP,来源,注释\n")
        for ip_data in enhanced_results:
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['countryCode']},{ip_data['isp']},{ip_data.get('source', 'cloudflare')},{ip_data.get('comment', '')}\n")
    
    # 所有输出文件都使用统一格式（包含✓标志和注释）
    with open('results/top_ips.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_ip_list_for_file(sorted_ips)
        f.write("\n".join(formatted_lines))
    
    with open('results/top_ips_details.csv', 'w', encoding='utf-8') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),国家代码,ISP,来源,注释\n")
        for ip_data in sorted_ips:
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['countryCode']},{ip_data['isp']},{ip_data.get('source', 'cloudflare')},{ip_data.get('comment', '')}\n")

    # 8. 显示统计结果
    print("\n" + "="*60)
    print(f"{'🔥 测试结果统计':^60}")
    print("="*60)
    print(f"IP池大小: {CONFIG['IP_POOL_SIZE']}")
    print(f"实际测试IP数: {len(ping_results)}")
    print(f"通过延迟测试IP数: {len(passed_ips)}")
    print(f"测速IP数: {len(enhanced_results)}")
    print(f"精选TOP IP: {len(sorted_ips)}")
    print(f"地理位置测试IP数: {min(CONFIG['GEO_TEST_LIMIT'], len(passed_ips))}")
    
    if sorted_ips:
        print(f"\n🏆【最佳IP TOP10】(按延迟升序排列，✓表示自定义IP)")
        formatted_top_ips = format_ip_list_for_display(sorted_ips[:10])
        for i, formatted_ip in enumerate(formatted_top_ips, 1):
            ip_data = sorted_ips[i-1]
            source_info = " [自定义]" if ip_data.get('source') == 'custom' else ""
            print(f"{i:2d}. {formatted_ip} (延迟:{ip_data['rtt']:.1f}ms, 速度:{ip_data['speed']:.1f}Mbps{source_info})")
        
        print(f"\n📋【全部精选IP】(按延迟升序排列，✓表示自定义IP)")
        formatted_all_ips = format_ip_list_for_display(sorted_ips)
        for i in range(0, len(formatted_all_ips), 2):
            line_ips = formatted_all_ips[i:i+2]
            print("  " + "  ".join(line_ips))
    
    print("="*60)
    print("✅ 结果已保存至 results/ 目录")
    print("📊 文件说明:")
    print("   - top_ips.txt: 精选IP列表 (ip:端口#国旗 国家简称✓ #注释)")
    print("   - top_ips_details.csv: 详细性能数据")
    print("❣️  结果已按延迟升序排列")
    print("="*60)
