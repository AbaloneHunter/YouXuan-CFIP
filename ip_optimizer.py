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
    "PORT": 443,  # TCP测试端口
    "RTT_RANGE": "0~40",  # 延迟范围(ms)
    "LOSS_MAX": 1.0,  # 最大丢包率(%)
    "THREADS": 500,  # 并发线程数
    "IP_POOL_SIZE": 100000,  # IP池总大小
    "TEST_IP_COUNT": 2000,  # 实际测试IP数量
    "TOP_IPS_LIMIT": 100,  # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    "IP_POOL_SOURCES": "1,2,3",  # IP池来源：1=自定义域名和IP, 2=自定义IP段, 3=官方IP池
    
    # 新增配置：注释显示设置
    "DOMAIN_COMMENT_SEPARATOR": "#",  # 域名和注释的分隔符
    "COMMENT_DISPLAY_FORMAT": "[{comment}]",  # 注释的显示格式
    
    # 地理位置查询设置
    "GEO_QUERY_ENABLED": True,  # 是否启用地理位置查询
    "GEO_QUERY_MODE": "DELAY_FIRST",  # 查询模式：DELAY_FIRST=延迟优先, SPEED_FIRST=速度优先, BOTH=两者都查
    "GEO_QUERY_COUNT": 200,  # 查询前多少个IP的地理位置
    
    # 备用测试URL列表
    "BACKUP_TEST_URLS": [
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/",
        "http://www.cloudflare.com/favicon.ico"
    ],
    
    # IP地理位置API配置
    "IP_GEO_API": {
        "timeout": 3,
        "retry": 2,
        "enable_cache": True
    },
    
    # 新增配置：域名测试设置
    "DOMAIN_TEST_ENABLED": True,  # 是否启用域名直接测试
    "DOMAIN_TEST_PORT": 443,  # 域名测试默认端口
    "DOMAIN_TEST_PROTOCOL": "https"  # 域名测试默认协议
}

# IP地理位置缓存
ip_geo_cache = {}

# IP详细信息存储
ip_details = {}  # 存储每个IP的详细信息：{ip: {"comment": "注释", "source": "来源", "domain": "原始域名"}}

# 域名详细信息存储
domain_details = {}  # 存储每个域名的详细信息：{domain: {"comment": "注释", "source": "来源"}}

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

def batch_get_ip_country_codes(ip_list):
    """
    批量获取IP国家代码
    """
    results = {}
    
    print(f"🌍 批量检测 {len(ip_list)} 个IP的地理位置...")
    with tqdm(total=len(ip_list), desc="IP地理位置", unit="IP") as pbar:
        for ip in ip_list:
            country_code = get_real_ip_country_code(ip)
            results[ip] = country_code
            pbar.update(1)
    
    return results

####################################################
# URL测试函数 - 增强版支持域名测试
####################################################

def url_test(target, url=None, timeout=None, retry=None, is_domain=False):
    """
    URL Test模式延迟检测
    支持域名和IP测试，更好的错误处理和超时控制
    
    Args:
        target: 测试目标（IP或域名）
        is_domain: 是否为域名测试
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
            
            # 如果是域名测试，使用域名作为连接目标
            connect_target = target if is_domain else hostname
            
            if scheme == 'https':
                # HTTPS请求
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                conn = http.client.HTTPSConnection(
                    connect_target, 
                    port=port, 
                    timeout=timeout,
                    context=context
                )
            else:
                # HTTP请求
                conn = http.client.HTTPConnection(
                    connect_target,
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

def url_test_requests(target, url=None, timeout=None, retry=None, is_domain=False):
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
            
            # 构建URL
            if is_domain:
                # 域名测试：直接使用域名
                actual_url = url.replace(parsed_url.hostname, target)
            else:
                # IP测试：使用IP替换hostname
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

def smart_url_test(target, url=None, timeout=None, retry=None, is_domain=False):
    """
    智能URL测试 - 自动选择最佳测试方法
    """
    # 先尝试http.client版本（更快）
    try:
        return url_test(target, url, timeout, retry, is_domain)
    except Exception:
        # 回退到requests版本
        return url_test_requests(target, url, timeout, retry, is_domain)

####################################################
# 其他测试函数
####################################################

def tcp_ping(target, port, timeout=2, is_domain=False):
    """TCP Ping测试 - 支持域名测试"""
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

def speed_test(target, is_domain=False):
    """速度测试 - 支持域名测试"""
    url = CONFIG["SPEED_URL"]
    timeout = CONFIG["SPEED_TIMEOUT"]
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        
        # 构建测试URL
        if is_domain:
            test_url = url.replace(host, target)
        else:
            if parsed_url.port:
                test_url = f"{parsed_url.scheme}://{target}:{parsed_url.port}{parsed_url.path}"
            else:
                test_url = f"{parsed_url.scheme}://{target}{parsed_url.path}"
        
        start_time = time.time()
        response = requests.get(
            test_url, 
            headers={'Host': host}, 
            timeout=timeout, 
            verify=False, 
            stream=True
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
# 核心功能函数 - 修改支持域名测试
####################################################

def init_env():
    """初始化环境"""
    for key, value in CONFIG.items():
        os.environ[key] = str(value)

def parse_custom_ips_file():
    """
    解析自定义IP文件，支持域名/IP/IP段后跟#注释
    返回: (domains_with_comments, individual_ips_with_comments, ip_subnets_with_comments)
    """
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    domains_with_comments = {}  # 域名->注释
    individual_ips_with_comments = {}  # IP->注释
    ip_subnets_with_comments = {}  # IP段->注释
    
    if not custom_file or not os.path.exists(custom_file):
        return domains_with_comments, individual_ips_with_comments, ip_subnets_with_comments
    
    print(f"🔧 读取自定义IP池文件: {custom_file}")
    separator = CONFIG["DOMAIN_COMMENT_SEPARATOR"]
    
    try:
        with open(custom_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # 解析注释
                original_line = line
                comment = ""
                if separator in line:
                    main_part, comment = line.split(separator, 1)
                    main_part = main_part.strip()
                    comment = comment.strip()
                else:
                    main_part = line
                
                # 检测是否为域名（包含字母）
                if any(c.isalpha() for c in main_part):
                    domains_with_comments[main_part] = comment
                    continue
                
                # 尝试解析为IP地址
                try:
                    ip_obj = ipaddress.ip_address(main_part)
                    individual_ips_with_comments[main_part] = comment
                    continue
                except ValueError:
                    pass
                
                # 尝试解析为IP段
                try:
                    network = ipaddress.ip_network(main_part, strict=False)
                    ip_subnets_with_comments[str(network)] = comment
                except ValueError:
                    print(f"⚠️ 第{line_num}行格式错误: {original_line}")
        
        print(f"✅ 自定义IP池解析完成: {len(domains_with_comments)}个域名, {len(individual_ips_with_comments)}个独立IP, {len(ip_subnets_with_comments)}个IP段")
        
    except Exception as e:
        print(f"🚨 读取自定义IP池失败: {e}")
    
    return domains_with_comments, individual_ips_with_comments, ip_subnets_with_comments

def generate_ip_pool():
    """
    根据配置的IP池来源生成测试目标池，支持域名直接测试
    """
    sources_config = CONFIG["IP_POOL_SOURCES"]
    sources = [s.strip() for s in sources_config.split(',')]
    
    print(f"📊 IP池来源配置: {sources_config}")
    
    total_test_pool = {}  # 存储测试目标的完整信息 {target: {"type": "ip/domain", "comment": "", "source": "", "domain": ""}}
    
    # 1. 自定义域名和IP
    if '1' in sources:
        domains_with_comments, individual_ips_with_comments, _ = parse_custom_ips_file()
        
        # 添加域名到测试池
        for domain, comment in domains_with_comments.items():
            total_test_pool[domain] = {
                "type": "domain",
                "comment": comment,
                "source": "custom",
                "domain": domain
            }
        
        # 添加独立IP到测试池
        for ip, comment in individual_ips_with_comments.items():
            total_test_pool[ip] = {
                "type": "ip",
                "comment": comment,
                "source": "custom",
                "domain": ip
            }
        
        print(f"✅ 来源1 - 自定义域名和IP: {len(domains_with_comments)}个域名, {len(individual_ips_with_comments)}个IP")
    
    # 2. 自定义IP段
    if '2' in sources:
        _, _, custom_subnets_with_comments = parse_custom_ips_file()
        custom_ip_count = CONFIG["IP_POOL_SIZE"] // 3
        
        custom_ip_pool = {}
        if custom_subnets_with_comments:
            print(f"🔧 从 {len(custom_subnets_with_comments)} 个自定义IP段生成IP...")
            with tqdm(total=min(custom_ip_count, len(custom_subnets_with_comments) * 10), 
                     desc="生成自定义IP段", unit="IP") as pbar:
                while len(custom_ip_pool) < custom_ip_count and custom_subnets_with_comments:
                    subnet = random.choice(list(custom_subnets_with_comments.keys()))
                    comment = custom_subnets_with_comments[subnet]
                    ip = generate_random_ip(subnet)
                    if ip not in custom_ip_pool:
                        custom_ip_pool[ip] = {
                            "type": "ip",
                            "comment": comment,
                            "source": "custom",
                            "domain": f"网段:{subnet}"
                        }
                        pbar.update(1)
        
        total_test_pool.update(custom_ip_pool)
        print(f"✅ 来源2 - 自定义IP段: {len(custom_ip_pool)} 个IP")
    
    # 3. 官方IP池
    if '3' in sources:
        cf_subnets = fetch_ip_ranges()
        if not cf_subnets:
            print("❌ 无法获取Cloudflare IP段")
        else:
            cf_ip_count = CONFIG["IP_POOL_SIZE"] // 2
            
            cf_ip_pool = {}
            print(f"🔧 从 {len(cf_subnets)} 个Cloudflare IP段生成IP...")
            with tqdm(total=cf_ip_count, desc="生成官方IP", unit="IP") as pbar:
                while len(cf_ip_pool) < cf_ip_count:
                    subnet = random.choice(cf_subnets)
                    ip = generate_random_ip(subnet)
                    if ip not in cf_ip_pool and ip not in total_test_pool:
                        cf_ip_pool[ip] = {
                            "type": "ip",
                            "comment": "Cloudflare官方",
                            "source": "cloudflare",
                            "domain": f"CF网段:{subnet}"
                        }
                        pbar.update(1)
            
            total_test_pool.update(cf_ip_pool)
            print(f"✅ 来源3 - 官方IP池: {len(cf_ip_pool)} 个IP")
    
    # 更新全局详细信息
    global ip_details, domain_details
    for target, info in total_test_pool.items():
        if info["type"] == "ip":
            ip_details[target] = info
        else:
            domain_details[target] = info
    
    full_test_pool = list(total_test_pool.keys())
    random.shuffle(full_test_pool)
    
    print(f"✅ 测试目标池生成完成: 总计 {len(full_test_pool)} 个目标 ({sum(1 for x in total_test_pool.values() if x['type'] == 'domain')}个域名, {sum(1 for x in total_test_pool.values() if x['type'] == 'ip')}个IP)")
    
    # 抽样测试目标
    test_count = min(CONFIG["TEST_IP_COUNT"], len(full_test_pool))
    test_pool = random.sample(full_test_pool, test_count)
    print(f"🔧 随机选择 {len(test_pool)} 个目标进行测试")
    
    return test_pool, total_test_pool

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

def fetch_ip_ranges():
    """获取Cloudflare官方IP段"""
    url = CONFIG["CLOUDFLARE_IPS_URL"]
    try:
        res = requests.get(url, timeout=10, verify=False)
        return res.text.splitlines()
    except Exception as e:
        print(f"🚨 获取Cloudflare IP段失败: {e}")
    return []

def ping_test(target):
    """延迟测试入口 - 支持域名和IP测试"""
    mode = CONFIG["MODE"]
    
    # 获取目标类型
    global domain_details, ip_details
    is_domain = target in domain_details
    
    if mode == "TCP":
        port = CONFIG["PORT"]
        rtt, loss = tcp_ping(target, port, is_domain=is_domain)
    elif mode == "URL_TEST":
        # 使用智能URL测试
        rtt, loss, _ = smart_url_test(target, is_domain=is_domain)
    else:
        port = CONFIG["PORT"]
        rtt, loss = tcp_ping(target, port, is_domain=is_domain)
    
    return (target, rtt, loss, is_domain)

def full_test(target_data):
    """完整测试（延迟 + 速度）"""
    target = target_data[0]
    is_domain = target_data[3]  # 从ping_test返回的第四个参数获取是否为域名
    speed = speed_test(target, is_domain=is_domain)
    return (*target_data, speed)

def select_targets_for_geo_query(target_list, target_info_map):
    """
    根据配置模式选择需要查询地理位置的IP（仅对IP目标查询）
    """
    geo_mode = CONFIG["GEO_QUERY_MODE"]
    query_count = CONFIG["GEO_QUERY_COUNT"]
    
    # 只对IP目标进行地理位置查询
    ip_targets = [t for t in target_list if not t[3]]  # t[3]是is_domain，False表示IP
    
    if geo_mode == "DELAY_FIRST":
        # 延迟优先：按延迟升序排列
        sorted_targets = sorted(ip_targets, key=lambda x: x[1])[:CONFIG["TOP_IPS_LIMIT"]]
        ips_to_query = [target_data[0] for target_data in sorted_targets[:query_count]]
        
    elif geo_mode == "SPEED_FIRST":
        # 速度优先：按速度降序排列（需要先进行速度测试）
        if len(ip_targets[0]) > 4:  # 确保有速度数据
            sorted_targets = sorted(ip_targets, key=lambda x: x[4] if len(x) > 4 else 0, reverse=True)[:CONFIG["TOP_IPS_LIMIT"]]
        else:
            # 如果没有速度数据，回退到延迟优先
            sorted_targets = sorted(ip_targets, key=lambda x: x[1])[:CONFIG["TOP_IPS_LIMIT"]]
        ips_to_query = [target_data[0] for target_data in sorted_targets[:query_count]]
        
    elif geo_mode == "BOTH":
        # 两者都查：取延迟前一半和速度前一半
        delay_sorted = sorted(ip_targets, key=lambda x: x[1])[:CONFIG["TOP_IPS_LIMIT"]]
        if len(ip_targets[0]) > 4:  # 确保有速度数据
            speed_sorted = sorted(ip_targets, key=lambda x: x[4] if len(x) > 4 else 0, reverse=True)[:CONFIG["TOP_IPS_LIMIT"]]
        else:
            speed_sorted = delay_sorted
        
        # 合并并去重
        half_count = query_count // 2
        ips_to_query = list(set(
            [target_data[0] for target_data in delay_sorted[:half_count]] +
            [target_data[0] for target_data in speed_sorted[:half_count]]
        ))[:query_count]
        
        # 最终的排序列表（延迟优先）
        sorted_targets = delay_sorted
    else:
        # 默认延迟优先
        sorted_targets = sorted(ip_targets, key=lambda x: x[1])[:CONFIG["TOP_IPS_LIMIT"]]
        ips_to_query = [target_data[0] for target_data in sorted_targets[:query_count]]
    
    return ips_to_query, sorted_targets

def enhance_selected_targets_with_country_info(target_list, country_map, target_info_map):
    """
    为选中的目标列表添加国家代码信息（仅IP目标）
    """
    enhanced_targets = []
    
    for target_data in target_list:
        target = target_data[0]
        rtt = target_data[1]
        loss = target_data[2]
        is_domain = target_data[3]
        speed = target_data[4] if len(target_data) > 4 else 0
        
        # 获取目标的详细信息
        target_info = target_info_map.get(target, {})
        
        # 只有IP目标才有国家代码，域名目标显示为DOM
        if is_domain:
            country_code = 'DOM'  # 域名标记
        else:
            country_code = country_map.get(target, 'UN')
        
        enhanced_target = {
            'target': target,
            'rtt': rtt,
            'loss': loss,
            'speed': speed,
            'countryCode': country_code,
            'comment': target_info.get('comment', ''),
            'source': target_info.get('source', 'cloudflare'),
            'domain': target_info.get('domain', target),
            'type': target_info.get('type', 'ip')
        }
        enhanced_targets.append(enhanced_target)
    
    return enhanced_targets

####################################################
# 格式化输出函数 - 修改支持域名输出
####################################################

def format_target_output(target_data, port=None):
    """
    输出 目标:端口#[注释] 国家简称 格式
    对于域名：domain.com:443#[注释] DOM
    对于IP：1.1.1.1:443#[注释] US
    """
    if port is None:
        port = CONFIG["PORT"]
    
    country_code = target_data.get('countryCode', 'UN')
    comment = target_data.get('comment', '')
    target_type = target_data.get('type', 'ip')
    
    # 格式化注释
    if comment:
        formatted_comment = CONFIG["COMMENT_DISPLAY_FORMAT"].format(comment=comment)
    else:
        formatted_comment = ""
    
    return f"{target_data['target']}:{port}#{formatted_comment} {country_code}"

def format_target_list_for_display(target_list, port=None):
    """
    格式化目标列表用于显示
    """
    if port is None:
        port = CONFIG["PORT"]
    
    formatted_targets = []
    for target_data in target_list:
        formatted_targets.append(format_target_output(target_data, port))
    
    return formatted_targets

def format_target_list_for_file(target_list, port=None):
    """
    格式化目标列表用于文件保存
    """
    if port is None:
        port = CONFIG["PORT"]
    
    formatted_lines = []
    for target_data in target_list:
        formatted_lines.append(format_target_output(target_data, port))
    
    return formatted_lines

####################################################
# 主逻辑 - 修改支持域名测试
####################################################
if __name__ == "__main__":
    # 0. 初始化环境
    init_env()
    
    # 1. 打印配置参数
    print("="*60)
    print(f"{'Cloudflare IP/域名优选工具':^60}")
    print("="*60)
    print(f"测试模式: {CONFIG['MODE']}")
    print(f"输出格式: 目标:端口#[注释] 国家简称")
    print(f"IP池来源: {CONFIG['IP_POOL_SOURCES']}")
    print(f"域名直接测试: {'启用' if CONFIG['DOMAIN_TEST_ENABLED'] else '禁用'}")
    print(f"地理位置查询: {'启用' if CONFIG['GEO_QUERY_ENABLED'] else '禁用'}")
    if CONFIG['GEO_QUERY_ENABLED']:
        print(f"查询模式: {CONFIG['GEO_QUERY_MODE']}")
        print(f"查询数量: 前{CONFIG['GEO_QUERY_COUNT']}个IP")
    
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
    print(f"测试目标数: {CONFIG['TEST_IP_COUNT']}")
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    if custom_file:
        print(f"自定义目标池: {custom_file}")
    else:
        print(f"Cloudflare IP源: {CONFIG['CLOUDFLARE_IPS_URL']}")
    print(f"测速URL: {CONFIG['SPEED_URL']}")
    print("="*60 + "\n")

    # 2. 生成测试目标池（包含域名和IP）
    test_pool, target_info_map = generate_ip_pool()
    if not test_pool:
        print("❌ 无法生成测试目标池，程序终止")
        exit(1)

    # 3. 第一阶段：延迟测试（筛选目标）
    ping_results = []
    mode_display = {
        "TCP": "🔌 TCP测试进度", 
        "URL_TEST": "🌐 URL测试进度"
    }
    progress_desc = mode_display.get(mode, "🚀 延迟测试进度")
    
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_target = {executor.submit(ping_test, target): target for target in test_pool}
        with tqdm(
            total=len(test_pool),
            desc=progress_desc,
            unit="目标",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_target):
                try:
                    ping_results.append(future.result())
                except Exception as e:
                    print(f"\n🔧 延迟测试异常: {e}")
                finally:
                    pbar.update(1)
    
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    passed_targets = [
        target_data for target_data in ping_results
        if rtt_min <= target_data[1] <= rtt_max and target_data[2] <= loss_max
    ]
    
    # 统计域名和IP数量
    domain_count = sum(1 for t in passed_targets if t[3])
    ip_count = sum(1 for t in passed_targets if not t[3])
    
    print(f"\n✅ 延迟测试完成: 总数 {len(ping_results)}, 通过 {len(passed_targets)} ({domain_count}个域名, {ip_count}个IP)")

    # 4. 第二阶段：测速（仅对通过延迟测试的目标）
    if not passed_targets:
        print("❌ 没有通过延迟测试的目标，程序终止")
        exit(1)
    
    full_results = []
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_target = {executor.submit(full_test, target_data): target_data for target_data in passed_targets}
        with tqdm(
            total=len(passed_targets),
            desc="📊 测速进度",
            unit="目标",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_target):
                try:
                    full_results.append(future.result())
                except Exception as e:
                    print(f"\n🔧 测速异常: {e}")
                finally:
                    pbar.update(1)

    # 5. 智能选择IP进行地理位置查询（仅对IP目标）
    if CONFIG["GEO_QUERY_ENABLED"] and full_results:
        # 选择需要查询地理位置的IP（排除域名）
        ips_to_query, sorted_targets = select_targets_for_geo_query(full_results, target_info_map)
        
        print(f"\n🔍 地理位置查询模式: {CONFIG['GEO_QUERY_MODE']}")
        print(f"📝 将查询前 {len(ips_to_query)} 个IP的地理位置")
        
        # 批量查询地理位置
        country_map = batch_get_ip_country_codes(ips_to_query)
        
        # 为选中的目标添加国家信息
        enhanced_results = enhance_selected_targets_with_country_info(sorted_targets, country_map, target_info_map)
        
        # 为其他目标设置默认国家代码
        final_enhanced_results = []
        for target_data in sorted_targets:
            target = target_data[0]
            if not target_data[3] and target in [e['target'] for e in enhanced_results]:  # IP目标且已查询
                final_enhanced_results.append(next(e for e in enhanced_results if e['target'] == target))
            else:
                # 域名目标或未查询地理位置的IP
                target_info = target_info_map.get(target, {})
                country_code = 'DOM' if target_data[3] else 'UN'  # 域名标记为DOM
                final_enhanced_results.append({
                    'target': target,
                    'rtt': target_data[1],
                    'loss': target_data[2],
                    'speed': target_data[4] if len(target_data) > 4 else 0,
                    'countryCode': country_code,
                    'comment': target_info.get('comment', ''),
                    'source': target_info.get('source', 'cloudflare'),
                    'domain': target_info.get('domain', target),
                    'type': target_info.get('type', 'ip')
                })
        
        sorted_enhanced_results = final_enhanced_results
    else:
        # 不查询地理位置，使用默认信息
        sorted_targets = sorted(
            full_results,
            key=lambda x: x[1]  # 按延迟排序
        )[:CONFIG["TOP_IPS_LIMIT"]]
        
        sorted_enhanced_results = []
        for target_data in sorted_targets:
            target_info = target_info_map.get(target_data[0], {})
            country_code = 'DOM' if target_data[3] else 'UN'  # 域名标记为DOM
            sorted_enhanced_results.append({
                'target': target_data[0],
                'rtt': target_data[1],
                'loss': target_data[2],
                'speed': target_data[4] if len(target_data) > 4 else 0,
                'countryCode': country_code,
                'comment': target_info.get('comment', ''),
                'source': target_info.get('source', 'cloudflare'),
                'domain': target_info.get('domain', target_data[0]),
                'type': target_info.get('type', 'ip')
            })

    # 6. 保存结果
    os.makedirs('results', exist_ok=True)
    
    with open('results/all_targets.txt', 'w') as f:
        f.write("\n".join([target[0] for target in ping_results]))
    
    with open('results/passed_targets.txt', 'w') as f:
        f.write("\n".join([target[0] for target in passed_targets]))
    
    with open('results/full_results.csv', 'w') as f:
        f.write("目标,类型,延迟(ms),丢包率(%),速度(Mbps),国家代码,注释,来源,原始域名\n")
        for target_data in sorted_enhanced_results:
            f.write(f"{target_data['target']},{target_data['type']},{target_data['rtt']:.2f},{target_data['loss']:.2f},{target_data['speed']:.2f},{target_data['countryCode']},{target_data['comment']},{target_data['source']},{target_data['domain']}\n")
    
    # 使用新格式保存（目标:端口#[注释] 国家简称）
    with open('results/top_targets.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_target_list_for_file(sorted_enhanced_results)
        f.write("\n".join(formatted_lines))
    
    with open('results/top_targets_details.csv', 'w', encoding='utf-8') as f:
        f.write("目标,类型,延迟(ms),丢包率(%),速度(Mbps),国家代码,注释,来源,原始域名\n")
        for target_data in sorted_enhanced_results:
            f.write(f"{target_data['target']},{target_data['type']},{target_data['rtt']:.2f},{target_data['loss']:.2f},{target_data['speed']:.2f},{target_data['countryCode']},{target_data['comment']},{target_data['source']},{target_data['domain']}\n")

    # 7. 显示统计结果
    print("\n" + "="*60)
    print(f"{'🔥 测试结果统计':^60}")
    print("="*60)
    print(f"测试目标总数: {len(ping_results)}")
    print(f"通过延迟测试目标数: {len(passed_targets)}")
    print(f"测速目标数: {len(full_results)}")
    print(f"精选TOP目标: {len(sorted_enhanced_results)}")
    
    # 统计最终结果中的域名和IP数量
    final_domain_count = sum(1 for t in sorted_enhanced_results if t['type'] == 'domain')
    final_ip_count = sum(1 for t in sorted_enhanced_results if t['type'] == 'ip')
    print(f"精选目标分布: {final_domain_count}个域名, {final_ip_count}个IP")
    
    if CONFIG["GEO_QUERY_ENABLED"]:
        geo_queried_count = len([t for t in sorted_enhanced_results if t['countryCode'] not in ['UN', 'DOM']])
        print(f"地理位置查询IP数: {geo_queried_count}")
    
    if sorted_enhanced_results:
        # 分别显示域名和IP的TOP10
        domain_targets = [t for t in sorted_enhanced_results if t['type'] == 'domain']
        ip_targets = [t for t in sorted_enhanced_results if t['type'] == 'ip']
        
        if domain_targets:
            print(f"\n🏆【最佳域名 TOP{min(5, len(domain_targets))}】(按延迟升序排列)")
            formatted_top_domains = format_target_list_for_display(domain_targets[:5])
            for i, formatted_domain in enumerate(formatted_top_domains, 1):
                target_data = domain_targets[i-1]
                source_info = " [自定义]" if target_data.get('source') == 'custom' else ""
                print(f"{i:2d}. {formatted_domain} (延迟:{target_data['rtt']:.1f}ms, 速度:{target_data['speed']:.1f}Mbps{source_info})")
        
        if ip_targets:
            print(f"\n🏆【最佳IP TOP{min(5, len(ip_targets))}】(按延迟升序排列)")
            formatted_top_ips = format_target_list_for_display(ip_targets[:5])
            for i, formatted_ip in enumerate(formatted_top_ips, 1):
                target_data = ip_targets[i-1]
                source_info = " [自定义]" if target_data.get('source') == 'custom' else ""
                print(f"{i:2d}. {formatted_ip} (延迟:{target_data['rtt']:.1f}ms, 速度:{target_data['speed']:.1f}Mbps{source_info})")
        
        print(f"\n📋【全部精选目标】(按延迟升序排列)")
        formatted_all_targets = format_target_list_for_display(sorted_enhanced_results)
        for i in range(0, len(formatted_all_targets), 2):
            line_targets = formatted_all_targets[i:i+2]
            print("  " + "  ".join(line_targets))
    
    print("="*60)
    print("✅ 结果已保存至 results/ 目录")
    print("📊 文件说明:")
    print("   - top_targets.txt: 精选目标列表 (目标:端口#[注释] 国家简称)")
    print("   - top_targets_details.csv: 详细性能数据")
    print("🗑️  结果已按延迟升序排列")
    print("="*60)
