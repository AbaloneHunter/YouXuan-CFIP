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
    "URL_TEST_RETRY": 2,  # URL测试重试次数
    "PORT": 443,  # TCP测试端口
    "RTT_RANGE": "0~400",  # 延迟范围(ms)
    "LOSS_MAX": 2.0,  # 最大丢包率(%)
    "THREADS": 300,  # 并发线程数
    "IP_POOL_SIZE": 100000,  # IP池总大小
    "TEST_IP_COUNT": 1000,  # 实际测试IP数量
    "TOP_IPS_LIMIT": 100,  # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    
    # 备用测试URL列表
    "BACKUP_TEST_URLS": [
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/",
        "http://www.cloudflare.com/favicon.ico"
    ],
    
    # 国家代码到国旗和国家名称的映射
    "COUNTRY_INFO": {
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
        'ID': {'flag': '🇮🇩', 'name': '印尼'},
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
        'CN': {'flag': '⭐', 'name': '中·国'},      # 中国使用⭐
        'TW': {'flag': '🌶️', 'name': '台·湾'},     # 台湾使用🌶️
        'UN': {'flag': '🏴', 'name': '未知'}        # 未知国家
    },
    
    # IP类型标志
    "IP_TYPE_FLAGS": {
        "CUSTOM": "👏",    # 自定义IP
        "CLOUDFLARE": "👋" # Cloudflare官方IP
    },
    
    # IP地理位置API配置 - 增强配置
    "IP_GEO_API": {
        "timeout": 5,  # 增加超时时间
        "retry": 3,    # 增加重试次数
        "enable_cache": True,
        "delay_between_requests": 0.1,  # 请求间隔避免限流
        "max_workers": 50  # 减少并发数避免API限制
    }
}

# IP地理位置缓存
ip_geo_cache = {}

# 自定义IP标记跟踪
custom_ip_sources = {}  # 记录每个IP的来源：'custom' 或 'cloudflare'

####################################################
# IP地理位置查询函数 - 增强版本
####################################################

def get_real_ip_country_code(ip):
    """
    增强版IP地理位置查询 - 多API冗余 + 智能重试
    """
    # 检查缓存
    if CONFIG["IP_GEO_API"]["enable_cache"] and ip in ip_geo_cache:
        return ip_geo_cache[ip]
    
    # API列表 - 按优先级排序
    apis = [
        {
            'name': 'ipapi.co',
            'url': f"https://ipapi.co/{ip}/json/",
            'field': 'country_code',
            'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        },
        {
            'name': 'ip-api.com', 
            'url': f"http://ip-api.com/json/{ip}?fields=status,message,countryCode",
            'field': 'countryCode',
            'check_field': 'status',
            'check_value': 'success'
        },
        {
            'name': 'ipapi.com',
            'url': f"https://ipapi.com/ip_api.php?ip={ip}",
            'field': 'country_code',
            'headers': {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        }
    ]
    
    for api in apis:
        for attempt in range(CONFIG["IP_GEO_API"]["retry"]):
            try:
                # 添加请求间隔避免限流
                if attempt > 0:
                    time.sleep(1)
                
                headers = api.get('headers', {})
                if not headers:
                    headers = {'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Tester/1.0)'}
                
                response = requests.get(
                    api['url'], 
                    headers=headers,
                    timeout=CONFIG["IP_GEO_API"]["timeout"], 
                    verify=False
                )
                
                if response.status_code == 200:
                    data = response.json()
                    
                    # 检查API特定条件
                    if api.get('check_field') and api.get('check_value'):
                        if data.get(api['check_field']) != api['check_value']:
                            continue
                    
                    country_code = data.get(api['field'])
                    if country_code and country_code != 'UN' and country_code != 'None':
                        # 标准化国家代码
                        country_code = country_code.upper()
                        
                        # 缓存结果
                        if CONFIG["IP_GEO_API"]["enable_cache"]:
                            ip_geo_cache[ip] = country_code
                        
                        return country_code
                        
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except Exception:
                continue
            
            # 短暂延迟
            time.sleep(CONFIG["IP_GEO_API"]["delay_between_requests"])
    
    # 如果所有API都失败，返回未知
    return 'UN'

def batch_geo_lookup(ip_list):
    """
    批量地理查询 - 控制并发避免API限制
    """
    results = []
    
    print("🌍 正在检测IP真实地理位置...")
    
    with ThreadPoolExecutor(max_workers=CONFIG["IP_GEO_API"]["max_workers"]) as executor:
        future_to_ip = {executor.submit(get_real_ip_country_code, ip_data["ip"]): ip_data for ip_data in ip_list}
        
        with tqdm(
            total=len(ip_list),
            desc="地理位置查询",
            unit="IP",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_ip):
                ip_data = future_to_ip[future]
                try:
                    country_code = future.result()
                    ip_data['countryCode'] = country_code
                    results.append(ip_data)
                except Exception as e:
                    ip_data['countryCode'] = 'UN'
                    results.append(ip_data)
                finally:
                    pbar.update(1)
    
    return results

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
    解析自定义IP文件，区分单个IP和IP段
    返回: (individual_ips, ip_subnets)
    """
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    individual_ips = set()
    ip_subnets = set()
    
    if not custom_file or not os.path.exists(custom_file):
        return individual_ips, ip_subnets
    
    print(f"🔧 读取自定义IP池文件: {custom_file}")
    try:
        with open(custom_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
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
        
        print(f"✅ 自定义IP池解析完成: {len(individual_ips)}个独立IP, {len(ip_subnets)}个IP段")
        
    except Exception as e:
        print(f"🚨 读取自定义IP池失败: {e}")
    
    return individual_ips, ip_subnets

def fetch_ip_ranges():
    """获取Cloudflare官方IP段"""
    url = CONFIG["CLOUDFLARE_IPS_URL"]
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
        base_ip = subnet.split('/')[0]
        parts = base_ip.split('.')
        while len(parts) < 4:
            parts.append(str(random.randint(0, 255)))
        parts = [str(min(255, max(0, int(p)))) for p in parts[:3]] + [str(random.randint(1, 254))]
        return ".".join(parts)

def generate_ip_pool():
    """
    生成IP池：先使用自定义IP段生成IP，再用Cloudflare官方IP段补足
    返回IP列表和每个IP的来源信息
    """
    # 解析自定义IP文件
    custom_individual_ips, custom_subnets = parse_custom_ips_file()
    
    # 获取Cloudflare官方IP段
    cf_subnets = fetch_ip_ranges()
    if not cf_subnets:
        print("❌ 无法获取Cloudflare IP段，程序终止")
        exit(1)
    
    print(f"✅ 获取到 {len(cf_subnets)} 个Cloudflare官方IP段")
    
    total_ip_pool_size = CONFIG["IP_POOL_SIZE"]
    test_ip_count = CONFIG["TEST_IP_COUNT"]
    
    # 计算自定义IP段和Cloudflare IP段的分配比例
    custom_total = len(custom_individual_ips) + len(custom_subnets) * 10  # 估算自定义IP数量
    cf_total = len(cf_subnets) * 50  # 估算Cloudflare IP数量
    
    if custom_total > 0:
        custom_ratio = min(0.7, custom_total / (custom_total + cf_total))  # 自定义IP最多占70%
    else:
        custom_ratio = 0
    
    custom_ip_count = int(total_ip_pool_size * custom_ratio)
    cf_ip_count = total_ip_pool_size - custom_ip_count
    
    print(f"📊 IP池分配: 自定义IP {custom_ip_count}个, Cloudflare IP {cf_ip_count}个")
    
    # 生成自定义IP池
    custom_ip_pool = []
    if custom_individual_ips:
        # 添加独立IP
        for ip in custom_individual_ips:
            custom_ip_pool.append({
                "ip": ip,
                "source": "CUSTOM"
            })
            custom_ip_sources[ip] = 'custom'
    
    if custom_subnets:
        print(f"🔧 从 {len(custom_subnets)} 个自定义IP段生成IP...")
        # 改进的IP生成逻辑 - 确保生成足够数量的IP
        remaining_custom_count = custom_ip_count - len(custom_ip_pool)
        if remaining_custom_count > 0:
            # 为每个CIDR分配大致相等的IP数量
            base_ips_per_cidr = max(1, remaining_custom_count // len(custom_subnets))
            extra_ips = remaining_custom_count % len(custom_subnets)
            
            for i, subnet in enumerate(list(custom_subnets)):
                if len(custom_ip_pool) >= custom_ip_count:
                    break
                
                # 计算这个CIDR要生成多少个IP
                ips_this_cidr = base_ips_per_cidr
                if i < extra_ips:
                    ips_this_cidr += 1
                
                # 为每个CIDR生成指定数量的IP
                for _ in range(ips_this_cidr):
                    if len(custom_ip_pool) >= custom_ip_count:
                        break
                    ip = generate_random_ip(subnet)
                    if ip not in [item["ip"] for item in custom_ip_pool]:
                        custom_ip_pool.append({
                            "ip": ip,
                            "source": "CUSTOM"
                        })
                        custom_ip_sources[ip] = 'custom'
    
    # 生成Cloudflare IP池
    cf_ip_pool = []
    print(f"🔧 从 {len(cf_subnets)} 个Cloudflare IP段生成IP...")
    with tqdm(total=cf_ip_count, desc="生成Cloudflare IP", unit="IP") as pbar:
        while len(cf_ip_pool) < cf_ip_count:
            subnet = random.choice(cf_subnets)
            ip = generate_random_ip(subnet)
            if ip not in [item["ip"] for item in cf_ip_pool] and ip not in [item["ip"] for item in custom_ip_pool]:
                cf_ip_pool.append({
                    "ip": ip,
                    "source": "CLOUDFLARE"
                })
                custom_ip_sources[ip] = 'cloudflare'
                pbar.update(1)
    
    # 合并IP池并标记来源
    full_ip_pool = custom_ip_pool + cf_ip_pool
    random.shuffle(full_ip_pool)
    
    print(f"✅ IP池生成完成: 总计 {len(full_ip_pool)} 个IP")
    print(f"   - 自定义来源: {len(custom_ip_pool)} 个IP")
    print(f"   - Cloudflare来源: {len(cf_ip_pool)} 个IP")
    
    # 抽样测试IP
    if test_ip_count > len(full_ip_pool):
        test_ip_count = len(full_ip_pool)
    
    test_ip_pool = random.sample(full_ip_pool, test_ip_count)
    print(f"🔧 随机选择 {len(test_ip_pool)} 个IP进行测试")
    
    return test_ip_pool

def ping_test(ip_info):
    """延迟测试入口 - 支持两种模式"""
    mode = CONFIG["MODE"]
    ip = ip_info["ip"]  # 从字典中获取IP
    
    if mode == "TCP":
        rtt, loss = tcp_ping(ip, CONFIG["PORT"])
    elif mode == "URL_TEST":
        # 使用智能URL测试
        rtt, loss, _ = smart_url_test(ip)
    else:
        rtt, loss = tcp_ping(ip, CONFIG["PORT"])
    
    return {
        "ip": ip,
        "rtt": rtt,
        "loss": loss,
        "source": ip_info["source"]
    }

def full_test(ip_data):
    """完整测试（延迟 + 速度）"""
    ip = ip_data["ip"]
    speed = speed_test(ip)
    return {
        "ip": ip_data["ip"],
        "rtt": ip_data["rtt"],
        "loss": ip_data["loss"],
        "speed": speed,
        "source": ip_data["source"]
    }

def enhance_ip_with_country_info(ip_list):
    """
    为IP列表添加真实的国家代码信息 - 使用批量查询
    """
    print("🌍 开始增强IP地理位置信息...")
    return batch_geo_lookup(ip_list)

####################################################
# 格式化输出函数 - 修改：添加国家名称
####################################################

def format_ip_output(ip_data, port=None):
    """
    输出 ip:端口#来源标志国旗 国家名称·国家简称 格式
    例如: 
    104.16.132.229:443#👋🇺🇸 美国·US  (Cloudflare官方IP)
    192.168.1.1:443#👏⭐ 中·国·CN      (自定义IP)
    """
    if port is None:
        port = CONFIG["PORT"]
    
    country_code = ip_data.get('countryCode', 'UN')
    
    # 获取国家信息
    country_info = CONFIG["COUNTRY_INFO"].get(country_code, CONFIG["COUNTRY_INFO"]['UN'])
    flag = country_info['flag']
    country_name = country_info['name']
    
    # 获取来源标志
    source = ip_data.get('source', 'CLOUDFLARE')
    source_flag = CONFIG["IP_TYPE_FLAGS"].get(source, '👋')
    
    # 格式：ip:端口#来源标志国旗 国家名称·国家简称
    return f"{ip_data['ip']}:{port}#{source_flag}{flag} {country_name}·{country_code}"

def format_ip_list_for_display(ip_list, port=None):
    """格式化IP列表用于显示（统一格式）"""
    if port is None:
        port = CONFIG["PORT"]
    
    formatted_ips = []
    for ip_data in ip_list:
        formatted_ips.append(format_ip_output(ip_data, port))
    
    return formatted_ips

def format_ip_list_for_file(ip_list, port=None):
    """格式化IP列表用于文件保存（统一格式）"""
    if port is None:
        port = CONFIG["PORT"]
    
    formatted_lines = []
    for ip_data in ip_list:
        formatted_lines.append(format_ip_output(ip_data, port))
    
    return formatted_lines

####################################################
# 新增：URL测试验证函数
####################################################

def validate_test_urls():
    """
    验证测试URL的可用性
    """
    print("🔍 验证测试URL可用性...")
    
    for test_url in CONFIG["BACKUP_TEST_URLS"]:
        try:
            start_time = time.time()
            response = requests.get(test_url, timeout=5, verify=False)
            rtt = (time.time() - start_time) * 1000
            
            if response.status_code < 500:
                print(f"✅ {test_url} - 可用 (延迟: {rtt:.1f}ms, 状态码: {response.status_code})")
                return test_url
            else:
                print(f"⚠️ {test_url} - 状态码 {response.status_code}")
        except Exception as e:
            print(f"❌ {test_url} - 错误: {e}")
    
    print("🚨 所有测试URL都不可用，使用默认URL")
    return CONFIG["BACKUP_TEST_URLS"][0]

####################################################
# 主逻辑
####################################################
if __name__ == "__main__":
    # 0. 初始化环境
    init_env()
    
    # 1. 验证并选择最佳测试URL
    best_url = validate_test_urls()
    CONFIG["URL_TEST_TARGET"] = best_url
    print(f"🎯 使用测试URL: {best_url}")
    
    # 2. 打印配置参数
    print("="*60)
    print(f"{'Cloudflare IP优选工具':^60}")
    print("="*60)
    print(f"测试模式: {CONFIG['MODE']}")
    print(f"输出格式: ip:端口#来源标志国旗 国家名称·国家简称")
    print(f"来源标志: 👏=自定义 👋=Cloudflare官方")
    print(f"地理位置API: 多API冗余 (提高成功率)")
    
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
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    if custom_file:
        print(f"自定义IP池: {custom_file}")
    else:
        print(f"Cloudflare IP源: {CONFIG['CLOUDFLARE_IPS_URL']}")
    print(f"测速URL: {CONFIG['SPEED_URL']}")
    print("="*60 + "\n")

    # 3. 生成IP池（先自定义后Cloudflare补量）
    test_ip_pool = generate_ip_pool()
    if not test_ip_pool:
        print("❌ 无法生成IP池，程序终止")
        exit(1)

    # 4. 第一阶段：延迟测试（筛选IP）
    ping_results = []
    mode_display = {
        "TCP": "🔌 TCP测试进度", 
        "URL_TEST": "🌐 URL测试进度"
    }
    progress_desc = mode_display.get(mode, "🚀 延迟测试进度")
    
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_ip = {executor.submit(ping_test, ip_info): ip_info for ip_info in test_ip_pool}
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
    
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    passed_ips = [
        ip_data for ip_data in ping_results
        if rtt_min <= ip_data["rtt"] <= rtt_max and ip_data["loss"] <= loss_max
    ]
    print(f"\n✅ 延迟测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips)}")

    # 5. 第二阶段：测速（仅对通过延迟测试的IP）
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

    # 6. 为IP添加真实国家代码信息 - 使用增强版
    enhanced_results = enhance_ip_with_country_info(full_results)

    # 统计地理查询成功率
    known_countries = len([ip for ip in enhanced_results if ip['countryCode'] != 'UN'])
    unknown_countries = len([ip for ip in enhanced_results if ip['countryCode'] == 'UN'])
    success_rate = (known_countries / len(enhanced_results)) * 100 if enhanced_results else 0
    
    print(f"📊 地理查询统计: 成功 {known_countries}, 未知 {unknown_countries}, 成功率 {success_rate:.1f}%")

    # 7. 按性能排序：精选IP（延迟升序，速度降序）
    sorted_ips = sorted(
        enhanced_results,
        key=lambda x: (x['rtt'], -x['speed'])  # 延迟升序，速度降序
    )

    print(f"✅ 性能排序完成: 按延迟升序、速度降序排列 {len(sorted_ips)} 个精选IP")

    # 8. 最佳IP：从精选IP中选取前TOP_IPS_LIMIT个
    top_limit = CONFIG["TOP_IPS_LIMIT"]
    best_ips = sorted_ips[:top_limit] if len(sorted_ips) > top_limit else sorted_ips

    print(f"🎯 最佳IP选择: 从{len(sorted_ips)}个精选IP中选取前{len(best_ips)}个作为最佳IP")
    
    # 9. 保存结果
    os.makedirs('results', exist_ok=True)

    # 保存全部精选IP（按性能排序的所有IP）
    with open('results/all_sorted_ips.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_ip_list_for_file(sorted_ips)
        f.write("\n".join(formatted_lines))
        print(f"💾 已保存 {len(formatted_lines)} 个精选IP到 all_sorted_ips.txt")

    # 保存最佳IP（前TOP_IPS_LIMIT个）
    with open('results/top_ips.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_ip_list_for_file(best_ips)
        f.write("\n".join(formatted_lines))
        print(f"💾 已保存 {len(formatted_lines)} 个最佳IP到 top_ips.txt")

    # 保存详细数据（全部精选IP）
    with open('results/ip_details.csv', 'w', encoding='utf-8') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),国家代码,国家名称,来源,排名\n")
        for i, ip_data in enumerate(sorted_ips, 1):
            country_info = CONFIG["COUNTRY_INFO"].get(ip_data['countryCode'], CONFIG["COUNTRY_INFO"]['UN'])
            country_name = country_info['name']
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['countryCode']},{country_name},{ip_data['source']},{i}\n")
        print(f"💾 已保存 {len(sorted_ips)} 个IP的详细数据到 ip_details.csv")

    # 10. 按来源和国家分组统计
    source_stats = {}
    country_stats = {}

    for ip_data in enhanced_results:
        source = ip_data['source']
        country = ip_data['countryCode']
        country_info = CONFIG["COUNTRY_INFO"].get(country, CONFIG["COUNTRY_INFO"]['UN'])
        country_name = country_info['name']
        
        # 来源统计
        if source not in source_stats:
            source_stats[source] = {'count': 0, 'avg_rtt': 0, 'avg_speed': 0}
        source_stats[source]['count'] += 1
        source_stats[source]['avg_rtt'] += ip_data['rtt']
        source_stats[source]['avg_speed'] += ip_data['speed']
        
        # 国家统计
        if country not in country_stats:
            country_stats[country] = {'count': 0, 'name': country_name, 'avg_rtt': 0, 'avg_speed': 0}
        country_stats[country]['count'] += 1
        country_stats[country]['avg_rtt'] += ip_data['rtt']
        country_stats[country]['avg_speed'] += ip_data['speed']

    # 计算平均值
    for stats in [source_stats, country_stats]:
        for key in stats:
            if stats[key]['count'] > 0:
                stats[key]['avg_rtt'] /= stats[key]['count']
                stats[key]['avg_speed'] /= stats[key]['count']

    # 11. 显示统计结果
    print("\n" + "="*60)
    print(f"{'🔥 测试结果统计':^60}")
    print("="*60)
    print(f"IP池大小: {CONFIG['IP_POOL_SIZE']}")
    print(f"实际测试IP数: {len(ping_results)}")
    print(f"通过延迟测试IP数: {len(enhanced_results)}")
    print(f"精选IP总数: {len(sorted_ips)}")
    print(f"最佳IP数量: {len(best_ips)} (前{top_limit}个)")
    print(f"地理查询成功率: {success_rate:.1f}%")

    print(f"\n📊 来源分布:")
    for source, stats in source_stats.items():
        source_name = "自定义" if source == "CUSTOM" else "Cloudflare官方"
        source_flag = "👏" if source == "CUSTOM" else "👋"
        print(f"  {source_flag} {source_name}: {stats['count']}个IP, 平均延迟{stats['avg_rtt']:.1f}ms, 平均速度{stats['avg_speed']:.1f}Mbps")

    print(f"\n🌍 国家分布:")
    for country, stats in sorted(country_stats.items(), key=lambda x: x[1]['count'], reverse=True):
        country_info = CONFIG["COUNTRY_INFO"].get(country, CONFIG["COUNTRY_INFO"]['UN'])
        flag = country_info['flag']
        name = stats['name']
        print(f"  {flag} {name}: {stats['count']}个IP, 平均延迟{stats['avg_rtt']:.1f}ms, 平均速度{stats['avg_speed']:.1f}Mbps")

    if best_ips:
        # 显示最佳IP（前20个或全部，取较小值）
        display_count = min(20, len(best_ips))
        
        print(f"\n🏆【最佳IP TOP{display_count} (共{len(best_ips)}个)】")
        formatted_best_ips = format_ip_list_for_display(best_ips[:display_count])
        for i, formatted_ip in enumerate(formatted_best_ips, 1):
            ip_data = best_ips[i-1]
            print(f"{i:2d}. {formatted_ip} (延迟:{ip_data['rtt']:.1f}ms, 速度:{ip_data['speed']:.1f}Mbps)")
        
        # 显示全部精选IP的分布（简要版）
        print(f"\n📋【精选IP分布 (共{len(sorted_ips)}个)】")
        print(f"  🥇 前10名: 延迟{min(ip['rtt'] for ip in sorted_ips[:10]):.1f}ms ~ {max(ip['rtt'] for ip in sorted_ips[:10]):.1f}ms")
        if len(sorted_ips) > 20:
            print(f"  🥈 前20名: 延迟{min(ip['rtt'] for ip in sorted_ips[:20]):.1f}ms ~ {max(ip['rtt'] for ip in sorted_ips[:20]):.1f}ms")
        if len(sorted_ips) > 50:
            print(f"  🥉 前50名: 延迟{min(ip['rtt'] for ip in sorted_ips[:50]):.1f}ms ~ {max(ip['rtt'] for ip in sorted_ips[:50]):.1f}ms")
        
        # 显示延迟分布
        delay_ranges = [
            (0, 50, "0-50ms"),
            (50, 100, "50-100ms"), 
            (100, 200, "100-200ms"),
            (200, 300, "200-300ms"),
            (300, float('inf'), "300ms+")
        ]
        
        print(f"\n⏱️ 【延迟分布】")
        for min_delay, max_delay, label in delay_ranges:
            count = len([ip for ip in sorted_ips if min_delay <= ip['rtt'] < max_delay])
            if count > 0:
                percentage = (count / len(sorted_ips)) * 100
                print(f"  {label}: {count}个IP ({percentage:.1f}%)")

    print("="*60)
    print("✅ 结果已保存至 results/ 目录")
    print("📊 文件说明:")
    print(f"   - all_sorted_ips.txt: 全部{len(sorted_ips)}个精选IP (按性能排序)")
    print(f"   - top_ips.txt: 前{len(best_ips)}个最佳IP")
    print(f"   - ip_details.csv: 详细性能数据和排名")
    print("="*60)
