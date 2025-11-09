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
    "URL_TEST_TIMEOUT": 5,  # URL测试超时(秒) - 为IPv6增加时间
    "URL_TEST_RETRY": 2,  # URL测试重试次数
    "PING_COUNT": 3,  # Ping次数 - 减少以加快测试
    "PING_TIMEOUT": 5,  # Ping超时(秒) - 为IPv6增加时间
    "PORT": 443,  # TCP测试端口
    "RTT_RANGE": "0~400",  # 延迟范围(ms)
    "LOSS_MAX": 2.0,  # 最大丢包率(%)
    "THREADS": 400,  # 并发线程数 - 减少以避免IPv6连接问题
    "IP_POOL_SIZE": 100000,  # IP池总大小
    "TEST_IP_COUNT": 1000,  # 实际测试IP数量 - 减少IPv6测试数量
    "TOP_IPS_LIMIT": 100,  # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CLOUDFLARE_IPS_V6_URL": "https://www.cloudflare.com/ips-v6",  # 新增IPv6 IP段URL
    "LOCAL_IP_POOL": True,  # 是否只使用本地IP池（True:只使用本地, False:使用URL）
    "LOCAL_IP_POOL_FILE": "Local-IPpool.txt",  # 本地IP池文件路径
    "ENABLE_IPV6": True,  # 是否启用IPv6测试 - 默认关闭，需要时手动开启
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 8,  # 测速超时时间 - 为IPv6增加时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=5000000",  # 测速URL - 减少数据量
    
    # IPv6专用测试URL（支持IPv6访问）
    "IPV6_TEST_URLS": [
        "http://ipv6.google.com/generate_204",
        "http://www.gstatic.com/generate_204",  # 这个也支持IPv6
        "http://cp.cloudflare.com/",
    ],
    
    # 备用测试URL列表
    "BACKUP_TEST_URLS": [
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/",
        "http://www.cloudflare.com/favicon.ico"
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
# IPv6专用工具函数
####################################################

def is_ipv6_address(ip_str):
    """检查是否为IPv6地址"""
    try:
        return ':' in ip_str and ipaddress.IPv6Address(ip_str)
    except:
        return False

def format_ipv6_for_url(ip):
    """格式化IPv6地址用于URL"""
    if is_ipv6_address(ip):
        return f"[{ip}]"
    return ip

def format_ipv6_for_socket(ip):
    """格式化IPv6地址用于socket连接"""
    if is_ipv6_address(ip):
        return ip
    return ip

def get_ipv6_test_url():
    """获取支持IPv6的测试URL"""
    for test_url in CONFIG["IPV6_TEST_URLS"]:
        try:
            # 简单的可用性检查
            response = requests.get(test_url, timeout=5, verify=False)
            if response.status_code < 500:
                return test_url
        except:
            continue
    return CONFIG["IPV6_TEST_URLS"][0]  # 回退到第一个

####################################################
# IP工具函数
####################################################

def is_valid_ip(ip_str):
    """检查是否为有效的IP地址"""
    try:
        ipaddress.ip_address(ip_str)
        return True
    except:
        return False

def is_valid_subnet(subnet_str):
    """检查是否为有效的IP段"""
    try:
        ipaddress.ip_network(subnet_str, strict=False)
        return True
    except:
        return False

def extract_ip_from_line(line):
    """从行中提取IP地址"""
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    
    # 移除注释部分
    if '#' in line:
        line = line.split('#')[0].strip()
    
    # 处理带端口的格式 ip:port
    if ':' in line:
        # 检查是否是IPv6地址（包含多个冒号）
        if line.count(':') >= 2:
            # 可能是IPv6地址，尝试解析
            if line.count(']') > 0:
                # IPv6带端口格式 [::1]:443
                parts = line.split(']')
                if len(parts) >= 1:
                    ip_part = parts[0].replace('[', '')
                    if is_valid_ip(ip_part):
                        return ip_part
            else:
                # 纯IPv6地址
                if is_valid_ip(line):
                    return line
        else:
            # IPv4带端口格式 1.1.1.1:443
            ip_part = line.split(':')[0]
            if is_valid_ip(ip_part):
                return ip_part
    else:
        # 纯IP格式
        if is_valid_ip(line):
            return line
    
    return None

def generate_ips_from_subnet(subnet, count=10):
    """从IP段生成指定数量的随机IP"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        ips = []
        
        # 计算可用的IP数量
        if network.num_addresses > 2:  # 排除网络地址和广播地址
            available_ips = list(network.hosts())
            if len(available_ips) > count:
                ips = random.sample(available_ips, count)
            else:
                ips = available_ips
        
        return [str(ip) for ip in ips]
    except:
        return []

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
    
    # 如果是IPv6地址，使用专门的IPv6查询或返回UN
    if is_ipv6_address(ip):
        # 尝试IPv6专用的地理位置查询
        try:
            # ipapi.co 支持IPv6
            response = requests.get(f'https://ipapi.co/{ip}/json/', 
                                  timeout=CONFIG["IP_GEO_API"]["timeout"], 
                                  verify=False)
            if response.status_code == 200:
                data = response.json()
                country_code = data.get('country_code')
                if country_code:
                    ip_geo_cache[ip] = country_code
                    return country_code
        except:
            pass
        return 'UN'  # IPv6直接返回未知
    
    # IPv4的查询逻辑保持不变
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
# URL测试函数 - 修复IPv6支持
####################################################

def url_test(ip, url=None, timeout=None, retry=None):
    """
    URL Test模式延迟检测 - 修复IPv6支持
    """
    if url is None:
        # 根据IP类型选择测试URL
        if is_ipv6_address(ip):
            url = get_ipv6_test_url()
        else:
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
                
                # 处理IPv6地址
                if is_ipv6_address(ip):
                    target_ip = f"[{ip}]"
                    # 对于IPv6，使用host参数而不是修改Host头
                    actual_hostname = ip
                else:
                    target_ip = ip
                    actual_hostname = hostname
                
                conn = http.client.HTTPSConnection(
                    target_ip, 
                    port=port, 
                    timeout=timeout,
                    context=context
                )
            else:
                # HTTP请求
                if is_ipv6_address(ip):
                    target_ip = f"[{ip}]"
                    actual_hostname = ip
                else:
                    target_ip = ip
                    actual_hostname = hostname
                
                conn = http.client.HTTPConnection(
                    target_ip,
                    port=port,
                    timeout=timeout
                )
            
            # 设置请求头 - 对于IPv6直接访问，不需要Host头
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Tester/1.0)',
                'Accept': '*/*',
                'Connection': 'close'
            }
            
            # 只有非直接IP访问时才添加Host头
            if actual_hostname != ip:
                headers['Host'] = actual_hostname
            
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
        except Exception as e:
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
    备选的requests库版本URL测试 - 修复IPv6支持
    """
    if url is None:
        if is_ipv6_address(ip):
            url = get_ipv6_test_url()
        else:
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
            if is_ipv6_address(ip):
                # IPv6地址
                if parsed_url.port:
                    actual_url = f"{parsed_url.scheme}://[{ip}]:{parsed_url.port}{parsed_url.path}"
                else:
                    actual_url = f"{parsed_url.scheme}://[{ip}]{parsed_url.path}"
                # 对于IPv6直接访问，不需要Host头
                headers = {
                    'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Tester/1.0)',
                    'Accept': '*/*'
                }
            else:
                # IPv4地址
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
                allow_redirects=False,  # 禁止重定向以避免问题
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
    # 对于IPv6，优先使用requests版本
    if is_ipv6_address(ip):
        return url_test_requests(ip, url, timeout, retry)
    else:
        # 先尝试http.client版本（更快）
        try:
            return url_test(ip, url, timeout, retry)
        except Exception:
            # 回退到requests版本
            return url_test_requests(ip, url, timeout, retry)

####################################################
# 其他测试函数 - 修复IPv6支持
####################################################

def custom_ping(ip):
    """自定义Ping测试 - 修复IPv6支持"""
    target = urlparse(CONFIG["PING_TARGET"]).netloc or CONFIG["PING_TARGET"]
    count = CONFIG["PING_COUNT"]
    timeout = CONFIG["PING_TIMEOUT"]
    
    try:
        if is_ipv6_address(ip):
            # IPv6 ping命令
            if os.name == 'nt':  # Windows
                cmd = f"ping -n {count} -w {timeout*1000} {target}"
            else:  # Linux/Mac
                cmd = f"ping6 -c {count} -W {timeout} {target}"
        else:
            # IPv4 ping命令
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
        return float('inf'), 100.0

def tcp_ping(ip, port, timeout=2):
    """TCP Ping测试 - 修复IPv6支持"""
    retry = CONFIG["TCP_RETRY"]
    success_count = 0
    total_rtt = 0
    
    # 处理IPv6地址
    if is_ipv6_address(ip):
        target_ip = format_ipv6_for_socket(ip)
        # 对于IPv6，增加超时时间
        timeout = max(timeout, 3)
    else:
        target_ip = ip
        
    for _ in range(retry):
        start = time.time()
        try:
            # 设置socket选项以支持IPv6
            if is_ipv6_address(ip):
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_ip, port))
            rtt = (time.time() - start) * 1000
            total_rtt += rtt
            success_count += 1
            sock.close()
        except:
            pass
        time.sleep(0.1)
    
    loss_rate = 100 - (success_count / retry * 100)
    avg_rtt = total_rtt / success_count if success_count > 0 else float('inf')
    return avg_rtt, loss_rate

def speed_test(ip):
    """速度测试 - 修复IPv6支持"""
    url = CONFIG["SPEED_URL"]
    timeout = CONFIG["SPEED_TIMEOUT"]
    
    # 对于IPv6，减少测试数据量
    if is_ipv6_address(ip):
        url = url.replace('10000000', '2000000')  # 减少到2MB
        timeout = max(timeout, 8)  # 增加超时时间
    
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        
        # 处理IPv6地址
        if is_ipv6_address(ip):
            actual_url = f"https://[{ip}]{parsed_url.path}"
            headers = {'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Tester/1.0)'}
        else:
            actual_url = f"https://{ip}{parsed_url.path}"
            headers = {'Host': host, 'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Tester/1.0)'}
            
        start_time = time.time()
        response = requests.get(
            actual_url, headers=headers, timeout=timeout, verify=False, stream=True
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
# 清理本地IP池功能
####################################################

def clean_local_ip_pool():
    """
    清除本地IP池中的重复IP和延迟测试未通过的IP
    不生成任何备份和报告文件
    """
    local_file = CONFIG["LOCAL_IP_POOL_FILE"]
    
    if not os.path.exists(local_file):
        print(f"❌ 未找到本地IP池文件: {local_file}")
        return
    
    print(f"🔍 开始清理本地IP池文件: {local_file}")
    
    # 读取原始文件内容
    with open(local_file, 'r', encoding='utf-8') as f:
        original_lines = f.readlines()
    
    # 提取所有IP（保留原始行结构用于注释）
    ip_to_line = {}
    unique_ips = set()
    duplicate_count = 0
    
    for line in original_lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
            
        ip = extract_ip_from_line(line)
        if ip:
            if ip in unique_ips:
                duplicate_count += 1
                continue
            unique_ips.add(ip)
            ip_to_line[ip] = line
    
    print(f"📊 分析完成: 总IP数 {len(unique_ips)}, 重复IP {duplicate_count}个")
    
    if not unique_ips:
        print("❌ 未找到有效IP，清理终止")
        return
    
    # 测试IP的延迟
    print("🚀 开始延迟测试筛选IP...")
    test_results = []
    
    # 减少线程数以避免IPv6连接问题
    threads = min(CONFIG["THREADS"], 50)
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ip = {executor.submit(ping_test, ip): ip for ip in unique_ips}
        with tqdm(total=len(unique_ips), desc="延迟测试", unit="IP") as pbar:
            for future in as_completed(future_to_ip):
                try:
                    test_results.append(future.result())
                except Exception:
                    pass
                finally:
                    pbar.update(1)
    
    # 筛选符合延迟要求的IP
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    
    passed_ips = [
        ip_data for ip_data in test_results
        if rtt_min <= ip_data[1] <= rtt_max and ip_data[2] <= loss_max
    ]
    
    print(f"✅ 延迟测试完成: 总数 {len(test_results)}, 通过 {len(passed_ips)}")
    
    if not passed_ips:
        print("❌ 没有IP通过延迟测试，清理终止")
        return
    
    # 构建新的IP列表（保留原始格式）
    cleaned_ips = []
    passed_ip_set = {ip_data[0] for ip_data in passed_ips}
    
    for ip, original_line in ip_to_line.items():
        if ip in passed_ip_set:
            cleaned_ips.append(original_line)
    
    # 直接覆盖原文件
    with open(local_file, 'w', encoding='utf-8') as f:
        # 写入文件头注释
        f.write(f"# 清理时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# 原始IP数: {len(unique_ips)}, 清理后: {len(cleaned_ips)}\n")
        f.write(f"# 延迟范围: {CONFIG['RTT_RANGE']}ms, 最大丢包: {CONFIG['LOSS_MAX']}%\n")
        f.write(f"# 重复IP已移除: {duplicate_count}个\n")
        f.write(f"# 未通过延迟测试: {len(unique_ips) - len(cleaned_ips)}个\n\n")
        
        # 写入清理后的IP
        for line in cleaned_ips:
            f.write(line + '\n')
    
    print(f"🎉 清理完成!")
    print(f"✅ 原始IP数: {len(unique_ips)}")
    print(f"✅ 清理后IP数: {len(cleaned_ips)}")
    print(f"✅ 移除重复IP: {duplicate_count}个")
    print(f"✅ 移除无效IP: {len(unique_ips) - len(cleaned_ips)}个")
    print(f"💾 结果已保存到: {local_file}")

####################################################
# 核心功能函数
####################################################

def init_env():
    """初始化环境"""
    for key, value in CONFIG.items():
        os.environ[key] = str(value)

def analyze_local_ip_pool():
    """
    分析本地IP池文件，识别IPv4/IPv6 IP段和IP列表
    """
    local_file = CONFIG["LOCAL_IP_POOL_FILE"]
    if not os.path.exists(local_file):
        print(f"❌ 未找到本地IP池文件: {local_file}")
        return [], [], [], []
    
    print(f"🔍 分析本地IP池文件: {local_file}")
    
    ipv4_ips = []
    ipv6_ips = []
    ipv4_subnets = []
    ipv6_subnets = []
    
    try:
        with open(local_file, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # 尝试提取IP
            ip = extract_ip_from_line(line)
            if ip:
                if is_ipv6_address(ip):
                    ipv6_ips.append(ip)
                else:
                    ipv4_ips.append(ip)
                continue
            
            # 尝试识别IP段
            if '/' in line:
                subnet_part = line.split('#')[0].strip() if '#' in line else line
                try:
                    network = ipaddress.ip_network(subnet_part, strict=False)
                    if network.version == 4:
                        ipv4_subnets.append(str(network))
                    else:
                        ipv6_subnets.append(str(network))
                except:
                    # 不是有效的IP段
                    pass
        
        print(f"✅ 分析完成:")
        print(f"   IPv4单IP: {len(ipv4_ips)} 个")
        print(f"   IPv6单IP: {len(ipv6_ips)} 个") 
        print(f"   IPv4网段: {len(ipv4_subnets)} 个")
        print(f"   IPv6网段: {len(ipv6_subnets)} 个")
        
        return ipv4_ips, ipv6_ips, ipv4_subnets, ipv6_subnets
        
    except Exception as e:
        print(f"🚨 分析本地IP池文件失败: {e}")
        return [], [], [], []

def generate_ips_from_local_pool():
    """
    从本地IP池生成测试IP列表
    """
    ipv4_ips, ipv6_ips, ipv4_subnets, ipv6_subnets = analyze_local_ip_pool()
    
    all_ips = []
    
    # 添加单IP
    all_ips.extend(ipv4_ips)
    if CONFIG["ENABLE_IPV6"]:
        all_ips.extend(ipv6_ips)
    
    # 从IPv4网段生成IP
    ipv4_from_subnets = []
    for subnet in ipv4_subnets:
        ips = generate_ips_from_subnet(subnet, 3)  # 每个网段生成3个IP
        ipv4_from_subnets.extend(ips)
    
    all_ips.extend(ipv4_from_subnets)
    
    # 从IPv6网段生成IP（如果启用）
    if CONFIG["ENABLE_IPV6"]:
        ipv6_from_subnets = []
        for subnet in ipv6_subnets:
            ips = generate_ips_from_subnet(subnet, 2)  # 每个IPv6网段生成2个IP
            ipv6_from_subnets.extend(ips)
        all_ips.extend(ipv6_from_subnets)
    
    # 去重
    unique_ips = list(set(all_ips))
    
    print(f"📊 生成的测试IP统计:")
    print(f"   IPv4单IP: {len(ipv4_ips)} 个")
    print(f"   IPv6单IP: {len(ipv6_ips)} 个")
    print(f"   IPv4网段生成: {len(ipv4_from_subnets)} 个")
    if CONFIG["ENABLE_IPV6"]:
        print(f"   IPv6网段生成: {len(ipv6_from_subnets)} 个")
    print(f"   总计唯一IP: {len(unique_ips)} 个")
    
    return unique_ips

def fetch_cloudflare_ip_ranges():
    """
    从Cloudflare URL获取IP段
    """
    urls = [CONFIG["CLOUDFLARE_IPS_URL"]]
    if CONFIG["ENABLE_IPV6"]:
        urls.append(CONFIG["CLOUDFLARE_IPS_V6_URL"])
    
    all_subnets = []
    for url in urls:
        try:
            print(f"🌐 从Cloudflare获取IP段: {url}")
            res = requests.get(url, timeout=10, verify=False)
            if res.status_code == 200:
                subnets = res.text.splitlines()
                subnets = [subnet.strip() for subnet in subnets if subnet.strip()]
                print(f"✅ 从Cloudflare获取到 {len(subnets)} 个IP段")
                all_subnets.extend(subnets)
            else:
                print(f"❌ Cloudflare返回状态码: {res.status_code}")
        except Exception as e:
            print(f"🚨 获取Cloudflare IP段失败: {e}")
    
    return all_subnets

def generate_random_ip(subnet):
    """根据CIDR生成子网内的随机合法IP"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        if network.version == 6:
            # IPv6生成策略
            network_addr = int(network.network_address)
            broadcast_addr = int(network.broadcast_address)
            # 对于IPv6，生成更少的IP
            random_ip_int = random.randint(network_addr, broadcast_addr)
            return str(ipaddress.IPv6Address(random_ip_int))
        else:
            # IPv4生成策略
            network_addr = int(network.network_address)
            broadcast_addr = int(network.broadcast_address)
            first_ip = network_addr + 1
            last_ip = broadcast_addr - 1
            random_ip_int = random.randint(first_ip, last_ip)
            return str(ipaddress.IPv4Address(random_ip_int))
    except Exception as e:
        # 备用生成方法
        if ':' in subnet:  # IPv6
            return "2001:db8::1"  # 示例IPv6
        else:  # IPv4
            base_ip = subnet.split('/')[0]
            parts = base_ip.split('.')
            while len(parts) < 4:
                parts.append(str(random.randint(0, 255)))
            parts = [str(min(255, max(0, int(p)))) for p in parts[:3]] + [str(random.randint(1, 254))]
            return ".".join(parts)

def generate_cloudflare_ip_pool():
    """
    生成Cloudflare IP池
    """
    subnets = fetch_cloudflare_ip_ranges()
    if not subnets:
        return []
    
    ip_pool_size = CONFIG["IP_POOL_SIZE"]
    full_ip_pool = set()
    
    print(f"🔧 正在生成 {ip_pool_size} 个Cloudflare随机IP...")
    
    # 分离IPv4和IPv6子网
    ipv4_subnets = [s for s in subnets if ':' not in s]
    ipv6_subnets = [s for s in subnets if ':' in s]
    
    with tqdm(total=ip_pool_size, desc="生成Cloudflare IP", unit="IP") as pbar:
        while len(full_ip_pool) < ip_pool_size:
            # 根据配置决定生成IPv4还是IPv6
            if CONFIG["ENABLE_IPV6"] and ipv6_subnets and random.random() < 0.3:  # 30%概率生成IPv6
                subnet = random.choice(ipv6_subnets)
            else:
                subnet = random.choice(ipv4_subnets)
            
            ip = generate_random_ip(subnet)
            if ip not in full_ip_pool:
                full_ip_pool.add(ip)
                pbar.update(1)
    
    ip_list = list(full_ip_pool)
    print(f"✅ 成功生成 {len(ip_list)} 个Cloudflare随机IP")
    return ip_list

def get_test_ip_pool():
    """
    根据配置获取测试IP池
    """
    if CONFIG["LOCAL_IP_POOL"]:
        # 使用本地IP池
        ip_list = generate_ips_from_local_pool()
        if not ip_list:
            print("❌ 无法从本地IP池生成IP列表，程序终止")
            exit(1)
        
        # 如果IP数量超过测试数量，随机选择
        test_ip_count = min(CONFIG["TEST_IP_COUNT"], len(ip_list))
        if len(ip_list) > test_ip_count:
            test_ips = random.sample(ip_list, test_ip_count)
            print(f"🔧 从本地IP池随机选择 {test_ip_count} 个IP进行测试")
        else:
            test_ips = ip_list
            print(f"🔧 使用全部 {len(ip_list)} 个本地IP进行测试")
        
        return test_ips
    else:
        # 使用Cloudflare IP池
        ip_list = generate_cloudflare_ip_pool()
        if not ip_list:
            print("❌ 无法生成Cloudflare IP池，程序终止")
            exit(1)
        
        test_ip_count = min(CONFIG["TEST_IP_COUNT"], len(ip_list))
        test_ips = random.sample(ip_list, test_ip_count)
        print(f"🔧 从Cloudflare IP池选择 {test_ip_count} 个IP进行测试")
        
        return test_ips

def ping_test(ip):
    """延迟测试入口 - 支持三种模式"""
    mode = CONFIG["MODE"]
    
    if mode == "PING":
        rtt, loss = custom_ping(ip)
    elif mode == "TCP":
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
    """
    enhanced_ips = []
    
    print("🌍 正在检测IP真实地理位置...")
    
    # 对于IPv6，减少并发数
    threads = min(CONFIG["THREADS"], 20) if any(is_ipv6_address(ip_data[0]) for ip_data in ip_list) else CONFIG["THREADS"]
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_ip = {}
        for ip_data in ip_list:
            ip = ip_data[0]
            future = executor.submit(get_real_ip_country_code, ip)
            future_to_ip[future] = ip_data
        
        with tqdm(total=len(ip_list), desc="IP地理位置", unit="IP") as pbar:
            for future in as_completed(future_to_ip):
                ip_data = future_to_ip[future]
                try:
                    country_code = future.result()
                    ip = ip_data[0]
                    rtt = ip_data[1]
                    loss = ip_data[2]
                    speed = ip_data[3] if len(ip_data) > 3 else 0
                    
                    enhanced_ip = {
                        'ip': ip,
                        'rtt': rtt,
                        'loss': loss,
                        'speed': speed,
                        'countryCode': country_code,
                        'isp': "Cloudflare",
                        'is_ipv6': is_ipv6_address(ip)
                    }
                    enhanced_ips.append(enhanced_ip)
                except Exception:
                    # 如果查询失败，使用默认值
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
                        'is_ipv6': is_ipv6_address(ip)
                    }
                    enhanced_ips.append(enhanced_ip)
                finally:
                    pbar.update(1)
    
    return enhanced_ips

####################################################
# 格式化输出函数 - 统一为 'ip:端口#国旗 国家简称' 格式
####################################################

def format_ip_output(ip_data, port=None):
    """
    输出 ip:端口#国旗 国家简称 格式
    """
    if port is None:
        port = CONFIG["PORT"]
    
    country_code = ip_data.get('countryCode', 'UN')
    flag = CONFIG["COUNTRY_FLAGS"].get(country_code, '🏴')
    
    ip = ip_data['ip']
    # 如果是IPv6且包含方括号，移除方括号
    if ip.startswith('[') and ip.endswith(']'):
        ip = ip[1:-1]
    
    return f"{ip}:{port}#{flag} {country_code}"

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
# 新增：URL测试验证函数
####################################################

def validate_test_urls():
    """
    验证测试URL的可用性
    """
    print("🔍 验证测试URL可用性...")
    
    # 测试IPv4 URL
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
    import sys
    
    # 检查是否要执行清理功能
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean_local_ip_pool()
        sys.exit(0)
    
    # 0. 初始化环境
    init_env()
    
    # 检查IPv6支持并给出警告
    if CONFIG["ENABLE_IPV6"]:
        print("⚠️  IPv6支持已开启，请注意:")
        print("   - 测试速度可能较慢")
        print("   - 部分网络环境可能不支持IPv6")
        print("   - 如果卡住，请使用 Ctrl+C 中断并关闭IPv6支持")
        print("   - 建议首次使用时设置 TEST_IP_COUNT = 50 进行小规模测试")
        print()
    
    # 1. 验证并选择最佳测试URL
    best_url = validate_test_urls()
    CONFIG["URL_TEST_TARGET"] = best_url
    print(f"🎯 使用测试URL: {best_url}")
    
    # 2. 打印配置参数
    print("="*60)
    print(f"{'Cloudflare IP优选工具':^60}")
    print("="*60)
    print(f"测试模式: {CONFIG['MODE']}")
    print(f"输出格式: ip:端口#国旗 国家简称")
    print(f"地理位置API: 启用")
    print(f"本地IP池: {'开启' if CONFIG['LOCAL_IP_POOL'] else '关闭'}")
    print(f"IPv6支持: {'开启' if CONFIG['ENABLE_IPV6'] else '关闭'}")
    
    mode = CONFIG["MODE"]
    if mode == "PING":
        print(f"Ping目标: {CONFIG['PING_TARGET']}")
        print(f"Ping次数: {CONFIG['PING_COUNT']}")
        print(f"Ping超时: {CONFIG['PING_TIMEOUT']}秒")
    elif mode == "TCP":
        print(f"TCP端口: {CONFIG['PORT']}")
        print(f"TCP重试: {CONFIG['TCP_RETRY']}次")
    elif mode == "URL_TEST":
        print(f"URL测试目标: {CONFIG['URL_TEST_TARGET']}")
        print(f"URL测试超时: {CONFIG['URL_TEST_TIMEOUT']}秒")
        print(f"URL测试重试: {CONFIG['URL_TEST_RETRY']}次")
    
    print(f"延迟范围: {CONFIG['RTT_RANGE']}ms")
    print(f"最大丢包: {CONFIG['LOSS_MAX']}%")
    print(f"并发线程: {CONFIG['THREADS']}")
    print(f"测试IP数: {CONFIG['TEST_IP_COUNT']}")
    
    if CONFIG["LOCAL_IP_POOL"]:
        print(f"IP源: 本地IP池 ({CONFIG['LOCAL_IP_POOL_FILE']})")
    else:
        print(f"IP源: Cloudflare URL ({CONFIG['CLOUDFLARE_IPS_URL']})")
        print(f"IP池大小: {CONFIG['IP_POOL_SIZE']}")
    
    print(f"测速URL: {CONFIG['SPEED_URL']}")
    print("="*60)
    print("💡 提示: 使用 'python cf_ip_tester.py clean' 清理本地IP池")
    print("="*60 + "\n")

    # 3. 获取测试IP池
    test_ip_pool = get_test_ip_pool()
    print(f"🔧 最终测试IP数量: {len(test_ip_pool)}")

    # 统计IPv4/IPv6数量
    ipv4_count = sum(1 for ip in test_ip_pool if not is_ipv6_address(ip))
    ipv6_count = sum(1 for ip in test_ip_pool if is_ipv6_address(ip))
    print(f"📊 IP类型统计: IPv4: {ipv4_count}个, IPv6: {ipv6_count}个")

    # 4. 第一阶段：延迟测试（筛选IP）
    ping_results = []
    mode_display = {
        "PING": "🚀 Ping测试进度",
        "TCP": "🔌 TCP测试进度", 
        "URL_TEST": "🌐 URL测试进度"
    }
    progress_desc = mode_display.get(mode, "🚀 延迟测试进度")
    
    # 根据IPv6情况调整线程数
    threads = CONFIG["THREADS"]
    if ipv6_count > 0:
        threads = min(threads, 50)  # IPv6测试减少线程数
        print("🔧 检测到IPv6地址，已自动降低并发线程数")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
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
    
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    passed_ips = [
        ip_data for ip_data in ping_results
        if rtt_min <= ip_data[1] <= rtt_max and ip_data[2] <= loss_max
    ]
    print(f"\n✅ 延迟测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips)}")

    # 5. 第二阶段：测速（仅对通过延迟测试的IP）
    if not passed_ips:
        print("❌ 没有通过延迟测试的IP，程序终止")
        exit(1)
    
    full_results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
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

    # 6. 为IP添加真实国家代码信息
    enhanced_results = enhance_ip_with_country_info(full_results)

    # 7. 按性能排序
    sorted_ips = sorted(
        enhanced_results,
        key=lambda x: (-x['speed'], x['rtt'])
    )[:CONFIG["TOP_IPS_LIMIT"]]

    # 8. 保存结果（统一格式）
    os.makedirs('results', exist_ok=True)
    
    with open('results/all_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in ping_results]))
    
    with open('results/passed_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in passed_ips]))
    
    with open('results/full_results.csv', 'w') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),国家代码,ISP,来源,IP类型\n")
        for ip_data in enhanced_results:
            source = "本地IP池" if CONFIG["LOCAL_IP_POOL"] else "Cloudflare"
            ip_type = "IPv6" if ip_data.get('is_ipv6') else "IPv4"
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['countryCode']},{ip_data['isp']},{source},{ip_type}\n")
    
    # 所有输出文件都使用统一格式
    with open('results/top_ips.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_ip_list_for_file(sorted_ips)
        f.write("\n".join(formatted_lines))
    
    with open('results/top_ips_details.csv', 'w', encoding='utf-8') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),国家代码,ISP,来源,IP类型\n")
        for ip_data in sorted_ips:
            source = "本地IP池" if CONFIG["LOCAL_IP_POOL"] else "Cloudflare"
            ip_type = "IPv6" if ip_data.get('is_ipv6') else "IPv4"
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['countryCode']},{ip_data['isp']},{source},{ip_type}\n")

    # 9. 按国家分组统计
    country_stats = {}
    ip_type_stats = {'IPv4': 0, 'IPv6': 0}
    
    for ip_data in enhanced_results:
        country = ip_data['countryCode']
        ip_type = "IPv6" if ip_data.get('is_ipv6') else "IPv4"
        
        if country not in country_stats:
            country_stats[country] = {
                'count': 0,
                'ipv4_count': 0,
                'ipv6_count': 0,
                'avg_rtt': 0,
                'avg_speed': 0
            }
        
        country_stats[country]['count'] += 1
        if ip_type == "IPv4":
            country_stats[country]['ipv4_count'] += 1
            ip_type_stats['IPv4'] += 1
        else:
            country_stats[country]['ipv6_count'] += 1
            ip_type_stats['IPv6'] += 1
            
        country_stats[country]['avg_rtt'] += ip_data['rtt']
        country_stats[country]['avg_speed'] += ip_data['speed']
    
    for country in country_stats:
        if country_stats[country]['count'] > 0:
            country_stats[country]['avg_rtt'] /= country_stats[country]['count']
            country_stats[country]['avg_speed'] /= country_stats[country]['count']

    with open('results/country_stats.csv', 'w', encoding='utf-8') as f:
        f.write("国家代码,IP数量,IPv4数量,IPv6数量,平均延迟(ms),平均速度(Mbps),来源\n")
        for country, stats in country_stats.items():
            source = "本地IP池" if CONFIG["LOCAL_IP_POOL"] else "Cloudflare"
            f.write(f"{country},{stats['count']},{stats['ipv4_count']},{stats['ipv6_count']},{stats['avg_rtt']:.2f},{stats['avg_speed']:.2f},{source}\n")

    # 10. 显示统计结果
    print("\n" + "="*60)
    print(f"{'🔥 测试结果统计':^60}")
    print("="*60)
    print(f"实际测试IP数: {len(ping_results)}")
    print(f"通过延迟测试IP数: {len(passed_ips)}")
    print(f"测速IP数: {len(enhanced_results)}")
    print(f"精选TOP IP: {len(sorted_ips)}")
    print(f"IP来源: {'本地IP池' if CONFIG['LOCAL_IP_POOL'] else 'Cloudflare URL'}")
    print(f"IP类型分布: IPv4: {ip_type_stats['IPv4']}个, IPv6: {ip_type_stats['IPv6']}个")
    
    if not CONFIG["LOCAL_IP_POOL"]:
        print(f"IP池大小: {CONFIG['IP_POOL_SIZE']}")
    
    print(f"\n🌍 国家分布 (基于真实地理位置API):")
    for country, stats in sorted(country_stats.items(), key=lambda x: x[1]['count'], reverse=True):
        flag = CONFIG["COUNTRY_FLAGS"].get(country, '🏴')
        ip_type_info = f" (IPv4:{stats['ipv4_count']}, IPv6:{stats['ipv6_count']})" if stats['ipv6_count'] > 0 else ""
        print(f"  {flag} {country}: {stats['count']}个IP{ip_type_info}, 平均延迟{stats['avg_rtt']:.1f}ms, 平均速度{stats['avg_speed']:.1f}Mbps")
    
    if sorted_ips:
        print(f"\n🏆【最佳IP TOP10】")
        formatted_top_ips = format_ip_list_for_display(sorted_ips[:10])
        for i, formatted_ip in enumerate(formatted_top_ips, 1):
            ip_data = sorted_ips[i-1]
            ip_type = " [IPv6]" if ip_data.get('is_ipv6') else ""
            print(f"{i:2d}. {formatted_ip}{ip_type} (延迟:{ip_data['rtt']:.1f}ms, 速度:{ip_data['speed']:.1f}Mbps)")
        
        print(f"\n📋【全部精选IP】")
        formatted_all_ips = format_ip_list_for_display(sorted_ips)
        for i in range(0, len(formatted_all_ips), 2):
            line_ips = formatted_all_ips[i:i+2]
            print("  " + "  ".join(line_ips))
    
    print("="*60)
    print("✅ 结果已保存至 results/ 目录")
    print("📊 文件说明:")
    print("   - top_ips.txt: 精选IP列表 (ip:端口#国旗 国家简称)")
    print("   - top_ips_details.csv: 详细性能数据")
    print("   - country_stats.csv: 国家统计信息")
    print("="*60)
