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
    "PING_TARGET": "https://www.gstatic.com/generate_204",  # Ping测试目标
    "URL_TEST_TARGET": "https://www.gstatic.com/generate_204",  # URL测试目标
    "URL_TEST_TIMEOUT": 3,  # URL测试超时(秒)
    "URL_TEST_RETRY": 2,  # URL测试重试次数
    "PING_COUNT": 5,  # Ping次数
    "PING_TIMEOUT": 3,  # Ping超时(秒)
    "PORT": 443,  # TCP测试端口
    "RTT_RANGE": "0~400",  # 延迟范围(ms)
    "LOSS_MAX": 2.0,  # 最大丢包率(%)
    "THREADS": 300,  # 并发线程数
    "IP_POOL_SIZE": 100000,  # IP池总大小
    "TEST_IP_COUNT": 1000,  # 实际测试IP数量
    "TOP_IPS_LIMIT": 100,  # 最佳IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    
    # 备用测试URL列表
    "BACKUP_TEST_URLS": [
        "https://www.gstatic.com/generate_204",
        "https://cp.cloudflare.com/",
        "https://www.cloudflare.com/favicon.ico"
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
    
    # IP类型标志
    "IP_TYPE_FLAGS": {
        "CUSTOM": "👏",    # 自定义IP
        "CLOUDFLARE": "👋" # Cloudflare官方IP
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

def custom_ping(ip):
    """自定义Ping测试"""
    target = urlparse(CONFIG["PING_TARGET"]).netloc or CONFIG["PING_TARGET"]
    count = CONFIG["PING_COUNT"]
    timeout = CONFIG["PING_TIMEOUT"]
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
    解析自定义IP文件，支持多种格式：
    - CIDR格式: 192.168.0.0/24
    - 单个IPv4: 192.168.1.1
    - 单个IPv6: 2001:db8::1
    - 反代域名: example.com
    """
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    if not custom_file or not os.path.exists(custom_file):
        return {
            "cidr_ranges": [],
            "single_ips": [],
            "domains": []
        }
    
    cidr_ranges = []
    single_ips = []
    domains = []
    
    print(f"🔧 解析自定义IP文件: {custom_file}")
    
    try:
        with open(custom_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # 检测CIDR格式
                if '/' in line:
                    try:
                        network = ipaddress.ip_network(line, strict=False)
                        cidr_ranges.append(str(network))
                        continue
                    except ValueError:
                        pass
                
                # 检测IPv4地址
                try:
                    ipaddress.IPv4Address(line)
                    single_ips.append(line)
                    continue
                except ipaddress.AddressValueError:
                    pass
                
                # 检测IPv6地址
                try:
                    ipaddress.IPv6Address(line)
                    single_ips.append(line)
                    continue
                except ipaddress.AddressValueError:
                    pass
                
                # 剩下的认为是域名
                domains.append(line)
        
        print(f"✅ 自定义IP文件解析完成:")
        print(f"   - CIDR段: {len(cidr_ranges)} 个")
        print(f"   - 单个IP: {len(single_ips)} 个") 
        print(f"   - 域名: {len(domains)} 个")
        
    except Exception as e:
        print(f"🚨 读取自定义IP文件失败: {e}")
    
    return {
        "cidr_ranges": cidr_ranges,
        "single_ips": single_ips,
        "domains": domains
    }

def generate_ips_from_custom_pool(custom_data, target_count):
    """
    从自定义IP池生成IP地址
    """
    generated_ips = set()
    
    # 1. 首先添加所有单个IP
    for ip in custom_data["single_ips"]:
        if len(generated_ips) < target_count:
            generated_ips.add(ip)
    
    # 2. 从CIDR段生成IP - 改进逻辑
    cidr_ranges = custom_data["cidr_ranges"]
    if cidr_ranges and len(generated_ips) < target_count:
        # 计算还需要生成多少IP
        remaining_count = target_count - len(generated_ips)
        
        # 为每个CIDR分配大致相等的IP数量
        base_ips_per_cidr = max(1, remaining_count // len(cidr_ranges))
        extra_ips = remaining_count % len(cidr_ranges)
        
        print(f"🔧 从 {len(cidr_ranges)} 个CIDR段生成IP，每个段生成 {base_ips_per_cidr}-{base_ips_per_cidr+1} 个IP")
        
        for i, cidr in enumerate(cidr_ranges):
            if len(generated_ips) >= target_count:
                break
            try:
                # 计算这个CIDR要生成多少个IP
                ips_this_cidr = base_ips_per_cidr
                if i < extra_ips:
                    ips_this_cidr += 1
                
                network = ipaddress.ip_network(cidr, strict=False)
                available_ips = network.num_addresses - 2  # 减去网络地址和广播地址
                
                # 如果CIDR太小，调整生成数量
                if available_ips < ips_this_cidr:
                    ips_this_cidr = max(1, available_ips)
                
                # 为每个CIDR生成指定数量的IP
                for _ in range(ips_this_cidr):
                    if len(generated_ips) >= target_count:
                        break
                    ip = generate_random_ip(cidr)
                    if ip not in generated_ips:
                        generated_ips.add(ip)
                    else:
                        # 如果IP重复，重试
                        attempts = 0
                        while len(generated_ips) < target_count and attempts < 10:
                            ip = generate_random_ip(cidr)
                            if ip not in generated_ips:
                                generated_ips.add(ip)
                                break
                            attempts += 1
            except Exception as e:
                print(f"⚠️ 从CIDR {cidr} 生成IP失败: {e}")
    
    # 3. 如果还不够，随机从CIDR中继续生成
    if len(generated_ips) < target_count and cidr_ranges:
        print(f"🔧 补充生成 {target_count - len(generated_ips)} 个IP...")
        while len(generated_ips) < target_count:
            cidr = random.choice(cidr_ranges)
            ip = generate_random_ip(cidr)
            generated_ips.add(ip)
    
    # 4. 解析域名（可选，需要网络请求）
    domains = custom_data["domains"]
    if domains and len(generated_ips) < target_count:
        print("🔍 解析自定义域名...")
        for domain in domains:
            if len(generated_ips) >= target_count:
                break
            try:
                # 解析域名获取IP
                ips = socket.getaddrinfo(domain, None)
                for result in ips:
                    ip = result[4][0]
                    if len(generated_ips) < target_count:
                        generated_ips.add(ip)
                    else:
                        break
            except Exception as e:
                print(f"⚠️ 解析域名 {domain} 失败: {e}")
    
    print(f"✅ 自定义IP生成完成: {len(generated_ips)}/{target_count} 个IP")
    return list(generated_ips)

def generate_complete_ip_pool():
    """
    生成完整的IP池：先自定义IP，再Cloudflare官方IP补量
    """
    total_pool_size = CONFIG["IP_POOL_SIZE"]
    test_ip_count = CONFIG["TEST_IP_COUNT"]
    
    # 1. 解析自定义IP文件
    custom_data = parse_custom_ips_file()
    
    # 计算自定义IP的目标数量（占总数的30%）
    custom_target_count = min(total_pool_size // 3, test_ip_count // 3)
    
    # 2. 生成自定义IP
    custom_ips = []
    if custom_data["cidr_ranges"] or custom_data["single_ips"] or custom_data["domains"]:
        print(f"🎯 生成自定义IP池 ({custom_target_count}个)...")
        custom_ips = generate_ips_from_custom_pool(custom_data, custom_target_count)
        print(f"✅ 生成 {len(custom_ips)} 个自定义IP")
    else:
        print("ℹ️ 未找到自定义IP，全部使用Cloudflare官方IP")
    
    # 3. 计算需要补充的Cloudflare IP数量
    remaining_count = total_pool_size - len(custom_ips)
    
    # 4. 获取Cloudflare官方IP段
    cloudflare_ips = []
    if remaining_count > 0:
        print(f"🔧 从Cloudflare官方IP段补量生成 {remaining_count} 个IP...")
        cloudflare_subnets = fetch_cloudflare_ip_ranges()
        if cloudflare_subnets:
            cloudflare_ips = generate_cloudflare_ips(cloudflare_subnets, remaining_count)
            print(f"✅ 生成 {len(cloudflare_ips)} 个Cloudflare官方IP")
    
    # 5. 合并IP池并标记来源
    all_ips = []
    
    # 标记自定义IP
    for ip in custom_ips:
        all_ips.append({
            "ip": ip,
            "source": "CUSTOM",
            "type": get_ip_type(ip)
        })
    
    # 标记Cloudflare官方IP
    for ip in cloudflare_ips:
        all_ips.append({
            "ip": ip,
            "source": "CLOUDFLARE", 
            "type": get_ip_type(ip)
        })
    
    print(f"🎉 IP池构建完成: 总计 {len(all_ips)} 个IP")
    print(f"   - 自定义IP: {len(custom_ips)} 个")
    print(f"   - Cloudflare官方IP: {len(cloudflare_ips)} 个")
    
    return all_ips

def get_ip_type(ip):
    """获取IP类型"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version == 4:
            return "IPv4"
        elif ip_obj.version == 6:
            return "IPv6"
    except:
        return "Unknown"
    return "Unknown"

def fetch_cloudflare_ip_ranges():
    """获取Cloudflare官方IP段"""
    url = CONFIG["CLOUDFLARE_IPS_URL"]
    try:
        res = requests.get(url, timeout=10, verify=False)
        return res.text.splitlines()
    except Exception as e:
        print(f"🚨 获取Cloudflare IP段失败: {e}")
    return []

def generate_cloudflare_ips(subnets, target_count):
    """从Cloudflare IP段生成IP"""
    generated_ips = set()
    
    with tqdm(total=target_count, desc="生成Cloudflare IP", unit="IP") as pbar:
        while len(generated_ips) < target_count:
            subnet = random.choice(subnets)
            ip = generate_random_ip(subnet)
            if ip not in generated_ips:
                generated_ips.add(ip)
                pbar.update(1)
    
    return list(generated_ips)

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
    with tqdm(total=len(ip_list), desc="IP地理位置", unit="IP") as pbar:
        for ip_data in ip_list:
            # 修正这里：ip_data现在是字典，不是元组
            ip = ip_data['ip']  # 原来是 ip_data[0]
            rtt = ip_data['rtt']
            loss = ip_data['loss']
            speed = ip_data.get('speed', 0)  # 使用get避免KeyError
            
            country_code = get_real_ip_country_code(ip)
            
            enhanced_ip = {
                'ip': ip,
                'rtt': rtt,
                'loss': loss,
                'speed': speed,
                'countryCode': country_code,
                'source': ip_data.get('source', 'CLOUDFLARE'),
                'type': ip_data.get('type', 'Unknown'),
                'isp': "Cloudflare"
            }
            enhanced_ips.append(enhanced_ip)
            pbar.update(1)
    
    return enhanced_ips

####################################################
# 格式化输出函数 - 统一为 'ip:端口#来源标志国旗 国家简称' 格式
####################################################

def format_ip_output(ip_data, port=None):
    """
    输出 ip:端口#来源标志国旗 国家简称 格式
    例如: 
    104.16.132.229:443#👋🇺🇸 US  (Cloudflare官方IP)
    192.168.1.1:443#👏🇨🇳 CN      (自定义IP)
    """
    if port is None:
        port = CONFIG["PORT"]
    
    country_code = ip_data.get('countryCode', 'UN')
    flag = CONFIG["COUNTRY_FLAGS"].get(country_code, '🏴')
    
    # 获取来源标志
    source = ip_data.get('source', 'CLOUDFLARE')
    source_flag = CONFIG["IP_TYPE_FLAGS"].get(source, '👋')
    
    return f"{ip_data['ip']}:{port}#{source_flag}{flag} {country_code}"

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
    print(f"输出格式: ip:端口#来源标志国旗 国家简称")
    print(f"来源标志: 👏=自定义 👋=Cloudflare官方")
    print(f"地理位置API: 启用")
    
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
    print(f"IP池大小: {CONFIG['IP_POOL_SIZE']}")
    print(f"测试IP数: {CONFIG['TEST_IP_COUNT']}")
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    if custom_file:
        print(f"自定义IP池: {custom_file}")
    else:
        print(f"Cloudflare IP源: {CONFIG['CLOUDFLARE_IPS_URL']}")
    print(f"测速URL: {CONFIG['SPEED_URL']}")
    print("="*60 + "\n")

    # 3. 生成完整的IP池（先自定义，后Cloudflare补量）
    print("🔧 构建IP池策略: 先自定义IP，后Cloudflare官方IP补量")
    complete_ip_pool = generate_complete_ip_pool()
    
    if not complete_ip_pool:
        print("❌ 无法生成IP池，程序终止")
        exit(1)
    
    # 提取纯IP列表用于测试
    test_ip_count = CONFIG["TEST_IP_COUNT"]
    if test_ip_count > len(complete_ip_pool):
        test_ip_count = len(complete_ip_pool)
    
    test_ip_pool = random.sample(complete_ip_pool, test_ip_count)
    pure_ip_list = [item["ip"] for item in test_ip_pool]
    
    print(f"🔧 从完整IP池中随机选择 {len(test_ip_pool)} 个IP进行测试")
    
    # 4. 第一阶段：延迟测试（筛选IP）
    ping_results = []
    mode_display = {
        "PING": "🚀 Ping测试进度",
        "TCP": "🔌 TCP测试进度", 
        "URL_TEST": "🌐 URL测试进度"
    }
    progress_desc = mode_display.get(mode, "🚀 延迟测试进度")
    
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_ip = {executor.submit(ping_test, ip): ip for ip in pure_ip_list}
        with tqdm(
            total=len(pure_ip_list),
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
    
    # 5. 重建IP数据（包含来源信息）
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    
    passed_ips_data = []
    for ip_data in ping_results:
        ip, rtt, loss = ip_data
        # 找到对应的源信息
        source_info = next((item for item in test_ip_pool if item["ip"] == ip), None)
        if source_info and rtt_min <= rtt <= rtt_max and loss <= loss_max:
            passed_ips_data.append({
                "ip": ip,
                "rtt": rtt,
                "loss": loss,
                "source": source_info.get("source", "CLOUDFLARE"),
                "type": source_info.get("type", "Unknown")
            })
    
    print(f"\n✅ 延迟测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips_data)}")
    
    # 6. 第二阶段：测速
    if not passed_ips_data:
        print("❌ 没有通过延迟测试的IP，程序终止")
        exit(1)
    
    # 测速
    full_results = []
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_ip = {executor.submit(speed_test, ip_data["ip"]): ip_data for ip_data in passed_ips_data}
        with tqdm(
            total=len(passed_ips_data),
            desc="📊 测速进度",
            unit="IP",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_ip):
                try:
                    ip_data = future_to_ip[future]
                    speed = future.result()
                    full_results.append({
                        "ip": ip_data["ip"],
                        "rtt": ip_data["rtt"],
                        "loss": ip_data["loss"],
                        "speed": speed,
                        "source": ip_data["source"],
                        "type": ip_data["type"]
                    })
                except Exception as e:
                    print(f"\n🔧 测速异常: {e}")
                finally:
                    pbar.update(1)
    
    # 7. 为IP添加真实国家代码信息
    enhanced_results = enhance_ip_with_country_info(full_results)
    
    # 8. 按性能排序：精选IP（延迟升序，速度降序）
    sorted_ips = sorted(
        enhanced_results,
        key=lambda x: (x['rtt'], -x['speed'])  # 延迟升序，速度降序
    )

    print(f"✅ 性能排序完成: 按延迟升序、速度降序排列 {len(sorted_ips)} 个精选IP")

    # 9. 最佳IP：从精选IP中选取前TOP_IPS_LIMIT个
    top_limit = CONFIG["TOP_IPS_LIMIT"]
    best_ips = sorted_ips[:top_limit] if len(sorted_ips) > top_limit else sorted_ips

    print(f"🎯 最佳IP选择: 从{len(sorted_ips)}个精选IP中选取前{len(best_ips)}个作为最佳IP")
    
    # 10. 保存结果
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
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),国家代码,来源,类型,排名\n")
        for i, ip_data in enumerate(sorted_ips, 1):
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['countryCode']},{ip_data['source']},{ip_data['type']},{i}\n")
        print(f"💾 已保存 {len(sorted_ips)} 个IP的详细数据到 ip_details.csv")

    # 11. 按来源和国家分组统计
    source_stats = {}
    country_stats = {}

    for ip_data in enhanced_results:
        source = ip_data['source']
        country = ip_data['countryCode']
        
        # 来源统计
        if source not in source_stats:
            source_stats[source] = {'count': 0, 'avg_rtt': 0, 'avg_speed': 0}
        source_stats[source]['count'] += 1
        source_stats[source]['avg_rtt'] += ip_data['rtt']
        source_stats[source]['avg_speed'] += ip_data['speed']
        
        # 国家统计
        if country not in country_stats:
            country_stats[country] = {'count': 0, 'avg_rtt': 0, 'avg_speed': 0}
        country_stats[country]['count'] += 1
        country_stats[country]['avg_rtt'] += ip_data['rtt']
        country_stats[country]['avg_speed'] += ip_data['speed']

    # 计算平均值
    for stats in [source_stats, country_stats]:
        for key in stats:
            if stats[key]['count'] > 0:
                stats[key]['avg_rtt'] /= stats[key]['count']
                stats[key]['avg_speed'] /= stats[key]['count']

    # 12. 显示统计结果
    print("\n" + "="*60)
    print(f"{'🔥 测试结果统计':^60}")
    print("="*60)
    print(f"IP池大小: {len(complete_ip_pool)}")
    print(f"实际测试IP数: {len(ping_results)}")
    print(f"通过延迟测试IP数: {len(enhanced_results)}")
    print(f"精选IP总数: {len(sorted_ips)}")
    print(f"最佳IP数量: {len(best_ips)} (前{top_limit}个)")

    print(f"\n📊 来源分布:")
    for source, stats in source_stats.items():
        source_name = "自定义" if source == "CUSTOM" else "Cloudflare官方"
        source_flag = "👏" if source == "CUSTOM" else "👋"
        print(f"  {source_flag} {source_name}: {stats['count']}个IP, 平均延迟{stats['avg_rtt']:.1f}ms, 平均速度{stats['avg_speed']:.1f}Mbps")

    print(f"\n🌍 国家分布:")
    for country, stats in sorted(country_stats.items(), key=lambda x: x[1]['count'], reverse=True):
        flag = CONFIG["COUNTRY_FLAGS"].get(country, '🏴')
        print(f"  {flag} {country}: {stats['count']}个IP, 平均延迟{stats['avg_rtt']:.1f}ms, 平均速度{stats['avg_speed']:.1f}Mbps")

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
