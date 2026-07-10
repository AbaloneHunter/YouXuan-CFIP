import os
import sys
import io
import requests
import random
import time
import socket
import ssl
import http.client
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from tqdm import tqdm
import urllib3
import ipaddress

# 强制设置标准输出编码为 UTF-8
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

####################################################
# 配置参数
####################################################
CONFIG = {
    "VERSION": "2.7",               # 版本号
    "MODE": "TCP",                   # 测试模式：TCP / URL_TEST

    # === 延迟测试参数 ===
    "PORT": 443,                     # TCP测试端口
    "TCP_RETRY": 4,                  # 每个IP测延迟次数，取平均（XIU2默认4）
    "TCP_TIMEOUT": 2,                # TCP连接超时(秒)
    "RTT_MAX": 200,                  # 最大延迟(ms)，超过则丢弃（XIU2默认200ms）
    "LOSS_MAX": 30.0,                # 最大丢包率(%)（XIU2默认30%）
    "THREADS": 50,                  # 并发线程数

    # === 速度测试参数 ===
    "SPEED_MIN": 5.0,                # 期望最低速度，0=不过滤；设10表示≥10Mbps才保留
    "SPEED_TEST_BYTES": 10485760,    # 测速下载量(字节)，默认10MB
    "SPEED_TIMEOUT": 10,             # 测速超时(秒)

    # === IP池参数 ===
    "IP_POOL_SIZE": 20000,           # IP大池总大小
    "TEST_IP_COUNT": 5000,           # 实际测试IP数量
    "TOP_IPS_LIMIT": 300,            # 最终输出TOP数量
    # ★ 中文配置，逗号分隔，可选：自定义域名和IP,自定义IP段,官方CloudflareIP段
    "IP_POOL_SOURCES": "自定义域名和IP,自定义IP段",

    # === Cloudflare 官方IP段 ===
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CLOUDFLARE_IPS_V6_URL": "https://www.cloudflare.com/ips-v6",
    "CUSTOM_IPS_FILE": "custom_ips.txt",

    # === URL下载镜像（GitHub等链接自动加国内前缀）===
    "URL_DOWNLOAD_TIMEOUT": 15,
    "URL_DOWNLOAD_MAX_RETRIES": 2,
    "URL_MIRROR_PREFIXES": [
        "https://gh-proxy.com/"
    ],
    "URL_MIRROR_KEYWORDS": [
        "github.com", "raw.githubusercontent.com",
        "gist.github.com", "objects.githubusercontent.com",
        "codeload.github.com",
    ],

    # === 延迟测试URL（MODE=URL_TEST时使用）===
    "URL_TEST_TARGET": "http://www.gstatic.com/generate_204",
    "URL_TEST_TIMEOUT": 3,
    "URL_TEST_RETRY": 3,

    # === 国家/地区 国旗映射 ===
    "COUNTRY_FLAGS": {
        'CN': '❣️', 'TW': '❣️', 'US': '🇺🇸', 'SG': '🇸🇬', 'JP': '🇯🇵', 'HK': '🇭🇰', 'KR': '🇰🇷',
        'DE': '🇩🇪', 'GB': '🇬🇧', 'FR': '🇫🇷', 'CA': '🇨🇦', 'AU': '🇦🇺', 'NL': '🇳🇱', 'SE': '🇸🇪',
        'FI': '🇫🇮', 'NO': '🇳🇴', 'DK': '🇩🇰', 'CH': '🇨🇭', 'IT': '🇮🇹', 'ES': '🇪🇸', 'PT': '🇵🇹',
        'BE': '🇧🇪', 'AT': '🇦🇹', 'IE': '🇮🇪', 'PL': '🇵🇱', 'CZ': '🇨🇿', 'HU': '🇭🇺', 'RO': '🇷🇴',
        'BG': '🇧🇬', 'GR': '🇬🇷', 'TR': '🇹🇷', 'RU': '🇷🇺', 'UA': '🇺🇦', 'IL': '🇮🇱', 'AE': '🇦🇪',
        'SA': '🇸🇦', 'IN': '🇮🇳', 'TH': '🇹🇭', 'MY': '🇲🇾', 'ID': '🇮🇩', 'VN': '🇻🇳', 'PH': '🇵🇭',
        'BR': '🇧🇷', 'MX': '🇲🇽', 'AR': '🇦🇷', 'CL': '🇨🇱', 'CO': '🇨🇴', 'ZA': '🇿🇦', 'EG': '🇪🇬',
        'NG': '🇳🇬', 'KE': '🇰🇪', 'UN': '🏴'
    },

    # === 国家/地区 中文名称映射 ===
    "COUNTRY_NAMES": {
        'CN': '中·国', 'TW': '台·湾', 'US': '美国', 'SG': '新加坡', 'JP': '日本', 'HK': '香港', 'KR': '韩国',
        'DE': '德国', 'GB': '英国', 'FR': '法国', 'CA': '加拿大', 'AU': '澳大利亚', 'NL': '荷兰', 'SE': '瑞典',
        'FI': '芬兰', 'NO': '挪威', 'DK': '丹麦', 'CH': '瑞士', 'IT': '意大利', 'ES': '西班牙', 'PT': '葡萄牙',
        'BE': '比利时', 'AT': '奥地利', 'IE': '爱尔兰', 'PL': '波兰', 'CZ': '捷克', 'HU': '匈牙利', 'RO': '罗马尼亚',
        'BG': '保加利亚', 'GR': '希腊', 'TR': '土耳其', 'RU': '俄罗斯', 'UA': '乌克兰', 'IL': '以色列', 'AE': '阿联酋',
        'SA': '沙特', 'IN': '印度', 'TH': '泰国', 'MY': '马来西亚', 'ID': '印度尼西亚', 'VN': '越南', 'PH': '菲律宾',
        'BR': '巴西', 'MX': '墨西哥', 'AR': '阿根廷', 'CL': '智利', 'CO': '哥伦比亚', 'ZA': '南非', 'EG': '埃及',
        'NG': '尼日利亚', 'KE': '肯尼亚', 'UN': '未知'
    },

    # === IP地理位置API ===
    "IP_GEO_API": {"timeout": 3, "retry": 2, "enable_cache": True}
}

# IP来源中文名称到编号的映射
IP_SOURCE_MAP = {
    "自定义域名和IP": "1",
    "自定义IP段": "2",
    "官方CloudflareIP段": "3",
}

# 全局缓存
ip_geo_cache = {}
custom_ip_comments = {}
preformatted_targets = {}


####################################################
# 辅助函数
####################################################

def is_ipv6(host):
    """检测是否为IPv6地址"""
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False

def is_ip_address(host):
    """检测是否为IP地址"""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

def is_url(line):
    """检测是否为URL"""
    return line.startswith('http://') or line.startswith('https://')

def needs_mirror(url):
    """检查URL是否需要添加镜像前缀"""
    keywords = CONFIG.get("URL_MIRROR_KEYWORDS", [])
    url_lower = url.lower()
    return any(kw in url_lower for kw in keywords)

def build_mirror_urls(original_url):
    """生成要尝试的URL列表（原始URL + 镜像URL）"""
    urls_to_try = [original_url]
    if not needs_mirror(original_url):
        return urls_to_try
    for prefix in CONFIG.get("URL_MIRROR_PREFIXES", []):
        urls_to_try.append(prefix + original_url)
    return urls_to_try

def parse_target_with_port(target_str, default_port=None):
    """解析目标字符串，支持自定义端口，兼容IPv4/IPv6/域名"""
    if default_port is None:
        default_port = CONFIG["PORT"]

    if target_str.startswith('['):
        bracket_end = target_str.find(']')
        if bracket_end != -1:
            host = target_str[1:bracket_end]
            rest = target_str[bracket_end + 1:]
            if rest.startswith(':'):
                try:
                    port = int(rest[1:])
                    return host, port, f"[{host}]:{port}"
                except ValueError:
                    pass
            return host, default_port, f"[{host}]:{default_port}"

    if ':' in target_str:
        colon_count = target_str.count(':')
        if colon_count >= 2:
            try:
                ipaddress.ip_address(target_str)
                return target_str, default_port, f"[{target_str}]:{default_port}"
            except ValueError:
                pass
        if colon_count == 1:
            parts = target_str.rsplit(':', 1)
            host = parts[0]
            try:
                port = int(parts[1])
                if is_ipv6(host):
                    return host, port, f"[{host}]:{port}"
                return host, port, f"{host}:{port}"
            except ValueError:
                pass

    if is_ipv6(target_str):
        return target_str, default_port, f"[{target_str}]:{default_port}"
    return target_str, default_port, f"{target_str}:{default_port}"

def is_preformatted_target(line):
    """检测是否为已格式化的目标（包含#和国旗）"""
    return '#' in line and any(flag in line for flag in CONFIG["COUNTRY_FLAGS"].values())

def parse_preformatted_target(line):
    """解析已格式化的目标"""
    try:
        target_part, country_part = line.split('#', 1)
        target_part = target_part.strip()
        host, port, target = parse_target_with_port(target_part)

        country_code = 'UN'
        for code, flag in CONFIG["COUNTRY_FLAGS"].items():
            if flag in country_part:
                country_code = code
                break

        comment = ''
        for code, name in CONFIG["COUNTRY_NAMES"].items():
            if name in country_part:
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
        host, port, target = parse_target_with_port(content)
        return target, comment
    except Exception as e:
        print(f"解析简单目标失败: {line}, 错误: {e}")
        return None, ''

def extract_host(target):
    """从target中提取host"""
    if '[' in target:
        return target.split(']')[0].split('[')[-1]
    else:
        return target.rsplit(':', 1)[0]

def get_enabled_sources():
    """解析IP_POOL_SOURCES配置，支持中文和数字"""
    raw = CONFIG["IP_POOL_SOURCES"]
    sources = [s.strip() for s in raw.split(',') if s.strip()]
    enabled = set()
    for s in sources:
        if s in IP_SOURCE_MAP:
            enabled.add(IP_SOURCE_MAP[s])
        elif s in ('1', '2', '3'):
            enabled.add(s)
        else:
            print(f"  ⚠ 未知的IP池来源: {s}")
    return enabled

def get_source_display_name():
    """获取IP池来源的中文显示名称"""
    enabled = get_enabled_sources()
    names = []
    if '1' in enabled:
        names.append("自定义域名和IP")
    if '2' in enabled:
        names.append("自定义IP段")
    if '3' in enabled:
        names.append("官方CloudflareIP段")
    return " + ".join(names) if names else "无"


####################################################
# URL下载函数
####################################################

def download_url_content(url):
    """下载URL内容，返回文本行列表，自动尝试镜像前缀"""
    max_retries = CONFIG["URL_DOWNLOAD_MAX_RETRIES"]
    timeout = CONFIG["URL_DOWNLOAD_TIMEOUT"]
    urls_to_try = build_mirror_urls(url)

    for try_url in urls_to_try:
        source_label = "原始" if try_url == url else f"镜像({urlparse(try_url).hostname})"
        for attempt in range(max_retries):
            try:
                response = requests.get(try_url, timeout=timeout, verify=False)
                if response.status_code == 200:
                    lines = response.text.splitlines()
                    print(f"  ✓ [{source_label}] 下载成功: {try_url} ({len(lines)}行)")
                    return lines
                else:
                    print(f"  ✗ [{source_label}] HTTP {response.status_code} (尝试 {attempt+1}/{max_retries}): {try_url}")
            except Exception as e:
                print(f"  ✗ [{source_label}] {str(e)[:60]} (尝试 {attempt+1}/{max_retries}): {try_url}")

    print(f"  ✗ 所有源均下载失败: {url}")
    return []

def parse_downloaded_lines(lines):
    """解析下载的行列表，返回分类结果"""
    domains = []
    individual_ips = set()
    ip_subnets = set()

    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if is_url(line):
            nested_lines = download_url_content(line)
            if nested_lines:
                d, i, s = parse_downloaded_lines(nested_lines)
                domains.extend(d)
                individual_ips.update(i)
                ip_subnets.update(s)
            continue
        if is_preformatted_target(line):
            continue

        target, comment = parse_simple_target(line)
        if not target:
            continue

        host = extract_host(target)

        if any(c.isalpha() for c in host) and '.' in host and not is_ipv6(host):
            domains.append(f"{host}:{CONFIG['PORT']}")
            continue
        try:
            ipaddress.ip_address(host)
            individual_ips.add(target)
            continue
        except ValueError:
            pass
        try:
            network = ipaddress.ip_network(host, strict=False)
            ip_subnets.add(str(network))
        except ValueError:
            pass

    return domains, individual_ips, ip_subnets


####################################################
# IP地理位置查询
####################################################

def get_real_ip_country_code(host):
    """查询IP/域名的国家代码"""
    if CONFIG["IP_GEO_API"]["enable_cache"] and host in ip_geo_cache:
        return ip_geo_cache[host]

    ip_to_query = host
    try:
        ipaddress.ip_address(host)
    except ValueError:
        try:
            ip_to_query = socket.gethostbyname(host)
        except Exception:
            return 'UN'

    apis = [
        {'url': f'http://ip-api.com/json/{ip_to_query}?fields=status,message,countryCode',
         'field': 'countryCode', 'check_field': 'status', 'check_value': 'success'},
        {'url': f'https://ipinfo.io/{ip_to_query}/json',
         'field': 'country', 'check_field': 'country', 'check_value': None},
        {'url': f'https://api.ip.sb/geoip/{ip_to_query}',
         'field': 'country_code', 'check_field': 'country_code', 'check_value': None}
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
                    if CONFIG["IP_GEO_API"]["enable_cache"]:
                        ip_geo_cache[host] = country_code
                    return country_code
        except Exception:
            continue
    return 'UN'


####################################################
# 延迟测试（借鉴XIU2：纯TCP连接测延迟）
####################################################

def tcp_latency_test(target):
    """纯TCP连接测延迟，多次取平均，计算丢包率"""
    retry = CONFIG["TCP_RETRY"]
    timeout = CONFIG["TCP_TIMEOUT"]
    host, port, _ = parse_target_with_port(target)

    rtts = []
    success = 0

    for _ in range(retry):
        start = time.time()
        try:
            if is_ipv6(host):
                sock = socket.create_connection((host, port, 0, socket.AF_INET6), timeout=timeout)
            else:
                sock = socket.create_connection((host, port), timeout=timeout)
            rtt = (time.time() - start) * 1000
            rtts.append(rtt)
            success += 1
            sock.close()
        except Exception:
            pass

    if success == 0:
        return (target, float('inf'), float('inf'), 100.0)

    avg_rtt = sum(rtts) / len(rtts)
    min_rtt = min(rtts)
    loss_rate = ((retry - success) / retry) * 100
    return (target, avg_rtt, min_rtt, loss_rate)

def url_latency_test(target):
    """URL测试模式延迟检测"""
    url = CONFIG["URL_TEST_TARGET"]
    timeout = CONFIG["URL_TEST_TIMEOUT"]
    retry = CONFIG["URL_TEST_RETRY"]
    host, port, _ = parse_target_with_port(target)
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme.lower()
    hostname = parsed_url.hostname
    path = parsed_url.path or '/'

    rtts = []
    success = 0

    for _ in range(retry):
        try:
            start_time = time.time()
            if scheme == 'https':
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port=port, timeout=timeout, context=context)
            else:
                conn = http.client.HTTPConnection(host, port=port, timeout=timeout)

            headers = {'Host': hostname, 'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Tester/2.2)',
                       'Accept': '*/*', 'Connection': 'close'}
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            response.read()
            rtt = (time.time() - start_time) * 1000

            if response.status < 500:
                rtts.append(rtt)
                success += 1
            conn.close()
        except Exception:
            pass

    if success == 0:
        return (target, float('inf'), float('inf'), 100.0)

    avg_rtt = sum(rtts) / len(rtts)
    min_rtt = min(rtts)
    loss_rate = ((retry - success) / retry) * 100
    return (target, avg_rtt, min_rtt, loss_rate)

def latency_test(target):
    """延迟测试入口"""
    if CONFIG["MODE"] == "URL_TEST":
        return url_latency_test(target)
    else:
        return tcp_latency_test(target)


####################################################
# 速度测试（★双轨制测速：原生接口优先，失败降级域名直连）
####################################################

def cf_speed_test(test_host, port, download_bytes, timeout):
    """使用 speed.cloudflare.com 接口测速"""
    path = f"/__down?bytes={download_bytes}&measId=0"
    ssl_sock = None
    try:
        if is_ipv6(test_host):
            sock = socket.create_connection((test_host, port, 0, socket.AF_INET6), timeout=timeout)
        else:
            sock = socket.create_connection((test_host, port), timeout=timeout)

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ssl_sock = context.wrap_socket(sock, server_hostname='speed.cloudflare.com')
        ssl_sock.settimeout(timeout)

        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: speed.cloudflare.com\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; CF-SpeedTest/2.7)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        ssl_sock.sendall(request.encode())

        response_data = b""
        while b"\r\n\r\n" not in response_data:
            chunk = ssl_sock.recv(65536)
            if not chunk:
                break
            response_data += chunk

        header_end = response_data.find(b"\r\n\r\n")
        if header_end == -1:
            return 0.0

        headers_str = response_data[:header_end].decode('utf-8', errors='replace')
        body = response_data[header_end + 4:]

        status_line = headers_str.split('\r\n')[0]
        if '200' not in status_line:
            return 0.0

        start_time = time.time()
        total_bytes = len(body)

        while True:
            try:
                chunk = ssl_sock.recv(65536)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if time.time() - start_time > timeout:
                    break
            except socket.timeout:
                break
            except Exception:
                break

        duration = time.time() - start_time
        if duration > 0 and total_bytes > 0:
            return (total_bytes * 8 / duration) / 1e6
        return 0.0
    except Exception:
        return 0.0
    finally:
        if ssl_sock:
            try:
                ssl_sock.close()
            except:
                pass

def domain_fallback_speed_test(host, port, timeout):
    """
    降级测速：使用域名自身的 SNI 和 Host 请求根目录估算速度。
    适用于封锁了 speed.cloudflare.com 的 SNI 的 IP。
    """
    ssl_sock = None
    try:
        if is_ipv6(host):
            sock = socket.create_connection((host, port, 0, socket.AF_INET6), timeout=timeout)
        else:
            sock = socket.create_connection((host, port), timeout=timeout)

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.settimeout(timeout)

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: Mozilla/5.0 (compatible; CF-SpeedTest/2.7)\r\n"
            f"Accept: */*\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        ssl_sock.sendall(request.encode())

        response_data = b""
        while b"\r\n\r\n" not in response_data:
            chunk = ssl_sock.recv(65536)
            if not chunk:
                break
            response_data += chunk

        header_end = response_data.find(b"\r\n\r\n")
        if header_end == -1:
            return 0.0

        headers_str = response_data[:header_end].decode('utf-8', errors='replace')
        body = response_data[header_end + 4:]

        status_line = headers_str.split('\r\n')[0]
        if '200' not in status_line:
            return 0.0

        start_time = time.time()
        total_bytes = len(body)
        max_bytes = 2 * 1024 * 1024  # 降级测速最多下载2MB

        while total_bytes < max_bytes:
            try:
                chunk = ssl_sock.recv(65536)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if time.time() - start_time > timeout:
                    break
            except socket.timeout:
                break
            except Exception:
                break

        duration = time.time() - start_time
        # 至少下载了 100KB 才算有效，否则可能是空页面
        if duration > 0 and total_bytes > 100000:
            return (total_bytes * 8 / duration) / 1e6
        return 0.0
    except Exception:
        return 0.0
    finally:
        if ssl_sock:
            try:
                ssl_sock.close()
            except:
                pass

def speed_test(target):
    """
    速度测试入口：如果是域名，先解析真实IP用原生接口测，失败则降级用域名直连测。
    """
    download_bytes = CONFIG["SPEED_TEST_BYTES"]
    timeout = CONFIG["SPEED_TIMEOUT"]
    host, port, _ = parse_target_with_port(target)

    test_host = host
    is_domain = not is_ip_address(host)

    if is_domain:
        try:
            # 优先尝试解析 IPv4，避免本地 IPv6 网络不通导致失败
            addrs = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            if not addrs:
                addrs = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
            if not addrs:
                return 0.0
            test_host = addrs[0][4][0]
        except Exception:
            return 0.0

    # 1. 尝试使用 speed.cloudflare.com 接口测速
    speed = cf_speed_test(test_host, port, download_bytes, timeout)
    if speed > 0:
        return speed

    # 2. 如果是域名且上述测速失败，降级为使用域名自身 SNI 请求根目录测速
    if is_domain:
        return domain_fallback_speed_test(host, port, timeout)
    
    return 0.0


####################################################
# IP池生成
####################################################

def init_env():
    """初始化环境变量"""
    for key, value in CONFIG.items():
        os.environ[key] = str(value)

def parse_custom_ips_file():
    """解析自定义IP文件"""
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    domains = set()
    individual_ips = set()
    ip_subnets = set()
    preformatted = set()
    url_count = 0

    if not os.path.exists(custom_file):
        print(f"自定义IP文件 {custom_file} 不存在，已自动创建模板文件。")
        with open(custom_file, 'w', encoding='utf-8') as f:
            f.write("# ===== Cloudflare IP优选 自定义IP池 =====\n")
            f.write("# 每行一个目标，支持以下格式：\n")
            f.write("#\n")
            f.write("# 1. IPv4 地址:        1.1.1.1\n")
            f.write("# 2. IPv4 地址+端口:  1.1.1.1:8443\n")
            f.write("# 3. IPv4 网段:       104.16.0.0/12\n")
            f.write("# 4. IPv6 地址:       2606:4700::1111\n")
            f.write("# 5. IPv6 地址+端口: [2606:4700::1111]:8443\n")
            f.write("# 6. IPv6 网段:       2606:4700::/32\n")
            f.write("# 7. 域名:            example.com\n")
            f.write("# 8. URL(下载IP列表): https://raw.githubusercontent.com/xxx/ips.txt\n")
            f.write("#    (GitHub链接会自动尝试国内镜像)\n")
            f.write("#\n")
            f.write("# 行尾可用 # 添加注释\n")
        return domains, individual_ips, ip_subnets, preformatted

    print(f"读取自定义IP池文件: {custom_file}")
    try:
        with open(custom_file, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if is_preformatted_target(line):
                    target, country_code, comment, original_line = parse_preformatted_target(line)
                    if target:
                        preformatted.add(target)
                        preformatted_targets[target] = {
                            'countryCode': country_code, 'comment': comment, 'original_line': original_line
                        }
                    continue

                if is_url(line):
                    url_count += 1
                    print(f"\n  [URL下载] 第{line_num}行: {line}")
                    downloaded_lines = download_url_content(line)
                    if downloaded_lines:
                        dl_domains, dl_ips, dl_subnets = parse_downloaded_lines(downloaded_lines)
                        domains.update(dl_domains)
                        individual_ips.update(dl_ips)
                        ip_subnets.update(dl_subnets)
                        print(f"  [URL下载完成] 新增: {len(dl_domains)}域名, {len(dl_ips)}IP, {len(dl_subnets)}网段")
                    continue

                target, comment = parse_simple_target(line)
                if not target:
                    continue

                host = extract_host(target)

                if any(c.isalpha() for c in host) and '.' in host and not is_ipv6(host):
                    domains.add(target)
                    if comment:
                        custom_ip_comments[target] = comment
                    continue

                try:
                    ipaddress.ip_address(host)
                    individual_ips.add(target)
                    if comment:
                        custom_ip_comments[target] = comment
                    continue
                except ValueError:
                    pass

                try:
                    network = ipaddress.ip_network(host, strict=False)
                    ip_subnets.add(str(network))
                    if comment:
                        custom_ip_comments[str(network)] = comment
                except ValueError:
                    print(f"  第{line_num}行格式无法识别: {line}")

        print(f"\n自定义IP池解析完成:")
        print(f"  域名: {len(domains)}个, 独立IP: {len(individual_ips)}个, IP网段: {len(ip_subnets)}个")
        print(f"  已格式化目标: {len(preformatted)}个, URL下载源: {url_count}个")
    except Exception as e:
        print(f"读取自定义IP池失败: {e}")

    return domains, individual_ips, ip_subnets, preformatted

def fetch_ip_ranges():
    """获取Cloudflare官方IP段（v4+v6）"""
    urls = [CONFIG["CLOUDFLARE_IPS_URL"]]
    if "CLOUDFLARE_IPS_V6_URL" in CONFIG:
        urls.append(CONFIG["CLOUDFLARE_IPS_V6_URL"])
    all_ranges = []
    for url in urls:
        try:
            res = requests.get(url, timeout=10, verify=False)
            lines = res.text.splitlines()
            all_ranges.extend(lines)
            print(f"  获取IP段成功 ({url}): {len(lines)} 条")
        except Exception as e:
            print(f"  获取IP段失败 ({url}): {e}")
    return all_ranges

def generate_random_ip(subnet):
    """根据CIDR生成子网内的随机IP，支持IPv4和IPv6"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        network_addr = int(network.network_address)
        broadcast_addr = int(network.broadcast_address)

        if network.version == 6:
            if broadcast_addr - network_addr > 2**32:
                random_offset = random.randint(1, min(2**32 - 1, broadcast_addr - network_addr - 1))
            else:
                random_offset = random.randint(1, max(1, broadcast_addr - network_addr - 1))
            return str(ipaddress.IPv6Address(network_addr + random_offset))
        else:
            first_ip = network_addr + 1
            last_ip = broadcast_addr - 1
            if last_ip < first_ip:
                last_ip = first_ip
            return str(ipaddress.IPv4Address(random.randint(first_ip, last_ip)))
    except Exception:
        return None

def generate_ip_pool():
    """根据配置生成IP池"""
    enabled_sources = get_enabled_sources()
    print(f"IP池来源: {get_source_display_name()}")

    total_target_pool = set()
    target_pool_size = CONFIG["IP_POOL_SIZE"]

    domains, individual_ips, custom_subnets, preformatted = parse_custom_ips_file()

    if '1' in enabled_sources:
        source1_targets = set()
        source1_targets.update(domains)
        source1_targets.update(individual_ips)
        source1_targets.update(preformatted)
        total_target_pool.update(source1_targets)
        print(f"  [自定义域名和IP] 域名{len(domains)}个, IP{len(individual_ips)}个, 格式化{len(preformatted)}个 → 共{len(source1_targets)}个")

        if len(total_target_pool) >= target_pool_size:
            full_pool = list(total_target_pool)[:target_pool_size]
            test_count = min(CONFIG["TEST_IP_COUNT"], len(full_pool))
            print(f"  ✓ 自定义来源已满足大池需求，随机抽取 {test_count} 个测试")
            return random.sample(full_pool, test_count)

    if '2' in enabled_sources and len(total_target_pool) < target_pool_size:
        needed = target_pool_size - len(total_target_pool)
        if custom_subnets:
            print(f"  [自定义IP段] 从 {len(custom_subnets)} 个网段生成 {needed} 个IP...")
            pool = set()
            attempts = 0
            max_attempts = needed * 3
            with tqdm(total=needed, desc="生成自定义IP段", unit="IP") as pbar:
                while len(pool) < needed and attempts < max_attempts:
                    subnet = random.choice(list(custom_subnets))
                    ip = generate_random_ip(subnet)
                    if ip:
                        ip_str = f"[{ip}]:{CONFIG['PORT']}" if is_ipv6(ip) else f"{ip}:{CONFIG['PORT']}"
                        if ip_str not in pool and ip_str not in total_target_pool:
                            pool.add(ip_str)
                            pbar.update(1)
                    attempts += 1
            total_target_pool.update(pool)
            print(f"  [自定义IP段] 生成 {len(pool)} 个IP")

            if len(total_target_pool) >= target_pool_size:
                full_pool = list(total_target_pool)[:target_pool_size]
                test_count = min(CONFIG["TEST_IP_COUNT"], len(full_pool))
                print(f"  ✓ 来源已满足大池需求，随机抽取 {test_count} 个测试")
                return random.sample(full_pool, test_count)

    if '3' in enabled_sources and len(total_target_pool) < target_pool_size:
        cf_subnets = fetch_ip_ranges()
        if cf_subnets:
            needed = target_pool_size - len(total_target_pool)
            print(f"  [官方CloudflareIP段] 从 {len(cf_subnets)} 个网段生成 {needed} 个IP...")
            pool = set()
            attempts = 0
            max_attempts = needed * 3
            with tqdm(total=needed, desc="生成官方IP", unit="IP") as pbar:
                while len(pool) < needed and attempts < max_attempts:
                    subnet = random.choice(list(cf_subnets))
                    ip = generate_random_ip(subnet)
                    if ip:
                        ip_str = f"[{ip}]:{CONFIG['PORT']}" if is_ipv6(ip) else f"{ip}:{CONFIG['PORT']}"
                        if ip_str not in pool and ip_str not in total_target_pool:
                            pool.add(ip_str)
                            pbar.update(1)
                    attempts += 1
            total_target_pool.update(pool)
            print(f"  [官方CloudflareIP段] 生成 {len(pool)} 个IP")
        else:
            print("  [官方CloudflareIP段] 获取失败，跳过")

    full_pool = list(total_target_pool)
    random.shuffle(full_pool)
    actual_size = min(target_pool_size, len(full_pool))
    final_pool = full_pool[:actual_size]

    print(f"\nIP大池构建完成: {len(full_pool)} 个目标，使用前 {actual_size} 个")
    test_count = min(CONFIG["TEST_IP_COUNT"], len(final_pool))
    test_pool = random.sample(final_pool, test_count)
    print(f"随机选择 {len(test_pool)} 个目标进行测试")
    return test_pool


####################################################
# 地理位置增强
####################################################

def enhance_target_with_country_info(target_list):
    """为目标列表添加国家代码信息"""
    enhanced = []
    print(f"\n正在查询地理位置信息（包含域名，域名将解析为IP后查询）...")

    sorted_list = sorted(target_list, key=lambda x: x.get('rtt', float('inf')))

    api_success = 0
    api_fail = 0
    custom_count = 0

    with tqdm(total=len(sorted_list), desc="查询地理位置", unit="目标") as pbar:
        for i, item in enumerate(sorted_list):
            target = item['target']

            if target in preformatted_targets:
                item['countryCode'] = preformatted_targets[target]['countryCode']
                item['comment'] = preformatted_targets[target]['comment']
                custom_count += 1
            else:
                host = extract_host(target)
                item['countryCode'] = get_real_ip_country_code(host)
                item['comment'] = custom_ip_comments.get(target, '')
                if item['countryCode'] != 'UN':
                    api_success += 1
                else:
                    api_fail += 1

            item['isp'] = "Cloudflare"
            enhanced.append(item)
            pbar.update(1)

    print(f"  地理位置统计: 自定义 {custom_count}, API成功 {api_success}, API失败 {api_fail}")
    return enhanced


####################################################
# 格式化输出
####################################################

def get_country_display_name(country_code):
    return f"{CONFIG['COUNTRY_NAMES'].get(country_code, country_code)}·{country_code}"

def format_target_output(target_data):
    full_target = target_data['target']
    country_code = target_data.get('countryCode', 'UN')
    flag = CONFIG["COUNTRY_FLAGS"].get(country_code, '🏴')
    country_display = get_country_display_name(country_code)

    if target_data['target'] in preformatted_targets:
        return preformatted_targets[target_data['target']]['original_line']

    comment = target_data.get('comment', '')
    comment_str = f" {comment}" if comment else ''
    return f"{full_target}#{flag}{country_display}{comment_str}"


####################################################
# 主逻辑
####################################################
if __name__ == "__main__":
    init_env()

    print("=" * 60)
    print(f"{'Cloudflare IP优选工具 v' + CONFIG['VERSION'] + ' (XIU2风格)':^60}")
    print("=" * 60)
    print(f"测试模式: {CONFIG['MODE']}")
    print(f"IP池来源: {get_source_display_name()}")
    print(f"延迟测试: {CONFIG['TCP_RETRY']}次TCP连接, 超时{CONFIG['TCP_TIMEOUT']}秒")
    print(f"延迟上限: {CONFIG['RTT_MAX']}ms, 丢包上限: {CONFIG['LOSS_MAX']}%")
    print(f"测速数量: 所有通过延迟测试的IP/域名")
    print(f"测速参数: {CONFIG['SPEED_TEST_BYTES'] // 1048576}MB下载, 超时{CONFIG['SPEED_TIMEOUT']}秒")
    if CONFIG['SPEED_MIN'] > 0:
        print(f"速度过滤: ≥{CONFIG['SPEED_MIN']}Mbps")
    else:
        print(f"速度过滤: 不过滤")
    print(f"并发线程: {CONFIG['THREADS']}")
    print(f"IP大池: {CONFIG['IP_POOL_SIZE']}, 实际测试: {CONFIG['TEST_IP_COUNT']}")
    print(f"最终输出: TOP {CONFIG['TOP_IPS_LIMIT']}")
    print("=" * 60 + "\n")

    test_pool = generate_ip_pool()
    if not test_pool:
        print("无法生成目标池，程序终止")
        exit(1)

    print(f"\n{'=' * 60}")
    print(f"  第一阶段：延迟测试 ({len(test_pool)} 个目标)")
    print(f"{'=' * 60}\n")

    latency_results = []

    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        futures = {executor.submit(latency_test, t): t for t in test_pool}
        with tqdm(total=len(test_pool), desc="延迟测试", unit="IP",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            for future in as_completed(futures):
                try:
                    latency_results.append(future.result())
                except Exception as e:
                    print(f"测试异常: {e}")
                finally:
                    pbar.update(1)

    rtt_max = CONFIG["RTT_MAX"]
    loss_max = CONFIG["LOSS_MAX"]
    latency_passed = [
        r for r in latency_results
        if r[1] != float('inf') and r[1] <= rtt_max and r[3] <= loss_max
    ]
    latency_passed.sort(key=lambda x: x[1])

    if latency_passed:
        all_rtts = [r[1] for r in latency_passed]
        all_min_rtts = [r[2] for r in latency_passed]
        print(f"\n延迟测试完成:")
        print(f"  总测试: {len(latency_results)} 个")
        print(f"  通过: {len(latency_passed)} 个 (延迟≤{rtt_max}ms, 丢包≤{loss_max}%)")
        print(f"  丢弃: {len(latency_results) - len(latency_passed)} 个")
        print(f"  延迟范围: {min(all_min_rtts):.2f}ms ~ {max(all_rtts):.2f}ms")
        print(f"  平均延迟: {sum(all_rtts) / len(all_rtts):.2f}ms")

    if not latency_passed:
        print("\n没有通过延迟测试的目标，程序终止")
        exit(1)

    speed_test_count = len(latency_passed)
    speed_test_targets = latency_passed

    print(f"\n{'=' * 60}")
    print(f"  第二阶段：速度测试 (全部 {speed_test_count} 个)")
    print(f"{'=' * 60}\n")

    speed_results = []

    with ThreadPoolExecutor(max_workers=min(CONFIG["THREADS"], max(1, speed_test_count))) as executor:
        futures = {}
        for item in speed_test_targets:
            target = item[0]
            futures[executor.submit(speed_test, target)] = item

        with tqdm(total=len(speed_test_targets), desc="速度测试", unit="IP",
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]") as pbar:
            for future in as_completed(futures):
                item = futures[future]
                try:
                    speed = future.result()
                    speed_results.append({
                        'target': item[0],
                        'rtt': item[1],
                        'min_rtt': item[2],
                        'loss': item[3],
                        'speed': speed
                    })
                except Exception as e:
                    print(f"测速异常: {e}")
                    speed_results.append({
                        'target': item[0], 'rtt': item[1], 'min_rtt': item[2],
                        'loss': item[3], 'speed': 0.0
                    })
                finally:
                    pbar.update(1)

    speed_min = CONFIG["SPEED_MIN"]
    if speed_min > 0:
        speed_passed = [r for r in speed_results if r['speed'] >= speed_min]
        speed_failed = [r for r in speed_results if r['speed'] < speed_min]
        print(f"\n速度测试完成:")
        print(f"  总测速: {len(speed_results)} 个")
        print(f"  达标(≥{speed_min}Mbps): {len(speed_passed)} 个")
        print(f"  不达标: {len(speed_failed)} 个")
        if not speed_passed:
            print(f"\n⚠ 没有IP达到期望速度 {speed_min}Mbps!")
            best = max(speed_results, key=lambda x: x['speed'])
            print(f"  最高速度: {best['speed']:.2f}Mbps (延迟 {best['rtt']:.1f}ms)")
            print(f"  将使用全部结果（不过滤速度）")
            speed_passed = speed_results
    else:
        speed_passed = speed_results
        if speed_results:
            nonzero = [r['speed'] for r in speed_results if r['speed'] > 0]
            print(f"\n速度测试完成: {len(speed_passed)} 个")
            if nonzero:
                print(f"  有效测速: {len(nonzero)} 个 (>0 Mbps)")
                print(f"  速度范围: {min(nonzero):.2f} ~ {max(nonzero):.2f} Mbps")

    if speed_passed:
        speeds = [r['speed'] for r in speed_passed]
        nonzero_speeds = [s for s in speeds if s > 0]
        if nonzero_speeds:
            print(f"\n速度统计:")
            print(f"  最高: {max(nonzero_speeds):.2f} Mbps")
            print(f"  最低: {min(nonzero_speeds):.2f} Mbps")
            print(f"  平均: {sum(nonzero_speeds) / len(nonzero_speeds):.2f} Mbps")

    enhanced_results = enhance_target_with_country_info(speed_passed)

    sorted_targets = sorted(enhanced_results, key=lambda x: (x['rtt'], -x['speed']))

    os.makedirs('results', exist_ok=True)
    top_targets = sorted_targets[:CONFIG["TOP_IPS_LIMIT"]]

    with open('results/top_targets.txt', 'w', encoding='utf-8') as f:
        for t in top_targets:
            f.write(format_target_output(t) + '\n')

    with open('results/top_targets_details.csv', 'w', encoding='utf-8') as f:
        f.write("目标,平均延迟(ms),最小延迟(ms),丢包率(%),速度(Mbps),国家代码,国家名称,ISP,注释\n")
        for t in sorted_targets:
            country_display = get_country_display_name(t['countryCode'])
            f.write(f"{t['target']},{t['rtt']:.2f},{t['min_rtt']:.2f},{t['loss']:.2f},"
                    f"{t['speed']:.2f},{t['countryCode']},{country_display},{t['isp']},{t.get('comment', '')}\n")

    print(f"\n{'=' * 60}")
    print(f"{'测试结果总览':^60}")
    print(f"{'=' * 60}")
    print(f"延迟测试: {len(latency_results)} 个 → 通过 {len(latency_passed)} 个")
    print(f"速度测试: {speed_test_count} 个 → 有效 {len([r for r in speed_passed if r['speed'] > 0])} 个")
    print(f"最终输出: TOP {len(top_targets)} 个")

    if top_targets:
        top_rtts = [t['rtt'] for t in top_targets]
        top_speeds = [t['speed'] for t in top_targets if t['speed'] > 0]
        geo_count = sum(1 for t in top_targets if t['countryCode'] != 'UN')

        print(f"\n{'─' * 60}")
        print(f"TOP {len(top_targets)} 统计:")
        print(f"  延迟: {min(top_rtts):.1f}ms ~ {max(top_rtts):.1f}ms (平均 {sum(top_rtts) / len(top_rtts):.1f}ms)")
        if top_speeds:
            print(f"  速度: {min(top_speeds):.1f} ~ {max(top_speeds):.1f} Mbps (平均 {sum(top_speeds) / len(top_speeds):.1f} Mbps)")
        else:
            print(f"  速度: 无有效数据")
        print(f"  地理: {geo_count}/{len(top_targets)} 有归属地信息")

        print(f"\n{'─' * 60}")
        print(f"{'【最佳IP TOP10】':^60}")
        print(f"{'─' * 60}")
        print(f"{'#':>3} {'目标':<45} {'延迟':>8} {'速度':>10} {'地区'}")
        print(f"{'─' * 60}")

        for i, t in enumerate(top_targets[:10], 1):
            target_short = t['target'][:43]
            flag = CONFIG["COUNTRY_FLAGS"].get(t['countryCode'], '🏴')
            country_name = CONFIG["COUNTRY_NAMES"].get(t['countryCode'], '未知')
            speed_str = f"{t['speed']:>7.1f}Mbps" if t['speed'] > 0 else f"{'N/A':>10}"
            print(f"{i:>3} {target_short:<45} {t['rtt']:>6.1f}ms {speed_str} {flag}{country_name}")

    print(f"\n{'=' * 60}")
    print(f"结果已保存至 results/ 目录:")
    print(f"  - top_targets.txt: 精选前{CONFIG['TOP_IPS_LIMIT']}个目标")
    print(f"  - top_targets_details.csv: 全部详细数据")
    print(f"{'=' * 60}")
