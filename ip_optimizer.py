import os
import asyncio
import aiohttp
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
import psutil
from typing import List, Dict, Tuple, Any
import json
import hashlib

####################################################
# 可配置参数（程序开头）
####################################################
CONFIG = {
    "MODE": "URL_TEST",  # 测试模式：PING/TCP/URL_TEST
    "PING_TARGET": "http://www.gstatic.com/generate_204",  # Ping测试目标
    "URL_TEST_TARGET": "http://www.gstatic.com/generate_204",  # URL测试目标
    "URL_TEST_TIMEOUT": 3,  # URL测试超时(秒)
    "URL_TEST_RETRY": 2,  # URL测试重试次数
    "PING_COUNT": 5,  # Ping次数
    "PING_TIMEOUT": 3,  # Ping超时(秒)
    "PORT": 443,  # TCP测试端口
    "RTT_RANGE": "0~800",  # 延迟范围(ms)
    "LOSS_MAX": 10.0,  # 最大丢包率(%)
    "THREADS": 500,  # 增加并发线程数
    "ASYNC_CONCURRENCY": 1000,  # 异步并发数
    "IP_POOL_SIZE": 50000,  # IP池总大小
    "TEST_IP_COUNT": 2000,  # 增加测试IP数量
    "TOP_IPS_LIMIT": 100,  # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "TCP_RETRY": 3,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    
    # 智能IP生成配置
    "INTELLIGENT_IP_GENERATION": True,
    "TARGET_REGIONS": ["HK", "SG", "JP", "KR", "US"],
    "REGION_CIDR_MAP": {
        'US': ['104.16.0.0/12', '172.64.0.0/13', '173.245.48.0/20'],
        'HK': ['104.20.0.0/15', '172.67.0.0/16', '104.23.88.0/22'],
        'SG': ['104.24.0.0/14', '172.68.0.0/16', '104.27.0.0/16'],
        'JP': ['104.28.0.0/15', '172.69.0.0/16', '104.18.0.0/15'],
        'KR': ['104.19.0.0/16', '172.70.0.0/16'],
        'DE': ['104.21.0.0/16', '172.67.128.0/17'],
        'GB': ['104.22.0.0/15', '172.68.128.0/17']
    },
    
    # 新增：备用测试URL列表
    "BACKUP_TEST_URLS": [
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/",
        "http://www.cloudflare.com/favicon.ico",
        "http://one.one.one.one/",
        "https://1.1.1.1/",
        "http://www.apple.com/library/test/success.html"
    ],
    
    # 地区配置
    "ENABLE_REGION_MATCHING": True,  # 启用地区匹配
    "MANUAL_WORKER_REGION": "HK",  # 手动指定Worker地区
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
    
    # IP地理位置API配置
    "IP_GEO_API": {
        "timeout": 3,
        "retry": 2,
        "enable_cache": True
    },
    
    # 性能监控配置
    "ENABLE_MONITORING": True,
    "MEMORY_LIMIT_MB": 1024
}

####################################################
# 新增：性能监控类
####################################################
class PerformanceMonitor:
    def __init__(self):
        self.metrics = {
            'network_usage': [],
            'memory_usage': [],
            'scan_speed': [],
            'start_time': time.time()
        }
        self.running = False
        
    def start_monitoring(self):
        """启动实时性能监控"""
        self.running = True
        
        def monitor_loop():
            while self.running:
                try:
                    # 网络使用
                    net_io = psutil.net_io_counters()
                    self.metrics['network_usage'].append(net_io.bytes_sent + net_io.bytes_recv)
                    
                    # 内存使用
                    memory = psutil.virtual_memory()
                    self.metrics['memory_usage'].append(memory.percent)
                    
                    # 扫描速度
                    elapsed = time.time() - self.metrics['start_time']
                    if elapsed > 0:
                        speed = len(self.metrics.get('completed_tasks', [])) / elapsed
                        self.metrics['scan_speed'].append(speed)
                    
                    time.sleep(1)
                except Exception:
                    continue
        
        import threading
        thread = threading.Thread(target=monitor_loop, daemon=True)
        thread.start()
    
    def stop_monitoring(self):
        """停止监控"""
        self.running = False
    
    def get_stats(self):
        """获取统计信息"""
        if not self.metrics['memory_usage']:
            return "暂无数据"
        
        return {
            'avg_memory_usage': np.mean(self.metrics['memory_usage']),
            'max_memory_usage': np.max(self.metrics['memory_usage']),
            'avg_scan_speed': np.mean(self.metrics['scan_speed']) if self.metrics['scan_speed'] else 0,
            'total_network_usage': self.metrics['network_usage'][-1] if self.metrics['network_usage'] else 0
        }

####################################################
# 新增：智能IP生成器
####################################################
class IntelligentIPGenerator:
    def __init__(self, target_regions=None):
        self.target_regions = target_regions or CONFIG["TARGET_REGIONS"]
        self.region_cidr_map = CONFIG["REGION_CIDR_MAP"]
        
    def get_prioritized_subnets(self, subnets):
        """获取按地区优先级排序的子网列表"""
        if not CONFIG["INTELLIGENT_IP_GENERATION"]:
            return subnets
            
        prioritized = []
        # 首先添加目标地区的CIDR
        for region in self.target_regions:
            prioritized.extend(self.region_cidr_map.get(region, []))
        
        # 添加其他子网
        for subnet in subnets:
            if subnet not in prioritized:
                prioritized.append(subnet)
                
        return prioritized
    
    def generate_ip_pool_optimized(self, subnets, pool_size):
        """流式生成IP，避免内存爆炸"""
        prioritized_subnets = self.get_prioritized_subnets(subnets)
        
        def ip_generator():
            while True:
                # 70%概率选择优先子网，30%概率选择其他子网
                if random.random() < 0.7 and prioritized_subnets:
                    subnet = random.choice(prioritized_subnets)
                else:
                    subnet = random.choice(subnets)
                yield self.generate_random_ip(subnet)
        
        # 使用集合去重，限制内存使用
        unique_ips = set()
        max_attempts = pool_size * 3  # 最大尝试次数
        
        for i, ip in enumerate(ip_generator()):
            if len(unique_ips) >= pool_size or i >= max_attempts:
                break
            unique_ips.add(ip)
            
            # 内存保护
            if i % 1000 == 0 and self._check_memory_usage():
                break
        
        return list(unique_ips)
    
    def generate_random_ip(self, subnet):
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
    
    def _check_memory_usage(self):
        """检查内存使用情况"""
        if not CONFIG["ENABLE_MONITORING"]:
            return False
            
        memory = psutil.virtual_memory()
        return memory.percent > 90  # 内存使用超过90%时停止

####################################################
# 新增：异步URL测试引擎
####################################################
class AsyncURLTester:
    def __init__(self):
        self.connector = None
        self.session = None
        
    async def __aenter__(self):
        # 创建连接池
        self.connector = aiohttp.TCPConnector(
            limit=CONFIG["ASYNC_CONCURRENCY"],
            limit_per_host=50,
            ttl_dns_cache=300,
            use_dns_cache=True
        )
        self.session = aiohttp.ClientSession(
            connector=self.connector,
            timeout=aiohttp.ClientTimeout(total=CONFIG["URL_TEST_TIMEOUT"]),
            headers={'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Tester/1.0)'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
        if self.connector:
            await self.connector.close()
    
    async def test_ip_batch(self, ip_batch, test_url, progress_callback=None):
        """批量测试IP"""
        tasks = []
        for ip in ip_batch:
            task = asyncio.create_task(self._test_single_ip(ip, test_url))
            tasks.append(task)
        
        results = []
        for future in asyncio.as_completed(tasks):
            try:
                result = await future
                results.append(result)
                if progress_callback:
                    progress_callback(1)
            except Exception as e:
                if progress_callback:
                    progress_callback(1)
                continue
        
        return results
    
    async def _test_single_ip(self, ip, test_url):
        """测试单个IP"""
        parsed_url = urlparse(test_url)
        scheme = parsed_url.scheme
        hostname = parsed_url.hostname
        path = parsed_url.path or '/'
        
        success_count = 0
        total_rtt = 0
        delays = []
        
        for attempt in range(CONFIG["URL_TEST_RETRY"]):
            try:
                start_time = time.time()
                
                # 构建实际URL
                if parsed_url.port:
                    actual_url = f"{scheme}://{ip}:{parsed_url.port}{path}"
                else:
                    actual_url = f"{scheme}://{ip}{path}"
                
                headers = {'Host': hostname}
                
                async with self.session.get(
                    actual_url,
                    headers=headers,
                    ssl=False
                ) as response:
                    # 读取部分内容确认连接
                    await response.read()
                    
                    rtt = (time.time() - start_time) * 1000
                    
                    if response.status < 500:
                        success_count += 1
                        total_rtt += rtt
                        delays.append(rtt)
                
            except (asyncio.TimeoutError, aiohttp.ClientError, OSError):
                continue
            except Exception:
                continue
            
            # 短暂间隔
            if attempt < CONFIG["URL_TEST_RETRY"] - 1:
                await asyncio.sleep(0.05)
        
        # 计算平均延迟和丢包率
        if success_count > 0:
            avg_rtt = total_rtt / success_count
            loss_rate = ((CONFIG["URL_TEST_RETRY"] - success_count) / CONFIG["URL_TEST_RETRY"]) * 100
        else:
            avg_rtt = float('inf')
            loss_rate = 100.0
        
        return (ip, avg_rtt, loss_rate, delays)

####################################################
# 缓存和工具函数
####################################################
ip_geo_cache = {}

def get_real_ip_region(ip):
    """使用真实的地理位置API检测IP地区"""
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
            response = requests.get(api['url'], timeout=CONFIG["IP_GEO_API"]["timeout"])
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
                    region_code = map_country_to_region(country_code)
                    
                    if CONFIG["IP_GEO_API"]["enable_cache"]:
                        ip_geo_cache[ip] = region_code
                    
                    return region_code
        except Exception:
            continue
    
    return None

def map_country_to_region(country_code):
    """将国家代码映射到地区代码"""
    country_to_region = {
        'US': 'US', 'CA': 'US', 'MX': 'US',
        'SG': 'SG', 'JP': 'JP', 'KR': 'KR', 'TW': 'HK', 'MO': 'HK',
        'CN': 'HK',
        'DE': 'DE', 'FR': 'DE', 'GB': 'GB', 'NL': 'NL', 'SE': 'SE', 
        'FI': 'FI', 'IT': 'DE', 'ES': 'DE', 'CH': 'DE', 'RU': 'DE',
        'AU': 'SG', 'NZ': 'SG',
        'TH': 'SG', 'MY': 'SG', 'ID': 'SG', 'VN': 'SG', 'PH': 'SG',
        'IN': 'SG', 'BD': 'SG', 'PK': 'SG'
    }
    return country_to_region.get(country_code, 'US')

def format_ip_with_region(ip_data, port=None):
    """格式化IP输出为 ip:端口#国旗 地区名称 格式"""
    if port is None:
        port = CONFIG["PORT"]
    
    region_code = ip_data.get('regionCode', 'Unknown')
    region_info = CONFIG["REGION_MAPPING"].get(region_code, [f"🇺🇳 未知({region_code})"])
    flag_and_name = region_info[0]
    
    return f"{ip_data['ip']}:{port}#{flag_and_name}"

def format_ip_list_for_display(ip_list, port=None):
    """格式化IP列表用于显示（包含地区和纯IP:端口）"""
    if port is None:
        port = CONFIG["PORT"]
    
    formatted_ips = []
    for ip_data in ip_list:
        formatted_ips.append(format_ip_with_region(ip_data, port))
    
    return formatted_ips

def format_ip_list_for_file(ip_list, port=None, include_region=True):
    """格式化IP列表用于文件保存"""
    if port is None:
        port = CONFIG["PORT"]
    
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

def get_region_by_rtt(rtt, worker_region):
    """根据延迟智能推测地区"""
    if not worker_region:
        worker_region = 'HK'
    if rtt < 30:
        return worker_region
    elif rtt < 80:
        nearby_regions = get_nearby_regions(worker_region)
        return random.choice(nearby_regions) if nearby_regions else worker_region
    elif rtt < 150:
        asia_regions = ['SG', 'JP', 'KR', 'HK']
        return random.choice([r for r in asia_regions if r != worker_region])
    else:
        return random.choice(['US', 'DE', 'GB'])

def get_nearby_regions(region):
    """获取邻近地区列表"""
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
    """获取按优先级排序的所有地区"""
    nearby_regions = get_nearby_regions(region)
    all_regions = ['US', 'SG', 'JP', 'HK', 'KR', 'DE', 'SE', 'NL', 'FI', 'GB']
    return [region, *nearby_regions, *[r for r in all_regions if r != region and r not in nearby_regions]]

def get_smart_region_selection(worker_region, available_ips):
    """智能地区选择算法"""
    if not CONFIG["ENABLE_REGION_MATCHING"] or not worker_region:
        return available_ips
    
    priority_regions = get_all_regions_by_priority(worker_region)
    sorted_ips = []
    
    for region in priority_regions:
        region_ips = [ip for ip in available_ips if ip.get('regionCode') == region]
        sorted_ips.extend(region_ips)
    
    other_ips = [ip for ip in available_ips if ip.get('regionCode') not in priority_regions and ip.get('regionCode') is not None]
    sorted_ips.extend(other_ips)
    
    return sorted_ips

def detect_worker_region():
    """检测Worker地区"""
    try:
        manual_region = CONFIG["MANUAL_WORKER_REGION"]
        if manual_region and manual_region.strip():
            return manual_region.strip().upper()
        return 'HK'
    except Exception:
        return 'HK'

####################################################
# 核心功能函数
####################################################
def init_env():
    """初始化环境"""
    urllib3.disable_warnings()

def fetch_ip_ranges():
    """获取IP段"""
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    if custom_file and os.path.exists(custom_file):
        print(f"🔧 使用自定义IP池文件: {custom_file}")
        try:
            with open(custom_file, 'r') as f:
                return [line.strip() for line in f.readlines() if line.strip()]
        except Exception as e:
            print(f"🚨 读取自定义IP池失败: {e}")
    
    url = CONFIG["CLOUDFLARE_IPS_URL"]
    try:
        res = requests.get(url, timeout=10, verify=False)
        return res.text.splitlines()
    except Exception as e:
        print(f"🚨 获取Cloudflare IP段失败: {e}")
    return []

def validate_test_urls():
    """验证测试URL的可用性"""
    print("🔍 验证测试URL可用性...")
    for test_url in CONFIG["BACKUP_TEST_URLS"]:
        try:
            start_time = time.time()
            response = requests.get(test_url, timeout=5, verify=False)
            rtt = (time.time() - start_time) * 1000
            if response.status_code < 500:
                print(f"✅ {test_url} - 可用 (延迟: {rtt:.1f}ms, 状态码: {response.status_code})")
                return test_url
        except Exception as e:
            print(f"❌ {test_url} - 错误: {e}")
    return CONFIG["BACKUP_TEST_URLS"][0]

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

def enhance_ip_with_region_info(ip_list, worker_region):
    """为IP列表添加真实的地区信息"""
    enhanced_ips = []
    print("🌍 正在检测IP真实地理位置...")
    
    with tqdm(total=len(ip_list), desc="IP地理位置", unit="IP") as pbar:
        for ip_data in ip_list:
            ip = ip_data[0]
            rtt = ip_data[1]
            loss = ip_data[2]
            speed = ip_data[3] if len(ip_data) > 3 else 0
            
            region_code = get_real_ip_region(ip)
            if not region_code:
                region_code = get_region_by_rtt(rtt, worker_region)
            
            region_name = CONFIG["REGION_MAPPING"].get(region_code, [f"🇺🇳 未知({region_code})"])[0]
            
            enhanced_ip = {
                'ip': ip,
                'rtt': rtt,
                'loss': loss,
                'speed': speed,
                'regionCode': region_code,
                'regionName': region_name,
                'isp': "Cloudflare"
            }
            enhanced_ips.append(enhanced_ip)
            pbar.update(1)
    
    return enhanced_ips

def print_config_info():
    """打印配置信息"""
    print("="*60)
    print(f"{'🚀 IP网络优化器 v2.0 (异步增强版)':^60}")
    print("="*60)
    print(f"测试模式: {CONFIG['MODE']}")
    worker_region = detect_worker_region()
    print(f"Worker地区: {CONFIG['REGION_MAPPING'].get(worker_region, [worker_region])[0]}")
    print(f"地区匹配: {'启用' if CONFIG['ENABLE_REGION_MATCHING'] else '禁用'}")
    print(f"智能IP生成: {'启用' if CONFIG['INTELLIGENT_IP_GENERATION'] else '禁用'}")
    print(f"异步并发数: {CONFIG['ASYNC_CONCURRENCY']}")
    print(f"测试IP数量: {CONFIG['TEST_IP_COUNT']}")
    print("="*60 + "\n")

def save_results(all_results, passed_ips, enhanced_results, sorted_ips):
    """保存结果文件"""
    os.makedirs('results', exist_ok=True)
    
    # 保存各种格式的结果文件
    with open('results/all_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in all_results]))
    
    with open('results/passed_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in passed_ips]))
    
    with open('results/full_results.csv', 'w') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),地区代码,地区名称,ISP\n")
        for ip_data in enhanced_results:
            f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['regionCode']},{ip_data['regionName']},{ip_data['isp']}\n")
    
    with open('results/top_ips.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_ip_list_for_file(sorted_ips, include_region=True)
        f.write("\n".join(formatted_lines))
    
    with open('results/top_ips_plain.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_ip_list_for_file(sorted_ips, include_region=False)
        f.write("\n".join(formatted_lines))
    
    # 保存地区统计
    region_stats = {}
    for ip_data in enhanced_results:
        region = ip_data['regionCode']
        if region not in region_stats:
            region_stats[region] = {'count': 0, 'avg_rtt': 0, 'avg_speed': 0, 'region_name': ip_data['regionName']}
        region_stats[region]['count'] += 1
        region_stats[region]['avg_rtt'] += ip_data['rtt']
        region_stats[region]['avg_speed'] += ip_data['speed']
    
    for region in region_stats:
        if region_stats[region]['count'] > 0:
            region_stats[region]['avg_rtt'] /= region_stats[region]['count']
            region_stats[region]['avg_speed'] /= region_stats[region]['count']
    
    with open('results/region_stats.csv', 'w', encoding='utf-8') as f:
        f.write("地区代码,地区名称,IP数量,平均延迟(ms),平均速度(Mbps)\n")
        for region, stats in region_stats.items():
            f.write(f"{region},{stats['region_name']},{stats['count']},{stats['avg_rtt']:.2f},{stats['avg_speed']:.2f}\n")

def display_final_results(sorted_ips, enhanced_results, monitor):
    """显示最终结果"""
    # 地区统计
    region_stats = {}
    for ip_data in enhanced_results:
        region = ip_data['regionCode']
        if region not in region_stats:
            region_stats[region] = {'count': 0, 'avg_rtt': 0, 'avg_speed': 0, 'region_name': ip_data['regionName']}
        region_stats[region]['count'] += 1
        region_stats[region]['avg_rtt'] += ip_data['rtt']
        region_stats[region]['avg_speed'] += ip_data['speed']
    
    for region in region_stats:
        if region_stats[region]['count'] > 0:
            region_stats[region]['avg_rtt'] /= region_stats[region]['count']
            region_stats[region]['avg_speed'] /= region_stats[region]['count']
    
    # 显示结果
    print("\n" + "="*60)
    print(f"{'🔥 测试结果统计':^60}")
    print("="*60)
    
    if CONFIG["ENABLE_MONITORING"]:
        stats = monitor.get_stats()
        print(f"🏃 性能统计: 平均速度 {stats['avg_scan_speed']:.1f} IP/秒, 内存使用 {stats['avg_memory_usage']:.1f}%")
    
    print(f"📊 IP统计: 总数 {len(enhanced_results)}, 精选 {len(sorted_ips)}")
    
    print(f"\n🌍 地区分布:")
    for region, stats in sorted(region_stats.items(), key=lambda x: x[1]['count'], reverse=True):
        print(f"  {stats['region_name']}: {stats['count']}个IP, 平均延迟{stats['avg_rtt']:.1f}ms, 平均速度{stats['avg_speed']:.1f}Mbps")
    
    if sorted_ips:
        print(f"\n🏆【最佳IP TOP10 (带地区信息)】")
        formatted_top_ips = format_ip_list_for_display(sorted_ips[:10])
        for i, formatted_ip in enumerate(formatted_top_ips, 1):
            print(f"{i}. {formatted_ip}")
        
        print(f"\n🏆【最佳IP TOP10 (纯IP:端口)】")
        for i, ip_data in enumerate(sorted_ips[:10], 1):
            plain_ip = f"{ip_data['ip']}:{CONFIG['PORT']}"
            print(f"{i}. {plain_ip}")
    
    print("="*60)
    print("✅ 结果已保存至 results/ 目录")

####################################################
# 主程序入口
####################################################
async def main_async():
    """异步主函数"""
    # 初始化环境和监控
    init_env()
    monitor = PerformanceMonitor()
    if CONFIG["ENABLE_MONITORING"]:
        monitor.start_monitoring()
    
    try:
        # 1. 验证测试URL
        best_url = validate_test_urls()
        CONFIG["URL_TEST_TARGET"] = best_url
        print(f"🎯 使用测试URL: {best_url}")
        
        # 2. 显示配置信息
        print_config_info()
        
        # 3. 获取IP段并生成智能IP池
        subnets = fetch_ip_ranges()
        if not subnets:
            print("❌ 无法获取IP段，程序终止")
            return
        
        ip_generator = IntelligentIPGenerator()
        test_ip_count = CONFIG["TEST_IP_COUNT"]
        
        print(f"🔧 正在智能生成 {test_ip_count} 个测试IP...")
        test_ip_pool = ip_generator.generate_ip_pool_optimized(subnets, test_ip_count)
        print(f"✅ 成功生成 {len(test_ip_pool)} 个测试IP")
        
        # 4. 异步URL测试
        print(f"🚀 开始异步URL测试 (并发数: {CONFIG['ASYNC_CONCURRENCY']})...")
        
        batch_size = CONFIG["ASYNC_CONCURRENCY"]
        all_results = []
        
        with tqdm(total=len(test_ip_pool), desc="🌐 异步URL测试", unit="IP") as pbar:
            async with AsyncURLTester() as tester:
                for i in range(0, len(test_ip_pool), batch_size):
                    batch = test_ip_pool[i:i + batch_size]
                    batch_results = await tester.test_ip_batch(
                        batch, 
                        CONFIG["URL_TEST_TARGET"],
                        progress_callback=lambda x: pbar.update(x)
                    )
                    all_results.extend(batch_results)
        
        # 5. 筛选合格IP
        rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
        loss_max = CONFIG["LOSS_MAX"]
        passed_ips = [
            ip_data for ip_data in all_results
            if rtt_min <= ip_data[1] <= rtt_max and ip_data[2] <= loss_max
        ]
        print(f"✅ 延迟测试完成: 总数 {len(all_results)}, 通过 {len(passed_ips)}")
        
        if not passed_ips:
            print("❌ 没有通过延迟测试的IP，程序终止")
            return
        
        # 6. 测速阶段
        print("📊 开始测速阶段...")
        full_results = []
        with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
            future_to_ip = {executor.submit(speed_test, ip_data[0]): ip_data for ip_data in passed_ips}
            with tqdm(total=len(passed_ips), desc="📊 测速进度", unit="IP") as pbar:
                for future in as_completed(future_to_ip):
                    try:
                        ip_data = future_to_ip[future]
                        speed = future.result()
                        full_results.append((*ip_data, speed))
                    except Exception:
                        continue
                    finally:
                        pbar.update(1)
        
        # 7. 地区检测和智能排序
        worker_region = detect_worker_region()
        enhanced_results = enhance_ip_with_region_info(full_results, worker_region)
        
        if CONFIG["ENABLE_REGION_MATCHING"] and worker_region:
            print(f"🔧 正在按地区优先级排序...")
            region_sorted_ips = get_smart_region_selection(worker_region, enhanced_results)
            sorted_ips = sorted(
                region_sorted_ips,
                key=lambda x: (-x['speed'], x['rtt'], x['loss'])
            )[:CONFIG["TOP_IPS_LIMIT"]]
        else:
            sorted_ips = sorted(
                enhanced_results,
                key=lambda x: (-x['speed'], x['rtt'])
            )[:CONFIG["TOP_IPS_LIMIT"]]
        
        # 8. 保存结果
        save_results(all_results, passed_ips, enhanced_results, sorted_ips)
        
        # 9. 显示最终结果
        display_final_results(sorted_ips, enhanced_results, monitor)
        
    finally:
        monitor.stop_monitoring()

if __name__ == "__main__":
    # 运行异步主函数
    asyncio.run(main_async())
