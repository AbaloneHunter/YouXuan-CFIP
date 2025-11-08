
import os
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


####################################################
# 配置参数
####################################################
CONFIG = {
    # 测试模式配置
    "MODE": "URL_TEST",    # 测试模式：PING/TCP/URL_TEST
    "URL_TEST_TARGET": 
    "http://www.gstatic.com/generate_204",  # URL测试目标地址
    "URL_TEST_TIMEOUT": 3,                  # URL测试超时时间（秒）
    "URL_TEST_RETRY": 2,   # URL测试重试次数
    
    # 网络连接配置
    "PORT": 443,           # TCP测试端口号
    "RTT_RANGE": "0~300",  # 可接受的延迟范围（毫秒）
    "LOSS_MAX": 2.0,       # 最大丢包率（百分比）
    
    # 性能与资源配置
    "THREADS": 200,        # 并发线程数量
    "IP_POOL_SIZE": 50000, # IP池总大小（生成的IP数量）
    "TEST_IP_COUNT": 1000, # 实际测试的IP数量
    "TOP_IPS_LIMIT": 50,   # 最终精选的IP数量
    
    # 数据源配置
    "CLOUDFLARE_IPS_URL": 
    "https://www.cloudflare.com/ips-v4",  # Cloudflare IP段源地址
    
    # 地区映射配置
    "REGION_MAPPING": {
        'US': ['🇺🇸 美国', 'US', 'United States'],      # 美国地区
        'SG': ['🇸🇬 新加坡', 'SG', 'Singapore'],         # 新加坡地区
        'JP': ['🇯🇵 日本', 'JP', 'Japan'],               # 日本地区
        'HK': ['🇭🇰 香港', 'HK', 'Hong Kong'],           # 香港地区
        'KR': ['🇰🇷 韩国', 'KR', 'South Korea'],         # 韩国地区
        'DE': ['🇩🇪 德国', 'DE', 'Germany'],             # 德国地区
        'GB': ['🇬🇧 英国', 'GB', 'United Kingdom']       # 英国地区
    }
}

####################################################
# 核心测试函数
####################################################

def url_test(ip, url=None, timeout=None, retry=None):
    """URL测试函数 - 测试指定IP的连通性和延迟"""
    if url is None:
        url = CONFIG["URL_TEST_TARGET"]
    if timeout is None:
        timeout = CONFIG["URL_TEST_TIMEOUT"]
    if retry is None:
        retry = CONFIG["URL_TEST_RETRY"]
    
    success_count = 0
    total_rtt = 0
    
    parsed_url = urlparse(url)
    scheme = parsed_url.scheme.lower()
    hostname = parsed_url.hostname
    port = parsed_url.port or (443 if scheme == 'https' else 80)
    path = parsed_url.path or '/'
    
    for attempt in range(retry):
        try:
            start_time = time.time()
            
            if scheme == 'https':
                # 创建HTTPS连接（跳过证书验证）
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(ip, port=port, timeout=timeout, context=context)
            else:
                # 创建HTTP连接
                conn = http.client.HTTPConnection(ip, port=port, timeout=timeout)
            
            # 设置请求头
            headers = {
                'Host': hostname,
                'User-Agent': 'Mozilla/5.0 (compatible; CF-IP-Tester/1.0)',
                'Accept': '*/*',
                'Connection': 'close'
            }
            
            # 发送请求并测量延迟
            conn.request("GET", path, headers=headers)
            response = conn.getresponse()
            response.read()
            
            rtt = (time.time() - start_time) * 1000
            
            # 判断请求是否成功（状态码小于500）
            if response.status < 500:
                success_count += 1
                total_rtt += rtt
            
            conn.close()
            
        except Exception:
            continue
        
        # 重试间隔
        if attempt < retry - 1:
            time.sleep(0.1)
    
    # 计算平均延迟和丢包率
    if success_count > 0:
        avg_rtt = total_rtt / success_count
        loss_rate = ((retry - success_count) / retry) * 100
    else:
        avg_rtt = float('inf')  # 表示无限大（测试失败）
        loss_rate = 100.0
    
    return avg_rtt, loss_rate

def get_ip_region(ip):
    """获取IP地区信息 - 使用ip-api.com服务"""
    try:
        # 调用IP地理位置API
        response = requests.get(f'http://ip-api.com/json/{ip}?fields=status,countryCode', timeout=3)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                country_code = data.get('countryCode')
                # 国家代码到地区代码的映射
                region_map = {
                    'US': 'US', 'CA': 'US', 'MX': 'US',      # 北美地区映射到US
                    'SG': 'SG', 'JP': 'JP', 'KR': 'KR',      # 亚洲主要地区
                    'TW': 'HK', 'MO': 'HK', 'CN': 'HK',      # 中华地区映射到HK
                    'GB': 'GB', 'DE': 'DE', 'FR': 'DE'       # 欧洲地区
                }
                return region_map.get(country_code, 'US')    # 默认返回美国
    except:
        pass
    
    # 如果API调用失败，根据IP段推测地区
    if ip.startswith(('8.8.', '8.9.', '8.10.')):
        return 'US'      # 8.8.x.x 段通常在美国
    elif ip.startswith(('103.21.', '103.22.', '104.16.')):
        return 'SG'      # 103.21.x.x 段通常在新加坡
    elif ip.startswith(('108.162.', '162.158.')):
        return 'JP'      # 108.162.x.x 段通常在日本
    else:
        return 'US'      # 默认返回美国

####################################################
# 输出格式化函数
####################################################

def format_ip_with_region(ip_data, port=None):
    """格式化IP输出为：ip:端口#国旗 地区名称 格式"""
    if port is None:
        port = CONFIG["PORT"]
    
    region_code = ip_data.get('regionCode', 'US')
    region_info = CONFIG["REGION_MAPPING"].get(region_code, ['🇺🇸 美国'])
    flag_and_name = region_info[0]
    
    return f"{ip_data['ip']}:{port}#{flag_and_name}"

def format_ip_list_for_display(ip_list):
    """格式化IP列表用于显示"""
    formatted_ips = []
    for ip_data in ip_list:
        formatted_ips.append(format_ip_with_region(ip_data))
    return formatted_ips

####################################################
# 核心逻辑函数
####################################################

def init_env():
    """初始化环境变量"""
    for key, value in CONFIG.items():
        os.environ[key] = str(value)

def fetch_ip_ranges():
    """从Cloudflare获取IP地址段"""
    try:
        res = requests.get(CONFIG["CLOUDFLARE_IPS_URL"], timeout=10, verify=False)
        return res.text.splitlines()
    except Exception as e:
        print(f"获取IP段失败: {e}")
        return []

def generate_random_ip(subnet):
    """根据CIDR子网生成随机IP地址"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        network_addr = int(network.network_address)
        broadcast_addr = int(network.broadcast_address)
        first_ip = network_addr + 1    # 跳过网络地址
        last_ip = broadcast_addr - 1   # 跳过广播地址
        random_ip_int = random.randint(first_ip, last_ip)
        return str(ipaddress.IPv4Address(random_ip_int))
    except:
        # 如果CIDR解析失败，使用简单方法生成IP
        base_ip = subnet.split('/')[0]
        parts = base_ip.split('.')
        parts = parts[:3] + [str(random.randint(1, 254))]  # 最后一位随机生成
        return ".".join(parts)

def test_ip(ip):
    """测试单个IP的连通性和延迟"""
    try:
        rtt, loss = url_test(ip)
        return (ip, rtt, loss)
    except:
        return (ip, float('inf'), 100.0)  # 测试失败返回无限延迟和100%丢包

def enhance_ip_info(ip_data):
    """为IP数据添加地区信息"""
    ip, rtt, loss = ip_data
    region_code = get_ip_region(ip)
    region_name = CONFIG["REGION_MAPPING"].get(region_code, ['🇺🇸 美国'])[0]
    
    return {
        'ip': ip,
        'rtt': rtt,
        'loss': loss,
        'regionCode': region_code,
        'regionName': region_name
    }

####################################################
# 主程序
####################################################
if __name__ == "__main__":
    # 初始化环境
    init_env()
    
    print("=" * 50)
    print(f"{'Cloudflare IP扫描器':^50}")
    print("=" * 50)
    
    # 步骤1：获取Cloudflare IP段
    subnets = fetch_ip_ranges()
    if not subnets:
        print("❌ 无法获取IP段")
        exit(1)
    
    print(f"✅ 获取到 {len(subnets)} 个IP段")
    
    # 步骤2：生成随机IP池
    ip_pool_size = CONFIG["IP_POOL_SIZE"]
    test_ip_count = CONFIG["TEST_IP_COUNT"]
    
    full_ip_pool = set()
    print(f"生成 {ip_pool_size} 个随机IP...")
    
    with tqdm(total=ip_pool_size, desc="生成IP池") as pbar:
        while len(full_ip_pool) < ip_pool_size:
            subnet = random.choice(subnets)
            ip = generate_random_ip(subnet)
            if ip not in full_ip_pool:
                full_ip_pool.add(ip)
                pbar.update(1)
    
    # 从大池中随机选择测试IP
    test_ip_pool = random.sample(list(full_ip_pool), min(test_ip_count, len(full_ip_pool)))
    print(f"测试 {len(test_ip_pool)} 个IP")
    
    # 步骤3：并发测试IP延迟
    ping_results = []
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_ip = {executor.submit(test_ip, ip): ip for ip in test_ip_pool}
        with tqdm(total=len(test_ip_pool), desc="延迟测试") as pbar:
            for future in as_completed(future_to_ip):
                try:
                    ping_results.append(future.result())
                except:
                    pass
                finally:
                    pbar.update(1)
    
    # 步骤4：筛选合格的IP（符合延迟和丢包要求）
    rtt_min, rtt_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    loss_max = CONFIG["LOSS_MAX"]
    
    passed_ips = [
        ip_data for ip_data in ping_results
        if rtt_min <= ip_data[1] <= rtt_max and ip_data[2] <= loss_max
    ]
    
    print(f"✅ 通过测试: {len(passed_ips)}/{len(ping_results)}")
    
    if not passed_ips:
        print("❌ 没有合格的IP")
        exit(1)
    
    # 步骤5：为IP添加地理位置信息
    print("检测地理位置...")
    enhanced_ips = []
    for ip_data in tqdm(passed_ips, desc="地理位置"):
        enhanced_ips.append(enhance_ip_info(ip_data))
    
    # 步骤6：按延迟排序并选择最佳IP
    sorted_ips = sorted(enhanced_ips, key=lambda x: x['rtt'])[:CONFIG["TOP_IPS_LIMIT"]]
    
    # 步骤7：保存结果到文件
    os.makedirs('results', exist_ok=True)
    
    # 保存带地区信息的IP列表
    with open('results/top_ips.txt', 'w', encoding='utf-8') as f:
        for ip_data in sorted_ips:
            line = format_ip_with_region(ip_data)
            f.write(line + '\n')
    
    # 保存纯IP列表（无地区信息）
    with open('results/top_ips_plain.txt', 'w', encoding='utf-8') as f:
        for ip_data in sorted_ips:
            f.write(f"{ip_data['ip']}:{CONFIG['PORT']}\n")
    
    # 步骤8：显示最终结果
    print("\n" + "=" * 50)
    print(f"{'最佳IP结果':^50}")
    print("=" * 50)
    
    # 显示TOP 10 IP（带地区信息）
    print("🏆 【TOP 10 IP (带地区)】")
    formatted_ips = format_ip_list_for_display(sorted_ips[:10])
    for i, ip in enumerate(formatted_ips, 1):
        print(f"{i:2d}. {ip}")
    
    # 显示TOP 10 IP（纯IP格式）
    print(f"\n🏆 【TOP 10 IP (纯IP)】")
    for i, ip_data in enumerate(sorted_ips[:10], 1):
        print(f"{i:2d}. {ip_data['ip']}:{CONFIG['PORT']}")
    
    # 显示所有精选IP（带地区信息）
    print(f"\n📋 【全部 {len(sorted_ips)} 个IP】")
    all_formatted = format_ip_list_for_display(sorted_ips)
    for i in range(0, len(all_formatted), 2):
        line_ips = all_formatted[i:i+2]
        print("  " + "  ".join(line_ips))
    
    print("=" * 50)
    print("✅ 结果已保存至 results/ 目录")
    print("📁 top_ips.txt - 带地区信息的IP列表")
    print("📁 top_ips_plain.txt - 纯IP列表")
    print("=" * 50)
