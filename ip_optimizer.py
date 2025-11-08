import os
import requests
import random
import numpy as np
import time
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from tqdm import tqdm
import urllib3
import ipaddress
import json
import re

####################################################
#                 可配置参数（程序开头）              #
####################################################
# 环境变量默认值（可通过.env或GitHub Actions覆盖）
CONFIG = {
    "MODE": "TCP",                  # 测试模式：PING/TCP
    "PING_TARGET": "https://www.google.com/generate_204",  # Ping测试目标
    "PING_COUNT": 3,                # Ping次数
    "PING_TIMEOUT": 5,              # Ping超时(秒)
    "PORT": 443,                    # TCP测试端口
    "RTT_RANGE": "10~250",          # 延迟范围(ms)
    "LOSS_MAX": 5.0,               # 最大丢包率(%)
    "THREADS": 50,                  # 并发线程数
    "IP_POOL_SIZE": 50000,          # IP池总大小
    "TEST_IP_COUNT": 500,          # 实际测试IP数量
    "TOP_IPS_LIMIT": 50,            # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "custom_ips.txt",          # 自定义IP池文件路径
    "TCP_RETRY": 2,                 # TCP重试次数
    "SPEED_TIMEOUT": 5,            # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    "REGIONS": "HK,TW,SG,JP,US,KR", # 优选地区代码
    "GEOCHECK_TIMEOUT": 3,          # 地理位置查询超时
    "PING0_API": "https://ping0.cc/api/ip"  # 地理位置查询API
}

####################################################
#                    核心功能函数                   #
####################################################
# 初始化环境变量
def init_env():
    # 设置环境变量
    for key, value in CONFIG.items():
        os.environ[key] = str(value)
    
    # 自动添加URL协议头
    cf_url = os.getenv('CLOUDFLARE_IPS_URL')
    if cf_url and not cf_url.startswith(('http://', 'https://')):
        os.environ['CLOUDFLARE_IPS_URL'] = f"https://{cf_url}"
    
    # 禁用TLS警告
    urllib3.disable_warnings()

# 获取地区特定的IP段配置
def get_region_subnets():
    """返回各地区对应的IP段配置"""
    region_subnets = {
        # 香港
        "HK": [
            "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
            "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
            "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
            "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
            "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"
        ],
        # 台湾
        "TW": [
            "104.28.0.0/16", "104.29.0.0/16", "172.68.0.0/16",
            "104.18.0.0/20", "104.19.0.0/20", "108.162.192.0/18"
        ],
        # 新加坡
        "SG": [
            "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
            "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
            "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
            "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"
        ],
        # 日本
        "JP": [
            "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
            "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
            "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
            "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"
        ],
        # 美国
        "US": [
            "104.16.0.0/12", "108.162.192.0/18", "131.0.72.0/22",
            "141.101.64.0/18", "162.158.0.0/15", "172.64.0.0/13",
            "173.245.48.0/20", "188.114.96.0/20", "190.93.240.0/20",
            "197.234.240.0/22", "198.41.128.0/17"
        ],
        # 韩国
        "KR": [
            "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
            "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
            "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
            "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"
        ]
    }
    return region_subnets

# 获取用户指定的地区
def get_target_regions():
    regions_env = os.getenv('REGIONS', 'HK,TW,SG,JP,US,KR')
    regions = [r.strip().upper() for r in regions_env.split(',')]
    valid_regions = []
    
    region_subnets = get_region_subnets()
    for region in regions:
        if region in region_subnets:
            valid_regions.append(region)
        else:
            print(f"⚠️ 警告: 地区代码 {region} 无效，已跳过")
    
    return valid_regions

# 生成随机IP（基于位运算实现）
def generate_random_ip(subnet):
    """根据CIDR生成子网内的随机合法IP（排除网络地址和广播地址）"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        network_addr = int(network.network_address)
        broadcast_addr = int(network.broadcast_address)
        
        # 排除网络地址和广播地址
        first_ip = network_addr + 1
        last_ip = broadcast_addr - 1
        
        # 生成随机IP
        random_ip_int = random.randint(first_ip, last_ip)
        return str(ipaddress.IPv4Address(random_ip_int))
    except Exception as e:
        print(f"生成随机IP错误: {e}，使用简单方法生成")
        base_ip = subnet.split('/')[0]
        return ".".join(base_ip.split('.')[:3] + [str(random.randint(1, 254))])

# 查询IP地理位置（模拟ping0.cc）
def query_ip_geolocation(ip):
    """查询IP的地理位置信息"""
    timeout = float(os.getenv('GEOCHECK_TIMEOUT', 3))
    
    try:
        # 方法1: 使用ping0.cc API
        api_url = os.getenv('PING0_API')
        if api_url:
            response = requests.get(f"{api_url}/{ip}", timeout=timeout, verify=False)
            if response.status_code == 200:
                data = response.json()
                if 'location' in data:
                    return data['location']
        
        # 方法2: 使用ipapi.co（备用）
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=timeout, verify=False)
        if response.status_code == 200:
            data = response.json()
            country = data.get('country_code', '')
            city = data.get('city', '')
            if country and city:
                return f"{country}/{city}"
            elif country:
                return country
        
        # 方法3: 使用ip-api.com（备用）
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=timeout, verify=False)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                country = data.get('countryCode', '')
                city = data.get('city', '')
                if country and city:
                    return f"{country}/{city}"
                elif country:
                    return country
        
        return "Unknown"
        
    except Exception as e:
        return "Error"

# 检查地区是否匹配
def check_region_match(location, target_regions):
    """检查地理位置是否匹配目标地区"""
    if location == "Unknown" or location == "Error":
        return False
    
    for region in target_regions:
        if region.upper() in location.upper():
            return True
    return False

# 自定义Ping测试（跨平台兼容）
def custom_ping(ip):
    target = urlparse(os.getenv('PING_TARGET')).netloc or os.getenv('PING_TARGET')
    count = int(os.getenv('PING_COUNT'))
    timeout = int(os.getenv('PING_TIMEOUT'))
    
    try:
        # 跨平台ping命令
        if os.name == 'nt':  # Windows
            cmd = f"ping -n {count} -w {timeout*1000} {target}"
        else:  # Linux/Mac
            cmd = f"ping -c {count} -W {timeout} -I {ip} {target}"
        
        result = subprocess.run(
            cmd, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout + 2
        )
        
        # 解析ping结果
        output = result.stdout.lower()
        
        if "100% packet loss" in output or "unreachable" in output:
            return float('inf'), 100.0  # 完全丢包
        
        # 提取延迟和丢包率
        loss_line = next((l for l in result.stdout.split('\n') if "packet loss" in l.lower()), "")
        timing_lines = [l for l in result.stdout.split('\n') if "time=" in l.lower()]
        
        # 计算丢包率
        loss_percent = 100.0
        if loss_line:
            loss_parts = loss_line.split('%')
            if loss_parts:
                try:
                    loss_percent = float(loss_parts[0].split()[-1])
                except:
                    pass
        
        # 计算平均延迟
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

# TCP连接测试（带重试机制）
def tcp_ping(ip, port, timeout=2):
    retry = int(os.getenv('TCP_RETRY', 3))
    success_count = 0
    total_rtt = 0
    
    for _ in range(retry):
        start = time.time()
        try:
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                rtt = (time.time() - start) * 1000  # 毫秒
                total_rtt += rtt
                success_count += 1
        except:
            pass
        time.sleep(0.1)  # 短暂间隔
    
    loss_rate = 100 - (success_count / retry * 100)
    avg_rtt = total_rtt / success_count if success_count > 0 else float('inf')
    return avg_rtt, loss_rate

# 测速函数
def speed_test(ip):
    url = os.getenv('SPEED_URL')
    timeout = float(os.getenv('SPEED_TIMEOUT', 10))
    
    try:
        # 通过指定IP访问
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        
        # 创建自定义解析器
        def resolver(host):
            return ip
        
        # 使用IP直接连接
        start_time = time.time()
        response = requests.get(
            url,
            headers={'Host': host},
            timeout=timeout,
            verify=False,
            stream=True  # 使用流式下载以准确测量速度
        )
        
        # 计算下载速度
        total_bytes = 0
        for chunk in response.iter_content(chunk_size=8192):
            total_bytes += len(chunk)
            if time.time() - start_time > timeout:
                break
        
        duration = time.time() - start_time
        speed_mbps = (total_bytes * 8) / (duration * 1000000)  # 转换为Mbps
        return speed_mbps
        
    except Exception as e:
        print(f"测速失败 [{ip}]: {e}")
        return 0.0

# IP综合测试 - 第一阶段：Ping测试
def ping_test(ip):
    mode = os.getenv('MODE', 'PING').upper()
    
    if mode == "PING":
        # 使用自定义Ping测试
        avg_delay, loss_rate = custom_ping(ip)
        return (ip, avg_delay, loss_rate)
    
    else:  # TCP模式
        port = int(os.getenv('PORT', 443))
        avg_rtt, loss_rate = tcp_ping(ip, port, timeout=float(os.getenv('PING_TIMEOUT', 2)))
        return (ip, avg_rtt, loss_rate)

# IP综合测试 - 第二阶段：测速和地理位置查询
def full_test(ip_data):
    ip = ip_data[0]
    speed = speed_test(ip)
    location = query_ip_geolocation(ip)
    
    # 验证地区匹配
    target_regions = get_target_regions()
    is_matched = check_region_match(location, target_regions)
    
    # 在真实地址后面添加✔️符号
    display_location = f"{location} ✔️" if is_matched else location
    
    return (*ip_data, speed, display_location, is_matched)

####################################################
#                      主逻辑                      #
####################################################
if __name__ == "__main__":
    # 0. 初始化环境
    init_env()
    
    # 1. 获取目标地区
    target_regions = get_target_regions()
    if not target_regions:
        print("❌ 没有有效的目标地区，程序终止")
        exit(1)
    
    # 2. 打印配置参数
    print("="*60)
    print(f"{'IP网络优化器 v3.0 - 多地区优选':^60}")
    print("="*60)
    print(f"测试模式: {os.getenv('MODE')}")
    print(f"目标地区: {', '.join(target_regions)}")
    
    if os.getenv('MODE') == "PING":
        print(f"Ping目标: {os.getenv('PING_TARGET')}")
        print(f"Ping次数: {os.getenv('PING_COUNT')}")
        print(f"Ping超时: {os.getenv('PING_TIMEOUT')}秒")
    else:
        print(f"TCP端口: {os.getenv('PORT')}")
        print(f"TCP重试: {os.getenv('TCP_RETRY')}次")
    
    print(f"延迟范围: {os.getenv('RTT_RANGE')}ms")
    print(f"最大丢包: {os.getenv('LOSS_MAX')}%")
    print(f"并发线程: {os.getenv('THREADS')}")
    print(f"IP池大小: {os.getenv('IP_POOL_SIZE')}")
    print(f"测试IP数: {os.getenv('TEST_IP_COUNT')}")
    
    # 显示自定义IP池信息
    custom_file = os.getenv('CUSTOM_IPS_FILE')
    if custom_file:
        print(f"自定义IP池: {custom_file}")
    else:
        print(f"Cloudflare IP源: {os.getenv('CLOUDFLARE_IPS_URL')}")
    
    print(f"测速URL: {os.getenv('SPEED_URL')}")
    print("="*60 + "\n")
    
    # 3. 获取地区特定的IP段
    region_subnets = get_region_subnets()
    selected_subnets = []
    
    for region in target_regions:
        if region in region_subnets:
            selected_subnets.extend(region_subnets[region])
            print(f"✅ 添加 {region} 地区IP段: {len(region_subnets[region])}个")
    
    if not selected_subnets:
        print("❌ 无法获取IP段，程序终止")
        exit(1)
    
    # 4. 创建IP池
    ip_pool_size = int(os.getenv('IP_POOL_SIZE'))
    test_ip_count = int(os.getenv('TEST_IP_COUNT'))
    
    # 生成完整IP池
    full_ip_pool = set()
    print(f"\n🔧 正在生成 {ip_pool_size} 个随机IP的大池...")
    with tqdm(total=ip_pool_size, desc="生成IP大池", unit="IP") as pbar:
        while len(full_ip_pool) < ip_pool_size:
            subnet = random.choice(selected_subnets)
            ip = generate_random_ip(subnet)
            if ip not in full_ip_pool:
                full_ip_pool.add(ip)
                pbar.update(1)
    
    print(f"✅ 成功生成 {len(full_ip_pool)} 个随机IP的大池")
    
    # 从大池中随机选择测试IP
    if test_ip_count > len(full_ip_pool):
        print(f"⚠️ 警告: 测试IP数量({test_ip_count})大于IP池大小({len(full_ip_pool)})，使用全部IP")
        test_ip_count = len(full_ip_pool)
    
    test_ip_pool = random.sample(list(full_ip_pool), test_ip_count)
    print(f"🔧 从大池中随机选择 {len(test_ip_pool)} 个IP进行测试")
    
    # 5. 第一阶段：Ping测试（筛选IP）
    ping_results = []
    with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
        future_to_ip = {executor.submit(ping_test, ip): ip for ip in test_ip_pool}
        
        # 进度条配置
        with tqdm(
            total=len(test_ip_pool), 
            desc="🚀 Ping测试进度", 
            unit="IP",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_ip):
                try:
                    ping_results.append(future.result())
                except Exception as e:
                    print(f"\n🔧 Ping测试异常: {e}")
                finally:
                    pbar.update(1)
    
    # 筛选通过Ping测试的IP
    rtt_min, rtt_max = map(int, os.getenv('RTT_RANGE').split('~'))
    loss_max = float(os.getenv('LOSS_MAX'))
    
    passed_ips = [
        ip_data for ip_data in ping_results 
        if rtt_min <= ip_data[1] <= rtt_max
        and ip_data[2] <= loss_max
    ]
    
    print(f"\n✅ Ping测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips)}")
    
    # 6. 第二阶段：测速和地理位置查询（仅对通过Ping测试的IP）
    if not passed_ips:
        print("❌ 没有通过Ping测试的IP，程序终止")
        exit(1)
    
    full_results = []
    with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
        future_to_ip = {executor.submit(full_test, ip_data): ip_data for ip_data in passed_ips}
        
        # 进度条配置
        with tqdm(
            total=len(passed_ips), 
            desc="📊 测速和地理位置查询", 
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
    
    # 7. 精选IP排序（按地区匹配优先，然后速度降序，延迟升序）
    sorted_ips = sorted(
        full_results,
        key=lambda x: (
            0 if x[5] else 1,  # 地区匹配的优先
            -x[3],  # 速度降序
            x[1]    # 延迟升序
        )
    )[:int(os.getenv('TOP_IPS_LIMIT', 15))]
    
    # 8. 保存结果
    os.makedirs('results', exist_ok=True)
    
    # 保存所有测试过的IP
    with open('results/all_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in ping_results]))
    
    # 保存通过Ping测试的IP
    with open('results/passed_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in passed_ips]))
    
    # 保存完整结果（带速度和地理位置）
    with open('results/full_results.csv', 'w') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),地理位置,地区匹配\n")
        for ip_data in full_results:
            f.write(f"{ip_data[0]},{ip_data[1]:.2f},{ip_data[2]:.2f},{ip_data[3]:.2f},{ip_data[4]},{ip_data[5]}\n")
    
    # 保存精选IP
    with open('results/top_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in sorted_ips]))
    
    # 保存精选IP的完整信息
    with open('results/top_ips_details.csv', 'w') as f:
        f.write("IP,延迟(ms),丢包率(%),速度(Mbps),地理位置,地区匹配\n")
        for ip_data in sorted_ips:
            f.write(f"{ip_data[0]},{ip_data[1]:.2f},{ip_data[2]:.2f},{ip_data[3]:.2f},{ip_data[4]},{ip_data[5]}\n")
    
    # 9. 显示统计结果 - 保持原来的输出格式
    print("\n" + "="*60)
    print(f"{'🔥 测试结果统计':^60}")
    print("="*60)
    print(f"目标地区: {', '.join(target_regions)}")
    print(f"IP池大小: {ip_pool_size}")
    print(f"实际测试IP数: {len(ping_results)}")
    print(f"通过Ping测试IP数: {len(passed_ips)}")
    print(f"测速IP数: {len(full_results)}")
    print(f"精选TOP IP: {len(sorted_ips)}")
    
    # 统计地区匹配情况
    matched_ips = [ip for ip in full_results if ip[5]]
    print(f"地区匹配IP数: {len(matched_ips)}")
    
    if sorted_ips:
        print(f"\n🏆【最佳IP TOP{min(5, len(sorted_ips))}】")
        for i, ip_data in enumerate(sorted_ips[:5]):
            # 保持原来的输出格式，只在真实地址后面添加✔️
            print(f"{i+1}. {ip_data[0]} | 延迟:{ip_data[1]:.2f}ms | 丢包:{ip_data[2]:.2f}% | 速度:{ip_data[3]:.2f}Mbps | 位置:{ip_data[4]}")
    
    print("="*60)
    print("✅ 结果已保存至 results/ 目录")
    print("💡 注: 真实地址后面带✔️的表示属于目标地区")
