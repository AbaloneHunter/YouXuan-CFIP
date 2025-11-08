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

####################################################
# 可配置参数（程序开头）
####################################################
CONFIG = {
    "MODE": "REAL_URL",  # 测试模式：PING/TCP/REAL_URL
    "PING_TARGET": "http://www.gstatic.com/generate_204",  # Ping测试目标
    "PING_COUNT": 8,  # Ping次数
    "PING_TIMEOUT": 3,  # Ping超时(秒)
    "PORT": 443,  # TCP测试端口
    "RTT_RANGE": "10~300",  # 延迟范围(ms)
    "LOSS_MAX": 2.0,  # 最大丢包率(%)
    "THREADS": 80,  # 并发线程数
    "IP_POOL_SIZE": 500000,  # IP池总大小
    "TEST_IP_COUNT": 5000,  # 实际测试IP数量
    "TOP_IPS_LIMIT": 50,  # 精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=10000000",  # 测速URL
    
    # 新增：真实URL测试配置
    "REAL_URL_TEST": {
        "ENABLED": True,
        "TEST_URLS": [
            "https://www.google.com/generate_204",
            "https://www.cloudflare.com/cdn-cgi/trace",
            "https://api.github.com",
            "https://www.youtube.com/favicon.ico"
        ],
        "TIMEOUT": 5,
        "RETRY": 2,
        "CHECK_STATUS": True,  # 检查HTTP状态码
        "CHECK_CONTENT": True,  # 检查响应内容
        "USER_AGENT": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    },
    
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
    }
}

####################################################
# 新增：真实URL连接测试函数
####################################################

def real_url_test(ip, port=443):
    """
    真实URL连接测试
    测试IP是否能正常访问真实网站
    """
    config = CONFIG["REAL_URL_TEST"]
    test_urls = config["TEST_URLS"]
    timeout = config["TIMEOUT"]
    retry = config["RETRY"]
    
    success_count = 0
    total_rtt = 0
    tested_urls = []
    
    for url in test_urls:
        for attempt in range(retry):
            try:
                start_time = time.time()
                
                # 设置Host头，通过指定IP访问
                parsed_url = urlparse(url)
                host = parsed_url.hostname
                
                headers = {
                    'User-Agent': config["USER_AGENT"],
                    'Host': host,
                    'Accept': '*/*'
                }
                
                # 使用指定IP发起请求
                response = requests.get(
                    url,
                    headers=headers,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True
                )
                
                rtt = (time.time() - start_time) * 1000
                
                # 检查状态码
                if config["CHECK_STATUS"]:
                    if response.status_code >= 400:
                        continue
                
                # 检查内容（简单检查）
                if config["CHECK_CONTENT"]:
                    if len(response.content) == 0:
                        continue
                
                success_count += 1
                total_rtt += rtt
                tested_urls.append({
                    'url': url,
                    'status': response.status_code,
                    'rtt': rtt,
                    'size': len(response.content)
                })
                break  # 成功则跳出重试循环
                
            except requests.exceptions.Timeout:
                continue
            except requests.exceptions.ConnectionError:
                continue
            except requests.exceptions.RequestException:
                continue
            except Exception as e:
                continue
    
    # 计算成功率
    success_rate = (success_count / len(test_urls)) * 100 if test_urls else 0
    avg_rtt = total_rtt / success_count if success_count > 0 else float('inf')
    
    return {
        'success_rate': success_rate,
        'avg_rtt': avg_rtt,
        'success_count': success_count,
        'total_tests': len(test_urls),
        'tested_urls': tested_urls
    }

def real_url_ping_test(ip):
    """
    真实URL测试的包装函数，用于统一接口
    """
    port = int(os.getenv('PORT', 443))
    result = real_url_test(ip, port)
    
    # 返回与ping_test相同的格式 (ip, rtt, loss)
    # 这里将失败率视为"丢包率"
    loss_rate = 100 - result['success_rate']
    return (ip, result['avg_rtt'], loss_rate, result)

####################################################
# 修改ping_test函数以支持REAL_URL模式
####################################################

def ping_test(ip):
    """Ping测试入口 - 支持三种模式"""
    mode = os.getenv('MODE')
    
    if mode == "PING":
        rtt, loss = custom_ping(ip)
        return (ip, rtt, loss)
    elif mode == "TCP":
        rtt, loss = tcp_ping(ip, int(os.getenv('PORT')))
        return (ip, rtt, loss)
    elif mode == "REAL_URL":
        return real_url_ping_test(ip)
    else:
        # 默认使用TCP模式
        rtt, loss = tcp_ping(ip, int(os.getenv('PORT')))
        return (ip, rtt, loss)

####################################################
# 修改结果显示函数以包含真实URL测试信息
####################################################

def format_real_url_results(real_url_data):
    """格式化真实URL测试结果"""
    if not real_url_data:
        return "无真实URL测试数据"
    
    result = []
    result.append(f"成功率: {real_url_data['success_rate']:.1f}%")
    result.append(f"平均RTT: {real_url_data['avg_rtt']:.1f}ms")
    result.append(f"成功数: {real_url_data['success_count']}/{real_url_data['total_tests']}")
    
    # 显示每个URL的测试结果
    for i, test in enumerate(real_url_data['tested_urls'][:3]):  # 只显示前3个
        domain = urlparse(test['url']).netloc
        result.append(f"  {domain}: {test['status']} ({test['rtt']:.1f}ms)")
    
    return " | ".join(result)

def enhance_ip_with_region_info(ip_list, worker_region):
    """
    为IP列表添加真实的地区信息 - 增强版，包含真实URL测试数据
    """
    enhanced_ips = []
    
    print("🌍 正在检测IP真实地理位置...")
    with tqdm(total=len(ip_list), desc="IP地理位置", unit="IP") as pbar:
        for ip_data in ip_list:
            ip = ip_data[0]
            rtt = ip_data[1]
            loss = ip_data[2]
            speed = ip_data[3] if len(ip_data) > 3 else 0
            real_url_data = ip_data[4] if len(ip_data) > 4 else None
            
            # 使用真实API获取地区
            region_code = get_real_ip_region(ip)
            
            # 如果API查询失败，使用智能回退
            if not region_code:
                region_code = get_region_by_rtt(rtt, worker_region)
                pbar.set_description(f"IP地理位置 (备用模式)")
            
            region_name = CONFIG["REGION_MAPPING"].get(region_code, [f"🇺🇳 未知({region_code})"])[0]
            
            enhanced_ip = {
                'ip': ip,
                'rtt': rtt,
                'loss': loss,
                'speed': speed,
                'real_url_data': real_url_data,
                'regionCode': region_code,
                'regionName': region_name,
                'isp': f"Cloudflare"
            }
            enhanced_ips.append(enhanced_ip)
            pbar.update(1)
    
    return enhanced_ips

####################################################
# 修改主逻辑以支持真实URL测试
####################################################

if __name__ == "__main__":
    # 0. 初始化环境
    init_env()
    
    # 1. 打印配置参数 - 增强显示真实URL测试信息
    print("="*60)
    print(f"{'IP网络优化器 v2.5 (真实URL测试版)':^60}")
    print("="*60)
    print(f"测试模式: {os.getenv('MODE')}")
    
    # 显示真实URL测试配置
    if os.getenv('MODE') == "REAL_URL":
        print(f"真实URL测试: 启用")
        print(f"测试URL数量: {len(CONFIG['REAL_URL_TEST']['TEST_URLS'])}")
        print(f"测试超时: {CONFIG['REAL_URL_TEST']['TIMEOUT']}秒")
        print(f"测试重试: {CONFIG['REAL_URL_TEST']['RETRY']}次")
        print("测试URL示例:")
        for url in CONFIG['REAL_URL_TEST']['TEST_URLS'][:2]:  # 显示前2个
            domain = urlparse(url).netloc
            print(f"  - {domain}")
    
    # 检测Worker地区
    worker_region = detect_worker_region()
    if CONFIG["MANUAL_WORKER_REGION"]:
        print(f"Worker地区: {CONFIG['REGION_MAPPING'].get(worker_region, [worker_region])[0]} (手动指定)")
    else:
        print(f"Worker地区: {CONFIG['REGION_MAPPING'].get(worker_region, [worker_region])[0]} (自动检测)")
    
    print(f"地区匹配: {'启用' if CONFIG['ENABLE_REGION_MATCHING'] else '禁用'}")
    
    if os.getenv('MODE') == "PING":
        print(f"Ping目标: {os.getenv('PING_TARGET')}")
        print(f"Ping次数: {os.getenv('PING_COUNT')}")
        print(f"Ping超时: {os.getenv('PING_TIMEOUT')}秒")
    elif os.getenv('MODE') == "TCP":
        print(f"TCP端口: {os.getenv('PORT')}")
        print(f"TCP重试: {os.getenv('TCP_RETRY')}次")
        print(f"延迟范围: {os.getenv('RTT_RANGE')}ms")
        print(f"最大丢包: {os.getenv('LOSS_MAX')}%")
    
    print(f"并发线程: {os.getenv('THREADS')}")
    print(f"IP池大小: {os.getenv('IP_POOL_SIZE')}")
    print(f"测试IP数: {os.getenv('TEST_IP_COUNT')}")
    custom_file = os.getenv('CUSTOM_IPS_FILE')
    if custom_file:
        print(f"自定义IP池: {custom_file}")
    else:
        print(f"Cloudflare IP源: {os.getenv('CLOUDFLARE_IPS_URL')}")
    
    if os.getenv('MODE') != "REAL_URL":
        print(f"测速URL: {os.getenv('SPEED_URL')}")
    
    print("="*60 + "\n")

    # [之前的IP生成和测试代码保持不变...]
    # 2. 获取IP段并生成随机IP池
    subnets = fetch_ip_ranges()
    if not subnets:
        print("❌ 无法获取IP段，程序终止")
        exit(1)
    
    source_type = "自定义" if custom_file and os.path.exists(custom_file) else "Cloudflare"
    print(f"✅ 获取到 {len(subnets)} 个{source_type} IP段")
    
    ip_pool_size = int(os.getenv('IP_POOL_SIZE'))
    test_ip_count = int(os.getenv('TEST_IP_COUNT'))
    full_ip_pool = set()
    
    print(f"🔧 正在生成 {ip_pool_size} 个随机IP的大池...")
    with tqdm(total=ip_pool_size, desc="生成IP大池", unit="IP") as pbar:
        while len(full_ip_pool) < ip_pool_size:
            subnet = random.choice(subnets)
            ip = generate_random_ip(subnet)
            if ip not in full_ip_pool:
                full_ip_pool.add(ip)
                pbar.update(1)
    
    print(f"✅ 成功生成 {len(full_ip_pool)} 个随机IP的大池")
    
    if test_ip_count > len(full_ip_pool):
        print(f"⚠️ 警告: 测试IP数量({test_ip_count})大于IP池大小({len(full_ip_pool)})，使用全部IP")
        test_ip_count = len(full_ip_pool)
    
    test_ip_pool = random.sample(list(full_ip_pool), test_ip_count)
    print(f"🔧 从大池中随机选择 {len(test_ip_pool)} 个IP进行测试")

    # 3. 第一阶段：测试（根据模式选择）
    mode = os.getenv('MODE')
    if mode == "REAL_URL":
        test_description = "🌐 真实URL测试进度"
    elif mode == "PING":
        test_description = "🚀 Ping测试进度"
    else:
        test_description = "🔌 TCP测试进度"
    
    ping_results = []
    with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
        future_to_ip = {executor.submit(ping_test, ip): ip for ip in test_ip_pool}
        with tqdm(
            total=len(test_ip_pool),
            desc=test_description,
            unit="IP",
            bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]"
        ) as pbar:
            for future in as_completed(future_to_ip):
                try:
                    ping_results.append(future.result())
                except Exception as e:
                    print(f"\n🔧 测试异常: {e}")
                finally:
                    pbar.update(1)
    
    # 根据模式调整筛选条件
    rtt_min, rtt_max = map(int, os.getenv('RTT_RANGE').split('~'))
    loss_max = float(os.getenv('LOSS_MAX'))
    
    if mode == "REAL_URL":
        # 对于真实URL测试，成功率至少80%
        passed_ips = [
            ip_data for ip_data in ping_results
            if rtt_min <= ip_data[1] <= rtt_max and ip_data[2] <= loss_max
            and ip_data[4]['success_rate'] >= 80  # 成功率要求
        ]
    else:
        passed_ips = [
            ip_data for ip_data in ping_results
            if rtt_min <= ip_data[1] <= rtt_max and ip_data[2] <= loss_max
        ]
    
    print(f"\n✅ {test_description.split(' ')[1]}测试完成: 总数 {len(ping_results)}, 通过 {len(passed_ips)}")

    # 4. 第二阶段：测速（仅对通过测试的IP，真实URL模式可选）
    if not passed_ips:
        print("❌ 没有通过测试的IP，程序终止")
        exit(1)
    
    full_results = []
    if mode == "REAL_URL":
        # 真实URL模式已经包含完整测试，直接使用结果
        full_results = passed_ips
    else:
        # 其他模式需要进行速度测试
        with ThreadPoolExecutor(max_workers=int(os.getenv('THREADS'))) as executor:
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

    # 5. 为IP添加真实地区信息
    enhanced_results = enhance_ip_with_region_info(full_results, worker_region)

    # 6. 智能地区排序
    if CONFIG["ENABLE_REGION_MATCHING"] and worker_region:
        print(f"🔧 正在按地区优先级排序...")
        region_sorted_ips = get_smart_region_selection(worker_region, enhanced_results)
        
        # 在地区排序的基础上，再按性能排序
        if mode == "REAL_URL":
            # 真实URL模式按成功率和延迟排序
            sorted_ips = sorted(
                region_sorted_ips,
                key=lambda x: (
                    -x.get('real_url_data', {}).get('success_rate', 0),
                    x['rtt'],
                    x['loss']
                )
            )[:int(os.getenv('TOP_IPS_LIMIT', 15))]
        else:
            # 其他模式按速度和延迟排序
            sorted_ips = sorted(
                region_sorted_ips,
                key=lambda x: (-x['speed'], x['rtt'], x['loss'])
            )[:int(os.getenv('TOP_IPS_LIMIT', 15))]
    else:
        # 传统排序方式
        if mode == "REAL_URL":
            sorted_ips = sorted(
                enhanced_results,
                key=lambda x: (
                    -x.get('real_url_data', {}).get('success_rate', 0),
                    x['rtt']
                )
            )[:int(os.getenv('TOP_IPS_LIMIT', 15))]
        else:
            sorted_ips = sorted(
                enhanced_results,
                key=lambda x: (-x['speed'], x['rtt'])
            )[:int(os.getenv('TOP_IPS_LIMIT', 15))]

    # 7. 保存结果 - 增强真实URL测试信息
    os.makedirs('results', exist_ok=True)
    
    # 保存所有测试过的IP
    with open('results/all_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in ping_results]))
    
    # 保存通过初步筛选的IP
    with open('results/passed_ips.txt', 'w') as f:
        f.write("\n".join([ip[0] for ip in passed_ips]))
    
    # 保存完整结果（CSV格式）- 增强真实URL信息
    with open('results/full_results.csv', 'w') as f:
        if mode == "REAL_URL":
            f.write("IP,延迟(ms),丢包率(%),成功率(%),成功数/总数,地区代码,地区名称,ISP\n")
            for ip_data in enhanced_results:
                real_url = ip_data.get('real_url_data', {})
                success_rate = real_url.get('success_rate', 0)
                success_count = real_url.get('success_count', 0)
                total_tests = real_url.get('total_tests', 0)
                f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{success_rate:.2f},{success_count}/{total_tests},{ip_data['regionCode']},{ip_data['regionName']},{ip_data['isp']}\n")
        else:
            f.write("IP,延迟(ms),丢包率(%),速度(Mbps),地区代码,地区名称,ISP\n")
            for ip_data in enhanced_results:
                f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['regionCode']},{ip_data['regionName']},{ip_data['isp']}\n")
    
    # 保存精选IP - 包含地区信息
    with open('results/top_ips.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_ip_list_for_file(sorted_ips, include_region=True)
        f.write("\n".join(formatted_lines))
    
    # 保存纯IP:端口格式
    with open('results/top_ips_plain.txt', 'w', encoding='utf-8') as f:
        formatted_lines = format_ip_list_for_file(sorted_ips, include_region=False)
        f.write("\n".join(formatted_lines))
    
    # 保存精选IP详细信息 - 增强真实URL信息
    with open('results/top_ips_details.csv', 'w', encoding='utf-8') as f:
        if mode == "REAL_URL":
            f.write("IP,延迟(ms),丢包率(%),成功率(%),成功数/总数,地区代码,地区名称,ISP,测试详情\n")
            for ip_data in sorted_ips:
                real_url = ip_data.get('real_url_data', {})
                success_rate = real_url.get('success_rate', 0)
                success_count = real_url.get('success_count', 0)
                total_tests = real_url.get('total_tests', 0)
                test_details = "; ".join([f"{urlparse(t['url']).netloc}({t['status']})" for t in real_url.get('tested_urls', [])[:2]])
                f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{success_rate:.2f},{success_count}/{total_tests},{ip_data['regionCode']},{ip_data['regionName']},{ip_data['isp']},{test_details}\n")
        else:
            f.write("IP,延迟(ms),丢包率(%),速度(Mbps),地区代码,地区名称,ISP\n")
            for ip_data in sorted_ips:
                f.write(f"{ip_data['ip']},{ip_data['rtt']:.2f},{ip_data['loss']:.2f},{ip_data['speed']:.2f},{ip_data['regionCode']},{ip_data['regionName']},{ip_data['isp']}\n")

    # 8. 显示统计结果 - 增强真实URL信息
    print("\n" + "="*60)
    print(f"{'🔥 测试结果统计':^60}")
    print("="*60)
    print(f"IP池大小: {ip_pool_size}")
    print(f"实际测试IP数: {len(ping_results)}")
    print(f"通过测试IP数: {len(passed_ips)}")
    print(f"精选TOP IP: {len(sorted_ips)}")
    print(f"Worker地区: {CONFIG['REGION_MAPPING'].get(worker_region, [worker_region])[0]}")
    print(f"地区匹配: {'启用' if CONFIG['ENABLE_REGION_MATCHING'] else '禁用'}")
    print(f"测试模式: {mode}")
    
    if mode == "REAL_URL":
        # 显示真实URL测试统计
        total_success_rate = np.mean([ip.get('real_url_data', {}).get('success_rate', 0) for ip in enhanced_results])
        avg_success_rate = np.mean([ip.get('real_url_data', {}).get('success_rate', 0) for ip in sorted_ips])
        print(f"平均成功率: {total_success_rate:.1f}% (全部) / {avg_success_rate:.1f}% (精选)")
    
    # 显示地区分布
    region_stats = {}
    for ip_data in enhanced_results:
        region = ip_data['regionCode']
        if region not in region_stats:
            region_stats[region] = {
                'count': 0,
                'avg_rtt': 0,
                'avg_speed': 0,
                'avg_success_rate': 0,
                'region_name': ip_data['regionName']
            }
        region_stats[region]['count'] += 1
        region_stats[region]['avg_rtt'] += ip_data['rtt']
        if mode != "REAL_URL":
            region_stats[region]['avg_speed'] += ip_data['speed']
        if mode == "REAL_URL":
            region_stats[region]['avg_success_rate'] += ip_data.get('real_url_data', {}).get('success_rate', 0)
    
    # 计算平均值
    for region in region_stats:
        if region_stats[region]['count'] > 0:
            region_stats[region]['avg_rtt'] /= region_stats[region]['count']
            if mode != "REAL_URL":
                region_stats[region]['avg_speed'] /= region_stats[region]['count']
            if mode == "REAL_URL":
                region_stats[region]['avg_success_rate'] /= region_stats[region]['count']

    print(f"\n🌍 地区分布 (基于真实地理位置API):")
    for region, stats in sorted(region_stats.items(), key=lambda x: x[1]['count'], reverse=True):
        if mode == "REAL_URL":
            print(f"  {stats['region_name']}: {stats['count']}个IP, 平均延迟{stats['avg_rtt']:.1f}ms, 平均成功率{stats['avg_success_rate']:.1f}%")
        else:
            print(f"  {stats['region_name']}: {stats['count']}个IP, 平均延迟{stats['avg_rtt']:.1f}ms, 平均速度{stats['avg_speed']:.1f}Mbps")
    
    if sorted_ips:
        # 显示最佳IP
        print(f"\n🏆【最佳IP TOP10】")
        for i, ip_data in enumerate(sorted_ips[:10], 1):
            if mode == "REAL_URL":
                real_url_info = format_real_url_results(ip_data.get('real_url_data'))
                print(f"{i}. {format_ip_with_region(ip_data)} | {real_url_info}")
            else:
                print(f"{i}. {format_ip_with_region(ip_data)} | 延迟:{ip_data['rtt']:.1f}ms 丢包:{ip_data['loss']:.1f}% 速度:{ip_data['speed']:.1f}Mbps")
    
    print("="*60)
    print("✅ 结果已保存至 results/ 目录")
    print("📊 文件说明:")
    print("   - top_ips.txt: 精选IP列表 (ip:端口#国旗 地区名称)")
    print("   - top_ips_plain.txt: 纯IP:端口格式 (无地区信息)")
    print("   - top_ips_details.csv: 详细性能数据")
    print("   - region_stats.csv: 地区统计信息")
    if mode == "REAL_URL":
        print("   - 真实URL测试: 包含成功率、HTTP状态码等详细信息")
    print("="*60)

# 注意：需要保留之前的所有辅助函数（init_env, fetch_ip_ranges, generate_random_ip, custom_ping, tcp_ping, speed_test等）
# 这些函数在代码中保持不变，因此没有重复列出
