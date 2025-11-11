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
# 配置参数 - 调整延迟要求和优化测试
####################################################
CONFIG = {
    "MODE": "URL_TEST",  # 测试模式：TCP/URL_TEST
    "URL_TEST_TARGET": "http://www.gstatic.com/generate_204",  # URL测试目标
    "URL_TEST_TIMEOUT": 5,  # 增加URL测试超时(秒)
    "URL_TEST_RETRY": 2,   # 减少重试次数加快测试
    "PORT": 443,  # TCP测试端口
    "RTT_RANGE": "0~100",  # 放宽延迟范围(ms)
    "LOSS_MAX": 10.0,  # 放宽最大丢包率(%)
    "THREADS": 100,  # 进一步降低并发线程数
    "IP_POOL_SIZE": 20000,  # 减小IP池总大小
    "TEST_IP_COUNT": 500,   # 减少实际测试IP数量
    "TOP_IPS_LIMIT": 50,   # 减少精选IP数量
    "CLOUDFLARE_IPS_URL": "https://www.cloudflare.com/ips-v4",
    "CUSTOM_IPS_FILE": "custom_ips.txt",  # 自定义IP池文件路径
    "TCP_RETRY": 2,  # TCP重试次数
    "SPEED_TIMEOUT": 5,  # 测速超时时间
    "SPEED_URL": "https://speed.cloudflare.com/__down?bytes=5000000",  # 减小测速文件大小
    "IP_POOL_SOURCES": "1,2",  # 只使用自定义域名和IP段，去掉官方IP池
    
    # 新增配置：注释显示设置
    "DOMAIN_COMMENT_SEPARATOR": "#",  # 域名和注释的分隔符
    "COMMENT_DISPLAY_FORMAT": "[{comment}]",  # 注释的显示格式
    
    # 地理位置查询设置
    "GEO_QUERY_ENABLED": False,  # 暂时关闭地理位置查询以加快测试
    "GEO_QUERY_MODE": "DELAY_FIRST",  # 查询模式：DELAY_FIRST=延迟优先, SPEED_FIRST=速度优先, BOTH=两者都查
    "GEO_QUERY_COUNT": 50,  # 减少查询数量
    
    # 备用测试URL列表
    "BACKUP_TEST_URLS": [
        "http://www.gstatic.com/generate_204",
        "http://cp.cloudflare.com/generate_204",
        "http://cloudflare.com/favicon.ico"
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
    "DOMAIN_TEST_PROTOCOL": "https",  # 域名测试默认协议
    
    # 新增性能优化配置
    "MAX_IPS_PER_SUBNET": 20,  # 每个IP段最大生成IP数
    "MAX_GENERATION_ATTEMPTS": 500,  # 最大生成尝试次数
    
    # 新增测试优化配置
    "MIN_TEST_TARGETS": 10,  # 最小通过目标数，如果少于这个数会自动放宽条件
    "AUTO_ADJUST_THRESHOLD": 5,  # 自动调整阈值
}

# IP地理位置缓存
ip_geo_cache = {}

# IP详细信息存储
ip_details = {}  # 存储每个IP的详细信息：{ip: {"comment": "注释", "source": "来源", "domain": "原始域名"}}

# 域名详细信息存储
domain_details = {}  # 存储每个域名的详细信息：{domain: {"comment": "注释", "source": "来源"}}

####################################################
# 优化的测试函数 - 提高成功率
####################################################

def improved_url_test(target, url=None, timeout=None, retry=None, is_domain=False):
    """
    改进的URL测试 - 提高成功率
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
    
    # 如果主要URL测试失败，尝试备用URL
    test_urls = [url] + CONFIG["BACKUP_TEST_URLS"]
    
    for test_url in test_urls:
        if success_count > 0:  # 如果已经成功，不再尝试其他URL
            break
            
        parsed_test_url = urlparse(test_url)
        test_scheme = parsed_test_url.scheme.lower()
        test_hostname = parsed_test_url.hostname
        test_port = parsed_test_url.port or (443 if test_scheme == 'https' else 80)
        test_path = parsed_test_url.path or '/'
        
        for attempt in range(retry):
            try:
                start_time = time.time()
                
                # 如果是域名测试，使用域名作为连接目标
                connect_target = target if is_domain else test_hostname
                
                if test_scheme == 'https':
                    # HTTPS请求 - 更宽松的SSL配置
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    conn = http.client.HTTPSConnection(
                        connect_target, 
                        port=test_port, 
                        timeout=timeout,
                        context=context
                    )
                else:
                    # HTTP请求
                    conn = http.client.HTTPConnection(
                        connect_target,
                        port=test_port,
                        timeout=timeout
                    )
                
                # 设置更宽松的请求头
                headers = {
                    'Host': test_hostname,
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': '*/*',
                    'Accept-Encoding': 'gzip, deflate',
                    'Connection': 'close'
                }
                
                conn.request("GET", test_path, headers=headers)
                response = conn.getresponse()
                
                # 读取响应内容但不处理，只关心连接成功
                try:
                    response.read()
                except:
                    pass
                
                rtt = (time.time() - start_time) * 1000
                
                # 更宽松的成功条件：任何HTTP响应都算成功，包括4xx
                if response.status < 500:  # 1xx, 2xx, 3xx, 4xx 都接受
                    success_count += 1
                    total_rtt += rtt
                    delays.append(rtt)
                    break  # 这个URL成功就跳出重试循环
                
                conn.close()
                
            except socket.timeout:
                continue
            except (socket.gaierror, ConnectionRefusedError, ConnectionResetError, ssl.SSLError):
                continue
            except Exception as e:
                continue
            finally:
                try:
                    conn.close()
                except:
                    pass
            
            # 短暂间隔避免过于频繁
            if attempt < retry - 1:
                time.sleep(0.05)
    
    # 计算平均延迟和丢包率
    if success_count > 0:
        avg_rtt = total_rtt / success_count
        loss_rate = ((retry - success_count) / retry) * 100
    else:
        avg_rtt = float('inf')
        loss_rate = 100.0
    
    return avg_rtt, loss_rate, delays

def smart_ping_test(target):
    """智能延迟测试 - 自动选择最佳测试方法"""
    mode = CONFIG["MODE"]
    
    # 获取目标类型
    global domain_details, ip_details
    is_domain = target in domain_details
    
    try:
        if mode == "TCP":
            port = CONFIG["PORT"]
            rtt, loss = tcp_ping(target, port, is_domain=is_domain)
        else:
            # 使用改进的URL测试
            rtt, loss, _ = improved_url_test(target, is_domain=is_domain)
        
        return (target, rtt, loss, is_domain)
    except Exception as e:
        # 如果测试失败，返回无限延迟
        return (target, float('inf'), 100.0, is_domain)

def auto_adjust_threshold(ping_results):
    """
    自动调整阈值 - 如果没有足够的目标通过测试，自动放宽条件
    """
    if len(ping_results) == 0:
        return []
    
    # 获取所有有效的延迟（非无限）
    valid_rtts = [rtt for _, rtt, _, _ in ping_results if rtt < float('inf')]
    
    if len(valid_rtts) == 0:
        return []
    
    # 按延迟排序
    sorted_rtts = sorted(valid_rtts)
    
    # 如果通过的目标太少，自动调整阈值
    current_min, current_max = map(int, CONFIG["RTT_RANGE"].split('~'))
    current_loss_max = CONFIG["LOSS_MAX"]
    
    passed_targets = [
        target_data for target_data in ping_results
        if current_min <= target_data[1] <= current_max and target_data[2] <= current_loss_max
    ]
    
    if len(passed_targets) < CONFIG["MIN_TEST_TARGETS"]:
        print(f"⚠️ 通过的目标太少({len(passed_targets)}个)，自动放宽条件...")
        
        # 计算新的阈值
        if len(sorted_rtts) > 0:
            # 取前50%的延迟作为新范围
            median_index = len(sorted_rtts) // 2
            new_max_rtt = min(300, sorted_rtts[median_index] * 1.5)  # 最大不超过300ms
            
            # 放宽丢包率
            new_loss_max = 20.0
            
            print(f"🔧 调整延迟范围: {current_min}~{current_max}ms -> {current_min}~{int(new_max_rtt)}ms")
            print(f"🔧 调整丢包率: {current_loss_max}% -> {new_loss_max}%")
            
            # 使用新阈值筛选
            passed_targets = [
                target_data for target_data in ping_results
                if current_min <= target_data[1] <= new_max_rtt and target_data[2] <= new_loss_max
            ]
            
            print(f"✅ 调整后通过: {len(passed_targets)} 个目标")
    
    return passed_targets

# 其他函数保持不变，只替换核心测试函数
# [此处保留原有的 parse_custom_ips_file, generate_ip_pool, fetch_ip_ranges 等函数]
# 但将 ping_test 替换为 smart_ping_test

def parse_custom_ips_file():
    """解析自定义IP文件"""
    custom_file = CONFIG["CUSTOM_IPS_FILE"]
    domains_with_comments = {}
    individual_ips_with_comments = {}
    ip_subnets_with_comments = {}
    
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

def generate_random_ip_fast(subnet):
    """快速生成随机IP"""
    try:
        network = ipaddress.ip_network(subnet, strict=False)
        hosts = list(network.hosts())
        if hosts:
            return str(random.choice(hosts))
        else:
            return str(network.network_address)
    except Exception:
        base_ip = subnet.split('/')[0]
        parts = base_ip.split('.')
        while len(parts) < 4:
            parts.append(str(random.randint(0, 255)))
        parts = [str(min(255, max(0, int(p)))) for p in parts[:3]] + [str(random.randint(1, 254))]
        return ".".join(parts)

def generate_ip_pool():
    """生成测试目标池"""
    sources_config = CONFIG["IP_POOL_SOURCES"]
    sources = [s.strip() for s in sources_config.split(',')]
    
    print(f"📊 IP池来源配置: {sources_config}")
    
    total_test_pool = {}
    
    # 1. 自定义域名和IP
    if '1' in sources:
        domains_with_comments, individual_ips_with_comments, _ = parse_custom_ips_file()
        
        for domain, comment in domains_with_comments.items():
            total_test_pool[domain] = {
                "type": "domain",
                "comment": comment,
                "source": "custom",
                "domain": domain
            }
        
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
        custom_ip_count = min(CONFIG["IP_POOL_SIZE"] // 3, 1000)
        
        custom_ip_pool = {}
        if custom_subnets_with_comments:
            print(f"🔧 从 {len(custom_subnets_with_comments)} 个自定义IP段生成IP...")
            
            total_generated = 0
            pbar = tqdm(total=min(custom_ip_count, len(custom_subnets_with_comments) * 10), 
                       desc="生成自定义IP段", unit="IP")
            
            for subnet, comment in custom_subnets_with_comments.items():
                if total_generated >= custom_ip_count:
                    break
                    
                for _ in range(10):
                    if total_generated >= custom_ip_count:
                        break
                        
                    ip = generate_random_ip_fast(subnet)
                    if ip not in custom_ip_pool:
                        custom_ip_pool[ip] = {
                            "type": "ip",
                            "comment": comment,
                            "source": "custom",
                            "domain": f"网段:{subnet}"
                        }
                        total_generated += 1
                        pbar.update(1)
            
            pbar.close()
        
        total_test_pool.update(custom_ip_pool)
        print(f"✅ 来源2 - 自定义IP段: {len(custom_ip_pool)} 个IP")
    
    # 更新全局信息
    global ip_details, domain_details
    for target, info in total_test_pool.items():
        if info["type"] == "ip":
            ip_details[target] = info
        else:
            domain_details[target] = info
    
    full_test_pool = list(total_test_pool.keys())
    random.shuffle(full_test_pool)
    
    domain_count = sum(1 for x in total_test_pool.values() if x['type'] == 'domain')
    ip_count = sum(1 for x in total_test_pool.values() if x['type'] == 'ip')
    
    print(f"✅ 测试目标池生成完成: 总计 {len(full_test_pool)} 个目标 ({domain_count}个域名, {ip_count}个IP)")
    
    # 抽样测试目标
    test_count = min(CONFIG["TEST_IP_COUNT"], len(full_test_pool))
    test_pool = random.sample(full_test_pool, test_count)
    print(f"🔧 随机选择 {len(test_pool)} 个目标进行测试")
    
    return test_pool, total_test_pool

def fetch_ip_ranges():
    """获取Cloudflare官方IP段"""
    return []  # 暂时不获取官方IP段

def tcp_ping(target, port, timeout=2, is_domain=False):
    """TCP Ping测试"""
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
    """速度测试"""
    url = CONFIG["SPEED_URL"]
    timeout = CONFIG["SPEED_TIMEOUT"]
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        
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
    except Exception:
        return 0.0

# [此处保留其他辅助函数...]

####################################################
# 修改主逻辑 - 使用自动调整阈值
####################################################
if __name__ == "__main__":
    # 初始化环境
    for key, value in CONFIG.items():
        os.environ[key] = str(value)
    
    print("="*60)
    print(f"{'Cloudflare优选工具 - 宽松版':^60}")
    print("="*60)
    print(f"延迟范围: {CONFIG['RTT_RANGE']}ms")
    print(f"最大丢包: {CONFIG['LOSS_MAX']}%")
    print(f"自动调整: 启用 (最少{CONFIG['MIN_TEST_TARGETS']}个目标)")
    print("="*60)

    # 生成测试目标池
    test_pool, target_info_map = generate_ip_pool()
    if not test_pool:
        print("❌ 无法生成测试目标池，程序终止")
        exit(1)

    # 延迟测试
    ping_results = []
    print(f"\n🚀 开始延迟测试...")
    
    with ThreadPoolExecutor(max_workers=CONFIG["THREADS"]) as executor:
        future_to_target = {executor.submit(smart_ping_test, target): target for target in test_pool}
        with tqdm(total=len(test_pool), desc="延迟测试", unit="目标") as pbar:
            for future in as_completed(future_to_target):
                try:
                    result = future.result(timeout=10)
                    ping_results.append(result)
                except Exception:
                    pass
                finally:
                    pbar.update(1)

    # 使用自动调整阈值筛选目标
    passed_targets = auto_adjust_threshold(ping_results)
    
    if not passed_targets:
        print("❌ 没有通过延迟测试的目标")
        
        # 显示一些统计信息帮助调试
        valid_rtts = [rtt for _, rtt, _, _ in ping_results if rtt < float('inf')]
        if valid_rtts:
            print(f"📊 有效延迟统计: 最小值{min(valid_rtts):.1f}ms, 最大值{max(valid_rtts):.1f}ms, 平均值{np.mean(valid_rtts):.1f}ms")
        exit(1)

    # 显示通过的目标信息
    domain_count = sum(1 for t in passed_targets if t[3])
    ip_count = sum(1 for t in passed_targets if not t[3])
    
    print(f"✅ 延迟测试完成: 总数 {len(ping_results)}, 通过 {len(passed_targets)} ({domain_count}个域名, {ip_count}个IP)")
    
    # 简单测速和结果处理
    print(f"\n📊 进行简单测速...")
    final_results = []
    
    for target_data in passed_targets[:CONFIG["TOP_IPS_LIMIT"]]:  # 只对前N个测速
        speed = speed_test(target_data[0], is_domain=target_data[3])
        target_info = target_info_map.get(target_data[0], {})
        country_code = 'DOM' if target_data[3] else 'UN'
        
        final_results.append({
            'target': target_data[0],
            'rtt': target_data[1],
            'loss': target_data[2],
            'speed': speed,
            'countryCode': country_code,
            'comment': target_info.get('comment', ''),
            'source': target_info.get('source', 'custom'),
            'domain': target_info.get('domain', target_data[0]),
            'type': 'domain' if target_data[3] else 'ip'
        })

    # 按延迟排序
    final_results.sort(key=lambda x: x['rtt'])
    
    # 保存结果
    os.makedirs('results', exist_ok=True)
    
    with open('results/best_targets.txt', 'w', encoding='utf-8') as f:
        for target_data in final_results:
            line = f"{target_data['target']}:{CONFIG['PORT']}#[{target_data['comment']}] {target_data['countryCode']}\n"
            f.write(line)

    # 显示结果
    print(f"\n🏆 最佳目标 TOP10:")
    for i, target_data in enumerate(final_results[:10], 1):
        print(f"{i:2d}. {target_data['target']:25} [{target_data['comment']:10}] "
              f"{target_data['rtt']:5.1f}ms {target_data['loss']:4.1f}% {target_data['speed']:5.1f}Mbps")

    print(f"\n✅ 结果已保存至: results/best_targets.txt")
    print("="*60)
