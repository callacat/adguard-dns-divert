#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
域名提取和转换脚本
用于从各种格式的域名列表中提取域名，并转换为AdGuard Home可用的格式
支持处理以下格式：
- YAML格式的Clash规则列表
- dnsmasq格式的域名列表
- GFWList格式的域名列表（Base64编码）
- 普通文本格式的域名列表
"""

import os
import re
import sys
import yaml
import base64
import json
import urllib.request
import logging
from typing import List, Set, Dict, Any
from urllib.error import URLError

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('extract_domains')

# 正则表达式
DOMAIN_PATTERN = re.compile(r'^[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+$')
DOMAIN_PREFIX_PATTERN = re.compile(r'^\.([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)$')
CLASH_DOMAIN_PATTERN = re.compile(r'.*(?:DOMAIN|domain)[,:][ ]*([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)')
CLASH_DOMAIN_SUFFIX_PATTERN = re.compile(r'.*(?:DOMAIN-SUFFIX|domain-suffix)[,:][ ]*([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)')
DNSMASQ_PATTERN = re.compile(r'server=/([^/]+)/')
ADBLOCK_PATTERN = re.compile(r'^\|\|([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)\^')
URL_PATTERN = re.compile(r'https?://([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)')

def download_file(url: str) -> str:
    """从URL下载文件内容"""
    try:
        logger.info(f"下载文件：{url}")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read().decode('utf-8', errors='ignore')
    except URLError as e:
        logger.error(f"下载 {url} 失败：{e}")
        return ""
    except Exception as e:
        logger.error(f"下载 {url} 时出现未知错误：{e}")
        return ""

def is_valid_domain(domain: str) -> bool:
    """验证域名是否有效，并且不是纯IPv4地址"""
    if not domain or len(domain) > 253:
        return False
    if domain.startswith('.'):
        domain = domain[1:]
    if domain.endswith('.'):
        return False
    if '..' in domain:
        return False

    # 新增：排除IPv4地址
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if ipv4_pattern.match(domain):
        return False

    return bool(DOMAIN_PATTERN.match(domain))

def extract_domains_from_yaml(content: str) -> Set[str]:
    """从YAML格式的Clash规则列表中提取域名"""
    domains = set()
    
    # 首先尝试直接从文本中提取域名（针对可能包含域名但不是有效YAML的情况）
    for line in content.splitlines():
        line = line.strip()
        
        # 跳过注释和空行
        if not line or line.startswith('#'):
            continue
        
        # 检查是否是DOMAIN规则
        if 'DOMAIN,' in line.upper() or 'DOMAIN:' in line.upper():
            parts = re.split(r'[,:]', line, 1)
            if len(parts) > 1:
                domain = parts[1].strip()
                if is_valid_domain(domain):
                    domains.add(domain)
        
        # 检查是否是DOMAIN-SUFFIX规则
        elif 'DOMAIN-SUFFIX,' in line.upper() or 'DOMAIN-SUFFIX:' in line.upper():
            parts = re.split(r'[,:]', line, 1)
            if len(parts) > 1:
                domain = parts[1].strip()
                if is_valid_domain(domain):
                    domains.add(domain)
        
        # 尝试直接匹配域名
        elif is_valid_domain(line):
            domains.add(line)
        # 处理 .domain.com 格式
        elif line.startswith('.') and is_valid_domain(line[1:]):
            domains.add(line[1:])
        
        # 使用通用正则匹配
        else:
            # 尝试匹配DOMAIN
            match = CLASH_DOMAIN_PATTERN.match(line)
            if match:
                domain = match.group(1)
                if is_valid_domain(domain):
                    domains.add(domain)
                continue
            
            # 尝试匹配DOMAIN-SUFFIX
            match = CLASH_DOMAIN_SUFFIX_PATTERN.match(line)
            if match:
                domain = match.group(1)
                if is_valid_domain(domain):
                    domains.add(domain)
                continue
            
            # 尝试匹配URL中的域名
            match = URL_PATTERN.search(line)
            if match:
                domain = match.group(1)
                if is_valid_domain(domain):
                    domains.add(domain)
    
    # 然后尝试解析YAML
    try:
        data = yaml.safe_load(content)
        
        # 处理不同格式的Clash规则
        if isinstance(data, dict):
            # 检查是否存在payload字段（通常在Providers文件中）
            if 'payload' in data and isinstance(data['payload'], list):
                for item in data['payload']:
                    if isinstance(item, str):
                        # 检查是否是DOMAIN规则
                        if item.startswith('DOMAIN,') or item.startswith('DOMAIN:'):
                            parts = re.split(r'[,:]', item, 1)
                            if len(parts) > 1:
                                domain = parts[1].strip()
                                if is_valid_domain(domain):
                                    domains.add(domain)
                        
                        # 检查是否是DOMAIN-SUFFIX规则
                        elif item.startswith('DOMAIN-SUFFIX,') or item.startswith('DOMAIN-SUFFIX:'):
                            parts = re.split(r'[,:]', item, 1)
                            if len(parts) > 1:
                                domain = parts[1].strip()
                                if is_valid_domain(domain):
                                    domains.add(domain)
                        
                        # 尝试直接匹配域名
                        elif is_valid_domain(item):
                            domains.add(item)
                        
                        # 使用通用正则匹配
                        else:
                            # 尝试匹配DOMAIN
                            match = CLASH_DOMAIN_PATTERN.match(item)
                            if match:
                                domain = match.group(1)
                                if is_valid_domain(domain):
                                    domains.add(domain)
                                continue
                            
                            # 尝试匹配DOMAIN-SUFFIX
                            match = CLASH_DOMAIN_SUFFIX_PATTERN.match(item)
                            if match:
                                domain = match.group(1)
                                if is_valid_domain(domain):
                                    domains.add(domain)
                                continue
                            
                            # 尝试匹配URL中的域名
                            match = URL_PATTERN.search(item)
                            if match:
                                domain = match.group(1)
                                if is_valid_domain(domain):
                                    domains.add(domain)
            
            # 检查是否存在rules字段
            elif 'rules' in data and isinstance(data['rules'], list):
                for item in data['rules']:
                    if isinstance(item, str):
                        # 检查是否是DOMAIN规则
                        if item.startswith('DOMAIN,') or item.startswith('DOMAIN:'):
                            parts = re.split(r'[,:]', item, 1)
                            if len(parts) > 1:
                                domain = parts[1].strip()
                                if is_valid_domain(domain):
                                    domains.add(domain)
                        
                        # 检查是否是DOMAIN-SUFFIX规则
                        elif item.startswith('DOMAIN-SUFFIX,') or item.startswith('DOMAIN-SUFFIX:'):
                            parts = re.split(r'[,:]', item, 1)
                            if len(parts) > 1:
                                domain = parts[1].strip()
                                if is_valid_domain(domain):
                                    domains.add(domain)
                        
                        # 尝试直接匹配域名
                        elif is_valid_domain(item):
                            domains.add(item)
                        
                        # 使用通用正则匹配
                        else:
                            # 尝试匹配DOMAIN
                            match = CLASH_DOMAIN_PATTERN.match(item)
                            if match:
                                domain = match.group(1)
                                if is_valid_domain(domain):
                                    domains.add(domain)
                                continue
                            
                            # 尝试匹配DOMAIN-SUFFIX
                            match = CLASH_DOMAIN_SUFFIX_PATTERN.match(item)
                            if match:
                                domain = match.group(1)
                                if is_valid_domain(domain):
                                    domains.add(domain)
                                continue
                            
                            # 尝试匹配URL中的域名
                            match = URL_PATTERN.search(item)
                            if match:
                                domain = match.group(1)
                                if is_valid_domain(domain):
                                    domains.add(domain)
                                
            # 处理domain-set格式
            elif 'domains' in data and isinstance(data['domains'], list):
                for domain in data['domains']:
                    if isinstance(domain, str) and is_valid_domain(domain):
                        domains.add(domain)
            
            # 尝试遍历所有可能的键值对
            else:
                for key, value in data.items():
                    if isinstance(value, list):
                        for item in value:
                            if isinstance(item, str) and is_valid_domain(item):
                                domains.add(item)
        
        # 有些文件可能直接是列表
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    # 检查是否是DOMAIN规则
                    if item.startswith('DOMAIN,') or item.startswith('DOMAIN:'):
                        parts = re.split(r'[,:]', item, 1)
                        if len(parts) > 1:
                            domain = parts[1].strip()
                            if is_valid_domain(domain):
                                domains.add(domain)
                    
                    # 检查是否是DOMAIN-SUFFIX规则
                    elif item.startswith('DOMAIN-SUFFIX,') or item.startswith('DOMAIN-SUFFIX:'):
                        parts = re.split(r'[,:]', item, 1)
                        if len(parts) > 1:
                            domain = parts[1].strip()
                            if is_valid_domain(domain):
                                domains.add(domain)
                    
                    # 尝试直接匹配域名
                    elif is_valid_domain(item):
                        domains.add(item)
                    
                    # 使用通用正则匹配
                    else:
                        # 尝试匹配DOMAIN
                        match = CLASH_DOMAIN_PATTERN.match(item)
                        if match:
                            domain = match.group(1)
                            if is_valid_domain(domain):
                                domains.add(domain)
                            continue
                        
                        # 尝试匹配DOMAIN-SUFFIX
                        match = CLASH_DOMAIN_SUFFIX_PATTERN.match(item)
                        if match:
                            domain = match.group(1)
                            if is_valid_domain(domain):
                                domains.add(domain)
                            continue
                        
                        # 尝试匹配URL中的域名
                        match = URL_PATTERN.search(item)
                        if match:
                            domain = match.group(1)
                            if is_valid_domain(domain):
                                domains.add(domain)
                
    except yaml.YAMLError as e:
        logger.warning(f"解析YAML失败，已使用文本模式提取域名：{e}")
    except Exception as e:
        logger.warning(f"解析文件时出现未知错误，已使用文本模式提取域名：{e}")
    
    return domains

def extract_domains_from_dnsmasq(content: str) -> Set[str]:
    """从dnsmasq格式的域名列表中提取域名"""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            match = DNSMASQ_PATTERN.match(line)
            if match:
                domain = match.group(1)
                if is_valid_domain(domain):
                    domains.add(domain)
            # 尝试作为普通域名处理
            elif is_valid_domain(line):
                domains.add(line)
    return domains

def extract_domains_from_adblock(content: str) -> Set[str]:
    """从Adblock格式的域名列表中提取域名"""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith('!') and not line.startswith('#'):
            # 匹配 ||example.com^ 格式
            match = ADBLOCK_PATTERN.match(line)
            if match:
                domain = match.group(1)
                if is_valid_domain(domain):
                    domains.add(domain)
            # 匹配直接的域名
            elif is_valid_domain(line):
                domains.add(line)
            # 匹配URL中的域名
            else:
                match = URL_PATTERN.search(line)
                if match:
                    domain = match.group(1)
                    if is_valid_domain(domain):
                        domains.add(domain)
    return domains

def extract_domains_from_gfwlist(content: str) -> Set[str]:
    """从GFWList格式的域名列表中提取域名"""
    domains = set()
    try:
        # GFWList是Base64编码的，先解码
        decoded_content = base64.b64decode(content).decode('utf-8', errors='ignore')
        
        # GFWList类似AdBlock格式，但有一些特殊规则
        for line in decoded_content.splitlines():
            line = line.strip()
            # 跳过注释和空行
            if not line or line.startswith('!') or line.startswith('[') or line.startswith('#'):
                continue
                
            # 处理域名格式（||example.com^）
            if line.startswith('||') and '^' in line:
                domain = line[2:line.find('^')]
                if is_valid_domain(domain):
                    domains.add(domain)
            # 处理域名格式（|https://example.com）
            elif line.startswith('|http'):
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(line[1:]).netloc
                    if is_valid_domain(domain):
                        domains.add(domain)
                except:
                    pass
            # 处理普通域名
            elif '/' not in line and '.' in line and not line.startswith('.'):
                if is_valid_domain(line):
                    domains.add(line)
            # 尝试提取URL中的域名
            else:
                match = URL_PATTERN.search(line)
                if match:
                    domain = match.group(1)
                    if is_valid_domain(domain):
                        domains.add(domain)
    except Exception as e:
        logger.error(f"解析GFWList失败：{e}")
        
        # 尝试作为普通文本处理
        try:
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith('#') and not line.startswith('!'):
                    if is_valid_domain(line):
                        domains.add(line)
        except Exception as e2:
            logger.error(f"作为普通文本处理GFWList也失败：{e2}")
    
    return domains

def extract_domains_from_plain_text(content: str) -> Set[str]:
    """从普通文本格式的域名列表中提取域名"""
    domains = set()
    header_passed = False
    
    for line in content.splitlines():
        line = line.strip()
        
        # 跳过空行和注释
        if not line or line.startswith('#'):
            continue
        
        # 检查是否是头部信息部分
        if not header_passed and "NAME:" in line:
            # 可能是blackmatrix7的域名列表头部
            header_passed = True
            continue
        
        # 处理以点开头的域名（如.example.com）
        if line.startswith('.'):
            match = DOMAIN_PREFIX_PATTERN.match(line)
            if match:
                domain = match.group(1)
                if is_valid_domain(domain):
                    domains.add(domain)
            continue
        
        # 直接的域名
        if is_valid_domain(line):
            domains.add(line)
        else:
            # 尝试匹配URL中的域名
            match = URL_PATTERN.search(line)
            if match:
                domain = match.group(1)
                if is_valid_domain(domain):
                    domains.add(domain)
    
    return domains

def extract_domains_from_blackmatrix7_domain_txt(content: str) -> Set[str]:
    """从blackmatrix7的Domain.txt格式提取域名"""
    domains = set()
    header_section = True
    
    for line in content.splitlines():
        line = line.strip()
        
        # 跳过空行
        if not line:
            continue
        
        # 跳过头部注释
        if line.startswith('#'):
            continue
        
        # 检查是否已经过了头部注释部分
        if header_section and "DOMAIN:" in line:
            header_section = False
            continue
        
        # 处理正文部分
        if not header_section:
            # 检查是否是以点开头的域名（如.example.com）
            if line.startswith('.'):
                domain = line[1:]
                if is_valid_domain(domain):
                    domains.add(domain)
            # 直接的域名
            elif is_valid_domain(line):
                domains.add(line)
    
    return domains

def extract_domains_from_file(content: str, file_url: str) -> Set[str]:
    """根据文件类型提取域名"""
    file_name = file_url.split('/')[-1].lower()
    domains = set()
    
    # 根据文件扩展名或内容判断文件类型
    if "proxy_domain.txt" in file_url.lower():
        # 这是blackmatrix7项目中的Proxy_Domain.txt格式
        domains = extract_domains_from_blackmatrix7_domain_txt(content)
        logger.info(f"从blackmatrix7 Proxy_Domain.txt中提取到 {len(domains)} 个域名")
    elif "chinamax_domain.txt" in file_url.lower() or "china_domain.txt" in file_url.lower():
        # 这是blackmatrix7项目中的ChinaMax_Domain.txt或China_Domain.txt格式
        domains = extract_domains_from_blackmatrix7_domain_txt(content)
        logger.info(f"从blackmatrix7 ChinaMax_Domain.txt中提取到 {len(domains)} 个域名")
    elif file_name.endswith('.yaml') or file_name.endswith('.yml'):
        domains = extract_domains_from_yaml(content)
        logger.info(f"从YAML文件中提取到 {len(domains)} 个域名")
    elif file_name.endswith('.conf'):
        domains = extract_domains_from_dnsmasq(content)
        logger.info(f"从dnsmasq配置文件中提取到 {len(domains)} 个域名")
    elif file_name == 'gfwlist.txt':
        domains = extract_domains_from_gfwlist(content)
        logger.info(f"从GFWList文件中提取到 {len(domains)} 个域名")
    elif '.list' in file_name:
        # 尝试作为普通文本解析
        domains = extract_domains_from_plain_text(content)
        logger.info(f"从列表文件中提取到 {len(domains)} 个域名")
    else:
        # 尝试各种格式
        logger.info("未能确定文件类型，尝试多种格式解析")
        
        # 尝试作为普通文本解析
        text_domains = extract_domains_from_plain_text(content)
        if text_domains:
            logger.info(f"作为普通文本解析提取到 {len(text_domains)} 个域名")
            domains.update(text_domains)
        
        # 如果普通文本解析提取的域名很少，尝试其他方式
        if len(domains) < 10:
            # 尝试作为YAML解析
            yaml_domains = extract_domains_from_yaml(content)
            if yaml_domains:
                logger.info(f"作为YAML解析提取到 {len(yaml_domains)} 个域名")
                domains.update(yaml_domains)
            
            # 尝试作为dnsmasq配置解析
            dnsmasq_domains = extract_domains_from_dnsmasq(content)
            if dnsmasq_domains:
                logger.info(f"作为dnsmasq配置解析提取到 {len(dnsmasq_domains)} 个域名")
                domains.update(dnsmasq_domains)
            
            # 尝试作为AdBlock规则解析
            adblock_domains = extract_domains_from_adblock(content)
            if adblock_domains:
                logger.info(f"作为AdBlock规则解析提取到 {len(adblock_domains)} 个域名")
                domains.update(adblock_domains)
            
            # 尝试作为GFWList解析
            try:
                gfwlist_domains = extract_domains_from_gfwlist(content)
                if gfwlist_domains:
                    logger.info(f"作为GFWList解析提取到 {len(gfwlist_domains)} 个域名")
                    domains.update(gfwlist_domains)
            except:
                pass
    
    return domains

def process_sources(sources: List[str]) -> Set[str]:
    """处理源列表，下载并提取域名"""
    all_domains = set()
    
    for source in sources:
        content = download_file(source)
        if content:
            domains = extract_domains_from_file(content, source)
            logger.info(f"从 {source} 中提取了 {len(domains)} 个域名")
            all_domains.update(domains)
        else:
            logger.warning(f"下载 {url} 失败或内容为空")
    
    return all_domains

def save_domains_to_file(domains: Set[str], output_file: str) -> None:
    """将域名保存到文件"""
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        for domain in sorted(domains):
            f.write(f"{domain}\n")
    
    logger.info(f"已将 {len(domains)} 个域名保存到 {output_file}")

def read_custom_domains(file_path: str) -> Set[str]:
    """读取自定义域名列表"""
    if not os.path.exists(file_path):
        return set()
    
    domains = set()
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                if is_valid_domain(line):
                    domains.add(line)
                elif line.isalpha() and len(line) <= 5:
                    # ⭐ 新增：允许 cn hk mo 等国家TLD
                    domains.add(line)
                elif line.startswith('.') and is_valid_domain(line[1:]):
                    domains.add(line[1:])
    
    return domains

def read_dns_servers(file_path: str, default_servers: List[str]) -> List[str]:
    """读取DNS服务器列表"""
    if not os.path.exists(file_path):
        return default_servers
    
    servers = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                servers.append(line)
    
    return servers if servers else default_servers

if __name__ == "__main__":
    # 这个脚本可以独立运行进行测试
    if len(sys.argv) > 1:
        url = sys.argv[1]
        content = download_file(url)
        if content:
            domains = extract_domains_from_file(content, url)
            print(f"提取到 {len(domains)} 个域名")
            for domain in sorted(list(domains)[:20]):  # 只显示前20个
                print(domain)
            if len(domains) > 20:
                print("...")
        else:
            print(f"下载 {url} 失败或内容为空")
    else:
        print("使用方法: python extract_domains.py <url>")
        print("示例: python extract_domains.py https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaDomain.yaml")
