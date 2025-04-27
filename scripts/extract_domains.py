#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
脚本用于从各种格式的域名列表中提取域名，并转换为AdGuard Home可用的格式。
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
CLASH_DOMAIN_PATTERN = re.compile(r'.*(?:DOMAIN|domain)[,:]\s*([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)')
DNSMASQ_PATTERN = re.compile(r'server=/([^/]+)/')
ADBLOCK_PATTERN = re.compile(r'^\|\|([a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)\^')

def download_file(url: str) -> str:
    """从URL下载文件内容"""
    try:
        logger.info(f"下载文件：{url}")
        with urllib.request.urlopen(url) as response:
            return response.read().decode('utf-8', errors='ignore')
    except URLError as e:
        logger.error(f"下载 {url} 失败：{e}")
        return ""

def is_valid_domain(domain: str) -> bool:
    """验证域名是否有效"""
    if not domain or len(domain) > 253:
        return False
    if domain.startswith('.') or domain.endswith('.'):
        return False
    return bool(DOMAIN_PATTERN.match(domain))

def extract_domains_from_yaml(content: str) -> Set[str]:
    """从YAML格式的Clash规则列表中提取域名"""
    domains = set()
    try:
        # 尝试解析YAML
        data = yaml.safe_load(content)
        
        # 处理不同格式的Clash规则
        if isinstance(data, dict):
            # 检查是否存在payload字段（通常在Providers文件中）
            if 'payload' in data and isinstance(data['payload'], list):
                for item in data['payload']:
                    if isinstance(item, str):
                        # 提取DOMAIN或DOMAIN-SUFFIX规则
                        match = CLASH_DOMAIN_PATTERN.match(item)
                        if match:
                            domain = match.group(1)
                            if is_valid_domain(domain):
                                domains.add(domain)
            
            # 检查是否存在rules字段
            elif 'rules' in data and isinstance(data['rules'], list):
                for item in data['rules']:
                    if isinstance(item, str):
                        # 提取DOMAIN或DOMAIN-SUFFIX规则
                        match = CLASH_DOMAIN_PATTERN.match(item)
                        if match:
                            domain = match.group(1)
                            if is_valid_domain(domain):
                                domains.add(domain)
                                
            # 处理domain-set格式
            elif 'domains' in data and isinstance(data['domains'], list):
                for domain in data['domains']:
                    if isinstance(domain, str) and is_valid_domain(domain):
                        domains.add(domain)
        
        # 有些文件可能直接是列表
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, str):
                    # 检查是否为纯域名
                    if is_valid_domain(item):
                        domains.add(item)
                    else:
                        # 提取DOMAIN或DOMAIN-SUFFIX规则
                        match = CLASH_DOMAIN_PATTERN.match(item)
                        if match:
                            domain = match.group(1)
                            if is_valid_domain(domain):
                                domains.add(domain)
                                
    except yaml.YAMLError as e:
        logger.error(f"解析YAML失败：{e}")
        # 尝试逐行解析
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'):
                match = CLASH_DOMAIN_PATTERN.match(line)
                if match:
                    domain = match.group(1)
                    if is_valid_domain(domain):
                        domains.add(domain)
                elif is_valid_domain(line):
                    domains.add(line)
    
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
    return domains

def extract_domains_from_adblock(content: str) -> Set[str]:
    """从Adblock格式的域名列表中提取域名"""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith('!') and not line.startswith('#'):
            match = ADBLOCK_PATTERN.match(line)
            if match:
                domain = match.group(1)
                if is_valid_domain(domain):
                    domains.add(domain)
            elif is_valid_domain(line):
                domains.add(line)
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
    except Exception as e:
        logger.error(f"解析GFWList失败：{e}")
    
    return domains

def extract_domains_from_plain_text(content: str) -> Set[str]:
    """从普通文本格式的域名列表中提取域名"""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith('#'):
            if is_valid_domain(line):
                domains.add(line)
    return domains

def extract_domains_from_file(content: str, file_url: str) -> Set[str]:
    """根据文件类型提取域名"""
    file_name = file_url.split('/')[-1].lower()
    
    # 根据文件扩展名或内容判断文件类型
    if file_name.endswith('.yaml') or file_name.endswith('.yml'):
        return extract_domains_from_yaml(content)
    elif file_name.endswith('.conf'):
        return extract_domains_from_dnsmasq(content)
    elif file_name == 'gfwlist.txt':
        return extract_domains_from_gfwlist(content)
    elif '.list' in file_name:
        # 先尝试作为Clash规则解析
        domains = extract_domains_from_yaml(content)
        if not domains:
            # 如果没有提取到域名，再尝试作为普通文本解析
            domains = extract_domains_from_plain_text(content)
        return domains
    else:
        # 尝试各种格式
        domains = extract_domains_from_yaml(content)
        if not domains:
            domains = extract_domains_from_dnsmasq(content)
        if not domains:
            domains = extract_domains_from_adblock(content)
        if not domains:
            domains = extract_domains_from_plain_text(content)
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
    
    return domains

def read_config() -> Dict[str, Any]:
    """读取配置文件"""
    config_path = os.path.join('config', 'config.json')
    
    if not os.path.exists(config_path):
        # 如果配置文件不存在，创建默认配置
        config = {
            "cn_dns_enabled": True,
            "foreign_dns_enabled": True,
            "use_default_cn_dns": True,
            "use_default_foreign_dns": True,
            "sources": {
                "cn_domains": [
                    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaDomain.yaml",
                    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ChinaMedia.yaml",
                    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/ChinaMax/ChinaMax_Domain.yaml",
                    "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
                ],
                "foreign_domains": [
                    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Proxy/Proxy_Domain.yaml",
                    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyGFWlist.yaml",
                    "https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/Providers/ProxyMedia.yaml",
                    "https://raw.githubusercontent.com/gfwlist/gfwlist/master/gfwlist.txt"
                ]
            }
        }
        
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
    else:
        # 读取现有配置
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    
    return config

def generate_dns_files() -> None:
    """生成DNS服务器配置文件"""
    config = read_config()
    
    # 默认DNS服务器
    default_cn_dns = [
        "https://doh.pub/dns-query",
        "https://dns.alidns.com/dns-query"
    ]
    
    default_foreign_dns = [
        "https://1.1.1.1/dns-query",
        "https://8.8.8.8/dns-query"
    ]
    
    # 读取自定义DNS服务器
    cn_dns_path = os.path.join('config', 'cn_dns.txt')
    foreign_dns_path = os.path.join('config', 'foreign_dns.txt')
    
    cn_dns = []
    if os.path.exists(cn_dns_path):
        with open(cn_dns_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    cn_dns.append(line)
    
    foreign_dns = []
    if os.path.exists(foreign_dns_path):
        with open(foreign_dns_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    foreign_dns.append(line)
    
    # 根据配置生成最终DNS服务器列表
    final_cn_dns = []
    final_foreign_dns = []
    
    if config.get('cn_dns_enabled', True):
        if cn_dns and not config.get('use_default_cn_dns', True):
            final_cn_dns = cn_dns
        else:
            final_cn_dns = default_cn_dns
    
    if config.get('foreign_dns_enabled', True):
        if foreign_dns and not config.get('use_default_foreign_dns', True):
            final_foreign_dns = foreign_dns
        else:
            final_foreign_dns = default_foreign_dns
    
    # 保存DNS服务器列表
    os.makedirs('dist', exist_ok=True)
    
    with open(os.path.join('dist', 'cn_dns_active.txt'), 'w', encoding='utf-8') as f:
        for dns in final_cn_dns:
            f.write(f"{dns}\n")
    
    with open(os.path.join('dist', 'foreign_dns_active.txt'), 'w', encoding='utf-8') as f:
        for dns in final_foreign_dns:
            f.write(f"{dns}\n")
    
    logger.info(f"已生成DNS服务器配置文件")

def main() -> None:
    """主函数"""
    # 读取配置
    config = read_config()
    
    # 获取源列表
    cn_sources = config['sources']['cn_domains']
    foreign_sources = config['sources']['foreign_domains']
    
    # 提取域名
    logger.info("开始提取国内域名...")
    cn_domains = process_sources(cn_sources)
    
    logger.info("开始提取国外域名...")
    foreign_domains = process_sources(foreign_sources)
    
    # 读取自定义域名
    custom_cn_domains = read_custom_domains(os.path.join('config', 'custom_cn_domains.txt'))
    custom_foreign_domains = read_custom_domains(os.path.join('config', 'custom_foreign_domains.txt'))
    
    # 合并域名
    cn_domains.update(custom_cn_domains)
    foreign_domains.update(custom_foreign_domains)
    
    # 确保没有重复
    common_domains = cn_domains.intersection(foreign_domains)
    if common_domains:
        logger.warning(f"发现 {len(common_domains)} 个重复的域名，从国外域名列表中移除")
        foreign_domains -= common_domains
    
    # 保存域名
    save_domains_to_file(cn_domains, os.path.join('dist', 'cn_domains.txt'))
    save_domains_to_file(foreign_domains, os.path.join('dist', 'foreign_domains.txt'))
    
    # 生成DNS服务器配置文件
    generate_dns_files()
    
    logger.info("域名提取和处理完成")

if __name__ == "__main__":
    main()
