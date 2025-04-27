#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
域名提取和转换脚本
用于从各种格式的域名列表中提取域名，并转换为AdGuard Home可用的格式
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
                        # 尝试直接匹配域名
                        if is_valid_domain(item):
                            domains.add(item)
                        else:
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
                        # 尝试直接匹配域名
                        if is_valid_domain(item):
                            domains.add(item)
                        else:
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
                if is_valid_domain(line):
                    domains.add(line)
                else:
                    match = CLASH_DOMAIN_PATTERN.match(line)
                    if match:
                        domain = match.group(1)
                        if is_valid_domain(domain):
                            domains.add(domain)
    
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

if __name__ == "__main__":
    # 这个脚本可以独立运行进行测试
    if len(sys.argv) > 1:
        url = sys.argv[1]
        content = download_file(url)
        domains = extract_domains_from_file(content, url)
        print(f"提取到 {len(domains)} 个域名")
        for domain in sorted(list(domains)[:10]):
            print(domain)
        if len(domains) > 10:
            print("...")
