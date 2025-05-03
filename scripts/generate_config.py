#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
配置文件生成脚本
用于生成 AdGuard Home 的配置文件，包括白名单模式和黑名单模式
"""

import os
import sys
import json
import logging
import datetime
import urllib.request
from urllib.error import URLError
from typing import Dict, List, Set

# 避免循环导入
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import extract_domains

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('generate_config')

def load_config() -> dict:
    """加载配置文件"""
    config_path = os.path.join('config', 'config.json')
    
    if not os.path.exists(config_path):
        # 如果配置文件不存在，创建默认配置
        config = {
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
        logger.info(f"已创建默认配置文件 {config_path}")
    else:
        # 读取现有配置
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    
    return config

def process_sources(sources, custom_file=None) -> set:
    """处理源列表，下载并提取域名"""
    all_domains = set()
    
    for source in sources:
        content = extract_domains.download_file(source)
        if content:
            domains = extract_domains.extract_domains_from_file(content, source)
            logger.info(f"从 {source} 中提取了 {len(domains)} 个域名")
            all_domains.update(domains)
    
    if custom_file and os.path.exists(custom_file):
        custom_domains = extract_domains.read_custom_domains(custom_file)
        logger.info(f"从自定义文件中读取了 {len(custom_domains)} 个域名")
        all_domains.update(custom_domains)
    
    return all_domains

def read_custom_domain_dns(file_path: str) -> Dict[str, List[str]]:
    """读取自定义域名DNS配置
    
    文件格式:
    domain1.com: dns1, dns2, dns3
    domain2.com: dns4
    # 注释行
    """
    custom_dns = {}
    
    if not os.path.exists(file_path):
        logger.info(f"自定义域名DNS文件不存在: {file_path}")
        return custom_dns
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            
            # 跳过空行和注释
            if not line or line.startswith('#'):
                continue
            
            # 解析格式: domain: dns1, dns2, dns3
            if ':' not in line:
                logger.warning(f"第 {line_num} 行格式错误，缺少冒号: {line}")
                continue
            
            parts = line.split(':', 1)
            domain = parts[0].strip()
            dns_servers = [dns.strip() for dns in parts[1].split(',') if dns.strip()]
            
            if not domain:
                logger.warning(f"第 {line_num} 行域名为空")
                continue
            
            if not dns_servers:
                logger.warning(f"第 {line_num} 行DNS服务器为空")
                continue
            
            # 验证域名格式（允许TLD如cn、hk等）
            if not extract_domains.is_valid_domain(domain) and domain not in ['cn', 'hk', 'mo', 'tw', 'jp', 'kr', 'sg']:
                logger.warning(f"第 {line_num} 行域名格式无效: {domain}")
                continue
            
            custom_dns[domain] = dns_servers
            logger.info(f"添加自定义DNS规则: {domain} -> {dns_servers}")
    
    logger.info(f"从自定义DNS文件中读取了 {len(custom_dns)} 条规则")
    return custom_dns

def generate_whitelist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns=None) -> str:
    """生成白名单模式配置（命中国内域名走国内DNS，其他走国外DNS）"""
    config_lines = []
    
    # 添加头部注释
    config_lines.append("# AdGuard Home DNS 分流配置 - 白名单模式")
    config_lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    config_lines.append("# 白名单模式：命中国内域名走国内DNS，其他走国外DNS")
    if custom_domain_dns:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    
    # 添加默认上游DNS服务器（国外）
    config_lines.append("# 默认上游DNS服务器（国外）")
    for dns in foreign_dns:
        config_lines.append(dns)
    config_lines.append("")
    
    # 先添加自定义域名DNS规则（优先级最高）
    if custom_domain_dns:
        config_lines.append("#" + "="*50)
        config_lines.append(f"# 自定义域名DNS规则（共 {len(custom_domain_dns)} 个域名）")
        config_lines.append("# 这些规则优先级最高，会覆盖下面的国内/国外规则")
        config_lines.append("#" + "="*50)
        for domain, dns_list in sorted(custom_domain_dns.items()):
            dns_string = ' '.join(dns_list)
            config_lines.append(f"[/{domain}/]{dns_string}")
        config_lines.append("")
    
    # 从国内域名中排除已有自定义DNS的域名
    cn_domains_filtered = cn_domains - set(custom_domain_dns.keys()) if custom_domain_dns else cn_domains
    
    # 添加国内域名规则
    config_lines.append("#" + "="*50)
    config_lines.append(f"# 国内域名规则（共 {len(cn_domains_filtered)} 个域名）")
    if custom_domain_dns and len(cn_domains) != len(cn_domains_filtered):
        config_lines.append(f"# 已排除 {len(cn_domains) - len(cn_domains_filtered)} 个自定义DNS域名")
    config_lines.append("#" + "="*50)
    for domain in sorted(cn_domains_filtered):
        dns_list = ' '.join(cn_dns)
        config_lines.append(f"[/{domain}/]{dns_list}")
    
    return '\n'.join(config_lines)

def generate_blacklist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns=None) -> str:
    """生成黑名单模式配置（命中国外域名走国外DNS，其他走国内DNS）"""
    config_lines = []
    
    # 添加头部注释
    config_lines.append("# AdGuard Home DNS 分流配置 - 黑名单模式")
    config_lines.append(f"# 自动生成于 {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    config_lines.append("# 黑名单模式：命中国外域名走国外DNS，其他走国内DNS")
    if custom_domain_dns:
        config_lines.append("# 包含自定义域名DNS规则")
    config_lines.append("")
    
    # 添加默认上游DNS服务器（国内）
    config_lines.append("# 默认上游DNS服务器（国内）")
    for dns in cn_dns:
        config_lines.append(dns)
    config_lines.append("")
    
    # 先添加自定义域名DNS规则（优先级最高）
    if custom_domain_dns:
        config_lines.append("#" + "="*50)
        config_lines.append(f"# 自定义域名DNS规则（共 {len(custom_domain_dns)} 个域名）")
        config_lines.append("# 这些规则优先级最高，会覆盖下面的国内/国外规则")
        config_lines.append("#" + "="*50)
        for domain, dns_list in sorted(custom_domain_dns.items()):
            dns_string = ' '.join(dns_list)
            config_lines.append(f"[/{domain}/]{dns_string}")
        config_lines.append("")
    
    # 从国外域名中排除已有自定义DNS的域名
    foreign_domains_filtered = foreign_domains - set(custom_domain_dns.keys()) if custom_domain_dns else foreign_domains
    
    # 添加国外域名规则
    config_lines.append("#" + "="*50)
    config_lines.append(f"# 国外域名规则（共 {len(foreign_domains_filtered)} 个域名）")
    if custom_domain_dns and len(foreign_domains) != len(foreign_domains_filtered):
        config_lines.append(f"# 已排除 {len(foreign_domains) - len(foreign_domains_filtered)} 个自定义DNS域名")
    config_lines.append("#" + "="*50)
    for domain in sorted(foreign_domains_filtered):
        dns_list = ' '.join(foreign_dns)
        config_lines.append(f"[/{domain}/]{dns_list}")
    
    return '\n'.join(config_lines)

def debug_domain(domains, domain_to_check):
    """调试指定域名是否在域名列表中"""
    if domain_to_check in domains:
        logger.info(f"域名 {domain_to_check} 在列表中")
    else:
        logger.info(f"域名 {domain_to_check} 不在列表中")
        # 查找相似域名
        similar_domains = [d for d in domains if domain_to_check in d or d in domain_to_check]
        if similar_domains:
            logger.info(f"找到相似域名: {similar_domains}")

def remove_duplicates_in_list(domains):
    """在单个列表内部去重"""
    initial_count = len(domains)
    unique_domains = set(domains)
    if len(unique_domains) < initial_count:
        logger.info(f"从列表中移除了 {initial_count - len(unique_domains)} 个重复域名")
    return unique_domains

def main():
    """主函数"""
    # 加载配置
    config = load_config()
    
    # 获取DNS服务器
    default_cn_dns = ["https://doh.pub/dns-query", "https://dns.alidns.com/dns-query"]
    default_foreign_dns = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]
    
    cn_dns = extract_domains.read_dns_servers(os.path.join('config', 'cn_dns.txt'), default_cn_dns)
    foreign_dns = extract_domains.read_dns_servers(os.path.join('config', 'foreign_dns.txt'), default_foreign_dns)
    
    # 读取自定义域名DNS配置
    custom_domain_dns = read_custom_domain_dns(os.path.join('config', 'custom_domain_dns.txt'))
    
    logger.info(f"使用国内DNS服务器: {cn_dns}")
    logger.info(f"使用国外DNS服务器: {foreign_dns}")
    logger.info(f"自定义域名DNS规则数: {len(custom_domain_dns)}")
    
    # 获取域名源
    cn_sources = config.get('sources', {}).get('cn_domains', [])
    foreign_sources = config.get('sources', {}).get('foreign_domains', [])
    
    # 提取域名
    logger.info("开始提取国内域名...")
    cn_domains = process_sources(cn_sources, os.path.join('config', 'custom_cn_domains.txt'))
    
    logger.info("开始提取国外域名...")
    foreign_domains = process_sources(foreign_sources, os.path.join('config', 'custom_foreign_domains.txt'))
    
    # 单独在各自列表内去重
    logger.info("对国内域名列表进行去重...")
    cn_domains = remove_duplicates_in_list(cn_domains)
    logger.info(f"去重后国内域名数量: {len(cn_domains)}")
    
    logger.info("对国外域名列表进行去重...")
    foreign_domains = remove_duplicates_in_list(foreign_domains)
    logger.info(f"去重后国外域名数量: {len(foreign_domains)}")
    
    # 生成配置文件
    logger.info("生成白名单模式配置文件...")
    whitelist_config = generate_whitelist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns)
    
    logger.info("生成黑名单模式配置文件...")
    blacklist_config = generate_blacklist_config(cn_domains, foreign_domains, cn_dns, foreign_dns, custom_domain_dns)
    
    # 确保目录存在
    os.makedirs('dist', exist_ok=True)
    
    # 保存配置文件
    with open(os.path.join('dist', 'whitelist_mode.txt'), 'w', encoding='utf-8') as f:
        f.write(whitelist_config)
    
    with open(os.path.join('dist', 'blacklist_mode.txt'), 'w', encoding='utf-8') as f:
        f.write(blacklist_config)
    
    # 保存域名列表（用于调试）
    with open(os.path.join('dist', 'cn_domains.txt'), 'w', encoding='utf-8') as f:
        for domain in sorted(cn_domains):
            f.write(f"{domain}\n")
    
    with open(os.path.join('dist', 'foreign_domains.txt'), 'w', encoding='utf-8') as f:
        for domain in sorted(foreign_domains):
            f.write(f"{domain}\n")
    
    # 保存自定义域名DNS列表（用于调试）
    if custom_domain_dns:
        with open(os.path.join('dist', 'custom_domain_dns_debug.txt'), 'w', encoding='utf-8') as f:
            for domain, dns_list in sorted(custom_domain_dns.items()):
                f.write(f"{domain}: {', '.join(dns_list)}\n")
    
    logger.info("配置文件生成完成")
    logger.info(f"白名单模式：共 {len(cn_domains)} 个国内域名")
    logger.info(f"黑名单模式：共 {len(foreign_domains)} 个国外域名")
    logger.info(f"自定义域名DNS：共 {len(custom_domain_dns)} 个域名")
    
    # 统计被覆盖的域名
    if custom_domain_dns:
        cn_overridden = len(cn_domains.intersection(set(custom_domain_dns.keys())))
        foreign_overridden = len(foreign_domains.intersection(set(custom_domain_dns.keys())))
        
        if cn_overridden > 0:
            logger.info(f"自定义DNS覆盖了 {cn_overridden} 个国内域名")
        if foreign_overridden > 0:
            logger.info(f"自定义DNS覆盖了 {foreign_overridden} 个国外域名")

if __name__ == "__main__":
    main()
