#!/usr/bin/python3

import os
import json
import argparse
import schedule
import requests
import pyfiglet
from pathlib import Path
from cpe import CPE

from bot import *
from utils import Color, Db


def init_bot(conf: dict, proxy_url=''):
    """初始化机器人"""
    bots = []
    for name, v in conf.items():
        if v['enabled']:
            key = os.getenv(v['secrets']) or v['key']

            bot = globals()[f'{name}Bot'](key, proxy_url)
            bots.append(bot)
    return bots


def filter_trends(cve: dict):
    """根据关键词过滤"""
    keywords = conf['keywords']

    vendor = product = None
    for v in cve['vendors']:
        vendor = v['vendor']
        if vendor.upper() in [i.upper() for i in keywords['vendor']]:
            return True, vendor

        product = v['products'][0]['product']
        if product.upper() in [i.upper() for i in keywords['product']]:
            return True, product

    for i in keywords['others'] + keywords['vendor'] + keywords['product']:
        if ' '+i.upper()+' ' in (cve['description'] or '').upper():     # 前后加空格，避免误伤
            return True, i

    return False, vendor or product


def filter_last(cve: dict):
    """根据关键词过滤"""
    keywords = conf['keywords']

    vendor = product = None
    if cpe_list := cve['vulnerable_product']:
        for cpe in cpe_list:
            cpe = CPE(cpe)
            vendor = cpe.get_vendor()[0]
            if vendor.upper() in [i.upper() for i in keywords['vendor']]:
                return True, vendor

            product = cpe.get_product()[0]
            if product.upper() in [i.upper() for i in keywords['product']]:
                return True, product

    for i in keywords['others'] + keywords['vendor'] + keywords['product']:
        if ' '+i.upper()+' ' in (cve['summary']):   # 前后加空格，避免误伤
            return True, i

    return False, vendor or product


def job_trends():
    """获取热门漏洞"""
    time_frame = '24hrs' if args.time == 'day' else '7days'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36',
    }
    try:
        r = requests.get(
            f'https://cvetrends.com/api/cves/{time_frame}', headers=headers, timeout=15, proxies=conf['proxy']
        ).json()
    except Exception as e:
        Color.print_failed(f'[-] 获取数据失败：{e}')
        return

    new_file = r['updated']
    if new_file not in db.get_filenames():
        Color.print_success(f'[+] 发现新数据：{new_file}')

        # 寻找新漏洞
        if new_cves := db.find_new(r['data']):
            Color.print_focus(f'[+] 发现新漏洞：{len(new_cves)}个')
            db.add_file(new_file, r)    # 增加新数据

            filter_cves = []
            for cve in new_cves:
                hit, vendor = filter_trends(cve)
                filter_cves.append((hit, cve))
                if hit:
                    Color.print_failed(f'命中：{cve["cve"]}\t{vendor}')
                else:
                    Color.print_success(f'忽略：{cve["cve"]}\t{vendor}')

            # 机器人推送
            bots = init_bot(conf['bot'], conf['proxy'])
            for bot in bots:
                bot.send_trends(filter_cves)

            # 清理数据库
            db.cleanup()
        else:
            Color.print_success('[-] 没有新漏洞')
    else:
        Color.print_success('[-] 没有新数据')


def job_last():
    """获取最新漏洞"""
    try:
        r = requests.get(
            'https://cve.circl.lu/api/last/100', timeout=300, proxies=conf['proxy']
        ).json()
    except Exception as e:
        Color.print_failed(f'[-] 获取数据失败：{e}')
        return

    if not db.get_last():
        db.add_last(r)  # 创建文件

    # 寻找新漏洞
    if new_cves := db.find_new_last(r):
        Color.print_focus(f'[+] 发现新漏洞：{len(new_cves)}个')

        filter_cves = []
        for cve in new_cves:
            hit, vendor = filter_last(cve)
            if hit:
                Color.print_failed(f'命中：{cve["id"]}\t{vendor}')
                filter_cves.append((hit, cve))
            else:
                Color.print_success(f'忽略：{cve["id"]}\t{vendor}')

        # 机器人推送
        bots = init_bot(conf['bot'], conf['proxy'])
        for bot in bots:
            bot.send_last(filter_cves)

        db.add_last(r)  # 替换文件
    else:
        Color.print_success('[-] 没有新漏洞')


def job():
    """定时任务"""
    print(f'{pyfiglet.figlet_format("cvetrends")}\n')

    job_trends()    # 热门漏洞
    job_last()      # 最新漏洞


def argument():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--time', help='Time frame to search for CVEs', type=str, default='day', choices=['day', 'week'])
    parser.add_argument('-c', '--cron', help='Execute scheduled tasks every X minutes', type=int, required=False)
    parser.add_argument('-d', '--db', help='Keep database files X hours', type=int, required=False)
    parser.add_argument('-f', '--config', help='Use specified config file', type=str, required=False)
    return parser.parse_args()


if __name__ == '__main__':
    args = argument()

    root_path = Path(__file__).absolute().parent
    if args.config:
        config_path = Path(args.config).expanduser().absolute()
    else:
        config_path = root_path.joinpath('config.json')
    with open(config_path) as f:
        conf = json.load(f)
    db = Db(root_path.joinpath('db'), args.db or conf['db_hours'])

    if args.cron:
        schedule.every(args.cron).minutes.do(job)
        while True:
            schedule.run_pending()
    else:
        job()
