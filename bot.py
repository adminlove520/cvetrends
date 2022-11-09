import json
import requests
from cpe import CPE

from utils import Color


class feishuBot:
    """飞书群机器人
    https://open.feishu.cn/document/ukTMukTMukTM/ucTM5YjL3ETO24yNxkjN
    """

    def __init__(self, key, proxy_url='') -> None:
        self.key = key
        self.proxy = {'http': proxy_url, 'https': proxy_url} if proxy_url else {'http': None, 'https': None}

    def make_card_trends(self, hit: bool, cve: dict):
        vendor = product = None
        if vendors := cve['vendors']:
            vendor = vendors[0]['vendor']
            product = vendors[0]['products'][0]['product']

        publishedDate = cve['publishedDate'][:10] if cve['publishedDate'] else None
        lastModifiedDate = cve['lastModifiedDate'][:10] if cve['lastModifiedDate'] else None
        epss_score = '{:.2%}'.format(float(cve['epss_score'] or 0))
        vendor_advisories = cve['vendor_advisories'][0] if cve['vendor_advisories'] else None
        github = '\n'.join([i['url'] for i in cve['github_repos']])
        reddit = '\n'.join([i['reddit_url'] for i in cve['reddit_posts']])
        twitter = '\n'.join([f'https://twitter.com/{i["twitter_user_handle"]}/status/{i["tweet_id"]}' for i in cve['tweets']])

        return {
            'header': {
                'template': 'red' if hit else 'orange',
                'title': {
                    'content': f'【热门漏洞】{cve["cve"]} | {vendor} - {product}',
                    'tag': 'plain_text'
                }
            },
            'elements': [
                {
                    'tag': 'div',
                    'fields': [
                        {
                            'is_short': True,
                            'text': {
                                'content': f'**漏洞时间**\n公开：{publishedDate}\n更新：{lastModifiedDate}',
                                'tag': 'lark_md'
                            }
                        },
                        {
                            'is_short': True,
                            'text': {
                                'content': f'**漏洞等级**\nCVSS：{cve["severity"]}\nEPSS：{epss_score}',
                                'tag': 'lark_md'
                            }
                        }
                    ]
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**漏洞公告**\nhttps://nvd.nist.gov/vuln/detail/{cve["cve"]}\n{vendor_advisories or ""}',
                        'tag': 'lark_md'
                    }
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**漏洞概要**\n{cve["description"] or cve["tweets"][0]["tweet_text"]}',
                        'tag': 'lark_md'
                    }
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**GitHub**\n{github}',
                        'tag': 'lark_md'
                    }
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**Reddit**\n{reddit}',
                        'tag': 'lark_md'
                    }
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**Twitter**\n{twitter}',
                        'tag': 'lark_md'
                    }
                }
            ]
        }

    def make_card_last(self, hit: bool, cve: dict):
        vendor = product = None
        if cpe_list := cve['vulnerable_product']:
            cpe = CPE(cpe_list[0])
            vendor = cpe.get_vendor()[0]
            product = cpe.get_product()[0]

        Published = cve['Published'][:10] if cve['Published'] else None
        Modified = cve['Modified'][:10] if cve['Modified'] else None
        references = '\n'.join(cve['references'])

        return {
            'header': {
                'template': 'red' if hit else 'orange',
                'title': {
                    'content': f'【最新漏洞】{cve["id"]} | {vendor} - {product}',
                    'tag': 'plain_text'
                }
            },
            'elements': [
                {
                    'tag': 'div',
                    'fields': [
                        {
                            'is_short': True,
                            'text': {
                                'content': f'**漏洞时间**\n公开：{Published}\n更新：{Modified}',
                                'tag': 'lark_md'
                            }
                        },
                        {
                            'is_short': True,
                            'text': {
                                'content': f'**漏洞等级**\nCVSS：{str(cve["cvss"])}',
                                'tag': 'lark_md'
                            }
                        }
                    ]
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**漏洞公告**\nhttps://nvd.nist.gov/vuln/detail/{cve["id"]}',
                        'tag': 'lark_md'
                    }
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**漏洞概要**\n{cve["summary"]}',
                        'tag': 'lark_md'
                    }
                },
                {
                    'tag': 'div',
                    'text': {
                        'content': f'**References**\n{references}',
                        'tag': 'lark_md'
                    }
                }
            ]
        }

    def send_trends(self, cves: list):
        for cve in cves:
            r = self.send(self.make_card_trends(cve[0], cve[1]))
            if r.status_code == 200:
                Color.print_success(f'[+] feishuBot 发送成功 {cve[1]["cve"]}')
            else:
                Color.print_failed(f'[-] feishuBot 发送失败 {cve[1]["cve"]}')
                print(r.text)

    def send_last(self, cves: list):
        for cve in cves:
            r = self.send(self.make_card_last(cve[0], cve[1]))
            if r.status_code == 200:
                Color.print_success(f'[+] feishuBot 发送成功 {cve[1]["id"]}')
            else:
                Color.print_failed(f'[-] feishuBot 发送失败 {cve[1]["id"]}')
                print(r.text)

    def send(self, card: dict):
        data = {'msg_type': 'interactive', 'card': card}
        headers = {'Content-Type': 'application/json'}
        url = f'https://open.feishu.cn/open-apis/bot/v2/hook/{self.key}'
        return requests.post(url=url, headers=headers, data=json.dumps(data), proxies=self.proxy)
