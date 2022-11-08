import json
import pprint
from colorama import Fore
from pathlib import Path
from datetime import datetime, timedelta


class Color:
    @staticmethod
    def print_focus(data: str):
        print(Fore.YELLOW+data+Fore.RESET)

    @staticmethod
    def print_success(data: str):
        print(Fore.LIGHTGREEN_EX+data+Fore.RESET)

    @staticmethod
    def print_failed(data: str):
        print(Fore.LIGHTRED_EX+data+Fore.RESET)

    @staticmethod
    def print(data):
        pprint.pprint(data)


class Db:
    def __init__(self, db_path: Path, hours: int):
        self.db_path = db_path
        self.hours = hours      # 保留时间

    def get_last(self):
        """获取最近更新的30个CVE"""
        if self.db_path.joinpath('last.json').exists():
            with open(self.db_path.joinpath('last.json')) as f:
                return json.load(f)
        else:
            return []

    def find_new_last(self, data: list):
        """寻找新漏洞"""
        old_cves = [i['id'] for i in self.get_last()]
        return [i for i in data if i['id'] not in old_cves]

    def add_last(self, data: list):
        """创建last文件，如果存在则替换"""
        del_keys = ['capec', 'vulnerable_configuration', 'vulnerable_configuration_cpe_2_2', 'vulnerable_product']
        for d in data:
            [d.pop(key) for key in del_keys if key in d]

        with open(self.db_path.joinpath('last.json'), 'w+') as f:
            json.dump(data, f, indent=4)

    def get_files(self):
        """获取文件列表"""
        return sorted([i for i in self.db_path.iterdir() if i.suffix == '.json' and i.name != 'last.json'])

    def get_filenames(self):
        """获取文件名列表"""
        return sorted([i.stem for i in self.get_files()])

    def find_new(self, data: list):
        """寻找新漏洞"""
        old_cves = []
        for file in self.get_files():
            with open(file) as f:
                old_data = json.load(f)['data']
            for i in old_data:
                if i['cve'] not in old_cves:
                    old_cves.append(i['cve'])

        return [i for i in data if i['cve'] not in old_cves]

    def add_file(self, filename: str, data: dict):
        """创建文件"""
        del_keys = ['timegraph_data']
        for d in data['data']:
            [d.pop(key) for key in del_keys if key in d]

        with open(self.db_path.joinpath(f'{filename}.json'), 'w+') as f:
            json.dump(data, f, indent=4)

    def cleanup(self):
        """清理超出保留时间的文件"""
        files = self.get_files()
        end = datetime.strptime(files[-1].stem, "%Y-%m-%d %H:%M:%S")
        for file in files:
            if end - datetime.strptime(file.stem, "%Y-%m-%d %H:%M:%S") > timedelta(hours=self.hours):
                file.unlink(missing_ok=True)
