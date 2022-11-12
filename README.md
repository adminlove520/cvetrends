# cvetrends

一个方便获取实时漏洞趋势的爬虫和推送程序，支持对厂商/产品和关键词进行过滤。

- [cvetrends](#cvetrends)
  - [安装](#安装)
  - [运行](#运行)
    - [本地搭建](#本地搭建)
    - [Github Actions](#github-actions)
  - [关注我们](#关注我们)


## 安装

```sh
$ git clone https://github.com/VulnTotal-Team/cvetrends.git
$ cd cvetrends && pip install -r requirements.txt
```

## 运行

### 本地搭建

编辑配置文件 `config.json`，启用所需的订阅源和机器人（key 也可以通过环境变量传入），最好启用代理。

```sh
$ ./cvetrends.py --help     
usage: cvetrends.py [-h] [-t {day,week}] [-c CRON] [-d DB] [-f CONFIG]

options:
  -h, --help            show this help message and exit
  -t {day,week}, --time {day,week}
                        Time frame to search for CVEs
  -c CRON, --cron CRON  Execute scheduled tasks every X minutes
  -d DB, --db DB        Keep database files X hours
  -f CONFIG, --config CONFIG
                        Use specified config file

# 单次任务
$ ./cvetrends.py -t day

# 10分钟定时任务，数据库保留6小时
$ nohup ./cvetrends.py -t day -c 10 -d 6 > run.log 2>&1 &
```

### Github Actions

利用 Github Actions 提供的服务，你只需要 fork 本项目，在 Settings 中添加 secrets，即可完成部署。

目前支持的推送机器人及对应的 secrets：
- [飞书群机器人](https://open.feishu.cn/document/ukTMukTMukTM/ucTM5YjL3ETO24yNxkjN)：`FEISHU_KEY`

## 关注我们

[VulnTotal安全团队](https://github.com/VulnTotal-Team)成立于2022年。致力于分享高质量原创文章和开源工具，包括Web安全、移动安全、物联网/汽车安全、代码审计、网络攻防等，欢迎[关注或加入我们](https://github.com/VulnTotal-Team/.github/blob/main/README.md)！

GNU General Public License v3.0

[![Stargazers over time](https://starchart.cc/VulnTotal-Team/cvetrends.svg)](https://starchart.cc/VulnTotal-Team/cvetrends)
