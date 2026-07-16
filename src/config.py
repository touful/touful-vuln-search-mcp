"""配置管理模块

负责加载环境变量并提供统一的配置常量。
使用 python-dotenv 从项目根目录的 .env 文件读取配置。
"""

import os
from dotenv import load_dotenv

# 从当前模块所在目录向上查找 .env 文件 —— 项目根目录
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_env_path = os.path.join(_PROJECT_ROOT, ".env")
load_dotenv(_env_path)

# ========== NVD API Key ==========
NVD_API_KEY = os.getenv("NVD_API_KEY")
if not NVD_API_KEY:
    raise ValueError(
        "NVD_API_KEY 环境变量未设置。"
        "请在项目根目录的 .env 文件中设置 NVD_API_KEY=your_key"
    )

# ========== GitHub Token（可选）==========
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# ========== API 端点地址 ==========
NVD_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
OSV_API_BASE_URL = "https://api.osv.dev/v1"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
KEV_CATALOG_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EXPLOITDB_CSV_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

# ========== 速率限制 ==========
NVD_RATE_LIMIT = (50, 30)  # (最大请求数, 时间窗口/秒)，即 50次/30秒

# ========== 超时设置 ==========
NVD_TIMEOUT = 30  # NVD API 单个请求超时（秒）
OSV_TIMEOUT = 60  # OSV API 单个请求超时（秒），批量查询可能较慢

# ========== 代理配置 ==========
# 从环境变量读取代理地址，支持 HTTP_PROXY / HTTPS_PROXY / ALL_PROXY
# 代理示例: socks5://127.0.0.1:7890 或 http://127.0.0.1:7890
HTTP_PROXY = os.getenv("HTTP_PROXY", "") or os.getenv("ALL_PROXY", "")
HTTPS_PROXY = os.getenv("HTTPS_PROXY", "") or os.getenv("ALL_PROXY", "")

# ========== 磁盘缓存配置 ==========
# 缓存目录，支持环境变量 CACHE_DIR 覆盖为绝对路径
CACHE_DIR = os.getenv("CACHE_DIR", os.path.join(_PROJECT_ROOT, "cache"))

# 缓存文件名
KEV_CACHE_FILE = "kev_catalog.json"
EXPLOITDB_CACHE_FILE = "exploitdb.csv"

# 缓存 TTL（单位：小时），均支持环境变量覆盖
# KEV 目录更新频率低（CISA 不定期发布），默认 7 天
KEV_CACHE_TTL_HOURS = int(os.getenv("KEV_CACHE_TTL_HOURS", "168"))
# Exploit-DB 更新较频繁，默认 3 天
EXPLOITDB_CACHE_TTL_HOURS = int(os.getenv("EXPLOITDB_CACHE_TTL_HOURS", "72"))
