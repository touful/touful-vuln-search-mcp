"""CISA KEV 目录客户端

封装 CISA（美国网络安全与基础设施安全局）已知被利用漏洞（KEV）目录的获取。
KEV 目录是一个静态 JSON 文件，启动时全量加载到内存，之后查表即可。
只有确认正被野外利用的漏洞才会列入该目录。

端点: GET https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
当前规模: ~1600+ 条目
"""

import logging

from src.config import KEV_CATALOG_URL
from src.clients.base import BaseAPIClient
from src.clients.http_utils import resilient_request

logger = logging.getLogger(__name__)


class KEVClient(BaseAPIClient):
    """CISA KEV 目录异步客户端。

    在 MCP 服务启动时通过 load_catalog() 下载全量数据，
    之后通过 lookup() 进行内存查表。KEV 数据为公开数据集，无需认证。
    通过 resilient_request 实现"直连优先→代理回退"策略。

    Attributes:
        timeout: 单个请求超时（秒）。
    """

    def __init__(self, timeout: int = 30):
        """初始化 KEV 客户端。

        Args:
            timeout: 请求超时时间（秒），默认 30。
        """
        self.timeout = timeout

    async def load_catalog(self) -> list[dict]:
        """下载 CISA KEV 全量数据。

        Returns:
            KEV JSON 中的 vulnerabilities 列表，
            每项为包含 cveID、vendorProject、product 等字段的字典。

        Raises:
            RuntimeError: API 返回非 200 状态码或 JSON 解析失败。
        """
        response = await resilient_request(
            "GET",
            KEV_CATALOG_URL,
            timeout=self.timeout,
            direct_timeout=10.0,
            use_proxy_fallback=True,
        )
        self._raise_for_status(response, "KEV 目录 API")
        try:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])
            return vulnerabilities
        except (ValueError, KeyError) as e:
            raise RuntimeError(f"KEV 目录 JSON 解析失败: {e}") from e

    @staticmethod
    def build_index(catalog: list[dict]) -> dict[str, dict]:
        """为 KEV 目录构建 CVE ID → 记录的索引字典。

        将 O(n) 的线性查找优化为 O(1) 的哈希查找。

        Args:
            catalog: load_catalog() 返回的 vulnerabilities 列表。

        Returns:
            {cveID_upper: record} 的索引字典。
        """
        index: dict[str, dict] = {}
        for item in catalog:
            try:
                cve_id = item.get("cveID", "").upper()
                if cve_id:
                    index[cve_id] = item
            except Exception:
                continue
        return index

    @staticmethod
    def lookup(cve_id: str, catalog: list[dict]) -> dict | None:
        """在已加载的 KEV 目录中按 cveID 查表。

        Args:
            cve_id: CVE 编号，如 "CVE-2021-44228"。
            catalog: load_catalog() 返回的 vulnerabilities 列表。

        Returns:
            完整 KEV 记录字典，未找到则返回 None。
        """
        for item in catalog:
            try:
                if item.get("cveID", "").upper() == cve_id.upper():
                    return item
            except Exception:
                continue
        return None

    @staticmethod
    def get_stats(catalog: list[dict]) -> dict:
        """获取 KEV 目录的统计摘要。

        Args:
            catalog: load_catalog() 返回的 vulnerabilities 列表。

        Returns:
            统计字典，包含：
            - total: 总条目数
            - ransomware_count: 与勒索软件关联的条目数
            - recent_additions: 最近添加的 5 个 CVE（按 dateAdded 降序）
        """
        total = len(catalog)
        ransomware_count = 0

        try:
            sorted_items = sorted(
                catalog,
                key=lambda x: x.get("dateAdded", ""),
                reverse=True,
            )
        except Exception:
            sorted_items = catalog

        recent = []
        for i, item in enumerate(sorted_items):
            try:
                if item.get("knownRansomwareCampaignUse", "") == "Known":
                    ransomware_count += 1
                if i < 5:
                    recent.append({
                        "cveID": item.get("cveID", "N/A"),
                        "dateAdded": item.get("dateAdded", "N/A"),
                        "shortDescription": item.get("shortDescription", "N/A"),
                    })
            except Exception:
                continue

        return {
            "total": total,
            "ransomware_count": ransomware_count,
            "recent_additions": recent,
        }

