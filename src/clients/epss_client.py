"""FIRST.org EPSS API 异步客户端

封装 EPSS（漏洞利用预测评分系统）API 的异步请求，
支持单个和批量 CVE 的 EPSS 评分查询。
EPSS 评估漏洞在未来 30 天内被利用的概率，比 CVSS 更能反映实际利用可能性。

API 端点: GET https://api.first.org/data/v1/epss?cve=CVE-2021-44228
认证: 无需
批量: 逗号分隔，URL 查询字符串最长 2000 字符（约 100 个 CVE）
"""

import logging

from src.config import EPSS_API_BASE
from src.clients.base import BaseAPIClient
from src.clients.http_utils import resilient_request

logger = logging.getLogger(__name__)


class EPSSClient(BaseAPIClient):
    """FIRST.org EPSS API 异步客户端。

    封装 EPSS API 的查询逻辑，支持单个和批量 CVE 查询。
    通过 resilient_request 实现"直连优先→代理回退"策略。

    Attributes:
        timeout: 单个请求超时（秒）。
    """

    def __init__(self, timeout: int = 15):
        """初始化 EPSS 客户端。

        Args:
            timeout: 请求超时时间（秒），默认 15。
        """
        self.timeout = timeout

    async def get_scores(self, cve_ids: list[str]) -> dict:
        """批量查询多个 CVE 的 EPSS 评分。

        Args:
            cve_ids: CVE 编号列表，最多约 100 个（受 URL 长度限制）。

        Returns:
            EPSS API 返回的 JSON 响应字典，格式为:
            {
                "status": "OK",
                "data": [
                    {"cve": "CVE-2021-44228", "epss": "0.999",
                     "percentile": "1.0", "date": "2026-07-10"}
                ]
            }

        Raises:
            RuntimeError: API 返回非 200 状态码或业务状态异常。
            ValueError: cve_ids 为空。
        """
        if not cve_ids:
            raise ValueError("cve_ids 不能为空")
        if len(cve_ids) > 100:
            raise ValueError(
                f"cve_ids 最多 100 个，当前 {len(cve_ids)} 个。"
                f"请分批查询。"
            )

        cve_param = ",".join(cve_ids)
        params = {"cve": cve_param}

        response = await resilient_request(
            "GET",
            EPSS_API_BASE,
            params=params,
            timeout=self.timeout,
            direct_timeout=8.0,
            use_proxy_fallback=True,
        )
        self._raise_for_status(response, "EPSS API")
        data = response.json()
        # 校验业务状态码
        if data.get("status", "") != "OK":
            raise RuntimeError(
                f"EPSS API 返回业务错误: status={data.get('status')}, "
                f"message={data.get('message', '未知')}"
            )
        return data

    async def get_score(self, cve_id: str) -> dict | None:
        """查询单个 CVE 的 EPSS 评分。

        Args:
            cve_id: CVE 编号，如 "CVE-2021-44228"。

        Returns:
            单条 EPSS 数据字典，或 None（当 CVE 不在 EPSS 数据库中时）。
            字典格式: {"cve": "...", "epss": "0.999",
                        "percentile": "1.0", "date": "2026-07-10"}

        Raises:
            RuntimeError: API 返回非 200 状态码。
        """
        result = await self.get_scores([cve_id])
        data_list = result.get("data", [])
        if data_list:
            return data_list[0]
        return None
