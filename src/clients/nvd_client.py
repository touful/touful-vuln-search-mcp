"""NVD API 异步客户端

封装 NVD (National Vulnerability Database) CVE API 2.0 的异步请求，
包含令牌桶限速、错误分类处理与类型安全的响应。
"""

import logging

from aiolimiter import AsyncLimiter

from src.config import NVD_API_BASE_URL, NVD_RATE_LIMIT, NVD_TIMEOUT
from src.clients.base import BaseAPIClient
from src.clients.http_utils import resilient_request

logger = logging.getLogger(__name__)


class NVDClient(BaseAPIClient):
    """NVD CVE API 2.0 异步客户端。

    封装了请求限速、错误处理与重连逻辑。
    通过 resilient_request 实现"直连优先→代理回退"策略。

    Attributes:
        api_key: NVD API 密钥，用于提升速率限制。
        limiter: AsyncLimiter 令牌桶，限制 50 次/30 秒。
    """

    def __init__(self, api_key: str):
        """初始化 NVD 客户端。

        Args:
            api_key: NVD API 密钥字符串。
        """
        self.api_key = api_key
        self.limiter = AsyncLimiter(NVD_RATE_LIMIT[0], NVD_RATE_LIMIT[1])

    async def get_cve(self, cve_id: str) -> dict:
        """获取单个 CVE 的完整详情。

        Args:
            cve_id: CVE 编号，如 "CVE-2024-1234"。

        Returns:
            NVD API 返回的 JSON 响应字典。

        Raises:
            RuntimeError: API 限速 (403/429) 或其他 HTTP 错误。
            ValueError: 指定 CVE 不存在 (404)。
        """
        await self.limiter.acquire()

        response = await resilient_request(
            "GET",
            NVD_API_BASE_URL,
            params={"cveIds": cve_id},
            headers={"apiKey": self.api_key},
            timeout=NVD_TIMEOUT,
            direct_timeout=8.0,
            use_proxy_fallback=True,
        )
        self._raise_for_status(response, "NVD API", not_found_is_value_error=True)
        return response.json()

    async def search_cves(
        self, keyword: str, exact_match: bool = False, results: int = 10
    ) -> dict:
        """通过关键词搜索 CVE 漏洞。

        Args:
            keyword: 搜索关键词或 CPE 名称。
            exact_match: 是否精确匹配，默认 False（模糊搜索）。
            results: 返回结果数量，默认 10，最大 100。

        Returns:
            NVD API 返回的 JSON 响应字典。

        Raises:
            RuntimeError: API 限速 (403/429) 或其他 HTTP 错误。
        """
        await self.limiter.acquire()

        params = {
            "keywordSearch": keyword,
            "resultsPerPage": min(max(1, results), 100),
        }
        # Bug 修复: 仅在 exact_match=True 时传递 keywordExactMatch=""
        # NVD API 2.0 近期变更，传 "true"/"false" 或空值都会导致 HTTP 404
        if exact_match:
            params["keywordExactMatch"] = ""

        response = await resilient_request(
            "GET",
            NVD_API_BASE_URL,
            params=params,
            headers={"apiKey": self.api_key},
            timeout=NVD_TIMEOUT,
            direct_timeout=8.0,
            use_proxy_fallback=True,
        )
        self._raise_for_status(response, "NVD API")
        return response.json()

    async def get_cves_batch(self, cve_ids: list[str]) -> dict:
        """批量获取多个 CVE 的详情。

        使用 NVD API 的 cveIds 参数，逗号分隔最多 100 个。

        Args:
            cve_ids: CVE 编号列表，如 ["CVE-2024-1234", "CVE-2024-5678"]，
                      最多 100 个。

        Returns:
            NVD API 返回的 JSON 响应字典。

        Raises:
            ValueError: cve_ids 超过 100 个或为空。
            RuntimeError: API 限速 (403/429) 或其他 HTTP 错误。
        """
        if not cve_ids:
            raise ValueError("cve_ids 不能为空")
        if len(cve_ids) > 100:
            raise ValueError(f"cve_ids 最多 100 个，当前 {len(cve_ids)} 个")

        await self.limiter.acquire()

        cve_id_param = ",".join(cve_ids)

        response = await resilient_request(
            "GET",
            NVD_API_BASE_URL,
            params={"cveIds": cve_id_param},
            headers={"apiKey": self.api_key},
            timeout=NVD_TIMEOUT,
            direct_timeout=8.0,
            use_proxy_fallback=True,
        )
        self._raise_for_status(response, "NVD API")
        return response.json()
