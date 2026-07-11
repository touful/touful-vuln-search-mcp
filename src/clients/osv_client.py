"""OSV API 异步客户端

封装 OSV (Open Source Vulnerabilities) 数据库的异步查询，
支持单包查询、批量查询与漏洞详情获取。
"""

import logging
from urllib.parse import quote

from src.config import OSV_API_BASE_URL, OSV_TIMEOUT
from src.clients.base import BaseAPIClient
from src.clients.http_utils import resilient_request

logger = logging.getLogger(__name__)


class OSVClient(BaseAPIClient):
    """OSV 开源漏洞数据库异步客户端。

    OSV API 为公开接口，无需认证。
    通过 resilient_request 实现"直连优先→代理回退"策略。

    对 URL 路径参数进行 URL 编码，防止特殊字符导致请求异常。
    """

    async def query_package(
        self,
        package_name: str,
        ecosystem: str,
        version: str | None = None,
    ) -> dict:
        """查询指定包的已知漏洞。

        调用 OSV POST /v1/query 端点。

        Args:
            package_name: 包名，如 "lodash"、"curl"。
            ecosystem: 生态系统，如 "npm"、"PyPI"、"Maven"。
            version: 可选，指定版本号查询该版本的漏洞。

        Returns:
            OSV API 返回的 JSON 响应字典，包含 vulns 列表。

        Raises:
            RuntimeError: API 返回非 200 状态码。
        """
        request_body: dict = {
            "package": {
                "name": package_name,
                "ecosystem": ecosystem,
            },
        }
        if version is not None:
            request_body["version"] = version

        response = await resilient_request(
            "POST",
            f"{OSV_API_BASE_URL}/query",
            json_data=request_body,
            timeout=OSV_TIMEOUT,
            direct_timeout=8.0,
            use_proxy_fallback=True,
        )
        self._raise_for_status(response, "OSV API")
        return response.json()

    async def query_batch(self, queries: list[dict]) -> dict:
        """批量查询多个包的已知漏洞。

        调用 OSV POST /v1/querybatch 端点。
        每个查询项的格式与 query_package 的请求体一致。

        Args:
            queries: 查询列表，每项格式为：
                     {"package": {"name": "xxx", "ecosystem": "xxx"}, "version": "1.0"}
                     或 {"package": {"name": "xxx", "ecosystem": "xxx"}, "commit": "abc123"}
                     注意 version 和 commit 为 oneof 互斥。

        Returns:
            OSV API 返回的 JSON 响应字典，包含 results 列表。

        Raises:
            RuntimeError: API 返回非 200 状态码。
        """
        response = await resilient_request(
            "POST",
            f"{OSV_API_BASE_URL}/querybatch",
            json_data={"queries": queries},
            timeout=OSV_TIMEOUT,
            direct_timeout=8.0,
            use_proxy_fallback=True,
        )
        self._raise_for_status(response, "OSV API")
        return response.json()

    async def get_vuln(self, vuln_id: str) -> dict:
        """获取指定漏洞的完整详情。

        调用 OSV GET /v1/vulns/{id} 端点。
        vuln_id 会经过 URL 编码（safe=''），防止特殊字符注入。

        Args:
            vuln_id: 漏洞 ID，如 "GHSA-xxxx-xxxx-xxxx" 或 "CVE-2024-1234"。

        Returns:
            OSV API 返回的 JSON 响应字典。

        Raises:
            ValueError: 漏洞不存在 (404)。
            RuntimeError: API 返回其他非 200 状态码。
        """
        encoded_id = quote(vuln_id, safe="")
        response = await resilient_request(
            "GET",
            f"{OSV_API_BASE_URL}/vulns/{encoded_id}",
            timeout=OSV_TIMEOUT,
            direct_timeout=8.0,
            use_proxy_fallback=True,
        )
        self._raise_for_status(response, "OSV API", not_found_is_value_error=True)
        return response.json()
