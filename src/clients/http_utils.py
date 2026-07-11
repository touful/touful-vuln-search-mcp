"""HTTP 客户端通用工具模块

提供"直连优先→代理回退"策略，提升网络健壮性。
"""

import re
import httpx
import logging

from src.config import HTTP_PROXY, HTTPS_PROXY

logger = logging.getLogger(__name__)


def _redact_proxy_url(proxy_url: str) -> str:
    """脱敏代理 URL 中的用户名和密码。

    将 socks5://user:pass@host:port 格式中的用户名密码替换为 ***。

    Args:
        proxy_url: 原始代理 URL。

    Returns:
        脱敏后的代理 URL。
    """
    return re.sub(r"://[^@]*@", "://***:***@", proxy_url)


async def resilient_request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    json_data: dict | None = None,
    params: dict | None = None,
    timeout: float = 15.0,
    direct_timeout: float = 8.0,
    use_proxy_fallback: bool = True,
) -> httpx.Response:
    """执行 HTTP 请求，优先直连，超时则通过代理回退。

    策略:
    1. 先尝试直连（direct_timeout 超时）
    2. 如果超时或连接错误，且 use_proxy_fallback=True 且代理已配置，则通过代理重试
    3. 两次都失败才抛出异常

    注意: HTTP 4xx/5xx 不触发回退（业务错误，换代理也没用）。
    仅 TimeoutException / ConnectError / RemoteProtocolError 触发回退。

    Args:
        method: HTTP 方法 (GET/POST)
        url: 请求 URL
        headers: 请求头
        json_data: JSON 请求体（POST 时使用）
        params: URL 查询参数（GET 时使用）
        timeout: 代理模式下的超时时间
        direct_timeout: 直连模式下的超时时间（较短，快速失败）
        use_proxy_fallback: 是否启用代理回退（默认 True）

    Returns:
        httpx.Response 对象

    Raises:
        httpx.HTTPError: 直连和代理都失败时抛出
    """
    # === 第一次尝试：直连 ===
    direct_error = None
    try:
        return await _do_request(
            method, url, headers=headers, json_data=json_data,
            params=params, timeout=direct_timeout, proxy=None,
        )
    except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as e:
        logger.info("直连 %s 失败 (%s)，尝试代理回退...", url, type(e).__name__)
        direct_error = e

    # === 第二次尝试：代理回退 ===
    if not use_proxy_fallback:
        if direct_error is not None:
            raise direct_error
        raise RuntimeError("直连失败但无异常信息")

    proxy_url = _get_proxy_for_url(url)
    if not proxy_url:
        logger.warning("未配置代理，无法回退: %s", url)
        if direct_error is not None:
            raise direct_error
        raise RuntimeError("直连失败且未配置代理")

    logger.info("使用代理 %s 重试: %s", _redact_proxy_url(proxy_url), url)
    try:
        return await _do_request(
            method, url, headers=headers, json_data=json_data,
            params=params, timeout=timeout, proxy=proxy_url,
        )
    except Exception:
        logger.warning("代理请求也失败: %s", url)
        raise


async def _do_request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    json_data: dict | None = None,
    params: dict | None = None,
    timeout: float = 15.0,
    proxy: str | None = None,
) -> httpx.Response:
    """执行单次 HTTP 请求（内部辅助函数）。

    每次调用都独立创建 httpx.AsyncClient，避免跨请求状态污染。

    Args:
        method: HTTP 方法 (GET/POST)
        url: 请求 URL
        headers: 请求头
        json_data: JSON 请求体（POST 时使用）
        params: URL 查询参数（GET 时使用）
        timeout: 请求超时时间（秒）
        proxy: 代理 URL，如 socks5://127.0.0.1:7890

    Returns:
        httpx.Response 对象

    Raises:
        httpx.HTTPError: 请求失败时抛出
        ValueError: 不支持的 HTTP 方法
    """
    # 提前校验 HTTP 方法，避免无意义地创建 AsyncClient
    method_upper = method.upper()
    if method_upper not in ("GET", "POST"):
        raise ValueError(f"不支持的 HTTP 方法: {method}")

    client_kwargs: dict = {"timeout": timeout, "follow_redirects": True}
    if proxy:
        client_kwargs["proxy"] = proxy

    async with httpx.AsyncClient(**client_kwargs) as client:
        if method_upper == "GET":
            response = await client.get(url, headers=headers, params=params)
        else:  # POST
            response = await client.post(url, headers=headers, json=json_data, params=params)
        # 注：不再在此处调用 raise_for_status，由调用方通过 BaseAPIClient._raise_for_status 统一处理
        return response


async def simple_request(
    method: str,
    url: str,
    *,
    headers: dict | None = None,
    json_data: dict | None = None,
    params: dict | None = None,
    timeout: float = 30.0,
) -> httpx.Response:
    """执行简单的 HTTP 请求（无代理回退）。

    适用于 OSV、EPSS 等不需要代理回退的 API。
    每次调用独立创建 httpx.AsyncClient，避免跨请求状态污染。

    Args:
        method: HTTP 方法 (GET/POST)
        url: 请求 URL
        headers: 请求头
        json_data: JSON 请求体（POST 时使用）
        params: URL 查询参数（GET 时使用）
        timeout: 请求超时时间（秒），默认 30s

    Returns:
        httpx.Response 对象

    Raises:
        httpx.HTTPError: 请求失败时抛出
        ValueError: 不支持的 HTTP 方法
    """
    return await _do_request(
        method, url, headers=headers, json_data=json_data,
        params=params, timeout=timeout,
    )


def _get_proxy_for_url(url: str) -> str | None:
    """根据 URL 判断应该使用哪个代理。

    HTTPS 请求优先使用 HTTPS_PROXY，其次 HTTP_PROXY；
    HTTP 请求直接使用 HTTP_PROXY。

    Args:
        url: 请求的完整 URL

    Returns:
        代理 URL 字符串，无可用代理时返回 None
    """
    if url.startswith("https://"):
        return HTTPS_PROXY or HTTP_PROXY or None
    return HTTP_PROXY or None
