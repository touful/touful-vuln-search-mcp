"""API 客户端公共基类

提供统一的 HTTP 响应错误处理逻辑，供所有 API 客户端继承使用。
"""

import logging

import httpx

logger = logging.getLogger(__name__)


class BaseAPIClient:
    """所有 API 客户端的公共基类。

    封装统一的 HTTP 响应状态码处理逻辑：
    - 200: 正常的响应，不抛出
    - 404: 可选配置为 ValueError（资源未找到）
    - 403/429: RuntimeError（请求受限）
    - 其他非 200: RuntimeError（通用错误）

    错误消息中不暴露响应体内容，改用 logger.debug 记录详情。
    """

    def _raise_for_status(
        self,
        response: httpx.Response,
        api_name: str = "API",
        not_found_is_value_error: bool = False,
    ) -> None:
        """根据 HTTP 状态码抛出对应的异常。

        Args:
            response: httpx 响应对象。
            api_name: API 名称，用于异常消息标识。
            not_found_is_value_error: 404 时是否抛出 ValueError（默认 RuntimeError）。

        Raises:
            ValueError: 404 且 not_found_is_value_error=True 时。
            RuntimeError: 403/429 及其他非 200 状态码。
        """
        if response.status_code == 200:
            return
        if response.status_code == 404 and not_found_is_value_error:
            raise ValueError(f"{api_name}: 指定的资源未找到 (HTTP 404)")
        # 用 debug 级别记录响应体，不在异常消息中暴露给用户
        try:
            logger.debug(
                "%s 返回错误 (HTTP %s): %s",
                api_name,
                response.status_code,
                response.text[:300],
            )
        except Exception:
            pass
        if response.status_code in (403, 429):
            raise RuntimeError(
                f"{api_name} 请求受限 (HTTP {response.status_code})"
            )
        raise RuntimeError(
            f"{api_name} 返回错误 (HTTP {response.status_code})"
        )
