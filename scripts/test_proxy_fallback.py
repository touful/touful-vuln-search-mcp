#!/usr/bin/env python
"""代理回退机制运行时验证脚本

测试 resilient_request 的直连→代理回退行为。
必须在设置 HTTP_PROXY 环境变量后运行。

用法:
    $env:HTTP_PROXY="socks5://127.0.0.1:7892"
    python scripts/test_proxy_fallback.py

测试覆盖场景：
  - 代理本地连通性
  - 直连可达 API（不回退）
  - 直连失败 + 代理也失败（双重失败路径）
  - 直连超时 + 代理成功（核心回退场景，通过 mock 验证）
  - GitHub API 直连与代理可达性
  - use_proxy_fallback=False 且直连失败（无回退路径）
  - HTTP 4xx 不触发回退（业务错误换代理也没用）
  - ExploitClient 完整链路（Exploit-DB / GitHub / check_poc）
"""

import asyncio
import logging
import os
import sys
import time
from unittest.mock import patch, AsyncMock

# ============================================================
# 确保项目根目录在 sys.path 中
# ============================================================
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ============================================================
# 日志捕获
# ============================================================
captured_logs = []


class LogCaptureHandler(logging.Handler):
    def emit(self, record):
        captured_logs.append(self.format(record))


# 安装日志捕获
_log_handler = LogCaptureHandler()
_log_handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
logging.getLogger("src.clients.http_utils").addHandler(_log_handler)
logging.getLogger("src.clients.http_utils").setLevel(logging.INFO)


def get_logs_with(keyword: str) -> list[str]:
    """返回包含特定关键词的日志行"""
    return [l for l in captured_logs if keyword in l]


# ============================================================
# 测试结果收集器
# ============================================================
results = []
_log_before_test = 0


def record(name: str, passed: bool, detail: str = ""):
    """记录一条测试结果"""
    results.append({"name": name, "passed": passed, "detail": detail})
    icon = "[PASS]" if passed else "[FAIL]"
    print(f"\n  {icon} {name}")
    if detail:
        for line in detail.strip().split("\n"):
            print(f"     {line}")


def reset_log_marker():
    """重置日志标记，以便仅捕获当前测试的日志"""
    global _log_before_test
    _log_before_test = len(captured_logs)


def get_logs_since_marker(keyword: str = "") -> list[str]:
    """获取自上次标记以来的日志"""
    logs = captured_logs[_log_before_test:]
    if keyword:
        logs = [l for l in logs if keyword in l]
    return logs


# ============================================================
# 步骤 1：验证代理本地可达
# ============================================================
async def step1_test_proxy_reachable():
    """验证代理本地是否可达"""
    import httpx

    proxy = "socks5://127.0.0.1:7892"
    async with httpx.AsyncClient(proxy=proxy, timeout=15, follow_redirects=True) as client:
        try:
            resp = await client.get("https://api.github.com")
            record(
                "1. 代理本地连通性 (socks5://127.0.0.1:7892)",
                True,
                f"status={resp.status_code} len={len(resp.text)}",
            )
            return True
        except Exception as e:
            record(
                "1. 代理本地连通性 (socks5://127.0.0.1:7892)",
                False,
                f"{type(e).__name__}: {e}",
            )
            return False


# ============================================================
# 步骤 2a：直连可达 API（不回退）
# ============================================================
async def step2a_test_direct_success():
    """直连可达 API（EPSS），应成功且不触发代理"""
    from src.clients.http_utils import resilient_request

    reset_log_marker()
    try:
        resp = await resilient_request(
            "GET",
            "https://api.first.org/data/v1/epss?cve=CVE-2021-44228",
            timeout=15.0,
            direct_timeout=8.0,
        )
        ok = resp.status_code == 200
        # 验证没有"代理回退"日志（直连应成功）
        fallback_logs = get_logs_since_marker("代理回退")
        no_fallback = len(fallback_logs) == 0
        detail = f"status={resp.status_code}, 未触发回退={no_fallback}"
        record("2a. 直连可达 API (EPSS)", ok and no_fallback, detail)
        return ok and no_fallback
    except Exception as e:
        record("2a. 直连可达 API (EPSS)", False, f"{type(e).__name__}: {str(e)[:200]}")
        return False


# ============================================================
# 步骤 2b：双重失败路径（直连失败 + 代理也失败）
# ============================================================
async def step2b_test_double_fail():
    """假域名触发直连失败→代理回退→代理也失败"""
    from src.clients.http_utils import resilient_request
    import httpx

    reset_log_marker()
    try:
        resp = await resilient_request(
            "GET",
            "https://this-host-definitely-does-not-exist-12345.com",
            timeout=15.0,
            direct_timeout=5.0,
        )
        record(
            "2b. 双重失败路径 (假域名)",
            False,
            f"意外成功: status={resp.status_code}（预期应抛出异常）",
        )
        return False
    except Exception as e:
        exc_name = type(e).__name__
        is_connect_error = issubclass(type(e), httpx.ConnectError) or exc_name == "ConnectError"

        # 验证日志中确认了回退
        fallback_logs = get_logs_since_marker("代理回退")
        has_fallback_log = len(fallback_logs) > 0
        proxy_fail_logs = get_logs_since_marker("代理请求也失败")
        has_proxy_fail_log = len(proxy_fail_logs) > 0

        detail_parts = [
            f"异常={exc_name}",
            f"ConnectError={is_connect_error}",
            f"回退日志={has_fallback_log}",
            f"代理失败日志={has_proxy_fail_log}",
        ]
        if fallback_logs:
            detail_parts.append(f"日志原文: {fallback_logs[0]}")

        passed = is_connect_error and has_fallback_log
        record("2b. 双重失败路径 (假域名)", passed, ", ".join(detail_parts))
        return passed


# ============================================================
# 步骤 2c：核心场景——直连超时→代理成功（通过 mock 验证）
# ============================================================
async def step2c_test_fallback_to_proxy_success():
    """【核心场景】直连超时→代理回退成功

    通过 mock _do_request 第一次调用抛出 TimeoutException，
    验证函数能正确回退到代理并成功获取数据。
    """
    from src.clients.http_utils import resilient_request, _do_request
    import httpx

    reset_log_marker()

    # 创建一个真实的 httpx.Response 对象——模拟代理成功返回
    real_response = httpx.Response(
        status_code=200,
        json={"message": "mock-success"},
        request=httpx.Request("GET", "https://api.github.com"),
    )

    call_count = [0]
    second_call_kwargs = [None]  # 用于捕获第二次调用的参数

    async def mocked_do_request(method, url, **kwargs):
        """第一次调用（直连）抛超时，第二次调用（代理）正常返回"""
        call_count[0] += 1
        if call_count[0] == 1:
            # 第一次：直连 → 模拟超时
            raise httpx.TimeoutException("直连模拟超时", request=httpx.Request("GET", url))
        # 第二次：代理 → 记录 kwargs 用于断言
        second_call_kwargs[0] = kwargs
        return real_response

    try:
        with patch("src.clients.http_utils._do_request", side_effect=mocked_do_request):
            resp = await resilient_request(
                "GET",
                "https://api.github.com",
                timeout=15.0,
                direct_timeout=3.0,
                use_proxy_fallback=True,
            )

        # 验证代理回退日志
        fallback_logs = get_logs_since_marker("代理回退")
        has_fallback_log = len(fallback_logs) > 0

        # 验证调用了两次 _do_request（一次直连，一次代理）
        called_twice = call_count[0] == 2

        # 验证第二次调用（代理模式）传入了正确的 proxy 参数
        proxy_passed = False
        if second_call_kwargs[0] is not None:
            proxy_passed = "proxy" in second_call_kwargs[0] and second_call_kwargs[0]["proxy"] is not None

        passed = (resp.status_code == 200) and has_fallback_log and called_twice and proxy_passed
        detail_parts = [
            f"status={resp.status_code}",
            f"调用次数={call_count[0]}",
            f"回退日志={has_fallback_log}",
            f"代理参数={proxy_passed}",
        ]
        if fallback_logs:
            detail_parts.append(f"日志原文: {fallback_logs[0]}")
        record("2c. 核心场景: 直连超时→代理回退成功 [mock]", passed, ", ".join(detail_parts))
        return passed
    except Exception as e:
        record(
            "2c. 核心场景: 直连超时→代理回退成功 [mock]",
            False,
            f"{type(e).__name__}: {str(e)[:200]}",
        )
        return False


# ============================================================
# 步骤 2d：GitHub API 可达性测试
# ============================================================
async def step2d_test_github_reachability():
    """GitHub API 可达性（直连和代理均测试）

    注意：由于本机直连 GitHub 可达（返回 401），
    此测试验证的是网络连通性，而非直连→代理回退的对比。
    """
    from src.clients.http_utils import resilient_request

    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "touful-vuln-search-mcp-test",
    }

    # 直连
    t0 = time.time()
    direct_ok = False
    direct_detail = ""
    try:
        resp = await resilient_request(
            "GET",
            "https://api.github.com/search/code?q=CVE-2021-44228",
            headers=headers,
            timeout=8.0,
            direct_timeout=8.0,
            use_proxy_fallback=False,
        )
        direct_ok = True
        direct_detail = f"status={resp.status_code} 耗时={time.time()-t0:.1f}s"
    except Exception as e:
        direct_detail = f"{type(e).__name__}: {str(e)[:100]} 耗时={time.time()-t0:.1f}s"

    record("2d. GitHub API 直连可达性 (8s 超时)", direct_ok, direct_detail)

    # 代理（开启回退）
    t0 = time.time()
    proxy_ok = False
    proxy_detail = ""
    try:
        resp = await resilient_request(
            "GET",
            "https://api.github.com/search/code?q=CVE-2021-44228",
            headers=headers,
            timeout=15.0,
            direct_timeout=8.0,
            use_proxy_fallback=True,
        )
        proxy_ok = True
        proxy_detail = f"status={resp.status_code} 耗时={time.time()-t0:.1f}s"
    except Exception as e:
        proxy_detail = f"{type(e).__name__}: {str(e)[:100]} 耗时={time.time()-t0:.1f}s"

    record("2d. GitHub API 代理可达性 (8s直连+15s代理)", proxy_ok, proxy_detail)

    return direct_ok, proxy_ok


# ============================================================
# 步骤 2e：边界测试——use_proxy_fallback=False 且直连失败
# ============================================================
async def step2e_test_no_fallback_direct_fail():
    """边界测试：use_proxy_fallback=False 且直连失败"""
    from src.clients.http_utils import resilient_request

    reset_log_marker()
    try:
        resp = await resilient_request(
            "GET",
            "https://this-host-definitely-does-not-exist-12345.com",
            timeout=15.0,
            direct_timeout=3.0,
            use_proxy_fallback=False,
        )
        record("2e. 关闭回退+直连失败 (use_proxy_fallback=False)", False, "预期应抛出异常")
        return False
    except Exception as e:
        # 关闭回退时，直连失败应直接抛出异常，不应尝试代理。
        # 注意：源码中日志"尝试代理回退"在 use_proxy_fallback 判断之前已输出，
        # 所以不能判断"代理回退"关键词，而应判断"使用代理"或"重试"关键词
        #（这些只有在实际执行代理回退时才会输出）
        proxy_exec_logs = get_logs_since_marker("使用代理")
        no_proxy_executed = len(proxy_exec_logs) == 0
        detail = f"异常={type(e).__name__}, 未实际执行代理={no_proxy_executed}"
        if proxy_exec_logs:
            detail += f", 意外代理日志: {proxy_exec_logs[0]}"
        record(
            "2e. 关闭回退+直连失败 (use_proxy_fallback=False)",
            no_proxy_executed,
            detail,
        )
        return no_proxy_executed


# ============================================================
# 步骤 2f：边界测试——HTTP 4xx 不触发回退
# ============================================================
async def step2f_test_4xx_no_fallback():
    """边界测试：HTTP 4xx 不触发回退（业务错误，换代理无效）

    验证两个维度：
    1. 真实 401 响应：_do_request 正常返回 response → resilient_request 直接返回，不回退
    2. mock HTTPStatusError（4xx）：即使 _do_request 抛出 4xx 异常，也不应触发回退
    """
    from src.clients.http_utils import resilient_request, _do_request
    import httpx

    all_ok = True

    # === 子测试 1：真实 401 响应 ===
    reset_log_marker()
    try:
        resp = await resilient_request(
            "GET",
            "https://api.github.com/search/code?q=CVE-2021-44228",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "touful-vuln-search-mcp-test",
            },
            timeout=8.0,
            direct_timeout=8.0,
            use_proxy_fallback=True,
        )
        # 4xx 应直接返回，不应触发回退
        fallback_logs = get_logs_since_marker("代理回退")
        no_fallback = len(fallback_logs) == 0
        sub1_ok = no_fallback
        record(
            "2f-1. HTTP 4xx 不触发回退 (真实 401)",
            sub1_ok,
            f"status={resp.status_code}, 未触发回退={no_fallback}",
        )
        all_ok = all_ok and sub1_ok
    except Exception as e:
        fallback_logs = get_logs_since_marker("代理回退")
        no_fallback = len(fallback_logs) == 0
        record(
            "2f-1. HTTP 4xx 不触发回退 (真实 401)",
            no_fallback,
            f"异常={type(e).__name__}, 未触发回退={no_fallback}",
        )
        all_ok = all_ok and no_fallback

    # === 子测试 2：mock HTTPStatusError（4xx）→ 验证不触发回退 ===
    reset_log_marker()
    mock_request = httpx.Request("GET", "https://api.github.com/search/code")
    http_status_error = httpx.HTTPStatusError(
        "模拟 404 错误",
        request=mock_request,
        response=httpx.Response(status_code=404, request=mock_request),
    )

    async def mock_4xx_error(method, url, **kwargs):
        raise http_status_error

    try:
        with patch("src.clients.http_utils._do_request", side_effect=mock_4xx_error):
            try:
                resp = await resilient_request(
                    "GET",
                    "https://api.github.com/search/code",
                    headers={"Accept": "application/vnd.github.v3+json"},
                    timeout=8.0,
                    direct_timeout=5.0,
                    use_proxy_fallback=True,
                )
                # 如果成功，说明 mock 没生效
                record("2f-2. HTTP 4xx 不触发回退 (mock HTTPStatusError)", False, "mock 未生效")
                all_ok = False
            except httpx.HTTPStatusError:
                # 预期：直连的 HTTPStatusError 应直接向上传递，不触发回退
                fallback_logs = get_logs_since_marker("代理回退")
                no_fallback = len(fallback_logs) == 0
                sub2_ok = no_fallback
                record(
                    "2f-2. HTTP 4xx 不触发回退 (mock HTTPStatusError)",
                    sub2_ok,
                    f"异常向上传递, 未触发回退={no_fallback}",
                )
                all_ok = all_ok and sub2_ok
            except Exception as e:
                # 其他异常也检查是否触发回退
                fallback_logs = get_logs_since_marker("代理回退")
                no_fallback = len(fallback_logs) == 0
                record(
                    "2f-2. HTTP 4xx 不触发回退 (mock HTTPStatusError)",
                    no_fallback,
                    f"异常={type(e).__name__}, 未触发回退={no_fallback}",
                )
                all_ok = all_ok and no_fallback
    except Exception as e:
        record("2f-2. HTTP 4xx 不触发回退 (mock HTTPStatusError)", False, f"测试异常: {e}")
        all_ok = False

    return all_ok


# ============================================================
# 步骤 3：测试 ExploitClient 完整链路
# ============================================================
async def step3_test_exploit_client():
    """测试 ExploitClient 完整链路"""
    from src.clients.exploit_client import ExploitClient
    from src.config import GITHUB_TOKEN

    exploit = ExploitClient(github_token=GITHUB_TOKEN)

    # 3a. Exploit-DB CSV 下载
    try:
        rows = await exploit.search_exploitdb("CVE-2021-44228")
        ok = len(rows) > 0
        record("3a. ExploitClient-ExploitDB", ok, f"找到 {len(rows)} 条")
    except Exception as e:
        record("3a. ExploitClient-ExploitDB", False, f"{type(e).__name__}: {str(e)[:150]}")

    # 3b. GitHub 搜索
    try:
        results = await exploit.search_github("CVE-2021-44228")
        ok = len(results) > 0
        record("3b. ExploitClient-GitHub", ok, f"找到 {len(results)} 条")
    except Exception as e:
        record("3b. ExploitClient-GitHub", False, f"{type(e).__name__}: {str(e)[:150]}")

    # 3c. check_poc 完整链路
    try:
        poc = await exploit.check_poc("CVE-2021-44228")
        ok = poc["poc_confidence"] in ("WEAPONIZED", "PUBLIC_EXPLOIT", "PUBLIC_POC", "NONE")
        record(
            "3c. ExploitClient-check_poc",
            ok,
            f"confidence={poc['poc_confidence']} has_public_poc={poc['has_public_poc']}",
        )
    except Exception as e:
        record("3c. ExploitClient-check_poc", False, f"{type(e).__name__}: {str(e)[:150]}")


# ============================================================
# 主流程
# ============================================================
async def main():
    print("=" * 60)
    print("  代理回退机制运行时验证")
    print(f"  HTTP_PROXY = {os.environ.get('HTTP_PROXY', '未设置')}")
    print(f"  工作目录   = {os.getcwd()}")
    print("=" * 60)

    # 步骤 1：验证代理本地可达
    proxy_ok = await step1_test_proxy_reachable()
    if not proxy_ok:
        print("\n  [ABORT] 代理不可达，后续测试无法继续。")
        print("  请检查代理服务是否在 127.0.0.1:7892 运行。")
        return

    # 步骤 2：测试 resilient_request 函数层级
    await step2a_test_direct_success()       # 直连成功
    await step2b_test_double_fail()          # 双重失败
    await step2c_test_fallback_to_proxy_success()  # 【核心】直连超时→代理成功
    await step2d_test_github_reachability()  # GitHub 可达性
    await step2e_test_no_fallback_direct_fail()    # 关闭回退+直连失败
    await step2f_test_4xx_no_fallback()      # 4xx 不触发回退

    # 步骤 3：测试 ExploitClient
    await step3_test_exploit_client()

    # 步骤 4：汇总
    print("\n")
    print("=" * 60)
    print("  测试结果汇总")
    print("=" * 60)
    print(f"{'测试项':<50} {'结果':>6}")
    print(f"{'─' * 58}")
    for r in results:
        icon = "[OK]" if r["passed"] else "[!!]"
        print(f"{r['name']:<50} {icon:>6}")

    passed = sum(1 for r in results if r["passed"])
    failed = sum(1 for r in results if not r["passed"])
    total = len(results)
    print(f"{'─' * 58}")
    print(f"{'总计':<50} {passed}/{total} 通过, {failed} 失败")


if __name__ == "__main__":
    asyncio.run(main())
