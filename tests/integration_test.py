"""综合集成测试：验证所有模块导入、类型签名和客户端实例化"""
import os
import sys

# 使用相对路径推导项目根目录
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _project_root)

# 1. 配置模块
from src.config import (
    NVD_API_KEY, NVD_API_BASE_URL, OSV_API_BASE_URL,
    NVD_RATE_LIMIT, NVD_TIMEOUT, OSV_TIMEOUT,
)
# 验证 API Key 已正确加载（不为空），不比对具体值
assert NVD_API_KEY and isinstance(NVD_API_KEY, str), "NVD_API_KEY 应为非空字符串"
assert len(NVD_API_KEY) > 10, f"NVD_API_KEY 看起来太短: {NVD_API_KEY[:4]}..."
assert NVD_API_BASE_URL == "https://services.nvd.nist.gov/rest/json/cves/2.0"
assert OSV_API_BASE_URL == "https://api.osv.dev/v1"
assert NVD_RATE_LIMIT == (50, 30)
assert NVD_TIMEOUT == 30
assert OSV_TIMEOUT == 60
print("[OK] config.py 配置正确")

# 2. 客户端模块
from src.clients.nvd_client import NVDClient
from src.clients.osv_client import OSVClient

nvd = NVDClient(api_key="test-key-for-unit-test")
assert hasattr(nvd, "get_cve"), "缺少 get_cve 方法"
assert hasattr(nvd, "search_cves"), "缺少 search_cves 方法"
assert hasattr(nvd, "get_cves_batch"), "缺少 get_cves_batch 方法"
print("[OK] NVDClient 方法签名正确")

osv_client = OSVClient()
assert hasattr(osv_client, "query_package"), "缺少 query_package 方法"
assert hasattr(osv_client, "query_batch"), "缺少 query_batch 方法"
assert hasattr(osv_client, "get_vuln"), "缺少 get_vuln 方法"
print("[OK] OSVClient 方法签名正确")

# 3. 服务模块
from src.server import mcp, main
import asyncio


async def verify_tools():
    tools = await mcp.list_tools()
    expected = {
        "nvd_get_cve", "nvd_search_cve", "nvd_get_cves_batch",
        "osv_query_package", "osv_query_batch", "osv_get_vuln",
    }
    actual = {t.name for t in tools}
    assert expected == actual, f"工具列表不匹配! 期望: {expected}, 实际: {actual}"
    print(f"[OK] 6 个工具已正确注册: {', '.join(sorted(actual))}")

    # 验证注解
    for tool in tools:
        if hasattr(tool, 'annotations') and tool.annotations:
            ann = tool.annotations
            assert ann.readOnlyHint is True, f"{tool.name}: readOnlyHint 应为 True"
            assert ann.idempotentHint is True, f"{tool.name}: idempotentHint 应为 True"
            assert ann.openWorldHint is True, f"{tool.name}: openWorldHint 应为 True"
            assert ann.destructiveHint is False, f"{tool.name}: destructiveHint 应为 False"
    print("[OK] 所有工具注解正确 (readOnly=True, idempotent=True, openWorld=True, destructive=False)")

    # 验证描述为中文
    for tool in tools:
        desc = tool.description or ""
        has_chinese = any('\u4e00' <= c <= '\u9fff' for c in desc)
        assert has_chinese, f"{tool.name}: 描述应为中文"
    print("[OK] 所有工具描述均为中文")


asyncio.run(verify_tools())

# 4. verify lifespan
from src.server import app_lifespan
print(f"[OK] lifespan 函数: {app_lifespan.__name__}")

print("\n=== 全部测试通过! ===")
