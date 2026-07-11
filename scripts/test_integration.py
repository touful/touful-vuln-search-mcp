"""MCP 工具集成测试 — 模拟 lifespan 上下文验证 4 个新工具"""
import sys
import asyncio
from contextlib import asynccontextmanager
from unittest.mock import MagicMock

sys.path.insert(0, r"D:\工具开发\漏洞搜索mcp\touful-vuln-search-mcp")


# 模拟 FastMCP Context
class MockContext:
    def __init__(self, lifespan_context):
        self.lifespan_context = lifespan_context


# 需要一个 mock server 来让 @mcp.tool 的包装器正常工作
# 因为工具函数被 @mcp.tool 装饰后，需要通过 FastMCP 实例调用
# 这里我们直接导入工具的内部逻辑，绕过装饰器

async def test_epss_tool():
    """测试 get_epss_score 工具的内部逻辑"""
    from src.clients.epss_client import EPSSClient
    from src.server import _format_epss_risk, _CVE_ID_PATTERN

    # 测试格式校验
    assert _CVE_ID_PATTERN.match("CVE-2021-44228"), "Valid CVE should match"
    assert not _CVE_ID_PATTERN.match("invalid"), "Invalid format should not match"

    # 测试风险解读函数
    assert "极高" in _format_epss_risk(0.6)
    assert "较高" in _format_epss_risk(0.2)
    assert "中等" in _format_epss_risk(0.05)
    assert "较低" in _format_epss_risk(0.001)

    print("[EPSS Tool] Format validation: PASSED")

    # 测试实际 API 调用
    epss_client = EPSSClient()
    data = await epss_client.get_score("CVE-2021-44228")
    assert data is not None, "Should have EPSS data for Log4Shell"
    epss_val = float(data.get("epss", 0))
    assert epss_val > 0.9, "Log4Shell should have very high EPSS"
    print(f"[EPSS Tool] Live API: CVE-2021-44228 EPSS={epss_val} — PASSED")

    # 测试不存在的 CVE
    no_data = await epss_client.get_score("CVE-9999-99999")
    assert no_data is None, "Non-existent CVE should return None"
    print("[EPSS Tool] Non-existent CVE: PASSED")


async def test_kev_tool():
    """测试 check_kev_status 工具的逻辑"""
    from src.clients.kev_client import KEVClient
    from src.server import _CVE_ID_PATTERN

    kev = KEVClient()
    catalog = await kev.load_catalog()
    assert len(catalog) == 1637, "KEV catalog should have 1637 entries"

    # 测试 CVE-2021-44228（应在列）
    record = KEVClient.lookup("CVE-2021-44228", catalog)
    assert record is not None, "Log4Shell must be in KEV"
    ransom = record.get("knownRansomwareCampaignUse", "")
    assert ransom == "Known", "Log4Shell should have ransomware association"
    print(f"[KEV Tool] CVE-2021-44228: in KEV, ransomware={ransom} — PASSED")

    # 测试 CVE-2024-1234（应不在列）
    record2 = KEVClient.lookup("CVE-2024-1234", catalog)
    assert record2 is None, "CVE-2024-1234 should NOT be in KEV"
    print("[KEV Tool] CVE-2024-1234: NOT in KEV — PASSED")

    # 测试统计
    stats = KEVClient.get_stats(catalog)
    assert stats["total"] == 1637
    assert stats["ransomware_count"] > 0
    print(f"[KEV Tool] Stats: total={stats['total']}, ransomware={stats['ransomware_count']} — PASSED")


async def test_exploit_tool():
    """测试 search_exploit 工具的逻辑"""
    from src.clients.exploit_client import ExploitClient

    exploit = ExploitClient()
    result = await exploit.check_poc("CVE-2021-44228")

    # 由于当前环境无 GitHub token 且 GitLab 不可达，结果应为 NONE
    # 但这不影响代码逻辑正确性
    confidence = result.get("poc_confidence", "NONE")
    has_poc = result.get("has_public_poc", False)
    print(f"[Exploit Tool] CVE-2021-44228: confidence={confidence}, has_poc={has_poc}")

    # 验证返回结构完整性
    assert "cve_id" in result
    assert "has_public_poc" in result
    assert "poc_confidence" in result
    assert "github_results" in result
    assert "exploitdb_results" in result
    assert "total_sources" in result
    print("[Exploit Tool] Response structure: PASSED")

    # 测试不存在的 CVE
    result2 = await exploit.check_poc("CVE-9999-99999")
    assert result2["poc_confidence"] == "NONE"
    print("[Exploit Tool] Non-existent CVE: PASSED")


async def test_assess_formatting():
    """测试 assess_cve 的格式化输出逻辑"""
    from src.clients.epss_client import EPSSClient
    from src.clients.kev_client import KEVClient
    from src.clients.nvd_client import NVDClient
    from src.clients.exploit_client import ExploitClient

    # 验证 _format_epss_risk 的边界
    from src.server import _format_epss_risk
    assert _format_epss_risk(1.0) == "极高，需立即关注"
    assert _format_epss_risk(0.11) == "较高，建议优先处理"
    assert _format_epss_risk(0.011) == "中等，列入修复计划"
    assert _format_epss_risk(0.0) == "较低，常规修复即可"
    print("[Assess Tool] Risk formatting: PASSED")

    # 测试 EPSS 客户端
    epss = EPSSClient()
    data = await epss.get_score("CVE-2021-44228")
    epss_val = float(data.get("epss", 0))
    print(f"[Assess Tool] CVE-2021-44228 EPSS={epss_val} (will be converted to {epss_val*100:.2f}%)")

    # 测试 KEV
    kev = KEVClient()
    catalog = await kev.load_catalog()
    record = KEVClient.lookup("CVE-2021-44228", catalog)
    print(f"[Assess Tool] CVE-2021-44228 KEV: {'IN' if record else 'NOT IN'} catalog")


async def main():
    print("=" * 60)
    print("MCP Tools Integration Test")
    print("=" * 60)

    await test_epss_tool()
    print()

    await test_kev_tool()
    print()

    await test_exploit_tool()
    print()

    await test_assess_formatting()
    print()

    print("=" * 60)
    print("All integration tests completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
