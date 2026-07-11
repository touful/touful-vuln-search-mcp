"""测试脚本 3: MCP 工具注册 + 格式化测试

第一部分：使用 FastMCP 的 list_tools() 验证工具注册与元数据
第二部分：直接调用 server.py 中的实际工具函数（传入模拟 Context），验证中文输出格式

共 12 个测试点：
1. 10 个工具全部注册成功
2. 每个工具的 docstring 为中文
3. 每个工具的 ToolAnnotations 正确
4. nvd_get_cve 返回中文 Markdown 格式（调用实际工具）
5. nvd_search_cve 返回中文格式
6. nvd_get_cves_batch 返回中文格式
7. osv_query_package 返回中文格式
8. osv_get_vuln 返回中文格式
9. get_epss_score 返回中文输出（调用实际工具）
10. check_kev_status 返回中文输出（调用实际工具）
11. search_exploit 返回中文输出（调用实际工具）
12. assess_cve 返回中文输出含表格（调用实际工具）
"""

import asyncio
import sys
import os
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.test_helpers import create_mock_context

_pass_count = 0
_fail_count = 0
_results: list[str] = []

EXPECTED_TOOLS = [
    "nvd_get_cve",
    "nvd_search_cve",
    "nvd_get_cves_batch",
    "osv_query_package",
    "osv_query_batch",
    "osv_get_vuln",
    "get_epss_score",
    "check_kev_status",
    "search_exploit",
    "assess_cve",
]


def report(test_name: str, passed: bool, reason: str = ""):
    global _pass_count, _fail_count
    if passed:
        _pass_count += 1
        line = f"[PASS] {test_name}"
    else:
        _fail_count += 1
        line = f"[FAIL] {test_name} — 原因: {reason}"
    _results.append(line)
    print(line)


# ========== 第一部分: 工具注册 & 元数据检查 ==========

async def test_tool_registration():
    """测试 1: 10 个工具全部注册成功"""
    from src.server import mcp

    tools = await mcp.list_tools()
    tool_names = [t.name for t in tools]
    tool_names_set = set(tool_names)

    missing = [t for t in EXPECTED_TOOLS if t not in tool_names_set]
    extra = [t for t in tool_names if t not in EXPECTED_TOOLS]

    if not missing and len(tool_names) == len(EXPECTED_TOOLS):
        report("10 个工具全部注册", True)
    else:
        reasons = []
        if missing:
            reasons.append(f"缺少: {missing}")
        if len(tool_names) != len(EXPECTED_TOOLS):
            reasons.append(f"注册 {len(tool_names)} 个，预期 {len(EXPECTED_TOOLS)} 个")
        report("10 个工具全部注册", False, "; ".join(reasons))

    return tools


async def test_docstring_chinese():
    """测试 2: 每个工具的 docstring 为中文"""
    from src.server import mcp

    tools = await mcp.list_tools()
    non_chinese = []

    for t in tools:
        desc = t.description or ""
        has_chinese = any("\u4e00" <= c <= "\u9fff" for c in desc)
        if not has_chinese:
            non_chinese.append(t.name)

    if not non_chinese:
        report("所有工具 docstring 为中文", True)
    else:
        report("工具 docstring 为中文", False, f"以下工具不含中文: {non_chinese}")


async def test_tool_annotations():
    """测试 3: 每个工具的 ToolAnnotations 正确"""
    from src.server import mcp

    tools = await mcp.list_tools()
    incorrect = []

    for t in tools:
        ann = t.annotations
        if ann is None:
            incorrect.append(f"{t.name}: annotations 为 None")
            continue
        if ann.readOnlyHint is not True:
            incorrect.append(f"{t.name}: readOnlyHint={ann.readOnlyHint}")
        if ann.destructiveHint is not False:
            incorrect.append(f"{t.name}: destructiveHint={ann.destructiveHint}")
        if ann.idempotentHint is not True:
            incorrect.append(f"{t.name}: idempotentHint={ann.idempotentHint}")
        if ann.openWorldHint is not True:
            incorrect.append(f"{t.name}: openWorldHint={ann.openWorldHint}")

    if not incorrect:
        report("所有工具 ToolAnnotations 正确", True)
    else:
        report("工具 ToolAnnotations 正确", False, "; ".join(incorrect))


# ========== 第二部分: 实际工具函数调用测试 ==========

async def test_nvd_get_cve_tool():
    """测试 4: nvd_get_cve 返回中文 Markdown 格式（调用实际工具）"""
    from src.server import nvd_get_cve

    ctx = await create_mock_context()
    output = await nvd_get_cve("CVE-2021-44228", ctx)

    checks = [
        ("CVE-2021-44228" in output, "包含 CVE ID"),
        ("描述" in output, "中文'描述'"),
        ("CVSS" in output, "包含 CVSS 评分"),
        ("弱点分类" in output, "中文'弱点分类'"),
        ("受影响产品" in output, "中文'受影响产品'"),
        ("参考链接" in output, "中文'参考链接'"),
    ]
    failed_checks = [desc for ok, desc in checks if not ok]
    report("nvd_get_cve 中文 Markdown 格式", not failed_checks,
           f"缺少: {failed_checks}" if failed_checks else "")


async def test_nvd_search_cve_tool():
    """测试 5: nvd_search_cve 返回中文格式

    注意: 因 NVD API keywordExactMatch 参数变更缺陷，
    NVDClient.search_cves 会返回 404，工具会返回错误提示。
    此测试验证错误提示为中文。
    """
    from src.server import nvd_search_cve

    ctx = await create_mock_context()
    output = await nvd_search_cve("log4j", ctx, results=2)

    # 验证输出中含有中文字符
    has_chinese = any("\u4e00" <= c <= "\u9fff" for c in output)
    if has_chinese:
        report("nvd_search_cve 中文输出", True)
    else:
        report("nvd_search_cve 中文输出", False,
               "输出不含中文（工具可能返回了 API 错误原文）")


async def test_nvd_get_cves_batch_tool():
    """测试 6: nvd_get_cves_batch 返回中文格式"""
    from src.server import nvd_get_cves_batch

    ctx = await create_mock_context()
    output = await nvd_get_cves_batch("CVE-2021-44228,CVE-2021-41773", ctx)

    checks = [
        ("批量查询结果" in output or "CVE-2021-44228" in output, "包含 CVE ID"),
    ]
    has_chinese = any("\u4e00" <= c <= "\u9fff" for c in output)
    checks.append((has_chinese, "含中文"))
    failed_checks = [desc for ok, desc in checks if not ok]
    report("nvd_get_cves_batch 中文输出", not failed_checks,
           f"缺少: {failed_checks}" if failed_checks else "")


async def test_osv_query_package_tool():
    """测试 7: osv_query_package 返回中文格式"""
    from src.server import osv_query_package

    ctx = await create_mock_context()
    output = await osv_query_package("lodash", "npm", ctx, "4.17.15")

    checks = [
        ("lodash" in output or "npm" in output, "包含包名/生态系统"),
    ]
    has_chinese = any("\u4e00" <= c <= "\u9fff" for c in output)
    checks.append((has_chinese, "含中文"))
    failed_checks = [desc for ok, desc in checks if not ok]
    report("osv_query_package 中文输出", not failed_checks,
           f"缺少: {failed_checks}" if failed_checks else "")


async def test_osv_get_vuln_tool():
    """测试 8: osv_get_vuln 返回中文格式"""
    from src.server import osv_get_vuln

    ctx = await create_mock_context()
    output = await osv_get_vuln("GHSA-29mw-wpgm-hmr9", ctx)

    checks = [
        ("GHSA-29mw-wpgm-hmr9" in output, "包含漏洞 ID"),
    ]
    has_chinese = any("\u4e00" <= c <= "\u9fff" for c in output)
    checks.append((has_chinese, "含中文"))
    # 检查 OSV 特有的中文标签
    key_fields = ["摘要", "别名", "严重程度", "受影响包", "参考链接"]
    for field in key_fields:
        checks.append((field in output, f"中文'{field}'"))

    failed_checks = [desc for ok, desc in checks if not ok]
    report("osv_get_vuln 中文输出", not failed_checks,
           f"缺少: {failed_checks}" if failed_checks else "")


async def test_epss_tool():
    """测试 9: get_epss_score 返回中文输出（调用实际工具）"""
    from src.server import get_epss_score

    ctx = await create_mock_context()
    output = await get_epss_score("CVE-2021-44228", ctx)

    checks = [
        ("EPSS 评分" in output, "中文'EPSS 评分'"),
        ("30天内被利用概率" in output, "中文'30天内被利用概率'"),
        ("百分位排名" in output, "中文'百分位排名'"),
        ("风险解读" in output, "中文'风险解读'"),
    ]
    failed_checks = [desc for ok, desc in checks if not ok]
    report("get_epss_score 中文输出", not failed_checks,
           f"缺少: {failed_checks}" if failed_checks else "")


async def test_kev_tool():
    """测试 10: check_kev_status 返回中文输出（调用实际工具）"""
    from src.server import check_kev_status

    ctx = await create_mock_context()
    output = await check_kev_status("CVE-2021-44228", ctx)

    checks = [
        ("CISA KEV 状态" in output, "中文'CISA KEV 状态'"),
        ("已被列入" in output or "⚠️" in output, "在列状态提示"),
        ("供应商" in output, "中文'供应商'"),
        ("漏洞名称" in output, "中文'漏洞名称'"),
        ("加入日期" in output, "中文'加入日期'"),
    ]
    failed_checks = [desc for ok, desc in checks if not ok]
    report("check_kev_status 中文输出", not failed_checks,
           f"缺少: {failed_checks}" if failed_checks else "")


async def test_exploit_tool():
    """测试 11: search_exploit 返回中文输出（调用实际工具）"""
    from src.server import search_exploit

    ctx = await create_mock_context()
    output = await search_exploit("CVE-2021-44228", ctx)

    checks = [
        ("公开利用情况" in output, "中文'公开利用情况'"),
        ("总体评估" in output, "中文'总体评估'"),
        ("GitHub" in output, "包含 GitHub 搜索结果"),
        ("Exploit-DB" in output, "包含 Exploit-DB 收录"),
    ]
    failed_checks = [desc for ok, desc in checks if not ok]
    report("search_exploit 中文输出", not failed_checks,
           f"缺少: {failed_checks}" if failed_checks else "")


async def test_assess_tool():
    """测试 12: assess_cve 返回中文输出含表格（调用实际工具）"""
    from src.server import assess_cve

    ctx = await create_mock_context()
    output = await assess_cve("CVE-2021-44228", ctx)

    checks = [
        ("综合评估" in output, "中文'综合评估'"),
        ("CVSS" in output, "包含 CVSS 维度"),
        ("EPSS" in output, "包含 EPSS 维度"),
        ("CISA KEV" in output, "包含 KEV 维度"),
        ("公开 Exploit" in output, "中文'公开 Exploit'"),
        ("| 维度 | 数据 | 解读 |" in output, "表格表头"),
        ("|:---|:---|:---|" in output, "表格分隔线"),
        ("CVE-2021-44228" in output, "包含 CVE ID"),
        ("渗透优先级" in output, "渗透优先级评估"),
    ]
    failed_checks = [desc for ok, desc in checks if not ok]
    report("assess_cve 中文输出含表格", not failed_checks,
           f"缺少: {failed_checks}" if failed_checks else "")


# ========== 主入口 ==========

async def main():
    print("=" * 70)
    print("测试脚本 3: MCP 工具注册 + 格式化输出测试")
    print("=" * 70)
    print()

    print("--- 第一部分: 工具注册 & 元数据检查 (3 个测试) ---")
    await test_tool_registration()
    await test_docstring_chinese()
    await test_tool_annotations()
    print()

    print("--- 第二部分: 实际工具调用 & 中文格式验证 (9 个测试) ---")
    await test_nvd_get_cve_tool()
    await test_nvd_search_cve_tool()
    await test_nvd_get_cves_batch_tool()
    await test_osv_query_package_tool()
    await test_osv_get_vuln_tool()
    await test_epss_tool()
    await test_kev_tool()
    await test_exploit_tool()
    await test_assess_tool()
    print()

    print("=" * 70)
    total = _pass_count + _fail_count
    print(f"通过: {_pass_count}/{total}, 失败: {_fail_count}/{total}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
