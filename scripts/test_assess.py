"""测试脚本 2: assess_cve 综合评估测试

直接调用 server.py 中的实际 assess_cve 工具函数（传入模拟 Context），
验证 4 个场景的输出和中文格式。

测试 4 个场景 + 1 个格式验证：
1. CVE-2021-44228（Log4Shell）— 四维度均有数据
2. CVE-2024-1234（虚构低危 CVE）— 低优先级
3. CVE-9999-99999（不存在 CVE）— 提示未找到
4. 格式错误 "not-a-cve" — 返回格式错误提示
5. 验证中文输出含表格
"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.test_helpers import create_mock_context

_pass_count = 0
_fail_count = 0
_results: list[str] = []


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


# ========== 测试用例 ==========

async def test_assess_log4shell():
    """测试 1: CVE-2021-44228 — 四维度均有数据 → 优先级最高"""
    from src.server import assess_cve

    ctx = await create_mock_context()
    output = await assess_cve("CVE-2021-44228", ctx)

    reasons = []
    # 检查四维度
    checks = [
        ("CVSS" in output, "CVSS 维度"),
        ("EPSS" in output, "EPSS 维度"),
        ("CISA KEV" in output, "KEV 维度"),
        ("公开 Exploit" in output, "Exploit 维度"),
        ("CRITICAL" in output or "严重" in output, "CVSS 严重等级"),
        ("⚠️ 在列" in output, "KEV 在列"),
        ("渗透优先级" in output, "优先级评估"),
    ]
    for ok, desc in checks:
        if not ok:
            reasons.append(desc)

    passed = len(reasons) == 0
    report("assess CVE-2021-44228 (四维度齐全)", passed, "; ".join(reasons))


async def test_assess_low_priority():
    """测试 2: CVE-2024-1234 — 低优先级

    检证维度：
    - NVD: 有数据（CVSS MEDIUM 或更低）或无数据
    - KEV: 不在列
    - PoC: 无或仅 PUBLIC_POC
    """
    from src.server import assess_cve

    ctx = await create_mock_context()
    output = await assess_cve("CVE-2024-1234", ctx)

    reasons = []
    # 检查 KEV 不在列
    if "未列入" not in output and "✅ 不在列" not in output:
        reasons.append("KEV 状态应为不在列")

    # 检查没有 WEAPONIZED 或 PUBLIC_EXPLOIT
    if "WEAPONIZED" in output or "PUBLIC_EXPLOIT" in output:
        reasons.append("PoC 等级不应为武器化")

    # 检查优先级为低或中
    priority_low = "低" in output and "暂不优先" in output
    priority_medium = "中" in output and "有价值" in output
    if not (priority_low or priority_medium):
        reasons.append("优先级应为低或中")

    passed = len(reasons) == 0
    report("assess CVE-2024-1234 (低优先级)", passed, "; ".join(reasons))


async def test_assess_nonexistent():
    """测试 3: 不存在的 CVE "CVE-9999-99999" → NVD 返回空

    assess_cve 对无 NVD 数据的 CVE 输出 N/A 值，返回正常格式但不崩溃。
    """
    from src.server import assess_cve

    ctx = await create_mock_context()
    output = await assess_cve("CVE-9999-99999", ctx)

    # assess_cve 不会因为 NVD 无数据就崩溃，而是正常输出 N/A 值
    checks = [
        ("CVE-9999-99999" in output, "包含 CVE ID"),
        ("综合评估" in output, "正常输出格式"),
        ("N/A" in output, "无数据字段显示 N/A"),
        ("错误" not in output, "不包含异常关键词'错误'"),
        ("异常" not in output, "不包含异常关键词'异常'"),
    ]
    failed_checks = [desc for ok, desc in checks if not ok]
    if not failed_checks:
        report("assess CVE-9999-99999 (不存在 CVE)", True)
    else:
        report("assess CVE-9999-99999", False, f"检查失败: {failed_checks}")


async def test_assess_invalid_format():
    """测试 4: 格式错误 "not-a-cve" → 返回格式错误提示"""
    from src.server import assess_cve

    ctx = await create_mock_context()
    output = await assess_cve("not-a-cve", ctx)

    if "无效" in output or "格式" in output:
        report("assess not-a-cve (格式错误)", True)
    else:
        report("assess not-a-cve", False, f"未返回格式错误提示: {output[:100]}")


# ========== 格式化输出验证 ==========

async def test_assess_format():
    """测试 5: 验证 assess_cve 中文输出含表格"""
    from src.server import assess_cve

    ctx = await create_mock_context()
    output = await assess_cve("CVE-2021-44228", ctx)

    checks = [
        ("CVE-2021-44228" in output, "包含 CVE ID"),
        ("综合评估" in output, "中文标题"),
        ("CVSS" in output, "CVSS 维度"),
        ("EPSS" in output, "EPSS 维度"),
        ("CISA KEV" in output, "KEV 维度"),
        ("公开 Exploit" in output, "中文'公开 Exploit'"),
        ("|" in output, "表格格式（含 | 分隔符）"),
        ("渗透优先级" in output, "渗透优先级"),
    ]
    failed_checks = [desc for ok, desc in checks if not ok]
    if not failed_checks:
        report("assess_cve 中文输出含表格", True)
    else:
        report("assess_cve 中文输出含表格", False, f"缺少: {failed_checks}")


# ========== 主入口 ==========

async def main():
    print("=" * 70)
    print("测试脚本 2: assess_cve 综合评估测试（调用实际工具函数）")
    print("=" * 70)
    print()
    print("--- 核心评估测试 (4 个测试) ---")
    await test_assess_log4shell()
    await test_assess_low_priority()
    await test_assess_nonexistent()
    await test_assess_invalid_format()
    print()
    print("--- 格式化输出验证 (1 个测试) ---")
    await test_assess_format()
    print()
    print("=" * 70)
    total = _pass_count + _fail_count
    print(f"通过: {_pass_count}/{total}, 失败: {_fail_count}/{total}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
