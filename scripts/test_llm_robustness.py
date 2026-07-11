"""测试脚本: LLM 输入健壮性 + 输出友好性验证

直接调用 server.py 中的工具函数（传入模拟 Context），
验证 LLM 常见错误输入的容错能力、错误提示质量、输出 LLM 友好度。

测试类别:
  A. 空格与格式 (6)
  B. 错误参数类型 (5)
  C. 自然语言输入 (3)
  D. 批量查询边界 (3)
  E. OSV 特有边界 (3)
  F. 错误提示质量 (8)
  G. 输出 LLM 友好度 (6)
"""

import asyncio
import sys
import os
import json
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.test_helpers import create_mock_context
from src.config import GITHUB_TOKEN

# ========== 结果跟踪 ==========

CATEGORIES = ["A", "B", "C", "D", "E", "F", "G"]
CATEGORY_NAMES = {
    "A": "A.空格格式",
    "B": "B.错误参数",
    "C": "C.自然语言",
    "D": "D.批量边界",
    "E": "E.OSV边界",
    "F": "F.错误提示",
    "G": "G.LLM友好度",
}
CATEGORY_TOTALS = {"A": 6, "B": 5, "C": 3, "D": 3, "E": 3, "F": 8, "G": 6}

results: dict[str, dict[str, int]] = {
    cat: {"pass": 0, "fail": 0, "warn": 0} for cat in CATEGORIES
}
details: list[str] = []


def record(cat: str, test_id: str, status: str, reason: str = ""):
    """记录测试结果。status: PASS / FAIL / WARN"""
    results[cat][status.lower()] += 1
    msg = f"[{status}] {test_id}"
    if reason:
        msg += f" — {reason}"
    print(msg)
    details.append(msg)


def check_output_contains(output: str, keywords: list[str]) -> list[str]:
    """检查输出是否包含所有关键词，返回缺失的关键词列表"""
    missing = []
    for kw in keywords:
        if kw not in output:
            missing.append(kw)
    return missing


def ascii_check(passed: bool, label: str) -> str:
    """返回 ASCII 安全的检查标记"""
    return f"[OK] {label}" if passed else f"[--] {label}"


def ascii_x(label: str) -> str:
    """返回 ASCII 安全的缺失标记"""
    return f"[--] {label}"


async def main():
    print("=" * 72)
    print("LLM 输入健壮性 + 输出友好性验证测试")
    print("=" * 72)
    print()

    ctx = await create_mock_context()

    # ================================================================
    # A. 空格与格式 (6 个)
    # ================================================================
    print("--- A. 空格与格式 ---")
    from src.server import nvd_get_cve, nvd_get_cves_batch

    # A1: 前后空格
    out = await nvd_get_cve("  CVE-2021-44228  ", ctx)
    if "CVE-2021-44228" in out and "CVSS" in out:
        record("A", "A1 nvd_get_cve 前后空格", "PASS")
    else:
        record("A", "A1 nvd_get_cve 前后空格", "FAIL",
               f"未自动去除空格，返回: {out[:120]}")

    # A2: 小写转大写
    out = await nvd_get_cve("cve-2021-44228", ctx)
    if "CVE-2021-44228" in out and "CVSS" in out:
        record("A", "A2 nvd_get_cve 小写转大写", "PASS")
    else:
        record("A", "A2 nvd_get_cve 小写转大写", "FAIL",
               f"未处理小写，返回: {out[:120]}")

    # A3: 尾部换行
    out = await nvd_get_cve("cve-2021-44228\n", ctx)
    if "CVE-2021-44228" in out and "CVSS" in out:
        record("A", "A3 nvd_get_cve 尾部换行", "PASS")
    else:
        record("A", "A3 nvd_get_cve 尾部换行", "FAIL",
               f"未处理换行符，返回: {out[:120]}")

    # A4: NBSP 不间断空格
    out = await nvd_get_cve("CVE\u00a02021-44228", ctx)
    if "错误" in out and ("格式" in out or "无效" in out):
        record("A", "A4 nvd_get_cve NBSP不间断空格", "PASS",
               "返回了格式错误提示，未崩溃")
    else:
        record("A", "A4 nvd_get_cve NBSP不间断空格", "FAIL",
               f"行为异常: {out[:120]}")

    # A5: 逗号后有空格的批量查询
    out = await nvd_get_cves_batch("CVE-2021-44228, CVE-2017-0144, CVE-2020-1472", ctx)
    if "批量查询结果" in out and ("CVE-2021-44228" in out or "CVE-2017-0144" in out):
        record("A", "A5 nvd_get_cves_batch 逗号后空格", "PASS")
    else:
        record("A", "A5 nvd_get_cves_batch 逗号后空格", "FAIL",
               f"未正确处理逗号后空格: {out[:150]}")

    # A6: 分号分隔
    out = await nvd_get_cves_batch("CVE-2021-44228;CVE-2017-0144", ctx)
    if "逗号" in out or "分隔符" in out:
        record("A", "A6 nvd_get_cves_batch 分号分隔", "WARN",
               "返回了错误，但提示了分隔符应为逗号")
    elif "分号" in out or ";" in out:
        record("A", "A6 nvd_get_cves_batch 分号分隔", "WARN",
               "未明确指出逗号分隔符")
    else:
        record("A", "A6 nvd_get_cves_batch 分号分隔", "FAIL",
               f"未区分分号和逗号: {out[:120]}")

    # ================================================================
    # B. 错误参数类型 (5 个)
    # ================================================================
    print()
    print("--- B. 错误参数类型 ---")

    # B1: 空字符串 CVE
    out = await nvd_get_cve("", ctx)
    missing = check_output_contains(out, ["CVE", "输入"])
    if "请输入" in out or "不能为空" in out:
        record("B", "B1 nvd_get_cve 空字符串", "PASS",
               "提示了需要输入")
    elif "格式" in out:
        record("B", "B1 nvd_get_cve 空字符串", "WARN",
               "返回了格式错误，但未提示'请输入CVE编号'")
    else:
        record("B", "B1 nvd_get_cve 空字符串", "FAIL",
               f"未给出友好提示: {out[:120]}")

    # B2: 空关键词搜索
    from src.server import nvd_search_cve
    out = await nvd_search_cve("", ctx)
    if "请输入" in out or "搜索关键词" in out or "keyword" in out.lower():
        record("B", "B2 nvd_search_cve 空关键词", "WARN",
               "未崩溃但未提示'请输入搜索关键词'")
    elif "错误" in out or "异常" in out:
        record("B", "B2 nvd_search_cve 空关键词", "FAIL",
               f"空关键词处理不当: {out[:120]}")
    else:
        record("B", "B2 nvd_search_cve 空关键词", "WARN",
               f"以API结果返回了空关键词: {out[:100]}")

    # B3: 自然语言句子传给 assess_cve
    from src.server import assess_cve
    out = await assess_cve("just a sentence", ctx)
    if "无效" in out and "格式" in out:
        record("B", "B3 assess_cve 自然语言句子", "PASS",
               "格式校验拦截，未调用API")
    else:
        record("B", "B3 assess_cve 自然语言句子", "FAIL",
               f"未拦截: {out[:120]}")

    # B4: 超长输入
    long_input = "CVE-2021-" + "A" * 500
    out = await nvd_get_cve(long_input, ctx)
    if "过长" in out or "太长" in out or "长度" in out:
        record("B", "B4 nvd_get_cve 超长输入", "PASS",
               "返回了输入过长提示")
    elif "格式" in out and "无效" in out:
        record("B", "B4 nvd_get_cve 超长输入", "WARN",
               "未崩溃但未特别提示'输入过长'")
    else:
        record("B", "B4 nvd_get_cve 超长输入", "FAIL",
               f"行为异常: {out[:120]}")

    # B5: 路径遍历攻击
    from src.server import osv_get_vuln
    out = await osv_get_vuln("../../../etc/passwd", ctx)
    if "无效" in out or "格式" in out:
        record("B", "B5 osv_get_vuln 路径遍历", "PASS",
               "格式校验拦截")
    elif "未找到" in out or "错误" in out:
        record("B", "B5 osv_get_vuln 路径遍历", "WARN",
               "未明确拦截但未崩溃")
    else:
        record("B", "B5 osv_get_vuln 路径遍历", "FAIL",
               f"未拦截路径遍历: {out[:120]}")

    # ================================================================
    # C. 自然语言输入 (3 个)
    # ================================================================
    print()
    print("--- C. 自然语言输入 ---")

    # C1: "log4shell" 传给 nvd_get_cve
    out = await nvd_get_cve("log4shell", ctx)
    if "不是有效的" in out or ("CVE" in out and "编号" in out and "格式" in out):
        if "search" in out.lower() or "搜索" in out:
            record("C", "C1 nvd_get_cve log4shell", "PASS",
                   "格式校验+建议使用搜索")
        else:
            record("C", "C1 nvd_get_cve log4shell", "WARN",
                   "提示格式错误但未建议使用 nvd_search_cve")
    else:
        record("C", "C1 nvd_get_cve log4shell", "FAIL",
               f"未给出有用提示: {out[:120]}")

    # C2: 自然语言传给 nvd_search_cve
    out = await nvd_search_cve("tell me about log4j vulnerability", ctx)
    if "错误" in out or "异常" in out:
        record("C", "C2 nvd_search_cve 自然语言", "FAIL",
               f"自然语言搜索导致错误: {out[:120]}")
    else:
        record("C", "C2 nvd_search_cve 自然语言", "PASS",
               "未崩溃，返回搜索结果或空结果")

    # C3: 包名含空格
    from src.server import osv_query_package
    out = await osv_query_package("npm lodash", "npm", ctx)
    if "空格" in out or "格式" in out:
        record("C", "C3 osv_query_package 空格包名", "WARN",
               "未明确提示格式，但返回了可读结果")
    elif "npm lodash" in out or "lodash" in out:
        record("C", "C3 osv_query_package 空格包名", "WARN",
               "API接受了含空格的包名，未提示格式问题")
    else:
        record("C", "C3 osv_query_package 空格包名", "FAIL",
               f"异常结果: {out[:120]}")

    # ================================================================
    # D. 批量查询边界 (3 个)
    # ================================================================
    print()
    print("--- D. 批量查询边界 ---")

    # D1: 1 个 CVE
    out = await nvd_get_cves_batch("CVE-2021-44228", ctx)
    if "CVE-2021-44228" in out and ("描述" in out or "CVSS" in out):
        record("D", "D1 nvd_get_cves_batch 1个CVE", "PASS")
    else:
        record("D", "D1 nvd_get_cves_batch 1个CVE", "FAIL",
               f"单个CVE批量查询失败: {out[:120]}")

    # D2: 重复 CVE
    out = await nvd_get_cves_batch("CVE-2021-44228,CVE-2021-44228", ctx)
    if "CVE-2021-44228" in out:
        record("D", "D2 nvd_get_cves_batch 重复CVE", "PASS",
               "未崩溃，正常返回结果")
    else:
        record("D", "D2 nvd_get_cves_batch 重复CVE", "FAIL",
               f"重复CVE查询异常: {out[:120]}")

    # D3: 混合有效+无效 CVE
    out = await nvd_get_cves_batch(
        "CVE-2021-44228,CVE-9999-99999,not_a_cve", ctx
    )
    if "CVE-2021-44228" in out and ("无效" in out or "格式" in out):
        record("D", "D3 nvd_get_cves_batch 混合有效无效", "WARN",
               "部分结果返回，但混合模式处理不够完善")
    elif "CVE-2021-44228" in out:
        record("D", "D3 nvd_get_cves_batch 混合有效无效", "WARN",
               "已返回有效结果，但无效CVE需单独提示")
    elif "无效" in out and ("格式" in out):
        record("D", "D3 nvd_get_cves_batch 混合有效无效", "FAIL",
               "整体失败，应为部分结果+部分提示: 当前行为是遇到第一个无效CVE就返回错误")
    else:
        record("D", "D3 nvd_get_cves_batch 混合有效无效", "FAIL",
               f"异常行为: {out[:120]}")

    # ================================================================
    # E. OSV 特有边界 (3 个)
    # ================================================================
    print()
    print("--- E. OSV 边界 ---")

    # E1: 空包名
    out = await osv_query_package("", "npm", ctx)
    if "不能为空" in out or "缺少" in out or "请输入" in out:
        record("E", "E1 osv_query_package 空包名", "PASS",
               "提示了包名不能为空")
    elif "错误" in out or "异常" in out:
        record("E", "E1 osv_query_package 空包名", "WARN",
               "未友好提示但未崩溃")
    else:
        record("E", "E1 osv_query_package 空包名", "FAIL",
               f"空包名处理异常: {out[:120]}")

    # E2: 不完整的 GHSA ID
    out = await osv_get_vuln("GHSA", ctx)
    if "错误" in out or "异常" in out:
        record("E", "E2 osv_get_vuln 不完整GHSA", "FAIL",
               f"不完整GHSA返回了硬错误: {out[:120]}")
    elif "未找到" in out or "N/A" in out:
        record("E", "E2 osv_get_vuln 不完整GHSA", "PASS",
               "不崩溃，返回未找到或空结果")
    else:
        record("E", "E2 osv_get_vuln 不完整GHSA", "PASS",
               f"未崩溃: {out[:80]}")

    # E3: 空数组批量查询
    from src.server import osv_query_batch
    out = await osv_query_batch("[]", ctx)
    if "空" in out:
        record("E", "E3 osv_query_batch 空数组", "PASS",
               "提示了查询列表为空")
    elif "缺少" in out or "字段" in out:
        record("E", "E3 osv_query_batch 空数组", "WARN",
               "返回了字段缺失提示而非'列表为空'")
    else:
        record("E", "E3 osv_query_batch 空数组", "FAIL",
               f"空数组处理异常: {out[:120]}")

    # ================================================================
    # F. 错误提示质量 (8 个)
    # ================================================================
    print()
    print("--- F. 错误提示质量 ---")

    # F1: nvd_get_cve 非 CVE 格式 — 含"格式"+"YYYY-NNNN"+建议用 search
    out = await nvd_get_cve("log4shell", ctx)
    f1_checks = []
    if "格式" in out: f1_checks.append(ascii_check(True, "含格式"))
    else: f1_checks.append(ascii_x("缺格式"))
    if "YYYY" in out or "NNNN" in out or "CVE-0000" in out:
        f1_checks.append(ascii_check(True, "含格式示例"))
    else:
        f1_checks.append(ascii_x("缺格式示例"))
    if "search" in out.lower() or "搜索" in out:
        f1_checks.append(ascii_check(True, "含搜索建议"))
    else:
        f1_checks.append(ascii_x("缺搜索建议"))
    missing_f1 = [c for c in f1_checks if c.startswith("[--]")]
    if not missing_f1:
        record("F", "F1 nvd_get_cve 非CVE格式提示", "PASS")
    elif len(missing_f1) <= 2:
        record("F", "F1 nvd_get_cve 非CVE格式提示", "WARN",
               f"部分满足: {', '.join(f1_checks)}")
    else:
        record("F", "F1 nvd_get_cve 非CVE格式提示", "FAIL",
               f"不满足: {', '.join(missing_f1)}")

    # F2: nvd_get_cve 不存在 CVE — "未找到"+"确认编号"+建议搜索
    out = await nvd_get_cve("CVE-9999-99999", ctx)
    f2_checks = []
    if "未找到" in out or "不存在" in out or "无结果" in out:
        f2_checks.append(ascii_check(True, "提示未找到"))
    else:
        f2_checks.append(ascii_x("缺未找到"))
    if "确认" in out:
        f2_checks.append(ascii_check(True, "含确认"))
    else:
        f2_checks.append(ascii_x("缺确认"))
    if "search" in out.lower() or "搜索" in out:
        f2_checks.append(ascii_check(True, "含搜索建议"))
    else:
        f2_checks.append(ascii_x("缺搜索建议"))
    missing_f2 = [c for c in f2_checks if c.startswith("[--]")]
    if not missing_f2:
        record("F", "F2 nvd_get_cve 不存在CVE提示", "PASS")
    elif len(missing_f2) <= 1:
        record("F", "F2 nvd_get_cve 不存在CVE提示", "WARN",
               f"部分满足: {', '.join(f2_checks)}")
    else:
        record("F", "F2 nvd_get_cve 不存在CVE提示", "FAIL",
               f"不满足: {', '.join(missing_f2)}")

    # F3: nvd_search_cve 0 结果 — "无结果"+"尝试其他关键词"
    out = await nvd_search_cve(
        "xyzxyz_nonexistent_12345_abcdef", ctx, results=3
    )
    f3_checks = []
    if "无结果" in out or "未找到" in out or "没有" in out:
        f3_checks.append(ascii_check(True, "提示无结果"))
    else:
        f3_checks.append(ascii_x("缺无结果"))
    if "尝试" in out or "其他" in out:
        f3_checks.append(ascii_check(True, "含尝试其他关键词"))
    else:
        f3_checks.append(ascii_x("缺其他关键词建议"))
    missing_f3 = [c for c in f3_checks if c.startswith("[--]")]
    if not missing_f3:
        record("F", "F3 nvd_search_cve 0结果提示", "PASS")
    elif len(missing_f3) == 1:
        record("F", "F3 nvd_search_cve 0结果提示", "WARN",
               f"部分满足: {', '.join(f3_checks)}")
    else:
        record("F", "F3 nvd_search_cve 0结果提示", "FAIL",
               f"不满足: {', '.join(missing_f3)}")

    # F4: assess_cve 格式错误 — 含"CVE 编号格式"+示例
    out = await assess_cve("invalid", ctx)
    f4_checks = []
    if "CVE" in out and "格式" in out:
        f4_checks.append(ascii_check(True, "含CVE编号格式"))
    else:
        f4_checks.append(ascii_x("缺CVE编号格式"))
    if "YYYY" in out or "NNNN" in out or "CVE-0000" in out:
        f4_checks.append(ascii_check(True, "含示例"))
    else:
        f4_checks.append(ascii_x("缺示例"))
    missing_f4 = [c for c in f4_checks if c.startswith("[--]")]
    if not missing_f4:
        record("F", "F4 assess_cve 格式错误提示", "PASS")
    else:
        record("F", "F4 assess_cve 格式错误提示", "FAIL",
               f"不满足: {', '.join(missing_f4)}")

    # F5: osv_query_package 无结果 — "未找到"
    out = await osv_query_package(
        "nonexistent_pkg_xyz_98765", "npm", ctx
    )
    if "未发现" in out or "未找到" in out or "无" in out:
        record("F", "F5 osv_query_package 无结果提示", "PASS",
               "提示了未发现漏洞")
    else:
        record("F", "F5 osv_query_package 无结果提示", "FAIL",
               f"未提示未找到: {out[:100]}")

    # F6: EPSS 查不到某 CVE — "无 EPSS 数据"（不混淆为 CVE 不存在）
    from src.server import get_epss_score
    out = await get_epss_score("CVE-9999-99999", ctx)
    if "EPSS" in out and ("未找到" in out or "无" in out or "评分" in out):
        if "CVE" not in out.replace("EPSS", "").split("未找到")[-1][:20] \
           if "未找到" in out else True:
            record("F", "F6 EPSS 查不到CVE提示", "PASS",
                   "未混淆为CVE不存在")
        else:
            record("F", "F6 EPSS 查不到CVE提示", "WARN",
                   "提示了无EPSS数据（但细节含混）")
    else:
        record("F", "F6 EPSS 查不到CVE提示", "FAIL",
               f"未提示无EPSS数据: {out[:120]}")

    # F7: GitHub Token 缺失 — 说明只影响了 GitHub 搜索
    # 由于当前环境有 GITHUB_TOKEN，创建一个临时的无 Token 上下文
    from src.server import search_exploit
    from src.clients.exploit_client import ExploitClient
    from src.clients.nvd_client import NVDClient
    from src.clients.osv_client import OSVClient
    from src.clients.epss_client import EPSSClient
    from src.clients.kev_client import KEVClient
    from scripts.test_helpers import MockContext

    if GITHUB_TOKEN:
        # 有 Token: 创建一个无 Token 的模拟 Context 来测试
        no_token_exploit = ExploitClient(github_token="")
        no_token_nvd = NVDClient(api_key="dummy")
        no_token_kev_catalog = []
        no_token_kev_index = {}
        from src.config import NVD_API_KEY
        # 需要用真实 API key 才能让其他依赖正常工作
        no_token_nvd = NVDClient(api_key=NVD_API_KEY)
        no_token_ctx = MockContext({
            "nvd_client": no_token_nvd,
            "osv_client": OSVClient(),
            "epss_client": EPSSClient(),
            "kev_client": KEVClient(),
            "kev_catalog": [],
            "kev_index": {},
            "exploit_client": no_token_exploit,
        })
        out = await search_exploit("CVE-2021-44228", no_token_ctx)
        if "未配置" in out and "GitHub Token" in out and "跳过" in out:
            record("F", "F7 search_exploit Token缺失提示", "PASS",
                   "已说明Token缺失只影响GitHub搜索")
        else:
            record("F", "F7 search_exploit Token缺失提示", "FAIL",
                   f"未明确提示Token缺失: {out[:150]}")
    else:
        # 无 Token: 直接用真实上下文
        out = await search_exploit("CVE-2021-44228", ctx)
        if "未配置" in out and "GitHub Token" in out:
            record("F", "F7 search_exploit Token缺失提示", "PASS")
        else:
            record("F", "F7 search_exploit Token缺失提示", "FAIL",
                   f"未提示Token缺失: {out[:150]}")

    # F8: nvd_get_cves_batch 超 100 个 — "最多 100 个"
    too_many = ",".join([f"CVE-2024-{i:04d}" for i in range(1, 102)])
    out = await nvd_get_cves_batch(too_many, ctx)
    if "最多" in out and "100" in out:
        record("F", "F8 nvd_get_cves_batch 超100个提示", "PASS",
               "提示了最多100个的限制")
    else:
        record("F", "F8 nvd_get_cves_batch 超100个提示", "FAIL",
               f"未提示数量限制: {out[:120]}")

    # ================================================================
    # G. 输出 LLM 友好度 (6 个)
    # ================================================================
    print()
    print("--- G. 输出 LLM 友好度 ---")

    # G1: assess_cve 输出可操作的优先级建议语言
    out = await assess_cve("CVE-2021-44228", ctx)
    priority_keywords = ["立即", "优先", "重点关注", "修复", "🟠", "🔴", "🟡"]
    found_priority = [kw for kw in priority_keywords if kw in out]
    if found_priority:
        record("G", "G1 assess_cve 优先级建议", "PASS",
               f"含可操作建议: {found_priority[0]}")
    else:
        record("G", "G1 assess_cve 优先级建议", "FAIL",
               "输出中无可操作的优先级建议语言")

    # G2: nvd_get_cve 的 CVSS 评分含中文解读
    out = await nvd_get_cve("CVE-2021-44228", ctx)
    severity_cn = ["严重", "高危", "中危", "低危"]
    found_sev = [s for s in severity_cn if s in out]
    if found_sev:
        record("G", "G2 nvd_get_cve CVSS中文解读", "PASS",
               f"含{found_sev[0]}")
    else:
        # 可能 concise 模式
        if "CRITICAL" in out or "HIGH" in out:
            record("G", "G2 nvd_get_cve CVSS中文解读", "WARN",
                   "CVSS等级为英文，未转换为中文")
        else:
            record("G", "G2 nvd_get_cve CVSS中文解读", "FAIL",
                   "CVSS评分缺少等级解读")

    # G3: check_kev_status 用 ✅/⚠️ 符号
    from src.server import check_kev_status
    out_in_kev = await check_kev_status("CVE-2021-44228", ctx)
    out_not_kev = await check_kev_status("CVE-2024-9999", ctx)
    if "✅" in out_not_kev or "⚠️" in out_not_kev:
        record("G", "G3 check_kev_status 符号区分", "PASS",
               "在列或不在列均有直观符号")
    elif "✅" in out_in_kev or "⚠️" in out_in_kev:
        record("G", "G3 check_kev_status 符号区分", "PASS",
               "有符号区分状态")
    else:
        record("G", "G3 check_kev_status 符号区分", "FAIL",
               "未用 ✅/⚠️ 符号直观区分")

    # G4: get_epss_score 概率值附带中文解读
    out = await get_epss_score("CVE-2021-44228", ctx)
    risk_labels = ["极高", "较高", "中等", "较低", "风险解读"]
    found_risk = [r for r in risk_labels if r in out]
    if found_risk:
        record("G", "G4 get_epss_score 中文解读", "PASS",
               f"含中文解读: {found_risk[0]}")
    else:
        record("G", "G4 get_epss_score 中文解读", "FAIL",
               "概率值未附带中文解读")

    # G5: search_exploit 结果分开显示
    out = await search_exploit("CVE-2021-44228", ctx)
    if "GitHub" in out and "Exploit-DB" in out:
        record("G", "G5 search_exploit 结果结构", "PASS",
               "GitHub和Exploit-DB分开显示")
    else:
        record("G", "G5 search_exploit 结果结构", "FAIL",
               f"结果未分开显示: {out[:100]}")

    # G6: Markdown 格式正确性（表格/标题）
    # 检查是否包含至少一个 ## 标题且格式正确
    md_checks = []
    if re.search(r"^## ", out_in_kev, re.MULTILINE):
        md_checks.append(ascii_check(True, "标题格式"))
    else:
        md_checks.append(ascii_x("缺标题"))
    if "|" in out_in_kev and "---" in out_in_kev:
        md_checks.append(ascii_check(True, "表格格式"))
    elif "|" in out_in_kev:
        md_checks.append(ascii_check(True, "含表格(无分隔线)"))
    else:
        md_checks.append(ascii_x("缺表格"))
    if "[http" in out_in_kev or "<http" in out_in_kev:
        md_checks.append(ascii_check(True, "含链接"))
    missing_g6 = [c for c in md_checks if c.startswith("[--]")]
    if not missing_g6:
        record("G", "G6 Markdown格式正确性", "PASS")
    else:
        record("G", "G6 Markdown格式正确性", "WARN",
               f"部分格式问题: {', '.join(missing_g6)}")

    # ================================================================
    # 汇总
    # ================================================================
    print()
    print("=" * 72)
    print("汇总表")
    print("=" * 72)
    print(f"{'类别':<16} {'通过':>6} {'失败':>6} {'警告':>6}")
    print("-" * 36)
    total_pass = total_fail = total_warn = 0
    for cat in CATEGORIES:
        p = results[cat]["pass"]
        f = results[cat]["fail"]
        w = results[cat]["warn"]
        total_pass += p
        total_fail += f
        total_warn += w
        print(f"{CATEGORY_NAMES[cat]:<16} {p:>6} {f:>6} {w:>6}")
    print("-" * 36)
    total_cases = total_pass + total_fail + total_warn
    print(f"{'合计':<16} {total_pass:>6} {total_fail:>6} {total_warn:>6}")
    print(f"总用例数: {total_cases}")
    print()

    # 输出详细结果
    print("=" * 72)
    print("详细结果")
    print("=" * 72)
    for d in details:
        print(d)

    print()
    print("=" * 72)
    print(f"总通过: {total_pass}/{total_cases}, "
          f"失败: {total_fail}/{total_cases}, "
          f"警告: {total_warn}/{total_cases}")
    print("=" * 72)


if __name__ == "__main__":
    asyncio.run(main())
