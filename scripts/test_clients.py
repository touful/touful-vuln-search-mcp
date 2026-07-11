"""测试脚本 1: 底层 Client 连通性测试

测试所有 5 个 client 模块的 API 连通性：
NVDClient / OSVClient / EPSSClient / KEVClient / ExploitClient

共 15 个测试用例，每个打印 [PASS] 或 [FAIL]。
"""

import asyncio
import sys
import os

# 将项目根目录加入 path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 全局测试结果统计
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


# ========== NVDClient ==========

async def test_nvd_get_cve():
    """测试 1: nvd.get_cve("CVE-2021-44228") → 返回含 id/CVSS/descriptions 的 dict"""
    from src.clients.nvd_client import NVDClient
    from src.config import NVD_API_KEY
    nvd = NVDClient(api_key=NVD_API_KEY)
    try:
        result = await nvd.get_cve("CVE-2021-44228")
        vulnerabilities = result.get("vulnerabilities", [])
        if not vulnerabilities:
            report("nvd_get_cve", False, "vulnerabilities 为空")
            return
        cve = vulnerabilities[0].get("cve", {})
        cve_id = cve.get("id", "")
        has_cvss = bool(cve.get("metrics", {}))
        has_desc = bool(cve.get("descriptions", []))
        if cve_id and has_cvss and has_desc:
            report("nvd_get_cve (CVE-2021-44228)", True)
        else:
            report("nvd_get_cve", False, f"字段不完整: id={cve_id}, cvss={has_cvss}, desc={has_desc}")
    except Exception as e:
        report("nvd_get_cve", False, f"{type(e).__name__}: {e}")


async def test_nvd_search_cves():
    """测试 2: nvd.search_cves("log4j", results=2) → 返回 vulnerabilities 列表，totalResults > 0"""
    from src.clients.nvd_client import NVDClient
    from src.config import NVD_API_KEY
    nvd = NVDClient(api_key=NVD_API_KEY)
    try:
        result = await nvd.search_cves("log4j", exact_match=False, results=2)
        total = result.get("totalResults", 0)
        vulnerabilities = result.get("vulnerabilities", [])
        if total > 0 and len(vulnerabilities) > 0:
            report("nvd_search_cves (log4j)", True)
        else:
            report("nvd_search_cves", False, f"totalResults={total}, vulnerabilities={len(vulnerabilities)}")
    except ValueError as e:
        report("nvd_search_cves", False, f"ValueError: {e}")
    except Exception as e:
        report("nvd_search_cves", False, f"{type(e).__name__}: {e}")


async def test_nvd_get_cves_batch():
    """测试 3: nvd.get_cves_batch(["CVE-2021-44228", "CVE-2021-41773"]) → 返回 2 个 CVE"""
    from src.clients.nvd_client import NVDClient
    from src.config import NVD_API_KEY
    nvd = NVDClient(api_key=NVD_API_KEY)
    try:
        result = await nvd.get_cves_batch(["CVE-2021-44228", "CVE-2021-41773"])
        vulnerabilities = result.get("vulnerabilities", [])
        if len(vulnerabilities) == 2:
            report("nvd_get_cves_batch (2 CVE)", True)
        else:
            report("nvd_get_cves_batch", False, f"返回 {len(vulnerabilities)} 条，预期 2 条")
    except Exception as e:
        report("nvd_get_cves_batch", False, f"{type(e).__name__}: {e}")


# ========== OSVClient ==========

async def test_osv_query_package():
    """测试 4: osv.query_package("lodash", "npm", "4.17.15") → 返回 vulns 列表，len > 0"""
    from src.clients.osv_client import OSVClient
    osv = OSVClient()
    try:
        result = await osv.query_package("lodash", "npm", "4.17.15")
        vulns = result.get("vulns", [])
        if len(vulns) > 0:
            report("osv_query_package (lodash@4.17.15)", True)
        else:
            report("osv_query_package", False, "vulns 为空")
    except Exception as e:
        report("osv_query_package", False, f"{type(e).__name__}: {e}")


async def test_osv_query_batch():
    """测试 5: osv.query_batch → 返回 results 列表"""
    from src.clients.osv_client import OSVClient
    osv = OSVClient()
    try:
        queries = [{"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.15"}]
        result = await osv.query_batch(queries)
        results_list = result.get("results", [])
        if len(results_list) == 1:
            report("osv_query_batch", True)
        else:
            report("osv_query_batch", False, f"results 返回 {len(results_list)} 条")
    except Exception as e:
        report("osv_query_batch", False, f"{type(e).__name__}: {e}")


async def test_osv_get_vuln():
    """测试 6: osv.get_vuln("GHSA-29mw-wpgm-hmr9") → 返回 id/summary/aliases/affected"""
    from src.clients.osv_client import OSVClient
    osv = OSVClient()
    try:
        result = await osv.get_vuln("GHSA-29mw-wpgm-hmr9")
        vuln_id = result.get("id", "")
        summary = result.get("summary", "")
        aliases = result.get("aliases", [])
        affected = result.get("affected", [])
        if vuln_id and summary and aliases and affected:
            report("osv_get_vuln (GHSA-29mw-wpgm-hmr9)", True)
        else:
            missing = [k for k, v in [("id", vuln_id), ("summary", summary),
                                       ("aliases", aliases), ("affected", affected)] if not v]
            report("osv_get_vuln", False, f"缺少字段: {missing}")
    except Exception as e:
        report("osv_get_vuln", False, f"{type(e).__name__}: {e}")


# ========== EPSSClient ==========

async def test_epss_get_score():
    """测试 7: epss.get_score("CVE-2021-44228") → epss > 0.9, percentile > 0.9"""
    from src.clients.epss_client import EPSSClient
    epss = EPSSClient()
    try:
        data = await epss.get_score("CVE-2021-44228")
        if data is None:
            report("epss_get_score", False, "返回 None")
            return
        epss_val = float(data.get("epss", 0))
        percentile_val = float(data.get("percentile", 0))
        if epss_val > 0.9 and percentile_val > 0.9:
            report("epss_get_score (CVE-2021-44228)", True)
        else:
            report("epss_get_score", False, f"epss={epss_val}(预期>0.9), percentile={percentile_val}(预期>0.9)")
    except Exception as e:
        report("epss_get_score", False, f"{type(e).__name__}: {e}")


async def test_epss_get_scores():
    """测试 8: epss.get_scores(["CVE-2021-44228","CVE-2024-1234"]) → 返回 2 条
    
    EPSS API 返回结果按 CVE ID 字母序排列，不按请求顺序。
    """
    from src.clients.epss_client import EPSSClient
    epss = EPSSClient()
    try:
        data = await epss.get_scores(["CVE-2021-44228", "CVE-2024-1234"])
        data_list = data.get("data", [])
        if len(data_list) == 2:
            # 按 CVE ID 查找，不依赖返回顺序
            cve_map = {item["cve"]: item for item in data_list}
            log4j_data = cve_map.get("CVE-2021-44228")
            dummy_data = cve_map.get("CVE-2024-1234")
            if log4j_data and dummy_data:
                epss_log4j = float(log4j_data.get("epss", 0))
                epss_dummy = float(dummy_data.get("epss", 0))
                if epss_log4j > 0.9 and epss_log4j > epss_dummy:
                    report("epss_get_scores (2 CVE)", True)
                else:
                    report("epss_get_scores", False,
                           f"CVE-2021-44228 epss={epss_log4j}, CVE-2024-1234 epss={epss_dummy}")
            else:
                report("epss_get_scores", False, f"未找到预期 CVE: {list(cve_map.keys())}")
        else:
            report("epss_get_scores", False, f"返回 {len(data_list)} 条，预期 2 条")
    except Exception as e:
        report("epss_get_scores", False, f"{type(e).__name__}: {e}")


# ========== KEVClient ==========

async def test_kev_load_catalog():
    """测试 9: kev.load_catalog() → len > 1000"""
    from src.clients.kev_client import KEVClient
    kev = KEVClient()
    try:
        catalog = await kev.load_catalog()
        if len(catalog) > 1000:
            report("kev_load_catalog", True)
        else:
            report("kev_load_catalog", False, f"len={len(catalog)}, 预期 > 1000")
    except Exception as e:
        report("kev_load_catalog", False, f"{type(e).__name__}: {e}")


async def test_kev_lookup_found():
    """测试 10: kev.build_index(catalog) 查 "CVE-2021-44228" → 返回含 product/cveID 的 dict"""
    from src.clients.kev_client import KEVClient
    kev = KEVClient()
    try:
        catalog = await kev.load_catalog()
        index = KEVClient.build_index(catalog)
        record = index.get("CVE-2021-44228".upper())
        if record and record.get("cveID") == "CVE-2021-44228" and record.get("product"):
            report("kev_lookup (CVE-2021-44228 在列)", True)
        else:
            report("kev_lookup", False, "未找到或字段不全")
    except Exception as e:
        report("kev_lookup", False, f"{type(e).__name__}: {e}")


async def test_kev_lookup_not_found():
    """测试 11: kev.build_index(catalog) 查 "CVE-2024-1234" → None（不在 KEV 中）"""
    from src.clients.kev_client import KEVClient
    kev = KEVClient()
    try:
        catalog = await kev.load_catalog()
        index = KEVClient.build_index(catalog)
        record = index.get("CVE-2024-1234".upper())
        if record is None:
            report("kev_lookup (CVE-2024-1234 不在列)", True)
        else:
            report("kev_lookup", False, "CVE-2024-1234 意外在 KEV 中")
    except Exception as e:
        report("kev_lookup", False, f"{type(e).__name__}: {e}")


# ========== ExploitClient ==========

async def test_exploit_search_github():
    """测试 12: exploit.search_github("CVE-2021-44228") → 返回 list，每条含 name/html_url"""
    from src.clients.exploit_client import ExploitClient
    from src.config import GITHUB_TOKEN
    exploit = ExploitClient(github_token=GITHUB_TOKEN)
    try:
        results = await exploit.search_github("CVE-2021-44228")
        if len(results) >= 1:
            has_repo_name = all(r.get("name") for r in results)
            has_url = all(r.get("html_url") for r in results)
            if has_repo_name and has_url:
                report("exploit_search_github (CVE-2021-44228)", True)
            else:
                report("exploit_search_github", False, "结果缺少 name 或 html_url 字段")
        else:
            report("exploit_search_github", False, f"返回 {len(results)} 条，预期 >= 1")
    except Exception as e:
        report("exploit_search_github", False, f"{type(e).__name__}: {e}")


async def test_exploit_search_exploitdb():
    """测试 13: exploit.search_exploitdb("CVE-2021-44228") → 返回 list

    P5 已将搜索扩展到 codes 字段（主要字段），同时检查 description 作为备选，
    并使用词边界匹配避免假阳性。
    """
    from src.clients.exploit_client import ExploitClient
    exploit = ExploitClient()
    try:
        results = await exploit.search_exploitdb("CVE-2021-44228")
        if len(results) >= 1:
            has_edb_id = all(r.get("edb_id") for r in results)
            if has_edb_id:
                report("exploit_search_exploitdb (CVE-2021-44228)", True)
            else:
                report("exploit_search_exploitdb", False, "结果缺少 edb_id 字段")
        else:
            report("exploit_search_exploitdb", False,
                   f"返回 0 条。请检查 Exploit-DB CSV 是否仍可访问，"
                   f"或 CVE-2021-44228 条目是否仍在 codes 字段")
    except Exception as e:
        report("exploit_search_exploitdb", False, f"{type(e).__name__}: {e}")


async def test_exploit_check_poc_weaponized():
    """测试 14: exploit.check_poc("CVE-2021-44228") → has_public_poc=True"""
    from src.clients.exploit_client import ExploitClient
    from src.config import GITHUB_TOKEN
    exploit = ExploitClient(github_token=GITHUB_TOKEN)
    try:
        result = await exploit.check_poc("CVE-2021-44228")
        has_poc = result.get("has_public_poc", False)
        confidence = result.get("poc_confidence", "")
        if has_poc:
            report("exploit_check_poc (CVE-2021-44228)", True)
        else:
            report("exploit_check_poc", False, f"has_public_poc=False, confidence={confidence}")
    except Exception as e:
        report("exploit_check_poc", False, f"{type(e).__name__}: {e}")


async def test_exploit_check_poc_none():
    """测试 15: exploit.check_poc("CVE-2024-1234") → poc_confidence 为 NONE 或较低等级"""
    from src.clients.exploit_client import ExploitClient
    exploit = ExploitClient()
    try:
        result = await exploit.check_poc("CVE-2024-1234")
        confidence = result.get("poc_confidence", "NONE")
        acceptable = ("NONE", "PUBLIC_POC")
        if confidence in acceptable:
            report("exploit_check_poc (CVE-2024-1234 无 PoC)", True)
        else:
            report("exploit_check_poc", False, f"poc_confidence={confidence}, 预期 NONE 或 PUBLIC_POC")
    except Exception as e:
        report("exploit_check_poc", False, f"{type(e).__name__}: {e}")


# ========== 主入口 ==========

async def main():
    print("=" * 70)
    print("测试脚本 1: 底层 Client 连通性测试")
    print("=" * 70)
    print()
    print("--- NVDClient (3 个测试) ---")
    await test_nvd_get_cve()
    await test_nvd_search_cves()
    await test_nvd_get_cves_batch()
    print()
    print("--- OSVClient (3 个测试) ---")
    await test_osv_query_package()
    await test_osv_query_batch()
    await test_osv_get_vuln()
    print()
    print("--- EPSSClient (2 个测试) ---")
    await test_epss_get_score()
    await test_epss_get_scores()
    print()
    print("--- KEVClient (3 个测试) ---")
    await test_kev_load_catalog()
    await test_kev_lookup_found()
    await test_kev_lookup_not_found()
    print()
    print("--- ExploitClient (4 个测试) ---")
    await test_exploit_search_github()
    await test_exploit_search_exploitdb()
    await test_exploit_check_poc_weaponized()
    await test_exploit_check_poc_none()
    print()
    print("=" * 70)
    total = _pass_count + _fail_count
    print(f"通过: {_pass_count}/{total}, 失败: {_fail_count}/{total}")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(main())
