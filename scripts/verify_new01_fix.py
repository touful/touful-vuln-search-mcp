"""验证脚本: NEW-01 修复效果 — assess_cve CVSS 提取已改用 _find_primary_metric

验证 `_find_primary_metric` 在 assess_cve 中的实际效果：
- 对包含 Secondary 指标的 CVE 能否正确提取 Primary 评分
- 对所有 V31 都是 Secondary 的极端情况能否正确处理
- 与取 `[0]` 方案对比差异（包括 type 和 score 两个维度）
- 验证 assess_cve 实际输出中是否包含正确的 Primary 评分

运行方式:
    D:\software\program\miniconda\envs\py312\python.exe scripts\verify_new01_fix.py
"""

import asyncio
import os
import sys

# 将项目根目录加入 path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import NVD_API_KEY
from src.clients.nvd_client import NVDClient
from src.server import _find_primary_metric


# 测试 CVE（TST-001 已知有 Secondary 指标的）
TEST_CVES = [
    "CVE-2024-3094",   # Red Hat source 排在 NVD 前 — 修复前会取错
    "CVE-2020-1472",   # V31 全是 Secondary — 极端情况
    "CVE-2021-44228",  # 知名漏洞 — 应有 NVD Primary
    "CVE-2017-0144",   # EternalBlue
    "CVE-2022-22965",  # Spring4Shell
]


async def verify_cve(nvd: NVDClient, cve_id: str) -> dict:
    """使用 _find_primary_metric 验证单个 CVE 的 CVSS 提取。"""
    result = await nvd.get_cve(cve_id)
    vulns = result.get("vulnerabilities", [])
    if not vulns:
        return {"cve_id": cve_id, "error": "vulnerabilities 为空"}

    cve = vulns[0].get("cve", {})
    metrics = cve.get("metrics", {})

    # 获取 V31 所有指标
    all_v31 = metrics.get("cvssMetricV31", [])
    v31_details = []
    for idx, m in enumerate(all_v31):
        source = m.get("source", "N/A")
        mtype = m.get("type", "N/A")
        score = m.get("cvssData", {}).get("baseScore", "N/A")
        v31_details.append({
            "index": idx,
            "source": source,
            "type": mtype,
            "baseScore": score,
        })

    # 使用 _find_primary_metric 提取 Primary
    primary_v31 = _find_primary_metric(metrics, "cvssMetricV31")
    primary_score = primary_v31["cvssData"]["baseScore"] if primary_v31 else None
    primary_type = primary_v31.get("type") if primary_v31 else None
    primary_source = primary_v31.get("source") if primary_v31 else None

    # 模拟修复前的方案 B（取 [0]）
    first_score = all_v31[0]["cvssData"]["baseScore"] if all_v31 else None
    first_type = all_v31[0].get("type", "N/A") if all_v31 else "N/A"
    first_source = all_v31[0].get("source", "N/A") if all_v31 else "N/A"

    # 多维比较
    type_same = (primary_type == first_type) if primary_v31 else None
    score_same = (abs(primary_score - first_score) < 0.001) if (primary_score is not None and first_score is not None) else None
    source_same = (primary_source == first_source) if primary_v31 else None

    # 检查是否有 V2 作为 fallback
    primary_v2 = _find_primary_metric(metrics, "cvssMetricV2")
    v2_score = primary_v2["cvssData"]["baseScore"] if primary_v2 else None

    return {
        "cve_id": cve_id,
        "v31_count": len(all_v31),
        "v31_details": v31_details,
        "has_primary_v31": primary_v31 is not None,
        "primary_score": primary_score,
        "primary_type": primary_type,
        "primary_source": primary_source,
        "first_score": first_score,
        "first_type": first_type,
        "first_source": first_source,
        "type_same": type_same,
        "score_same": score_same,
        "source_same": source_same,
        "v2_score": v2_score,
    }


async def main():
    print("=" * 70)
    print("NEW-01 修复验证: _find_primary_metric CVSS 提取效果")
    print("=" * 70)
    print()

    nvd = NVDClient(api_key=NVD_API_KEY)

    results = []
    for cve in TEST_CVES:
        try:
            r = await verify_cve(nvd, cve)
            results.append(r)
            print(f"--- {r['cve_id']} ---")
            print(f"  V31 数组元素数: {r['v31_count']}")
            for d in r['v31_details']:
                print(f"    [{d['index']}] source={d['source']}, type={d['type']}, score={d['baseScore']}")
            print(f"  _find_primary_metric -> score={r['primary_score']}, type={r['primary_type']}, source={r['primary_source']}")
            print(f"  [0] 方案 -> score={r['first_score']}, type={r['first_type']}, source={r['first_source']}")

            # 多维对比
            print(f"  比较: type一致={r['type_same']}, score一致={r['score_same']}, source一致={r['source_same']}")

            if r['primary_score'] is None:
                print(f"  ⚠️ V31 无 Primary 元素! _find_primary_metric 返回 None")
                if r['v2_score'] is not None:
                    print(f"     V2 fallback Primary 可用: {r['v2_score']}")
            elif r['type_same'] is False:
                print(f"  ✅ 修复关键功效: Primary type 与 [0] type 不同!")
                print(f"     [0] 是 {r['first_type']}({r['first_source']}), Primary 是 {r['primary_type']}({r['primary_source']})")
            elif r['score_same'] is True:
                print(f"  ✅ Primary 与 [0] 分数相同({r['primary_score']}), 当前 CVE 无差异")
            else:
                print(f"  ✅ Primary({r['primary_score']}) != [0]({r['first_score']}), 差异={abs(r['primary_score'] - r['first_score'])}")

            if r['v2_score'] is not None:
                print(f"  V2 fallback Primary 评分: {r['v2_score']}")
            print()
        except Exception as e:
            print(f"  ERROR {cve}: {type(e).__name__}: {e}")
            print()

    # 结果对比表格
    print("=" * 70)
    print("修复效果对比表（多维）")
    print("=" * 70)
    h = f"{'CVE ID':<20} {'V31数':<6} {'Primary来源':<24} {'Primary type':<14} {'[0]来源':<24} {'[0] type':<14} {'Score同?':<8}"
    print(h)
    print("-" * 110)
    for r in results:
        p_src = r['primary_source'] or "None"
        p_type = r['primary_type'] or "None"
        f_src = r['first_source'] or "N/A"
        score_ok = "=" if r['score_same'] else ("!" if r['score_same'] is False else "?")
        print(f"{r['cve_id']:<20} {r['v31_count']:<6} {p_src:<24} {str(p_type):<14} {f_src:<24} {r['first_type']:<14} {score_ok:<8}")

    print()
    print("=" * 70)
    print(f"总计: {len(results)}/{len(TEST_CVES)} 成功")

    # ===== 验证结论 =====
    print()
    print("验证结论:")
    all_pass = True

    for r in results:
        if r.get("error"):
            print(f"  [失败] {r['cve_id']}: {r['error']}")
            all_pass = False
            continue

        if r['cve_id'] == "CVE-2024-3094":
            # 期望: [0] 是 Secondary, Primary 在 [1]
            if r['type_same'] is False:
                print(f"  [通过] CVE-2024-3094: _find_primary_metric 正确取到 Primary(NVD), [0] 是 Secondary(Red Hat)")
                print(f"          虽然分数巧合相同(10.0), 但 type 和 source 的差异验证了修复的正确性")
            else:
                print(f"  [注意] CVE-2024-3094: Primary 与 [0] 的 type 一致, 可能 NVD 数据顺序已变化")
                all_pass = False

        if r['cve_id'] == "CVE-2020-1472":
            if r['has_primary_v31'] is False:
                print(f"  [通过] CVE-2020-1472: V31 无 Primary (全 Secondary), _find_primary_metric 返回 None")
                print(f"          [0] 方案会错误地取到 Microsoft 5.5 分")
                if r['v2_score'] is not None:
                    print(f"          后续 fallback 到 V2 Primary: {r['v2_score']} (正确兜底)")
            else:
                print(f"  [注意] CVE-2020-1472: V31 中存在 Primary, NVD 数据可能已变更")
                all_pass = False

    print()
    if all_pass:
        print("全部验证通过! NEW-01 修复正确生效。")
    else:
        print("部分验证需要关注，详见上方各 CVE 的分析。")

    # ===== 集成验证: 调用 assess_cve 验证实际输出 =====
    print()
    print("=" * 70)
    print("集成验证: assess_cve 实际输出中的 CVSS 评分")
    print("=" * 70)
    print()

    from src.server import assess_cve
    from scripts.test_helpers import create_mock_context

    ctx = await create_mock_context()

    for cve_id in TEST_CVES:
        try:
            output = await assess_cve(cve_id, ctx)
            # 从输出中提取 CVSS 分数行
            lines = output.split("\n")
            for line in lines:
                if "CVSS" in line and "|" in line:
                    print(f"  {cve_id}: {line.strip()}")
                    break
            else:
                print(f"  {cve_id}: 输出中未找到 CVSS 行")
                # 打印前几行定位
                for line in lines[:10]:
                    print(f"    {line}")
        except Exception as e:
            print(f"  {cve_id}: assess_cve 调用异常: {e}")

    print()
    print("集成验证完成。")

    return results


if __name__ == "__main__":
    asyncio.run(main())
