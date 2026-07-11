r"""验证 NVD API 的 CVSS metrics 数组结构

检查 cvssMetricV31/cvssMetricV30/cvssMetricV2 数组中是否会出现多个元素，
以及 [0] 是否总是 Primary。

安全说明：API Key 通过环境变量 NVD_API_KEY 读取，不硬编码在脚本中。

使用方式：
    py312_env\python.exe scripts\verify_cvss_extraction.py
"""

import io
import json
import time
import sys
import os
import httpx
from pathlib import Path

# ---- 编码修复：确保 stdout 能正确输出 UTF-8 中文 ----
if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')

# ---- 从环境变量 / .env 文件读取 API Key ----
def _load_api_key() -> str:
    """按优先级从多个来源读取 NVD API Key。"""
    # 1. 直接检查环境变量
    key = os.environ.get("NVD_API_KEY")
    if key:
        return key
    # 2. 尝试从项目根目录的 .env 文件加载
    try:
        from dotenv import load_dotenv
        env_path = Path(__file__).resolve().parent.parent / ".env"
        if env_path.exists():
            load_dotenv(env_path)
            key = os.environ.get("NVD_API_KEY")
            if key:
                return key
    except ImportError:
        pass
    # 3. 如果都没有，报错退出（禁止硬编码）
    print("错误: 未找到 NVD_API_KEY 环境变量。请在 .env 文件中设置，或通过 set NVD_API_KEY=xxx 设置。")
    sys.exit(1)

API_KEY = _load_api_key()

# 已知常见 CNA UUID 到组织名称的映射（用于识别 Secondary 来源）
CNA_UUID_MAP = {
    "134c704f-9b21-4f2e-91b3-4a467353bcc0": "CISA ADP",
    "secalert@redhat.com": "Red Hat",
    "secure@microsoft.com": "Microsoft",
    "nvd@nist.gov": "NVD",
}

# 要查询的 CVE 列表
CVE_LIST = [
    "CVE-2021-44228",  # Log4Shell — 超高知名度，多 CNA 评分
    "CVE-2024-3094",   # xz backdoor — 新漏洞，不同 CNA 顺序
    "CVE-2017-0144",   # EternalBlue — 老漏洞，NVD + ADP
    "CVE-2023-44487",  # HTTP/2 Rapid Reset — 较新
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2020-1472",   # ZeroLogon — 特殊：V31 全 Secondary
    "CVE-2019-0708",   # BlueKeep
    "CVE-2017-5638",   # Struts2
]

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def query_cve(cve_id: str) -> dict | None:
    """查询单个 CVE，返回完整 JSON 响应
    
    实现指数退避重试，应对 NVD API 免费 Key 限速（5次/30秒滚动窗口）。
    """
    url = f"{BASE_URL}?cveId={cve_id}"
    headers = {"apiKey": API_KEY}

    for attempt in range(3):
        try:
            resp = httpx.get(url, headers=headers, timeout=30.0)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 403:
                wait = 8 * (attempt + 1)  # 指数退避：8s, 16s, 24s
                print(f"  [WARN] {cve_id} 返回 403（可能限速），等待 {wait}s 后重试 ({attempt+1}/3)")
                time.sleep(wait)
            elif resp.status_code == 404:
                print(f"  [WARN] {cve_id} 返回 404 Not Found")
                return None
            else:
                wait = 6 * (attempt + 1)
                print(f"  [WARN] {cve_id} 返回 {resp.status_code}，等待 {wait}s 后重试 ({attempt+1}/3)")
                time.sleep(wait)
        except httpx.TimeoutException:
            wait = 8 * (attempt + 1)
            print(f"  [WARN] {cve_id} 超时，等待 {wait}s 后重试 ({attempt+1}/3)")
            time.sleep(wait)
        except Exception as e:
            print(f"  [ERROR] {cve_id} 查询异常: {e}")
            return None
    return None


def analyze_metrics(cve_id: str, data: dict) -> dict:
    """分析单个 CVE 的 metrics 结构"""
    result = {
        "cve_id": cve_id,
        "has_metrics": False,
        "cvssMetricV31": {"count": 0, "types": [], "first_type": None},
        "cvssMetricV30": {"count": 0, "types": [], "first_type": None},
        "cvssMetricV2": {"count": 0, "types": [], "first_type": None},
        "summary": "",
    }

    try:
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            result["summary"] = "无 vulnerabilities 数据"
            return result

        cve = vulns[0].get("cve", {})
        metrics = cve.get("metrics", {})
        if not metrics:
            result["summary"] = "无 metrics 字段"
            return result

        result["has_metrics"] = True

        # 分析 cvssMetricV31
        v31_list = metrics.get("cvssMetricV31", [])
        if v31_list:
            result["cvssMetricV31"]["count"] = len(v31_list)
            result["cvssMetricV31"]["types"] = [m.get("type", "NO_TYPE") for m in v31_list]
            result["cvssMetricV31"]["first_type"] = v31_list[0].get("type", "NO_TYPE")
            # 记录各元素的 source 和 type
            for i, m in enumerate(v31_list):
                result["cvssMetricV31"][f"elem_{i}"] = {
                    "type": m.get("type"),
                    "source": m.get("source"),
                    "baseScore": m.get("cvssData", {}).get("baseScore") if m.get("cvssData") else None,
                    "vectorString": m.get("cvssData", {}).get("vectorString") if m.get("cvssData") else None,
                }

        # 分析 cvssMetricV30
        v30_list = metrics.get("cvssMetricV30", [])
        if v30_list:
            result["cvssMetricV30"]["count"] = len(v30_list)
            result["cvssMetricV30"]["types"] = [m.get("type", "NO_TYPE") for m in v30_list]
            result["cvssMetricV30"]["first_type"] = v30_list[0].get("type", "NO_TYPE")
            for i, m in enumerate(v30_list):
                result["cvssMetricV30"][f"elem_{i}"] = {
                    "type": m.get("type"),
                    "source": m.get("source"),
                    "baseScore": m.get("cvssData", {}).get("baseScore") if m.get("cvssData") else None,
                    "vectorString": m.get("cvssData", {}).get("vectorString") if m.get("cvssData") else None,
                }

        # 分析 cvssMetricV2
        v2_list = metrics.get("cvssMetricV2", [])
        if v2_list:
            result["cvssMetricV2"]["count"] = len(v2_list)
            result["cvssMetricV2"]["types"] = [m.get("type", "NO_TYPE") for m in v2_list]
            result["cvssMetricV2"]["first_type"] = v2_list[0].get("type", "NO_TYPE")
            for i, m in enumerate(v2_list):
                result["cvssMetricV2"][f"elem_{i}"] = {
                    "type": m.get("type"),
                    "source": m.get("source"),
                    "baseScore": m.get("cvssData", {}).get("baseScore") if m.get("cvssData") else None,
                    "vectorString": m.get("cvssData", {}).get("vectorString") if m.get("cvssData") else None,
                }

        # 生成摘要
        parts = []
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            info = result[key]
            if info["count"] > 0:
                types_str = ", ".join(info["types"])
                parts.append(f"{key}: {info['count']}个元素, types=[{types_str}]")
        result["summary"] = " | ".join(parts) if parts else "有 metrics 但无 CVSS 数组"

    except Exception as e:
        result["summary"] = f"解析异常: {e}"

    return result


def main():
    print("=" * 80)
    print("NVD API CVSS Metrics 结构验证")
    print("=" * 80)
    print()

    all_results = []

    for i, cve_id in enumerate(CVE_LIST):
        print(f"[{i+1}/{len(CVE_LIST)}] 查询 {cve_id} ...")
        data = query_cve(cve_id)

        if data:
            result = analyze_metrics(cve_id, data)
            all_results.append(result)
            print(f"  => {result['summary']}")
        else:
            print(f"  => 查询失败，跳过")
            all_results.append({
                "cve_id": cve_id,
                "has_metrics": False,
                "summary": "查询失败",
            })

        # NVD API 免费 key 限速约 5 次/30 秒，每查询完一个等 6 秒
        if i < len(CVE_LIST) - 1:
            wait_time = 6
            print(f"  等待 {wait_time} 秒（API 限速）...")
            time.sleep(wait_time)
        print()

    # ===== 输出汇总表格 =====
    print()
    print("=" * 80)
    print("汇总分析")
    print("=" * 80)
    print()

    # 表头
    header = f"{'CVE ID':20s} | {'Metric类型':15s} | {'元素数':6s} | {'types':25s} | {'[0]的type':12s}"
    sep = "-" * 80
    print(sep)
    print(header)
    print(sep)

    for r in all_results:
        if not r.get("has_metrics"):
            print(f"{r['cve_id']:20s} | {'(无metrics)':15s} | {'N/A':6s} | {'N/A':25s} | {'N/A':12s}")
            print(sep)
            continue

        found_any = False
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            info = r[key]
            if info["count"] > 0:
                found_any = True
                types_str = ", ".join(info["types"]) if info["types"] else "N/A"
                first_type = info["first_type"] or "N/A"
                cve_display = r["cve_id"] if not found_any else ""
                # 已经打印过就不再显示 cve_id
                if found_any and cve_display == "":
                    print(f"{'':20s} | {key:15s} | {info['count']:6d} | {types_str:25s} | {first_type:12s}")
                else:
                    print(f"{r['cve_id']:20s} | {key:15s} | {info['count']:6d} | {types_str:25s} | {first_type:12s}")

        if not found_any:
            print(f"{r['cve_id']:20s} | {'(空metrics)':15s} | {'N/A':6s} | {'N/A':25s} | {'N/A':12s}")

        print(sep)

    # ===== 详细记录 =====
    print()
    print("=" * 80)
    print("详细记录")
    print("=" * 80)

    for r in all_results:
        print()
        print(f"--- {r['cve_id']} ---")
        if not r.get("has_metrics"):
            print(f"  状态: {r.get('summary', 'N/A')}")
            continue

        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            info = r[key]
            if info["count"] > 0:
                print(f"  {key}: {info['count']} 个元素")
                for i in range(info["count"]):
                    elem_key = f"elem_{i}"
                    if elem_key in info:
                        elem = info[elem_key]
                        src = elem['source']
                        org = CNA_UUID_MAP.get(src, src)  # 解析 UUID 为组织名
                        print(f"    [{i}] type={elem['type']}, source={org}, "
                              f"baseScore={elem['baseScore']}, vector={elem.get('vectorString', 'N/A')}")
            else:
                print(f"  {key}: 无")

    # ===== 统计结论 =====
    print()
    print("=" * 80)
    print("统计结论")
    print("=" * 80)
    print()

    # 统计是否有 Secondary
    has_secondary_any = False
    first_not_primary = False
    secondary_positions = []

    for r in all_results:
        if not r.get("has_metrics"):
            continue
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            info = r[key]
            for i, t in enumerate(info.get("types", [])):
                if t == "Secondary":
                    has_secondary_any = True
                    secondary_positions.append((r["cve_id"], key, i))
                if i == 0 and t != "Primary":
                    first_not_primary = True

    # 问题 1: 是否包含 Secondary
    print(f"Q1: NVD API 是否会在返回中包含 Secondary 类型指标？")
    print(f"    答案: {'是' if has_secondary_any else '否'}")
    if has_secondary_any:
        print(f"    发现 Secondary 的位置: {secondary_positions}")
    print()

    # 问题 2: Secondary 在数组中的位置
    print(f"Q2: 如果包含 Secondary，它在数组中的位置是什么？")
    if has_secondary_any:
        # 分析 Secondary 是否总是在最后
        all_at_end = True
        for cve_id, key, pos in secondary_positions:
            r = next(x for x in all_results if x["cve_id"] == cve_id)
            info = r[key]
            count = info["count"]
            if pos != count - 1:
                all_at_end = False
                print(f"    {cve_id} / {key} : Secondary 在位置 [{pos}]（共 {count} 个元素）- 不在末尾!")
            else:
                print(f"    {cve_id} / {key} : Secondary 在位置 [{pos}]（共 {count} 个元素）- 在末尾")
        if all_at_end:
            print(f"    结论: 所有 Secondary 均在数组末尾")
        else:
            print(f"    结论: 部分 Secondary 不在数组末尾 [!]")
    else:
        print(f"    本次测试未发现 Secondary 类型")
    print()

    # 问题 3: [0] 是否总是 Primary
    print(f"Q3: 直接取 [0] 在所有测试 CVE 中是否都能取到 Primary？")
    if first_not_primary:
        print(f"    答案: 否 - 存在 [0] 不是 Primary 的情况 [!]")
    else:
        print(f"    答案: 是 - 所有测试 CVE 的 [0] 都是 Primary [+]")
    print()

    # 问题 4: 方案评估
    print(f"Q4: 建议评估：[0] 方案是否安全？还是必须用 _find_primary_metric？")
    if has_secondary_any:
        risk_level = "高风险" if first_not_primary else "低风险（但存在隐患）"
        print(f"    NVD API 会返回 Secondary 指标，数组长度可能 >1。")
        if first_not_primary:
            print(f"    - 存在 [0] 不是 Primary 的实例 -> 方案 B（取 [0]）不安全!")
        else:
            print(f"    - 当前测试中 [0] 始终是 Primary，但 NVD 文档不做保证。")
        print(f"    - 风险等级: {risk_level}")
        print(f"    - 推荐方案: 方案 A（_find_primary_metric）更安全可靠")
    else:
        print(f"    本次 8 个 CVE 中未出现 Secondary，数组长度均为 1。")
        print(f"    但仅 8 个样本不足以确认 NVD API 永远不会返回多元素数组。")
        print(f"    NVD API 文档并未保证数组中只有一个元素。")
        print(f"    推荐方案: 方案 A（_find_primary_metric），防御式编程更稳健")
    print()

    # 输出 JSON 详细结果供进一步分析
    print("=" * 80)
    print("完整 JSON 结果")
    print("=" * 80)
    json_str = json.dumps(all_results, ensure_ascii=False, indent=2)
    print(json_str)

    # 保存到文件（UTF-8 编码，确保原始数据完整可读）
    output_dir = Path(__file__).resolve().parent
    output_path = output_dir / "cvss_verify_report.json"
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(json_str)
    print(f"\n原始数据已保存: {output_path}")


if __name__ == "__main__":
    main()
