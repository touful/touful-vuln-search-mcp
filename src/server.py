"""touful-vuln-search-mcp 服务入口

FastMCP 服务，整合 NVD CVE 查询、OSV 开源漏洞查询、
EPSS 评分、CISA KEV 检查、公开 Exploit 搜索和综合评估。
通过 HTTP transport 对外暴露 10 个 MCP 工具。
"""

import argparse
import asyncio
import json
import logging
import re
from contextlib import asynccontextmanager

from fastmcp import FastMCP, Context
from fastmcp.tools.base import ToolAnnotations

from src.config import NVD_API_KEY, GITHUB_TOKEN
from src.config import KEV_CACHE_FILE, KEV_CACHE_TTL_HOURS
from src.config import EXPLOITDB_CACHE_FILE, EXPLOITDB_CACHE_TTL_HOURS
from src.clients.nvd_client import NVDClient
from src.clients.osv_client import OSVClient
from src.clients.epss_client import EPSSClient
from src.clients.kev_client import KEVClient
from src.clients.exploit_client import ExploitClient
from src.cache import is_cache_fresh

logger = logging.getLogger(__name__)

# CVE ID 格式正则：CVE-YYYY-NNNN，其中 YYYY 为年份，NNNN 为至少 4 位数字
_CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
# OSV 漏洞 ID 格式正则：仅允许字母数字和 - . : 字符
_VULN_ID_PATTERN = re.compile(r"^[A-Za-z0-9\-:.]+$")


def _format_osv_vuln(vuln: dict) -> str:
    """将 OSV API 返回的单个 Vulnerability 对象格式化为结构化中文文本。

    Args:
        vuln: OSV API /v1/vulns/{id} 端点返回的 Vulnerability 对象。

    Returns:
        格式化的 Markdown 中文文本。
    """
    lines: list[str] = []

    # --- 漏洞 ID ---
    try:
        vuln_id = vuln.get("id", "N/A")
    except Exception:
        vuln_id = "N/A"
    lines.append(f"### {vuln_id}")

    # --- 摘要 ---
    try:
        summary = vuln.get("summary", "")
    except Exception:
        summary = ""
    lines.append(f"**摘要**: {summary if summary else 'N/A'}")

    # --- 别名 ---
    try:
        aliases = vuln.get("aliases", [])
    except Exception:
        aliases = []
    if aliases:
        lines.append(f"**别名**: {', '.join(aliases)}")
    else:
        lines.append(f"**别名**: 无")

    # --- 发布时间 ---
    try:
        published = vuln.get("published", "")
        published = published[:10] if published else "N/A"
    except Exception:
        published = "N/A"
    lines.append(f"**发布时间**: {published}")

    # --- 最后更新 ---
    try:
        modified = vuln.get("modified", "")
        modified = modified[:10] if modified else "N/A"
    except Exception:
        modified = "N/A"
    lines.append(f"**最后更新**: {modified}")

    lines.append("")

    # --- 严重程度 & CWE ---
    try:
        severity_list = vuln.get("severity", [])
    except Exception:
        severity_list = []

    severity_str = "N/A"
    if severity_list:
        try:
            for s in severity_list:
                s_type = s.get("type", "")
                if s_type in ("CVSS_V3", "CVSS_V4"):
                    severity_str = s.get("score", "N/A")
                    break
        except Exception:
            pass
        # severity 列表存在但无匹配类型时，回退到 database_specific
        if severity_str == "N/A":
            try:
                db_specific = vuln.get("database_specific", {})
                severity_str = db_specific.get("severity", "N/A")
            except Exception:
                severity_str = "N/A"
    else:
        try:
            db_specific = vuln.get("database_specific", {})
            severity_str = db_specific.get("severity", "N/A")
        except Exception:
            severity_str = "N/A"

    try:
        db_specific = vuln.get("database_specific", {})
        cwe_ids = db_specific.get("cwe_ids", [])
        cwe_str = ", ".join(cwe_ids) if cwe_ids else "N/A"
    except Exception:
        cwe_str = "N/A"

    lines.append(f"**严重程度**: {severity_str} | **CWE**: {cwe_str}")
    lines.append("")

    # --- 受影响包 ---
    lines.append("**受影响包**:")
    try:
        affected = vuln.get("affected", [])
    except Exception:
        affected = []

    if not affected:
        lines.append("- 无受影响包信息")
    else:
        for aff in affected:
            try:
                pkg = aff.get("package", {})
                pkg_name = pkg.get("name", "N/A")
                pkg_eco = pkg.get("ecosystem", "N/A")
                pkg_purl = pkg.get("purl", "N/A")
            except Exception:
                pkg_name = "N/A"
                pkg_eco = "N/A"
                pkg_purl = "N/A"

            try:
                ranges = aff.get("ranges", [])
            except Exception:
                ranges = []
            try:
                versions = aff.get("versions", [])
            except Exception:
                versions = []

            range_strs: list[str] = []
            if ranges:
                for r in ranges:
                    try:
                        r_type = r.get("type", "")
                        if r_type in ("SEMVER", "ECOSYSTEM", "GIT"):
                            events = r.get("events", [])
                            introduced = ""
                            fixed = ""
                            last_affected = ""
                            limit_val = ""
                            for e in events:
                                if "introduced" in e:
                                    introduced = e["introduced"]
                                if "fixed" in e:
                                    fixed = e["fixed"]
                                if "last_affected" in e:
                                    last_affected = e["last_affected"]
                                if "limit" in e:
                                    limit_val = e["limit"]
                            # 构建完整版本范围描述
                            parts: list[str] = []
                            if introduced:
                                parts.append(f">= {introduced}")
                            if fixed:
                                parts.append(f"< {fixed}")
                            if last_affected:
                                parts.append(f"<= {last_affected}")
                            if limit_val:
                                parts.append(f"< {limit_val}")
                            if parts:
                                range_strs.append(", ".join(parts))
                    except Exception:
                        pass
            elif versions:
                version_display: list[str] = versions[:10]
                if len(versions) > 10:
                    version_display.append("...及更多")
                range_strs.append(f"受影响版本: {', '.join(version_display)}")

            range_info = " | ".join(range_strs) if range_strs else "版本范围未知"
            lines.append(
                f"- {pkg_eco}:{pkg_name} ({pkg_purl}) | 版本范围: {range_info}"
            )

    lines.append("")

    # --- 参考链接 ---
    lines.append("**参考链接**:")
    try:
        references = vuln.get("references", [])
    except Exception:
        references = []

    if references:
        for ref in references[:10]:
            try:
                ref_type = ref.get("type", "N/A")
                ref_url = ref.get("url", "N/A")
            except Exception:
                ref_type = "N/A"
                ref_url = "N/A"
            lines.append(f"- [{ref_type}] {ref_url}")
        if len(references) > 10:
            lines.append(f"- ...及更多 {len(references) - 10} 条链接")
    else:
        lines.append("- 无参考链接")

    lines.append("")

    # --- 详情 ---
    try:
        details = vuln.get("details", "")
    except Exception:
        details = ""
    if details:
        if len(details) > 500:
            details = details[:500] + "..."
        lines.append(f"**详情**: {details}")

    return "\n".join(lines)


# END _format_osv_vuln


# ========== 生命周期管理 ==========

@asynccontextmanager
async def app_lifespan(server: FastMCP):
    """应用生命周期管理：缓存优先加载 + 后台异步刷新。

    yield 之前仅做本地磁盘 I/O（毫秒级），不发起任何网络请求；
    网络下载放在 yield 之前创建的 asyncio.Task 后台执行，
    确保服务启动在 1 秒内完成，不因网络波动阻塞。
    """
    nvd_client = NVDClient(api_key=NVD_API_KEY)
    osv_client = OSVClient()
    epss_client = EPSSClient()
    kev_client = KEVClient()
    exploit_client = ExploitClient(github_token=GITHUB_TOKEN)

    # ── 仅本地磁盘 I/O（毫秒级） ──────────────────────────
    kev_from_cache, _exploitdb_from_cache = await asyncio.gather(
        kev_client.load_from_cache(),
        exploit_client.load_from_cache(),
    )

    if kev_from_cache is not None:
        kev_catalog = kev_from_cache
        kev_index = KEVClient.build_index(kev_catalog)
        logger.info("KEV 从缓存加载，共 %d 条", len(kev_catalog))
    else:
        kev_catalog: list[dict] = []
        kev_index: dict[str, dict] = {}

    if _exploitdb_from_cache is not None:
        exploit_client._csv_cache = _exploitdb_from_cache
        logger.info(
            "Exploit-DB 从缓存加载，共 %d 条", len(_exploitdb_from_cache)
        )

    lifespan_ctx = {
        "nvd_client": nvd_client,
        "osv_client": osv_client,
        "epss_client": epss_client,
        "kev_client": kev_client,
        "kev_catalog": kev_catalog,
        "kev_index": kev_index,
        "exploit_client": exploit_client,
    }

    # ── 后台刷新任务 ──────────────────────────
    async def _background_refresh() -> None:
        """后台异步刷新缓存（仅在过期或缺失时下载）。"""

        async def _refresh_kev() -> None:
            try:
                new_catalog = await kev_client.fetch_and_save()
                if new_catalog:
                    lifespan_ctx["kev_catalog"] = new_catalog
                    lifespan_ctx["kev_index"] = \
                        KEVClient.build_index(new_catalog)
                    logger.info(
                        "KEV 后台刷新完成，共 %d 条", len(new_catalog)
                    )
            except Exception as e:
                logger.warning("KEV 后台刷新失败: %s", e)

        async def _refresh_exploitdb() -> None:
            try:
                await exploit_client.fetch_and_save()
                logger.info("Exploit-DB 后台刷新完成")
            except Exception as e:
                logger.warning("Exploit-DB 后台刷新失败: %s", e)

        refresh_ops: list = []
        if (
            kev_from_cache is None
            or not is_cache_fresh(KEV_CACHE_FILE, KEV_CACHE_TTL_HOURS)
        ):
            refresh_ops.append(_refresh_kev())
        if (
            _exploitdb_from_cache is None
            or not is_cache_fresh(
                EXPLOITDB_CACHE_FILE, EXPLOITDB_CACHE_TTL_HOURS
            )
        ):
            refresh_ops.append(_refresh_exploitdb())

        if refresh_ops:
            await asyncio.gather(*refresh_ops, return_exceptions=True)

    # 在 yield 之前创建后台任务，确保服务运行期间并发执行
    _refresh_task = asyncio.create_task(_background_refresh())

    try:
        yield lifespan_ctx
    finally:
        logger.info("MCP 服务资源清理中...")
        # 取消尚未完成的后台刷新任务
        if not _refresh_task.done():
            _refresh_task.cancel()
            try:
                await _refresh_task
            except asyncio.CancelledError:
                pass
        else:
            # 任务已完成，检查是否有未捕获的异常
            exc = _refresh_task.exception()
            if exc is not None:
                logger.error("后台刷新任务异常退出: %s", exc)
        # 清理 ExploitDB 内存缓存
        try:
            exploit_client.clear_cache()
        except Exception:
            pass
        logger.info("MCP 服务资源清理完成")


# ========== FastMCP 服务实例 ==========

mcp = FastMCP(
    name="touful-vuln-search-mcp",
    lifespan=app_lifespan,
)

# ========== 工具函数 ==========

# 所有工具共用的注解配置
_TOOL_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    idempotentHint=True,
    openWorldHint=True,
    destructiveHint=False,
)

# ========== NVD 工具 ==========


def _find_primary_metric(metrics_dict: dict, key: str) -> dict | None:
    """从指标字典中提取指定类型的 Primary 指标。

    Args:
        metrics_dict: NVD API 返回的 metrics 字典。
        key: 指标类型key，如 "cvssMetricV31"、"cvssMetricV2"。

    Returns:
        Primary 指标字典，未找到时返回 None。
    """
    try:
        for m in metrics_dict.get(key, []):
            if m.get("type") == "Primary":
                return m
    except Exception:
        return None
    return None


def _format_nvd_cve(cve: dict, concise: bool = False) -> str:
    """将 NVD API 返回的单个 CVE 对象格式化为 LLM 友好的结构化中文文本。

    每个字段使用独立的 try-except 包裹，单个字段提取失败不影响整体输出。

    Args:
        cve: NVD API 返回的 CVE 字典（即 data["vulnerabilities"][0]["cve"]）。
        concise: True 时仅输出 CVE ID + 描述 + CVSS v3.1 摘要。

    Returns:
        格式化的 Markdown 中文文本。
    """
    # -- 安全的字段提取 helper --
    def _safe(d, key, default="N/A"):
        try:
            v = d.get(key)
            return v if v is not None else default
        except Exception:
            return default

    cve_id = _safe(cve, "id", "未知")

    # 英文描述
    try:
        descriptions = cve.get("descriptions", [])
        description = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            "无英文描述",
        )
    except Exception:
        description = "无英文描述"

    published = _safe(cve, "published", "N/A")
    last_modified = _safe(cve, "lastModified", "N/A")
    vuln_status = _safe(cve, "vulnStatus", "N/A")
    source_identifier = _safe(cve, "sourceIdentifier", "N/A")

    # 状态中文映射
    status_map = {
        "Analyzed": "已分析",
        "Modified": "已修改",
        "Rejected": "已拒绝",
        "Awaiting Analysis": "待分析",
        "Undergoing Analysis": "分析中",
    }
    status_cn = status_map.get(vuln_status, vuln_status)

    # CVSS v3.1 指标
    try:
        cvss_v31_metric = _find_primary_metric(cve.get("metrics", {}), "cvssMetricV31")
    except Exception:
        cvss_v31_metric = None

    cvss_v31_data = cvss_v31_metric.get("cvssData") if cvss_v31_metric else None
    cvss_v31_score = cvss_v31_data.get("baseScore", "N/A") if cvss_v31_data else "N/A"
    cvss_v31_severity_en = cvss_v31_data.get("baseSeverity", "N/A") if cvss_v31_data else "N/A"
    cvss_v31_vector = cvss_v31_data.get("vectorString", "N/A") if cvss_v31_data else "N/A"
    cvss_v31_exploitability = cvss_v31_metric.get("exploitabilityScore", "N/A") if cvss_v31_metric else "N/A"
    cvss_v31_impact = cvss_v31_metric.get("impactScore", "N/A") if cvss_v31_metric else "N/A"

    severity_cn_map = {
        "CRITICAL": "严重",
        "HIGH": "高危",
        "MEDIUM": "中危",
        "LOW": "低危",
    }
    cvss_v31_severity = severity_cn_map.get(cvss_v31_severity_en, cvss_v31_severity_en)

    # CVSS v2.0 指标
    try:
        cvss_v2_metric = _find_primary_metric(cve.get("metrics", {}), "cvssMetricV2")
        cvss_v2_data = cvss_v2_metric.get("cvssData") if cvss_v2_metric else None
    except Exception:
        cvss_v2_metric = None
        cvss_v2_data = None

    cvss_v2_score = cvss_v2_data.get("baseScore", "N/A") if cvss_v2_data else "N/A"
    cvss_v2_severity_en = cvss_v2_data.get("baseSeverity", "N/A") if cvss_v2_data else "N/A"
    cvss_v2_severity = severity_cn_map.get(cvss_v2_severity_en, cvss_v2_severity_en)

    # CWE 弱点分类
    try:
        weaknesses = []
        for weak in cve.get("weaknesses", []):
            for desc in weak.get("description", []):
                if desc.get("lang") == "en":
                    weaknesses.append(desc.get("value", ""))
    except Exception:
        weaknesses = []
    cwe_text = "\n".join(f"- {w}" for w in weaknesses) if weaknesses else "无分类"

    # CPE 受影响产品
    try:
        cpe_list = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    if match.get("vulnerable", False):
                        cpe_list.append(match.get("criteria", ""))
    except Exception:
        cpe_list = []
    cpe_text = "\n".join(f"- {c}" for c in cpe_list) if cpe_list else "无 CPE 数据"

    # 参考链接
    try:
        refs = cve.get("references", [])
        if refs:
            lines = []
            for r in refs:
                url = r.get("url", "")
                if not url:
                    continue
                tags = ", ".join(r.get("tags", []))
                if tags:
                    lines.append(f"- <{url}> (标签: {tags})")
                else:
                    lines.append(f"- <{url}>")
            ref_text = "\n".join(lines)
        else:
            ref_text = "无"
    except Exception:
        ref_text = "无"

    # ---- 输出 ----
    if concise:
        return (
            f"## {cve_id}\n"
            f"**描述**: {description}\n"
            f"**CVSS v3.1**: {cvss_v31_score} ({cvss_v31_severity})"
        )
    else:
        return (
            f"## {cve_id}\n"
            f"**描述**: {description}\n"
            f"**发布时间**: {published}\n"
            f"**最后修改**: {last_modified}\n"
            f"**状态**: {status_cn}\n"
            f"**数据来源**: {source_identifier}\n"
            f"\n"
            f"### CVSS 评分\n"
            f"**CVSS v3.1**: {cvss_v31_score} ({cvss_v31_severity}) - {cvss_v31_vector}\n"
            f"**可利用性评分**: {cvss_v31_exploitability} | **影响评分**: {cvss_v31_impact}\n"
            f"**CVSS v2.0**: {cvss_v2_score} ({cvss_v2_severity})\n"
            f"\n"
            f"### 弱点分类 (CWE)\n"
            f"{cwe_text}\n"
            f"\n"
            f"### 受影响产品 (CPE)\n"
            f"{cpe_text}\n"
            f"\n"
            f"### 参考链接\n"
            f"{ref_text}"
        )


@mcp.tool(
    annotations=_TOOL_ANNOTATIONS,
)
async def nvd_get_cve(cve_id: str, ctx: Context, concise: bool = False) -> str:
    """通过 CVE ID 从 NVD 获取漏洞详情，含 CVSS 评分、CWE 分类、受影响产品等。

    此工具调用 NVD CVE API 2.0，根据 CVE 编号查询完整漏洞信息，
    包括 CVSS 评分、CWE 弱点分类、受影响的软件产品和版本等。

    P2 将在此处完善格式化输出逻辑。
    """
    cve_id = cve_id.strip().upper()
    if not cve_id:
        return "⚠️ 请输入 CVE 编号。示例：`CVE-2021-44228`"
    # CVE ID 格式校验
    if not _CVE_ID_PATTERN.match(cve_id):
        return (
            f"❌ 无效的 CVE 编号格式：`{cve_id}`\n"
            f"正确格式：`CVE-YYYY-NNNN`（年份-序号），例如 `CVE-2021-44228`\n"
            f"💡 如果不确定 CVE 编号，可使用 `nvd_search_cve` 按关键词搜索。"
        )

    try:
        client: NVDClient = ctx.lifespan_context["nvd_client"]
        result = await client.get_cve(cve_id)
        vulnerabilities = result.get("vulnerabilities", [])
        if not vulnerabilities:
            return (
                f"⚠️ 未找到 CVE：`{cve_id}`\n"
                f"请确认编号是否正确。如不确定，可尝试用 `nvd_search_cve` 搜索相关关键词。"
            )
        cve = vulnerabilities[0].get("cve")
        if cve is None:
            return f"API 返回数据格式异常：缺少 CVE 字段 (CVE: {cve_id})"
        return _format_nvd_cve(cve, concise)
    except ValueError as e:
        return f"⚠️ 未找到 CVE：`{cve_id}`\n请确认编号是否正确。如不确定，可尝试用 `nvd_search_cve` 搜索相关关键词。"
    except RuntimeError as e:
        return f"API 错误: {e}"
    except Exception as e:
        return f"查询异常: {type(e).__name__}: {e}"


@mcp.tool(
    annotations=_TOOL_ANNOTATIONS,
)
async def nvd_search_cve(
    keyword: str,
    ctx: Context,
    exact_match: bool = False,
    concise: bool = False,
    results: int = 10,
) -> str:
    """通过关键词搜索 NVD 中的 CVE 漏洞。

    支持模糊搜索与精确匹配两种模式，可指定返回结果数量。
    适用于根据软件名称、厂商或关键词查找相关 CVE。

    P2 将在此处完善搜索结果的格式化输出。
    """
    keyword = keyword.strip()
    if not keyword:
        return "⚠️ 请输入搜索关键词。示例：`nvd_search_cve \"log4j\"`"
    try:
        client: NVDClient = ctx.lifespan_context["nvd_client"]
        result = await client.search_cves(
            keyword=keyword,
            exact_match=exact_match,
            results=results,
        )
        total = result.get("totalResults", 0)
        vulnerabilities = result.get("vulnerabilities", [])
        if not vulnerabilities:
            return (
                f"未找到匹配关键词 \"{keyword}\" 的 CVE\n"
                f"💡 建议尝试其他关键词或使用更短的搜索词。"
            )
        count = len(vulnerabilities)
        total_info = f"共 {total} 条" if total > 0 else f"API 返回 totalResults=0，实际获取"
        lines = [
            f"## 搜索结果: \"{keyword}\" ({total_info} {count} 条)",
            "---",
        ]
        for vuln in vulnerabilities:
            cve_data = vuln.get("cve")
            if cve_data is None:
                lines.append("- ⚠️ (数据格式异常：缺少 cve 字段)")
                continue
            lines.append(_format_nvd_cve(cve_data, concise))
            lines.append("---")
        return "\n".join(lines)
    except ValueError as e:
        return f"参数错误: {e}"
    except RuntimeError as e:
        return f"API 错误: {e}"
    except Exception as e:
        return f"查询异常: {type(e).__name__}: {e}"


@mcp.tool(
    annotations=_TOOL_ANNOTATIONS,
)
async def nvd_get_cves_batch(
    cve_ids: str,
    ctx: Context,
    concise: bool = False,
) -> str:
    """批量获取多个 CVE 详情，cve_ids 用逗号分隔，如 'CVE-2024-1234,CVE-2024-5678'，最多 100 个。

    适用于一次性查询多个 CVE 信息，使用 NVD API 的批量查询端点，
    显著减少 API 调用次数。

    P2 将在此处完善批量结果的摘要格式化输出。
    """
    try:
        client: NVDClient = ctx.lifespan_context["nvd_client"]
        cve_list = [cid.strip().upper() for cid in cve_ids.split(",") if cid.strip()]
        if not cve_list:
            return "⚠️ 请输入至少一个 CVE 编号。示例：`nvd_get_cves_batch \"CVE-2021-44228,CVE-2017-0144\"`"
        if len(cve_list) > 100:
            return f"错误: 最多支持 100 个 CVE，当前 {len(cve_list)} 个"
        # CVE ID 格式校验（含分隔符友好提示）
        for cid in cve_list:
            if not _CVE_ID_PATTERN.match(cid):
                return (
                    f"❌ 无效的 CVE 编号格式：`{cid}`\n"
                    f"正确格式：`CVE-YYYY-NNNN`（年份-序号），例如 `CVE-2021-44228`\n"
                    f"💡 多个 CVE 请使用英文逗号 `,` 分隔，例如 `\"CVE-2021-44228,CVE-2017-0144\"`\n"
                    f"💡 如果不确定 CVE 编号，可使用 `nvd_search_cve` 按关键词搜索。"
                )
        try:
            result = await client.get_cves_batch(cve_list)
            total = result.get("totalResults", 0)
            vulnerabilities = result.get("vulnerabilities", [])
            count = len(vulnerabilities)
            lines = [
                f"## 批量查询结果: {len(cve_list)} 个 CVE，返回 {count} 条",
                "---",
            ]
            for vuln in vulnerabilities:
                cve_data = vuln.get("cve")
                if cve_data is None:
                    lines.append("- ⚠️ (数据格式异常：缺少 cve 字段)")
                    continue
                lines.append(_format_nvd_cve(cve_data, concise))
                lines.append("---")
            return "\n".join(lines)
        except Exception:
            # 批量查询失败，逐条回退
            fallback_limit = 20
            lines = ["## NVD 批量查询结果", ""]
            lines.append(
                f"⚠️ 批量 API 查询失败，正在逐条回退查询"
                f"（最多 {min(len(cve_list), fallback_limit)} 个 CVE，可能耗时较长）..."
            )
            lines.append("")
            pending = cve_list[:fallback_limit]
            overflow = cve_list[fallback_limit:]
            succeeded = []
            failed = []
            for cid in pending:
                try:
                    r = await client.get_cve(cid)
                    vulns = r.get("vulnerabilities", [])
                    if vulns:
                        succeeded.append(cid)
                        lines.append(_format_nvd_cve(vulns[0]["cve"], concise=True))
                        lines.append("---")
                    else:
                        failed.append(cid)
                except Exception:
                    failed.append(cid)
            
            if overflow:
                lines.append(f"\n⚠️ 超过回退上限（{fallback_limit}），以下 {len(overflow)} 个 CVE 未查询: {', '.join(overflow)}")
            if succeeded:
                lines.insert(3, f"✅ 成功 {len(succeeded)} 个，失败 {len(failed)} 个")
            if failed:
                lines.append(f"\n⚠️ 以下 CVE 查询失败: {', '.join(failed)}")
            
            return "\n".join(lines)
    except ValueError as e:
        return f"参数错误: {e}"
    except RuntimeError as e:
        return f"API 错误: {e}"
    except Exception as e:
        return f"查询异常: {type(e).__name__}: {e}"


# ========== OSV 工具 ==========


@mcp.tool(
    annotations=_TOOL_ANNOTATIONS,
)
async def osv_query_package(
    package_name: str,
    ecosystem: str,
    ctx: Context,
    version: str | None = None,
) -> str:
    """通过包名和生态系统从 OSV 数据库查询漏洞，例如 package_name='lodash', ecosystem='npm'。

    查询 OSV 开源漏洞数据库中指定包的所有已知漏洞。
    生态系统包括 npm、PyPI、Maven、Go、crates.io 等。
    返回漏洞 ID 列表，可进一步使用 osv_get_vuln 获取完整详情。
    """
    package_name = package_name.strip()
    if not package_name:
        return "⚠️ 请输入包名。示例：`osv_query_package \"lodash\" \"npm\"`"
    try:
        client: OSVClient = ctx.lifespan_context["osv_client"]
        result = await client.query_package(
            package_name=package_name,
            ecosystem=ecosystem,
            version=version,
        )
        vulns = result.get("vulns", [])
        if not vulns:
            return (
                f"## 包 {ecosystem}:{package_name} 的漏洞查询结果\n\n"
                f"未发现已知漏洞。"
            )
        lines: list[str] = []
        lines.append(f"## 包 {ecosystem}:{package_name} 的漏洞查询结果")
        lines.append(f"发现 {len(vulns)} 个已知漏洞：")
        for v in vulns:
            try:
                v_id = v.get("id", "N/A")
                v_modified = v.get("modified", "")
                v_modified = v_modified[:10] if v_modified else "未知"
            except Exception:
                v_id = "N/A"
                v_modified = "未知"
            lines.append(f"- {v_id} (更新于 {v_modified})")
        lines.append("")
        if vulns:
            try:
                hint_id = vulns[0].get("id", "xxxx")
            except Exception:
                hint_id = "xxxx"
            lines.append(
                f"> 提示：使用 osv_get_vuln(\"{hint_id}\") 获取任一漏洞的完整详情。"
            )
        return "\n".join(lines)
    except RuntimeError as e:
        return f"API 错误: {e}"
    except Exception as e:
        return f"查询异常: {type(e).__name__}: {e}"


@mcp.tool(
    annotations=_TOOL_ANNOTATIONS,
)
async def osv_query_batch(
    queries_json: str,
    ctx: Context,
) -> str:
    """批量查询多个包的 OSV 漏洞，queries_json 为 JSON 字符串数组，每项含 package_name/ecosystem/version。

    一次性查询多个包的漏洞信息，减少 API 往返次数。
    JSON 格式示例:
    [{"package_name": "lodash", "ecosystem": "npm", "version": "4.17.20"}]
    按查询子项分组输出漏洞摘要列表，可使用 osv_get_vuln 获取详细内容。
    """
    try:
        queries = json.loads(queries_json)
        if not isinstance(queries, list):
            return "错误: queries_json 必须是 JSON 数组"
        if not queries:
            return "⚠️ 查询列表为空，请至少提供一个包含 package_name 和 ecosystem 的查询项。"
    except json.JSONDecodeError as e:
        return f"JSON 解析错误: {e}"
    try:
        client: OSVClient = ctx.lifespan_context["osv_client"]
        # 将简化格式转换为 OSV API 的完整 query 格式
        osv_queries = []
        original_indices: list[int] = []  # 映射 osv_queries → queries 索引
        for idx, q in enumerate(queries):
            pkg_name = q.get("package_name")
            pkg_eco = q.get("ecosystem")
            if not pkg_name or not pkg_eco:
                logger.warning("查询项 %s 缺少必需字段 package_name/ecosystem，已跳过", q)
                continue  # 跳过缺少必填字段的查询项
            q_body: dict = {
                "package": {
                    "name": pkg_name,
                    "ecosystem": pkg_eco,
                },
            }
            if q.get("version"):
                q_body["version"] = q["version"]
            osv_queries.append(q_body)
            original_indices.append(idx)

        if not osv_queries:
            return (
                "## 批量查询结果\n\n"
                f"共提交 {len(queries)} 个查询项，均缺少必填字段（package_name 和 ecosystem），"
                "请检查输入。"
            )
        result = await client.query_batch(osv_queries)
        results_list = result.get("results", [])
        if not results_list:
            return "## 批量查询结果\n\n所有查询均未发现漏洞。"
        lines: list[str] = []
        lines.append("## 批量查询结果")
        # 提示跳过的查询项
        skipped = len(queries) - len(osv_queries)
        if skipped > 0:
            lines.append(
                f"> 共提交 {len(queries)} 个查询项，其中 {skipped} 个因缺少必填字段被跳过。"
            )
            lines.append("")
        for i, res in enumerate(results_list):
            try:
                res_vulns = res.get("vulns", [])
            except Exception:
                res_vulns = []
            try:
                orig_idx = original_indices[i] if i < len(original_indices) else 0
                if i >= len(original_indices):
                    logger.warning(
                        "API 返回结果数 (%d) 超过有效查询数 (%d)，可能存在映射异常",
                        len(results_list), len(original_indices),
                    )
                query_item = queries[orig_idx] if orig_idx < len(queries) else {}
                q_name = query_item.get("package_name", "N/A")
                q_eco = query_item.get("ecosystem", "N/A")
            except Exception:
                q_name = "N/A"
                q_eco = "N/A"
            lines.append(f"### 查询 {i + 1}: {q_eco}:{q_name}")
            if not res_vulns:
                lines.append("未发现漏洞。")
            else:
                lines.append(f"发现 {len(res_vulns)} 个漏洞：")
                for v in res_vulns:
                    try:
                        v_id = v.get("id", "N/A")
                        v_modified = v.get("modified", "")
                        v_modified = v_modified[:10] if v_modified else "未知"
                    except Exception:
                        v_id = "N/A"
                        v_modified = "未知"
                    lines.append(f"- {v_id} (更新于 {v_modified})")
                try:
                    first_id = res_vulns[0].get("id", "xxxx")
                except Exception:
                    first_id = "xxxx"
                lines.append("")
                lines.append(f"> 提示：使用 osv_get_vuln(\"{first_id}\") 获取完整详情。")
            lines.append("")
        return "\n".join(lines).rstrip()
    except KeyError as e:
        return f"参数错误: JSON 中缺少必需字段 {e}"
    except RuntimeError as e:
        return f"API 错误: {e}"
    except Exception as e:
        return f"查询异常: {type(e).__name__}: {e}"


@mcp.tool(
    annotations=_TOOL_ANNOTATIONS,
)
async def osv_get_vuln(
    vuln_id: str,
    ctx: Context,
) -> str:
    """通过漏洞 ID（如 GHSA-xxxx 或 CVE-xxxx）从 OSV 获取漏洞完整详情。

    查询 OSV 数据库中指定漏洞的完整信息，包括描述、受影响的包版本范围、
    参考链接、修复版本等详细信息。支持 GHSA、CVE、DSA 等编号。
    返回 Markdown 格式的结构化漏洞详情，含 CVSS 评分、CWE 分类及受影响版本范围。
    """
    vuln_id = vuln_id.strip()
    if not vuln_id:
        return "⚠️ 请输入漏洞 ID（如 `GHSA-29mw-wpgm-hmr9`）"
    # vuln_id 格式校验
    if not _VULN_ID_PATTERN.match(vuln_id):
        return (
            f"❌ 无效的漏洞 ID 格式：`{vuln_id}`\n"
            f"支持格式：`GHSA-xxxx-xxxx-xxxx`、`CVE-YYYY-NNNN`、`DSA-XXXX` 等"
        )

    try:
        client: OSVClient = ctx.lifespan_context["osv_client"]
        result = await client.get_vuln(vuln_id)
        return _format_osv_vuln(result)
    except ValueError as e:
        return f"未找到: {e}"
    except RuntimeError as e:
        return f"API 错误: {e}"
    except Exception as e:
        return f"查询异常: {type(e).__name__}: {e}"


# ========== EPSS 工具 ==========


def _epss_risk_label(probability: float) -> str:
    """根据 EPSS 概率值返回简短中文风险标签。

    Args:
        probability: 0~1 之间的概率值。

    Returns:
        中文风险标签（极高/较高/中等/较低）。
    """
    if probability > 0.5:
        return "极高"
    if probability > 0.1:
        return "较高"
    if probability > 0.01:
        return "中等"
    return "较低"


def _format_epss_risk(probability: float) -> str:
    """根据 EPSS 概率值返回中文风险解读。

    Args:
        probability: 0~1 之间的概率值。

    Returns:
        中文风险等级描述。
    """
    label = _epss_risk_label(probability)
    descriptions = {
        "极高": "极高，需立即关注",
        "较高": "较高，建议优先处理",
        "中等": "中等，列入修复计划",
        "较低": "较低，常规修复即可",
    }
    return descriptions.get(label, f"{label}，常规修复即可")


@mcp.tool(annotations=_TOOL_ANNOTATIONS)
async def get_epss_score(cve_id: str, ctx: Context) -> str:
    """查询 CVE 的 EPSS 评分（漏洞利用预测评分系统），评估未来 30 天内被利用的概率。

    EPSS 比 CVSS 更能反映漏洞在实际攻击中被利用的可能性。
    返回 0~1 的概率值和在所有 CVE 中的百分位排名。
    """
    cve_id = cve_id.strip().upper()
    if not _CVE_ID_PATTERN.match(cve_id):
        return (
            f"❌ 无效的 CVE 编号格式：`{cve_id}`\n"
            f"正确格式：`CVE-YYYY-NNNN`（年份-序号），例如 `CVE-2021-44228`\n"
            f"💡 如果不确定 CVE 编号，可使用 `nvd_search_cve` 按关键词搜索。"
        )

    try:
        client: EPSSClient = ctx.lifespan_context["epss_client"]
        data = await client.get_score(cve_id)
    except RuntimeError as e:
        return f"API 错误: {e}"
    except Exception as e:
        return f"查询异常: {type(e).__name__}: {e}"

    if data is None:
        return (
            f"## {cve_id} EPSS 评分\n\n"
            f"**状态**: 未找到 EPSS 数据，该 CVE 可能未被收录或尚在评分中。\n\n"
            f"> EPSS 评分覆盖已分析完成的 CVE，新发布的 CVE 可能暂无评分。"
        )

    try:
        epss_val = float(data.get("epss", 0))
        percentile_val = float(data.get("percentile", 0))
        score_date = data.get("date", "N/A")
    except Exception:
        return f"## {cve_id} EPSS 评分\n\n**状态**: EPSS 数据格式异常，无法解析。\n原始数据: {data}"

    prob_pct = epss_val * 100
    percentile_pct = percentile_val * 100
    risk_text = _format_epss_risk(epss_val)

    return (
        f"## {cve_id} EPSS 评分\n\n"
        f"**30天内被利用概率**: {prob_pct:.2f}%\n"
        f"**百分位排名**: {percentile_pct:.2f}%（高于 {percentile_pct:.2f}% 的 CVE）\n"
        f"**评分日期**: {score_date}\n"
        f"**风险解读**: {risk_text}\n\n"
        f"> EPSS 是漏洞利用预测评分系统，评估漏洞在未来 30 天内被成功利用的概率。"
        f"与 CVSS 不同，EPSS 反映的是实际威胁活跃度而非理论严重程度。"
    )


# ========== CISA KEV 工具 ==========


@mcp.tool(annotations=_TOOL_ANNOTATIONS)
async def check_kev_status(cve_id: str, ctx: Context) -> str:
    """检查 CVE 是否在 CISA 已知被利用漏洞（KEV）目录中。

    只有确认正被野外利用的漏洞才会列入 KEV 目录，
    由美国网络安全与基础设施安全局维护。
    如果在 KEV 中，说明该漏洞正在被攻击者积极利用，必须立即修复。
    """
    cve_id = cve_id.strip().upper()
    if not _CVE_ID_PATTERN.match(cve_id):
        return (
            f"❌ 无效的 CVE 编号格式：`{cve_id}`\n"
            f"正确格式：`CVE-YYYY-NNNN`（年份-序号），例如 `CVE-2021-44228`\n"
            f"💡 如果不确定 CVE 编号，可使用 `nvd_search_cve` 按关键词搜索。"
        )

    try:
        kev_index: dict[str, dict] = ctx.lifespan_context["kev_index"]
        if not kev_index:
            return (
                f"## {cve_id} CISA KEV 状态\n\n"
                f"**状态**: ⚠️ KEV 数据不可用\n\n"
                f"> KEV 目录在服务启动时加载失败，请联系管理员检查网络连接。"
                f"当前无法判断该 CVE 是否在 KEV 目录中。"
            )
        record = kev_index.get(cve_id)
    except Exception as e:
        return f"查询异常: {type(e).__name__}: {e}"

    if record is None:
        return (
            f"## {cve_id} CISA KEV 状态\n\n"
            f"**状态**: ✅ 未列入 CISA KEV 目录，暂无野外利用确认\n\n"
            f"> KEV 目录由 CISA 维护，仅收录已被证实野外利用的漏洞。"
            f"未在列不代表绝对安全，请结合其他情报综合判断。"
        )

    try:
        vendor = record.get("vendorProject", "N/A")
        product = record.get("product", "N/A")
        vuln_name = record.get("vulnerabilityName", "N/A")
        date_added = record.get("dateAdded", "N/A")
        due_date = record.get("dueDate", "N/A")
        ransomware = record.get("knownRansomwareCampaignUse", "")
        ransomware_text = "是 ⚠️" if ransomware == "Known" else "否"
        notes = record.get("notes", "N/A")
        short_desc = record.get("shortDescription", "N/A")
        required_action = record.get("requiredAction", "N/A")
    except Exception:
        return (
            f"## {cve_id} CISA KEV 状态\n\n"
            f"**状态**: ⚠️ 已被列入 CISA KEV 目录（数据解析异常）\n\n"
            f"原始数据: {record}"
        )

    lines = [
        f"## {cve_id} CISA KEV 状态",
        "",
        "**状态**: ⚠️ 已被列入 CISA 已知被利用漏洞目录",
        "",
        f"| 项目 | 内容 |",
        f"|:---|:---|",
        f"| 供应商/产品 | {vendor} / {product} |",
        f"| 漏洞名称 | {vuln_name} |",
        f"| 加入日期 | {date_added} |",
        f"| 修复截止 | {due_date} |",
        f"| 勒索软件关联 | {ransomware_text} |",
        f"| 备注 | {notes} |",
        "",
        f"**简述**: {short_desc}",
        "",
        f"**要求措施**: {required_action}",
    ]

    return "\n".join(lines)


# ========== 公开 Exploit 搜索工具 ==========


@mcp.tool(annotations=_TOOL_ANNOTATIONS)
async def search_exploit(cve_id: str, ctx: Context) -> str:
    """搜索 CVE 的公开利用代码（PoC/Exploit），包括 GitHub、Exploit-DB 等来源。

    帮助判断漏洞是否已有现成的利用工具，降低安全研究人员的工作量。
    结果包括 GitHub 仓库搜索结果和 Exploit-DB 收录情况。
    """
    cve_id = cve_id.strip().upper()
    if not _CVE_ID_PATTERN.match(cve_id):
        return (
            f"❌ 无效的 CVE 编号格式：`{cve_id}`\n"
            f"正确格式：`CVE-YYYY-NNNN`（年份-序号），例如 `CVE-2021-44228`\n"
            f"💡 如果不确定 CVE 编号，可使用 `nvd_search_cve` 按关键词搜索。"
        )

    try:
        client: ExploitClient = ctx.lifespan_context["exploit_client"]
        has_github_token = bool(client.github_token)
        result = await client.check_poc(cve_id)
    except Exception as e:
        return f"查询异常: {type(e).__name__}: {e}"

    try:
        confidence = result.get("poc_confidence", "NONE")
        github = result.get("github_results", [])
        exploitdb = result.get("exploitdb_results", [])
        has_poc = result.get("has_public_poc", False)
    except Exception:
        return f"查询异常: 结果格式异常，无法解析。原始数据: {result}"

    confidence_cn = {
        "WEAPONIZED": "🔴 WEAPONIZED（武器化）— 存在 Metasploit 或完整攻击框架模块",
        "PUBLIC_EXPLOIT": "🟠 PUBLIC_EXPLOIT（公开利用代码）— 已在 Exploit-DB 收录",
        "PUBLIC_POC": "🟡 PUBLIC_POC（公开 PoC）— GitHub 等平台存在概念验证代码",
        "NONE": "🟢 NONE — 暂未发现公开利用代码",
    }.get(confidence, confidence)

    lines = [
        f"## {cve_id} 公开利用情况",
        "",
        f"**总体评估**: {confidence_cn}",
        "",
    ]

    # GitHub 结果
    if github:
        lines.append("**GitHub 搜索结果**（前 5 条）:")
        for item in github[:5]:
            try:
                name = item.get("name", "N/A")
                url = item.get("html_url", "N/A")
                stars = item.get("stars", 0)
                desc = item.get("description", "无描述")
                lines.append(f"- [{name}]({url}) ⭐ {stars} | {desc}")
            except Exception:
                lines.append("- (解析异常)")
    else:
        if has_github_token:
            lines.append("**GitHub 搜索结果**: 未找到相关仓库（或 API 限速无法查询）")
        else:
            lines.append(
                "**GitHub 搜索结果**: 未配置 GitHub Token，已跳过 GitHub 搜索。"
                "在 .env 中设置 GITHUB_TOKEN 可启用此功能。"
            )

    lines.append("")

    # Exploit-DB 结果
    if exploitdb:
        lines.append("**Exploit-DB 收录**:")
        for item in exploitdb[:5]:
            try:
                edb_id = item.get("edb_id", "N/A")
                date = item.get("date", "N/A")
                author = item.get("author", "N/A")
                desc = item.get("description", "N/A")
                lines.append(
                    f"- EDB-ID: {edb_id} | {date} | {author} | {desc}"
                )
            except Exception:
                lines.append("- (解析异常)")
    else:
        lines.append("**Exploit-DB 收录**: 未找到相关利用代码")

    lines.append("")

    # 结论
    if has_poc:
        lines.append(
            f"**结论**: 已有公开利用代码可用，渗透测试人员可基于上述资源进行进一步研究。"
        )
    else:
        lines.append(
            f"**结论**: 暂未发现公开利用代码，可能需要自行开发 PoC。"
        )

    return "\n".join(lines)


# ========== 综合评估工具 ==========


@mcp.tool(annotations=_TOOL_ANNOTATIONS)
async def assess_cve(cve_id: str, ctx: Context) -> str:
    """对单个 CVE 进行综合快速评估，并发查询 NVD、EPSS、KEV、Exploit 四个数据源。

    一次性返回漏洞的 CVSS 严重程度、实际利用概率、野外利用状态、
    公开 Exploit 可用性，并给出渗透测试视角的优先级建议。
    适合在发现目标软件版本后，快速判断哪些 CVE 值得优先尝试。
    """
    cve_id = cve_id.strip().upper()
    if not _CVE_ID_PATTERN.match(cve_id):
        return (
            f"❌ 无效的 CVE 编号格式：`{cve_id}`\n"
            f"正确格式：`CVE-YYYY-NNNN`（年份-序号），例如 `CVE-2021-44228`\n"
            f"💡 如果不确定 CVE 编号，可使用 `nvd_search_cve` 按关键词搜索。"
        )

    # 并发调用四个数据源
    async def _fetch_nvd():
        try:
            client: NVDClient = ctx.lifespan_context["nvd_client"]
            r = await client.get_cve(cve_id)
            vulns = r.get("vulnerabilities", [])
            if vulns:
                return vulns[0].get("cve")
            return None
        except Exception:
            return None

    async def _fetch_epss():
        try:
            client: EPSSClient = ctx.lifespan_context["epss_client"]
            return await client.get_score(cve_id)
        except Exception:
            return None

    async def _check_kev():
        try:
            kev_index: dict[str, dict] = ctx.lifespan_context["kev_index"]
            if not kev_index:
                return "UNAVAILABLE"  # 特殊标记：数据不可用
            return kev_index.get(cve_id)
        except Exception:
            return "UNAVAILABLE"

    async def _check_poc():
        try:
            client: ExploitClient = ctx.lifespan_context["exploit_client"]
            return await client.check_poc(cve_id)
        except Exception:
            return None

    nvd_cve, epss_data, kev_record, poc_result = await asyncio.gather(
        _fetch_nvd(), _fetch_epss(), _check_kev(), _check_poc()
    )

    # ===== 提取各维度数据 =====

    # NVD — CVSS v3.1
    cvss_score = "N/A"
    cvss_severity = "N/A"
    cvss_interpretation = "N/A"
    try:
        if nvd_cve:
            descs = nvd_cve.get("descriptions", [])
            desc_text = next(
                (d.get("value", "") for d in descs if d.get("lang") == "en"), ""
            )
            metrics = nvd_cve.get("metrics", {})
            cvss_v31_entry = _find_primary_metric(metrics, "cvssMetricV31")
            if cvss_v31_entry:
                cvss_data = cvss_v31_entry.get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", "N/A")
                severity_en = cvss_data.get("baseSeverity", "N/A")
                severity_cn_map = {
                    "CRITICAL": "严重",
                    "HIGH": "高危",
                    "MEDIUM": "中危",
                    "LOW": "低危",
                }
                cvss_severity = severity_cn_map.get(severity_en, severity_en)
                vector = cvss_data.get("vectorString", "")
                # 简要解读
                parts = []
                if "AV:N" in vector:
                    parts.append("远程可利用")
                else:
                    parts.append("本地/邻接网络")
                if "AC:L" in vector:
                    parts.append("无需高权限")
                elif "AC:H" in vector:
                    parts.append("需高攻击复杂度")
                if "PR:N" in vector:
                    parts.append("无需认证")
                if "UI:N" in vector:
                    parts.append("无需用户交互")
                if "C:H" in vector:
                    parts.append("影响机密性")
                if "I:H" in vector:
                    parts.append("影响完整性")
                if "A:H" in vector:
                    parts.append("影响可用性")
                cvss_interpretation = "，".join(parts[:3]) if parts else "暂无解读"
            else:
                # 尝试 CVSS v2.0
                cvss_v2_entry = _find_primary_metric(metrics, "cvssMetricV2")
                if cvss_v2_entry:
                    cvss_data = cvss_v2_entry.get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", "N/A")
                    cvss_severity = cvss_data.get("baseSeverity", "N/A")
                    cvss_interpretation = "暂无 CVSS v3.1 数据"
    except Exception:
        cvss_score = "提取异常"
        cvss_severity = "提取异常"
        cvss_interpretation = "提取失败"

    # EPSS
    epss_prob_str = "N/A"
    epss_text = "N/A"
    epss_comment = ""
    try:
        if epss_data:
            epss_val = float(epss_data.get("epss", 0))
            epss_pct = epss_val * 100
            perc_val = float(epss_data.get("percentile", 0))
            epss_prob_str = f"{epss_pct:.2f}%"
            epss_text = f"高于 {perc_val * 100:.2f}% 的 CVE"
            epss_comment = _epss_risk_label(epss_val) + "利用概率"
    except Exception:
        epss_prob_str = "提取异常"

    # KEV
    kev_status = "✅ 不在列"
    kev_comment = ""
    try:
        if kev_record == "UNAVAILABLE":
            kev_status = "⚠️ 数据不可用"
            kev_comment = "KEV 目录加载失败，无法判断"
        elif kev_record:
            kev_status = "⚠️ 在列"
            ransom = kev_record.get("knownRansomwareCampaignUse", "")
            if ransom == "Known":
                kev_comment = "，且有勒索软件关联"
            else:
                kev_comment = "，正被野外利用"
    except Exception:
        kev_status = "提取异常"

    # Exploit
    poc_confidence = "NONE"
    poc_text = "未发现"
    poc_confidence_cn = "🟢 未发现公开利用代码"
    try:
        if poc_result:
            poc_confidence = poc_result.get("poc_confidence", "NONE")
            confidence_map = {
                "WEAPONIZED": "🔴 武器化（Metasploit/框架模块）",
                "PUBLIC_EXPLOIT": "🟠 公开利用代码（Exploit-DB）",
                "PUBLIC_POC": "🟡 公开 PoC（GitHub）",
                "NONE": "🟢 未发现公开利用代码",
            }
            poc_confidence_cn = confidence_map.get(
                poc_confidence, poc_confidence
            )
    except Exception:
        poc_confidence_cn = "提取异常"

    # ===== 评估优先级 =====
    priority_level = ""
    priority_reason = ""

    try:
        cvss_num = (
            float(cvss_score) if cvss_score not in ("N/A", "提取异常") else 0
        )
    except Exception:
        cvss_num = 0

    try:
        epss_num = (
            float(epss_data.get("epss", 0)) if epss_data else 0
        )
    except Exception:
        epss_num = 0

    if (
        cvss_num >= 7.0
        and epss_num > 0.5
        and kev_record is not None and kev_record != "UNAVAILABLE"
        and poc_confidence in ("WEAPONIZED", "PUBLIC_EXPLOIT")
    ):
        priority_level = "🔴 最高 — 立即尝试利用"
        priority_reason = (
            "该漏洞同时满足 CVSS 高危 + EPSS 极高 + KEV 在列 + 公开武器化利用代码，"
            "是所有条件中最严重的一档。有成熟工具可直接使用，攻击成功率极高。"
        )
    elif (
        (cvss_num >= 7.0 or epss_num > 0.1)
        and (
            (kev_record is not None and kev_record != "UNAVAILABLE")
            or poc_confidence != "NONE"
        )
    ):
        priority_level = "🟠 高 — 优先尝试"
        priority_reason = (
            "该漏洞在 CVSS/EPSS/KEV/Exploit 中多项触发，"
            "实际利用价值高，建议优先投入时间进行利用尝试。"
        )
    elif cvss_num >= 7.0 or epss_num > 0.01 or poc_confidence != "NONE":
        priority_level = "🟡 中 — 有价值，列入计划"
        priority_reason = (
            "该漏洞有一定利用价值，但部分条件未满足。"
            "建议列入渗透测试计划，但可排在更高优先级之后。"
        )
    else:
        priority_level = "🟢 低 — 暂不优先"
        priority_reason = (
            "该漏洞在各项指标中均不突出，实际利用可能性较低。"
            "建议将精力集中在更高优先级的漏洞上。"
        )

    # ===== 输出 =====
    lines = [
        f"## {cve_id} 综合评估",
        "",
        "| 维度 | 数据 | 解读 |",
        "|:---|:---|:---|",
        f"| CVSS v3.1 | {cvss_score} ({cvss_severity}) | {cvss_interpretation} |",
        f"| EPSS | {epss_prob_str} | {epss_text}（{epss_comment}）|",
        f"| CISA KEV | {kev_status} | {kev_comment} |",
        f"| 公开 Exploit | {poc_confidence_cn} | — |",
        "",
        f"**渗透优先级**: {priority_level}",
        f"**理由**: {priority_reason}",
        "",
    ]

    # 建议下一步
    lines.append("**建议下一步**:")
    next_steps = []
    if poc_confidence == "WEAPONIZED":
        next_steps.append(f"1. 搜索 Metasploit: `search {cve_id}`")
    if poc_result and poc_result.get("exploitdb_results"):
        for item in poc_result["exploitdb_results"][:3]:
            try:
                next_steps.append(f"- Exploit-DB 编号: {item.get('edb_id', 'N/A')}")
            except Exception:
                pass
    if poc_result and poc_result.get("github_results"):
        for item in poc_result["github_results"][:2]:
            try:
                name = item.get("name", "N/A")
                url = item.get("html_url", "N/A")
                next_steps.append(f"- GitHub PoC: [{name}]({url})")
            except Exception:
                pass
    if not next_steps:
        next_steps.append("1. 暂无可直接利用的公开工具，建议自行分析漏洞详情后编写 PoC")
        next_steps.append(f"2. 使用 nvd_get_cve(\"{cve_id}\") 查看完整漏洞详情")

    lines.extend(next_steps)

    return "\n".join(lines)


# ========== 服务入口 ==========


def main():
    """touful-vuln-search-mcp 服务命令行入口。

    支持通过 CLI 参数配置传输协议、绑定地址和端口。
    用法示例:
        python src/server.py --transport http --host 127.0.0.1 --port 8080
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )
    parser = argparse.ArgumentParser(
        description="touful-vuln-search-mcp - 统一漏洞搜索 MCP 服务"
    )
    parser.add_argument(
        "--transport",
        default="http",
        choices=["http", "sse", "streamable-http", "stdio"],
        help="传输协议 (默认: http)。可选: http, sse, streamable-http, stdio",
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="绑定 IP 地址 (默认: 127.0.0.1)。生产环境建议保持此设置",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8080,
        help="绑定端口 (默认: 8080)",
    )
    args = parser.parse_args()
    if args.host != "127.0.0.1" and args.transport != "stdio":
        logger.warning(
            "绑定地址为 %s，非 127.0.0.1。请确认在网络边界已做好访问控制。",
            args.host,
        )
    run_kwargs = {"transport": args.transport}
    if args.transport != "stdio":
        run_kwargs["host"] = args.host
        run_kwargs["port"] = args.port
    mcp.run(**run_kwargs)


if __name__ == "__main__":
    main()
