"""验证工具注册状态的测试脚本"""
import os
import sys

# 使用相对路径推导项目根目录
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _project_root)

import asyncio
from src.server import mcp


async def check_tools():
    tools = await mcp.list_tools()
    print(f"共注册 {len(tools)} 个工具:")
    for i, tool in enumerate(tools):
        desc = tool.description or ""
        if desc and len(desc) > 80:
            desc = desc[:80] + "..."
        print(f"  {i+1}. {tool.name}")
        if desc:
            print(f"      描述: {desc}")
        # 检查注解
        if hasattr(tool, 'annotations') and tool.annotations:
            ann = tool.annotations
            print(f"      注解: readOnly={ann.readOnlyHint}, "
                  f"idempotent={ann.idempotentHint}, "
                  f"openWorld={ann.openWorldHint}, "
                  f"destructive={ann.destructiveHint}")
    print()

    # 验证所有期望的工具都存在
    expected = [
        "nvd_get_cve",
        "nvd_search_cve",
        "nvd_get_cves_batch",
        "osv_query_package",
        "osv_query_batch",
        "osv_get_vuln",
    ]
    actual_names = {t.name for t in tools}
    missing = set(expected) - actual_names
    extra = actual_names - set(expected)

    if missing:
        print(f"[FAIL] 缺少工具: {missing}")
    else:
        print(f"[OK] 所有 6 个工具已注册")
    if extra:
        print(f"[WARN] 额外工具: {extra}")

    assert len(tools) >= 6, f"工具数量不足: {len(tools)}"
    assert not missing, f"缺少工具: {missing}"
    print("[OK] 验证通过!")


if __name__ == "__main__":
    asyncio.run(check_tools())
