"""MCP 服务启动模拟测试"""
import sys
import asyncio

sys.path.insert(0, r"D:\工具开发\漏洞搜索mcp\touful-vuln-search-mcp")


async def test_startup():
    from src.config import NVD_API_KEY, GITHUB_TOKEN
    from src.clients.nvd_client import NVDClient
    from src.clients.osv_client import OSVClient
    from src.clients.epss_client import EPSSClient
    from src.clients.kev_client import KEVClient
    from src.clients.exploit_client import ExploitClient

    nvd = NVDClient(api_key=NVD_API_KEY)
    osv = OSVClient()
    epss = EPSSClient()
    kev = KEVClient()
    exploit = ExploitClient(github_token=GITHUB_TOKEN)
    print("[Lifespan] All clients initialized")

    # KEV 加载（含降级）
    try:
        kev_catalog = await kev.load_catalog()
        kev_index = KEVClient.build_index(kev_catalog)
        print(f"[Lifespan] KEV catalog: {len(kev_catalog)} entries, index: {len(kev_index)} keys")
    except Exception as e:
        kev_catalog = []
        kev_index = {}
        print(f"[Lifespan] KEV load failed (degraded): {e}")

    # EPSS 测试
    epss_data = await epss.get_score("CVE-2021-44228")
    if epss_data:
        print(f"[Lifespan] EPSS test: {epss_data.get('epss')}")

    # KEV index 测试
    record = kev_index.get("CVE-2021-44228")
    if record:
        print(f"[Lifespan] KEV index lookup: {record.get('dateAdded')}")
    no_record = kev_index.get("CVE-2024-1234")
    print(f"[Lifespan] KEV index miss: {no_record is None}")

    # NVD 测试
    try:
        nvd_result = await nvd.get_cve("CVE-2021-44228")
        vulns = nvd_result.get("vulnerabilities", [])
        if vulns:
            cve = vulns[0].get("cve", {})
            desc = cve.get("descriptions", [{}])[0].get("value", "")[:60]
            print(f"[Lifespan] NVD test: {desc}...")
    except Exception as e:
        print(f"[Lifespan] NVD test skipped: {e}")

    print("[Lifespan] Startup simulation completed!")


if __name__ == "__main__":
    asyncio.run(test_startup())
