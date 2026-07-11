"""检查 CVE-2024-1234 的当前状态"""
import asyncio, httpx, os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

async def main():
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": os.getenv("NVD_API_KEY", "")}
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.get(url, params={"cveIds": "CVE-2024-1234"}, headers=headers)
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if vulns:
            cve = vulns[0]["cve"]
            print(f"CVE-2024-1234 当前状态: 已分配")
            print(f"  ID: {cve['id']}")
            print(f"  状态: {cve.get('vulnStatus', 'N/A')}")
            descs = cve.get("descriptions", [])
            for d in descs:
                if d.get("lang") == "en":
                    print(f"  描述: {d.get('value', '')[:200]}")
                    break
            metrics = cve.get("metrics", {})
            print(f"  V31 元素数: {len(metrics.get('cvssMetricV31', []))}")
        else:
            print("CVE-2024-1234: 未在 NVD 中找到 (未分配)")

asyncio.run(main())
