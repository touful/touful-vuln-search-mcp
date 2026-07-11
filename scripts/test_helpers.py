"""测试辅助模块：创建模拟 MCP Context，供 test_assess.py 和 test_mcp_tools.py 使用"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import NVD_API_KEY, GITHUB_TOKEN


class MockContext:
    """模拟 FastMCP 的 Context，提供 lifespan_context"""

    def __init__(self, lifespan_context):
        self.lifespan_context = lifespan_context


async def create_mock_context() -> MockContext:
    """创建带有完整 lifespan_context 的模拟 Context"""
    from src.clients.nvd_client import NVDClient
    from src.clients.osv_client import OSVClient
    from src.clients.epss_client import EPSSClient
    from src.clients.kev_client import KEVClient
    from src.clients.exploit_client import ExploitClient

    nvd_client = NVDClient(api_key=NVD_API_KEY)
    osv_client = OSVClient()
    epss_client = EPSSClient()
    kev_client = KEVClient()
    exploit_client = ExploitClient(github_token=GITHUB_TOKEN)
    kev_catalog = await kev_client.load_catalog()
    kev_index = KEVClient.build_index(kev_catalog)

    return MockContext({
        "nvd_client": nvd_client,
        "osv_client": osv_client,
        "epss_client": epss_client,
        "kev_client": kev_client,
        "kev_catalog": kev_catalog,
        "kev_index": kev_index,
        "exploit_client": exploit_client,
    })
