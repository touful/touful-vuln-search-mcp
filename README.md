# touful-vuln-search-mcp

统一漏洞搜索 MCP 服务，为渗透测试 Agent 提供一站式漏洞情报检索。

## 特性

- **5 大数据源**：NVD / OSV / EPSS / CISA KEV / Exploit-DB + GitHub
- **10 个 MCP 工具**：覆盖 CVE 查询、关键词搜索、批量查询、EPSS 评估、KEV 检查、Exploit 搜索、综合研判
- **中文输出**：所有工具返回中文 Markdown 格式，含优先级建议
- **代理回退**：直连优先→代理自动回退，适用于网络受限环境
- **LLM 友好**：输入容错（空格/大小写/自然语言）+ 错误提示含格式示例和工具建议

## 安装

```bash
# 克隆仓库
git clone https://github.com/touful/touful-vuln-search-mcp.git
cd touful-vuln-search-mcp

# 安装依赖（含 socks 代理支持）
pip install -e .
```

## 配置

复制 `.env.example` 为 `.env`，填入 API 密钥：

```env
NVD_API_KEY=your_nvd_api_key_here        # 必需，从 https://nvd.nist.gov/developers 申请
GITHUB_TOKEN=your_github_token_here       # 可选，提高 GitHub 搜索限额
# HTTP_PROXY=socks5://127.0.0.1:7890      # 可选，网络受限时启用
```

| 变量 | 必需 | 说明 |
|:---|:---|:---|
| `NVD_API_KEY` | ✅ | NVD API 密钥，免费申请 |
| `GITHUB_TOKEN` | ❌ | GitHub Personal Access Token，无需任何权限 |
| `HTTP_PROXY` | ❌ | 代理地址，支持 socks5/http |

## 启动

```bash
# HTTP 传输（默认）
python -m src.server --transport http --host 127.0.0.1 --port 8080

# stdio 模式（Claude Desktop / Cursor 集成）
python -m src.server --transport stdio
```

## MCP 客户端配置

**Claude Desktop** (`claude_desktop_config.json`)：

```json
{
  "mcpServers": {
    "touful-vuln-search": {
      "command": "python",
      "args": ["-m", "src.server", "--transport", "stdio"],
      "cwd": "/path/to/touful-vuln-search-mcp",
      "env": {
        "NVD_API_KEY": "your-key",
        "GITHUB_TOKEN": "ghp_xxx",
        "HTTP_PROXY": "socks5://127.0.0.1:7890"
      }
    }
  }
}
```

## 工具列表

| 工具 | 数据源 | 用途 |
|:---|:---|:---|
| `nvd_get_cve` | NVD | 查询单个 CVE 详情（CVSS/CWE/CPE/参考链接）|
| `nvd_search_cve` | NVD | 按关键词搜索 CVE |
| `nvd_get_cves_batch` | NVD | 批量查询（逗号分隔，最多 100）|
| `osv_query_package` | OSV | 查询软件包已知漏洞 |
| `osv_query_batch` | OSV | 批量查询软件包漏洞 |
| `osv_get_vuln` | OSV | 查询漏洞详情（含受影响版本范围）|
| `get_epss_score` | EPSS | 查询漏洞 30 天内被利用概率 |
| `check_kev_status` | CISA KEV | 检查是否在已知被利用漏洞目录 |
| `search_exploit` | GitHub+Exploit-DB | 搜索公开 PoC/Exploit |
| `assess_cve` | 全部 4 源 | 🎯 综合评估（CVSS+EPSS+KEV+Exploit 并发查询）|

## 数据源

| 数据源 | 说明 | 需要认证 |
|:---|:---|:---|
| [NVD](https://nvd.nist.gov/) | 美国国家漏洞数据库 | ✅ API Key |
| [OSV](https://osv.dev/) | Google 开源漏洞数据库 | 无 |
| [EPSS](https://www.first.org/epss) | 漏洞利用预测评分系统 | 无 |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | 已知被利用漏洞目录 | 无 |
| [Exploit-DB](https://www.exploit-db.com/) + GitHub | 公开利用代码搜索 | ❌ Token（可选）|

## 项目结构

```
touful-vuln-search-mcp/
├── src/
│   ├── server.py            # FastMCP 服务入口，10 个工具定义
│   ├── config.py            # 配置管理（环境变量/API端点）
│   └── clients/
│       ├── base.py          # 公共基类（统一错误处理）
│       ├── http_utils.py    # HTTP 工具（直连→代理回退）
│       ├── nvd_client.py    # NVD API 客户端（aiolimiter 限速）
│       ├── osv_client.py    # OSV API 客户端
│       ├── epss_client.py   # EPSS API 客户端
│       ├── kev_client.py    # CISA KEV 客户端
│       └── exploit_client.py   # Exploit 搜索客户端
├── tests/                   # 测试脚本
│   ├── check_config.py      # 配置检查
│   ├── check_tools.py       # 工具可用性检查
│   ├── integration_test.py  # 集成测试
│   └── test_osv_format.py   # OSV 格式测试
├── scripts/                 # 工具和测试脚本
│   ├── check_cve_2024_1234.py    # CVE 状态检查示例
│   ├── test_clients.py           # 客户端功能测试
│   ├── test_mcp_tools.py         # MCP 工具注册验证
│   ├── test_proxy_fallback.py    # 代理回退验证
│   ├── test_llm_robustness.py    # LLM 输入健壮性测试
│   └── ...                       # 其他验证脚本
├── docs/                    # 文档
├── pyproject.toml
├── .env.example
├── .gitignore
└── README.md
```

## 运行测试

```bash
# 检查配置是否正确
python tests/check_config.py

# 检查 MCP 工具是否可用
python tests/check_tools.py

# 集成测试
python tests/integration_test.py

# OSV 格式测试
python tests/test_osv_format.py
```

## 许可证

MIT
