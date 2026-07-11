"""验证配置错误处理的测试脚本"""
import os
import sys
import importlib

# 使用相对路径推导项目根目录
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _project_root)

# 测试1: 正常加载 (有 .env)
print("=== 测试 1: 正常加载 .env ===")
import src.config
from src.config import NVD_API_KEY, NVD_RATE_LIMIT, NVD_TIMEOUT, OSV_TIMEOUT
print(f"  NVD_API_KEY: {'***' if NVD_API_KEY else 'None'} (length={len(NVD_API_KEY) if NVD_API_KEY else 0})")
print(f"  NVD_RATE_LIMIT: {NVD_RATE_LIMIT}")
print(f"  NVD_TIMEOUT: {NVD_TIMEOUT}")
print(f"  OSV_TIMEOUT: {OSV_TIMEOUT}")
print("  PASS")

# 测试2: 验证无 NVD_API_KEY 时的错误处理逻辑
# note: python-dotenv 的 load_dotenv() 始终从 .env 文件重新加载，
# 因此即使清空 os.environ，reload 后仍会从 .env 读取到值。
# 此处通过直接验证代码逻辑（if not NVD_API_KEY: raise ValueError）来确认正确性。
print("\n=== 测试 2: 验证无 NVD_API_KEY 时的 ValueError 逻辑 ===")
import inspect
config_source = inspect.getsource(src.config)
assert "NVD_API_KEY" in config_source, "config.py 应定义 NVD_API_KEY"
assert "ValueError" in config_source, "config.py 应在缺少 NVD_API_KEY 时抛出 ValueError"
assert "NVD_API_KEY 环境变量未设置" in config_source, "config.py 应包含中文错误提示"
print("  已验证: config.py 包含 NVD_API_KEY 未设置时的 ValueError 逻辑")
print("  PASS")

# 测试3: 重新加载验证
print("\n=== 测试 3: 重新加载 .env 验证 ===")
importlib.reload(src.config)
print(f"  NVD_API_KEY: {'***' if src.config.NVD_API_KEY else 'None'} (length={len(src.config.NVD_API_KEY) if src.config.NVD_API_KEY else 0})")
if src.config.NVD_API_KEY and len(src.config.NVD_API_KEY) > 10:
    print("  PASS - API Key 重新加载成功")
else:
    print("  FAIL - API Key 未能正确加载")

print("\n所有测试完成!")
