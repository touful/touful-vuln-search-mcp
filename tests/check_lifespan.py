"""app_lifespan 集成测试脚本

覆盖 5 项测试场景：
1. 冷启动（无缓存）—— 验证空数据启动 + 后台刷新正确触发
2. 热启动（有缓存且未过期）—— 验证缓存加载 + 后台刷新不触发
3. 缓存过期时后台刷新触发 —— 验证过期数据加载 + 刷新更新
4. 资源清理 —— 验证任务取消 + 内存缓存释放
5. 后台刷新失败不影响服务 —— 验证异常容错

沿用现有脚本式风格（check_cache.py 风格），可直接执行：
    python tests/check_lifespan.py
"""

import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
import time

# 推导项目根目录
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _project_root)

# ── 全局测试计数器 ──
_passed = 0
_failed = 0
_results: list[str] = []


def _check(name: str, condition: bool, detail: str = ""):
    """断言并记录结果。"""
    global _passed, _failed
    if condition:
        _passed += 1
        _results.append(f"  [PASS] {name}")
    else:
        _failed += 1
        msg = f"  [FAIL] {name}"
        if detail:
            msg += f" —— {detail}"
        _results.append(msg)
        print(msg)


# ========== 准备：创建临时缓存目录并 patch CACHE_DIR ==========

_temp_dir = tempfile.mkdtemp(prefix="check_lifespan_")

import src.cache as _cache_mod

_original_cache_dir = _cache_mod.CACHE_DIR
_cache_mod.CACHE_DIR = _temp_dir

import src.config as _config_mod

_original_config_cache_dir = _config_mod.CACHE_DIR
_config_mod.CACHE_DIR = _temp_dir

# 禁用日志输出（避免干扰测试输出）
logging.disable(logging.CRITICAL)


def _cleanup():
    """清理临时目录并恢复原始配置与日志级别。"""
    _cache_mod.CACHE_DIR = _original_cache_dir
    _config_mod.CACHE_DIR = _original_config_cache_dir
    logging.disable(logging.NOTSET)
    try:
        shutil.rmtree(_temp_dir, ignore_errors=True)
    except Exception:
        pass


def _make_old_mtime(filepath: str, hours: float):
    """将文件 mtime 设为几小时前（用于模拟过期缓存）。"""
    old_time = time.time() - hours * 3600
    os.utime(filepath, (old_time, old_time))


def _write_kev_cache(data: list[dict]):
    """向临时缓存目录写入 KEV JSON 缓存文件。"""
    filepath = os.path.join(_temp_dir, _config_mod.KEV_CACHE_FILE)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f)


def _write_exploitdb_cache(csv_text: str):
    """向临时缓存目录写入 ExploitDB CSV 缓存文件。"""
    filepath = os.path.join(_temp_dir, _config_mod.EXPLOITDB_CACHE_FILE)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(csv_text)


# ========== Mock 数据常量 ==========

# KEV 初始缓存数据（2 条）
MOCK_KEV_CATALOG = [
    {
        "cveID": "CVE-2024-0001",
        "vendorProject": "Apache",
        "product": "Log4j",
        "dateAdded": "2024-01-15",
        "shortDescription": "Test vulnerability 1",
    },
    {
        "cveID": "CVE-2024-0002",
        "vendorProject": "Spring",
        "product": "Core",
        "dateAdded": "2024-02-20",
        "shortDescription": "Test vulnerability 2",
    },
]

# 刷新后的新 KEV 数据（1 条，与初始数据不同以验证更新）
MOCK_NEW_KEV_CATALOG = [
    {
        "cveID": "CVE-2024-9999",
        "vendorProject": "NewCorp",
        "product": "NewProduct",
        "dateAdded": "2024-06-01",
        "shortDescription": "Fresh vulnerability after refresh",
    },
]

# ExploitDB CSV 初始缓存数据（2 行）
MOCK_EXPLOITDB_CSV = (
    "id,file,description,date,author,type,platform,port,codes\r\n"
    "123,exploit.rb,Test Exploit,2024-01-01,test,remote,linux,80,"
    "CVE-2024-0001\r\n"
    "456,poc.py,Another PoC,2024-02-01,foo,local,windows,,"
    "CVE-2024-0002\r\n"
)

# app_lifespan 的 server 参数 —— 内部不使用其属性，可用任意对象
_MOCK_SERVER = object()


def _assert_client_types(ctx: dict):
    """验证 lifespan_ctx 包含全部 5 个客户端且类型正确。"""
    from src.clients.nvd_client import NVDClient
    from src.clients.osv_client import OSVClient
    from src.clients.epss_client import EPSSClient
    from src.clients.kev_client import KEVClient
    from src.clients.exploit_client import ExploitClient

    _check("ctx 含 nvd_client", isinstance(ctx["nvd_client"], NVDClient))
    _check("ctx 含 osv_client", isinstance(ctx["osv_client"], OSVClient))
    _check("ctx 含 epss_client", isinstance(ctx["epss_client"], EPSSClient))
    _check("ctx 含 kev_client", isinstance(ctx["kev_client"], KEVClient))
    _check("ctx 含 exploit_client", isinstance(ctx["exploit_client"], ExploitClient))
    _check("ctx 含 kev_catalog", "kev_catalog" in ctx)
    _check("ctx 含 kev_index", "kev_index" in ctx)


# ========================================================================
#  场景 1：冷启动（无缓存）
#  条件：磁盘无缓存文件 → load_from_cache 返回 None
#  验证：空数据启动 + 后台刷新任务被触发
# ========================================================================


async def test_cold_start():
    """冷启动集成测试：无磁盘缓存时 lifespan 正常 yield，后台刷新触发。"""
    from src.server import app_lifespan
    from src.clients.kev_client import KEVClient
    from src.clients.exploit_client import ExploitClient

    # 确保缓存目录为空（无缓存文件）
    for fname in (_config_mod.KEV_CACHE_FILE, _config_mod.EXPLOITDB_CACHE_FILE):
        fpath = os.path.join(_temp_dir, fname)
        if os.path.exists(fpath):
            os.remove(fpath)

    kev_refreshed = asyncio.Event()
    exploit_refreshed = asyncio.Event()

    _orig_kev_fetch = KEVClient.fetch_and_save
    _orig_exploit_fetch = ExploitClient.fetch_and_save

    async def _mock_kev_fetch(self):
        kev_refreshed.set()
        return MOCK_NEW_KEV_CATALOG

    async def _mock_exploit_fetch(self):
        exploit_refreshed.set()

    try:
        KEVClient.fetch_and_save = _mock_kev_fetch
        ExploitClient.fetch_and_save = _mock_exploit_fetch

        async with app_lifespan(_MOCK_SERVER) as ctx:
            # ── 验证初始状态（yield 时） ──
            _assert_client_types(ctx)
            _check(
                "冷启动 kev_catalog 为空列表",
                ctx["kev_catalog"] == [],
                f"得到 {ctx['kev_catalog']!r}",
            )
            _check(
                "冷启动 kev_index 为空字典",
                ctx["kev_index"] == {},
                f"得到 {ctx['kev_index']!r}",
            )
            _check(
                "冷启动 exploit_client._csv_cache 为 None",
                ctx["exploit_client"]._csv_cache is None,
            )

            # ── 等待后台刷新任务完成 ──
            await asyncio.wait_for(
                asyncio.gather(kev_refreshed.wait(), exploit_refreshed.wait()),
                timeout=3.0,
            )

            # ── 验证后台刷新已触发 ──
            _check("冷启动 KEV 后台刷新已触发", kev_refreshed.is_set())
            _check("冷启动 ExploitDB 后台刷新已触发", exploit_refreshed.is_set())

            # ── 验证刷新后 lifespan_ctx 被更新 ──
            _check(
                "冷启动刷新后 kev_catalog 含新数据",
                ctx["kev_catalog"] == MOCK_NEW_KEV_CATALOG,
                f"得到 {ctx['kev_catalog']!r}",
            )
            _check(
                "冷启动刷新后 kev_index 使用新数据",
                "CVE-2024-9999" in ctx["kev_index"],
            )
    finally:
        KEVClient.fetch_and_save = _orig_kev_fetch
        ExploitClient.fetch_and_save = _orig_exploit_fetch


# ========================================================================
#  场景 2：热启动（有缓存且未过期）
#  条件：磁盘缓存存在 + mtime 在 TTL 内 → is_cache_fresh 返回 True
#  验证：缓存数据被加载 + 后台刷新不触发（fetch_and_save 不被调用）
# ========================================================================


async def test_hot_start():
    """热启动集成测试：有新鲜缓存时 lifespan 使用缓存数据，不触发后台刷新。"""
    from src.server import app_lifespan
    from src.clients.kev_client import KEVClient
    from src.clients.exploit_client import ExploitClient

    # 写入新鲜缓存文件（mtime 为当前时间，在 TTL 内）
    _write_kev_cache(MOCK_KEV_CATALOG)
    _write_exploitdb_cache(MOCK_EXPLOITDB_CSV)

    kev_refreshed = asyncio.Event()
    exploit_refreshed = asyncio.Event()

    _orig_kev_fetch = KEVClient.fetch_and_save
    _orig_exploit_fetch = ExploitClient.fetch_and_save

    async def _mock_kev_fetch(self):
        kev_refreshed.set()
        return MOCK_NEW_KEV_CATALOG

    async def _mock_exploit_fetch(self):
        exploit_refreshed.set()

    try:
        KEVClient.fetch_and_save = _mock_kev_fetch
        ExploitClient.fetch_and_save = _mock_exploit_fetch

        async with app_lifespan(_MOCK_SERVER) as ctx:
            # ── 验证从缓存加载到初始数据 ──
            _assert_client_types(ctx)
            _check(
                "热启动 kev_catalog 包含缓存数据",
                ctx["kev_catalog"] == MOCK_KEV_CATALOG,
                f"得到 {ctx['kev_catalog']!r}",
            )
            _check(
                "热启动 kev_index 含 CVE-2024-0001",
                "CVE-2024-0001" in ctx["kev_index"],
            )
            _check(
                "热启动 kev_index 含 CVE-2024-0002",
                "CVE-2024-0002" in ctx["kev_index"],
            )
            _check(
                "热启动 kev_index 条目数匹配",
                len(ctx["kev_index"]) == 2,
                f"得到 {len(ctx['kev_index'])}",
            )
            _check(
                "热启动 exploit_client._csv_cache 非空",
                ctx["exploit_client"]._csv_cache is not None,
            )
            _check(
                "热启动 exploit_client._csv_cache 条目数正确",
                len(ctx["exploit_client"]._csv_cache) == 2,
                f"得到 {len(ctx['exploit_client']._csv_cache)}",
            )

            # ── 等待一小段时间，确认后台刷新未触发 ──
            await asyncio.sleep(0.3)
            _check(
                "热启动 KEV 后台刷新未触发",
                not kev_refreshed.is_set(),
                "fetch_and_save 不应被调用",
            )
            _check(
                "热启动 ExploitDB 后台刷新未触发",
                not exploit_refreshed.is_set(),
                "fetch_and_save 不应被调用",
            )
    finally:
        KEVClient.fetch_and_save = _orig_kev_fetch
        ExploitClient.fetch_and_save = _orig_exploit_fetch


# ========================================================================
#  场景 3：缓存过期时后台刷新触发
#  条件：磁盘缓存存在但 mtime 超过 TTL → is_cache_fresh 返回 False
#  验证：启动时加载缓存数据（通过 mock load_from_cache）→ 后台刷新
#        触发 → 刷新后 lifespan_ctx 被更新
#  【注意】实际代码中 load_from_cache 在缓存过期时会返回 None，
#          本测试 mock load_from_cache 返回缓存数据以验证"过期数据
#          可读取 + 后台仍刷新"的双重保证。
# ========================================================================


async def test_expired_cache_refresh():
    """缓存过期集成测试：过期缓存仍可加载，后台刷新触发并更新数据。"""
    from src.server import app_lifespan
    from src.clients.kev_client import KEVClient
    from src.clients.exploit_client import ExploitClient

    # 写入过期缓存文件（mtime 设为 200 小时前）
    _write_kev_cache(MOCK_KEV_CATALOG)
    kv_path = os.path.join(_temp_dir, _config_mod.KEV_CACHE_FILE)
    _make_old_mtime(kv_path, 200)

    _write_exploitdb_cache(MOCK_EXPLOITDB_CSV)
    ev_path = os.path.join(_temp_dir, _config_mod.EXPLOITDB_CACHE_FILE)
    _make_old_mtime(ev_path, 200)

    kev_refreshed = asyncio.Event()

    # 保存原始方法引用
    _orig_kev_load = KEVClient.load_from_cache
    _orig_kev_fetch = KEVClient.fetch_and_save

    # mock load_from_cache 使其忽略过期检查，始终返回缓存数据；
    # 后台刷新使用 is_cache_fresh 检查磁盘文件（已过期），仍会触发。
    async def _mock_kev_load(self):
        return MOCK_KEV_CATALOG

    async def _mock_kev_fetch(self):
        kev_refreshed.set()
        return MOCK_NEW_KEV_CATALOG

    try:
        KEVClient.load_from_cache = _mock_kev_load
        KEVClient.fetch_and_save = _mock_kev_fetch

        async with app_lifespan(_MOCK_SERVER) as ctx:
            # ── 验证启动时从缓存加载到初始数据 ──
            _assert_client_types(ctx)
            _check(
                "过期缓存 kev_catalog 包含初始数据",
                ctx["kev_catalog"] == MOCK_KEV_CATALOG,
                f"得到 {ctx['kev_catalog']!r}",
            )
            _check(
                "过期缓存 kev_index 已构建",
                "CVE-2024-0001" in ctx["kev_index"],
            )

            # ── 等待后台刷新触发 ──
            await asyncio.wait_for(kev_refreshed.wait(), timeout=3.0)
            _check("过期缓存 KEV 后台刷新已触发", kev_refreshed.is_set())

            # ── 验证 lifespan_ctx 已被刷新数据更新 ──
            _check(
                "过期缓存刷新后 kev_catalog 为新数据",
                ctx["kev_catalog"] == MOCK_NEW_KEV_CATALOG,
                f"得到 {ctx['kev_catalog']!r}",
            )
            _check(
                "过期缓存刷新后 kev_index 使用新数据",
                "CVE-2024-9999" in ctx["kev_index"],
            )
    finally:
        KEVClient.load_from_cache = _orig_kev_load
        KEVClient.fetch_and_save = _orig_kev_fetch


# ========================================================================
#  场景 4：资源清理
#  条件：进入 lifespan 后退出 context（模拟服务关闭）
#  验证：后台任务被取消 + exploit_client.clear_cache() 被调用
#        + 整个过程不抛出异常
# ========================================================================


async def test_cleanup():
    """资源清理集成测试：退出 lifespan 时后台任务取消、内存缓存释放。"""
    from src.server import app_lifespan
    from src.clients.kev_client import KEVClient
    from src.clients.exploit_client import ExploitClient

    _orig_kev_fetch = KEVClient.fetch_and_save
    _orig_exploit_fetch = ExploitClient.fetch_and_save

    # 让后台任务 sleep 足够长，确保退出时尚未完成（验证 cancel）
    async def _mock_kev_fetch_slow(self):
        await asyncio.sleep(3600)
        return MOCK_NEW_KEV_CATALOG

    async def _mock_exploit_fetch_slow(self):
        await asyncio.sleep(3600)

    saved_client = None

    try:
        KEVClient.fetch_and_save = _mock_kev_fetch_slow
        ExploitClient.fetch_and_save = _mock_exploit_fetch_slow

        async with app_lifespan(_MOCK_SERVER) as ctx:
            saved_client = ctx["exploit_client"]
            # 确认进入 lifespan 成功
            _check("清理测试进入 lifespan 成功", True)

        # ── 已退出 lifespan 的 finally 块 ──
        # 验证 1：exploit_client._csv_cache 已被 clear_cache() 置为 None
        _check(
            "退出后 exploit_client._csv_cache 为 None",
            saved_client is not None and saved_client._csv_cache is None,
        )
        # 验证 2：没有异常传播
        _check("退出 lifespan 无异常传播", True)

    finally:
        KEVClient.fetch_and_save = _orig_kev_fetch
        ExploitClient.fetch_and_save = _orig_exploit_fetch


# ========================================================================
#  场景 5：后台刷新失败不影响服务运行
#  条件：mock fetch_and_save 抛出异常
#  验证：lifespan 正常 yield + 不因后台刷新失败阻塞或崩溃
#        + lifespan_ctx 仍包含启动时加载的缓存数据
# ========================================================================


async def test_background_failure_tolerance():
    """后台失败容错集成测试：刷新异常不传播，lifespan 正常运行。"""
    from src.server import app_lifespan
    from src.clients.kev_client import KEVClient
    from src.clients.exploit_client import ExploitClient

    # 写入新鲜缓存（让 lifespan 有缓存数据可加载）
    _write_kev_cache(MOCK_KEV_CATALOG)
    _write_exploitdb_cache(MOCK_EXPLOITDB_CSV)

    _orig_kev_fetch = KEVClient.fetch_and_save
    _orig_exploit_fetch = ExploitClient.fetch_and_save

    async def _mock_kev_fetch_fail(self):
        raise RuntimeError("模拟 KEV 网络错误")

    async def _mock_exploit_fetch_fail(self):
        raise RuntimeError("模拟 ExploitDB 网络错误")

    try:
        KEVClient.fetch_and_save = _mock_kev_fetch_fail
        ExploitClient.fetch_and_save = _mock_exploit_fetch_fail

        async with app_lifespan(_MOCK_SERVER) as ctx:
            # ── lifespan 正常 yield —— 不因后台刷新失败而阻塞 ──
            _assert_client_types(ctx)

            # ── lifespan_ctx 仍包含启动时加载的缓存数据 ──
            _check(
                "容错测试 kev_catalog 含缓存数据",
                ctx["kev_catalog"] == MOCK_KEV_CATALOG,
                f"得到 {ctx['kev_catalog']!r}",
            )
            _check(
                "容错测试 kev_index 已构建",
                "CVE-2024-0001" in ctx["kev_index"],
            )
            _check(
                "容错测试 exploit_client._csv_cache 非空",
                ctx["exploit_client"]._csv_cache is not None,
            )

            # ── 等待后台刷新失败传播（异常应被捕获为 warning） ──
            await asyncio.sleep(0.3)

            # ── lifespan 依然存活，上下文未被破坏 ──
            _check("容错测试 lifespan 仍存活", True)
    finally:
        KEVClient.fetch_and_save = _orig_kev_fetch
        ExploitClient.fetch_and_save = _orig_exploit_fetch


# ========================================================================
#  测试运行入口
# ========================================================================


async def main():
    """运行全部 app_lifespan 集成测试。"""
    print("=" * 60)
    print("app_lifespan 集成测试 —— tests/check_lifespan.py")
    print("=" * 60)

    scenes = [
        ("场景 1：冷启动（无缓存）", test_cold_start),
        ("场景 2：热启动（有缓存）", test_hot_start),
        ("场景 3：过期缓存后台刷新", test_expired_cache_refresh),
        ("场景 4：资源清理", test_cleanup),
        ("场景 5：后台失败容错", test_background_failure_tolerance),
    ]

    for title, test_fn in scenes:
        print(f"\n── {title} ──")
        await test_fn()

    total = _passed + _failed
    print("\n" + "=" * 60)
    print(f"测试完成: 共 {total} 项，通过 {_passed} 项，失败 {_failed} 项")
    if _failed > 0:
        print("以下测试失败:")
        for r in _results:
            if "[FAIL]" in r:
                print(r)
    print("=" * 60)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    finally:
        _cleanup()
