"""磁盘缓存层测试脚本

覆盖: 缓存命中/未命中/过期/损坏、原子写入、KEV/ExploitDB 各方法。
沿用现有脚本式风格，可直接 `python tests/check_cache.py` 运行。
"""

import asyncio
import json
import os
import shutil
import sys
import tempfile
import time

# 推导项目根目录
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _project_root)

# 记录测试结果
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


# ========== 准备：创建临时缓存目录并 patch ==========

_temp_dir = tempfile.mkdtemp(prefix="check_cache_")
import src.cache as _cache_mod

_original_cache_dir = _cache_mod.CACHE_DIR
_cache_mod.CACHE_DIR = _temp_dir

# 也要 patch config 中的 CACHE_DIR，因为 is_cache_fresh 内部用 get_cache_age_hours 拼接路径
import src.config as _config_mod

_original_config_cache_dir = _config_mod.CACHE_DIR
_config_mod.CACHE_DIR = _temp_dir


def _cleanup():
    """清理临时目录并恢复原始配置。"""
    _cache_mod.CACHE_DIR = _original_cache_dir
    _config_mod.CACHE_DIR = _original_config_cache_dir
    try:
        shutil.rmtree(_temp_dir, ignore_errors=True)
    except Exception:
        pass


def _make_old_mtime(filepath: str, hours: float):
    """将文件 mtime 设为几小时前。"""
    old_time = time.time() - hours * 3600
    os.utime(filepath, (old_time, old_time))


# ==================== 基础缓存读写测试 ====================


async def test_json_cache_hit():
    """测试 JSON 缓存命中"""
    filename = "test_hit.json"
    data = {"items": [1, 2, 3], "name": "test"}
    filepath = os.path.join(_temp_dir, filename)
    os.makedirs(_temp_dir, exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f)
    result = await _cache_mod.load_json_cache(filename)
    _check("JSON 缓存命中", result == data, f"期望 {data}，得到 {result}")
    # 标记为新鲜
    _make_old_mtime(filepath, 0)
    fresh = _cache_mod.is_cache_fresh(filename, 24)
    _check("JSON 缓存新鲜度检查", fresh is True)


async def test_json_cache_miss():
    """测试 JSON 缓存未命中"""
    result = await _cache_mod.load_json_cache("nonexistent_file.json")
    _check("JSON 缓存未命中返回 None", result is None, f"得到 {result}")


async def test_json_cache_corrupted():
    """测试 JSON 缓存损坏（优雅降级）"""
    filename = "test_corrupt.json"
    filepath = os.path.join(_temp_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write("this is not valid json {{{")
    result = await _cache_mod.load_json_cache(filename)
    _check("JSON 缓存损坏返回 None", result is None)


async def test_json_cache_stale():
    """测试 JSON 缓存过期"""
    filename = "test_stale.json"
    data = ["old_data"]
    filepath = os.path.join(_temp_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f)
    _make_old_mtime(filepath, 5)  # 设为 5 小时前
    fresh = _cache_mod.is_cache_fresh(filename, 1)  # TTL=1h，应收过期
    _check("JSON 缓存过期检查 (5h vs 1h)", fresh is False)


async def test_text_cache_hit():
    """测试文本缓存命中"""
    filename = "test_text.txt"
    content = "id,name\n1,test\n"
    filepath = os.path.join(_temp_dir, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    result = await _cache_mod.load_text_cache(filename)
    _check("文本缓存命中", result == content)


async def test_text_cache_miss():
    """测试文本缓存未命中"""
    result = await _cache_mod.load_text_cache("nonexistent_text.txt")
    _check("文本缓存未命中返回 None", result is None)


async def test_atomic_write_json():
    """测试 JSON 原子写入"""
    filename = "test_atomic.json"
    data = {"atomic": True, "count": 42}
    await _cache_mod.save_json_cache(filename, data)
    result = await _cache_mod.load_json_cache(filename)
    _check("原子写入后读取一致", result == data)
    # 验证没有遗留临时文件
    tmp_files = [f for f in os.listdir(_temp_dir) if ".tmp" in f and filename in f]
    _check("无遗留临时文件", len(tmp_files) == 0, f"遗留: {tmp_files}")


async def test_atomic_write_text():
    """测试文本原子写入"""
    filename = "test_atomic_text.csv"
    content = "id,name\n1,test\n2,foo"
    await _cache_mod.save_text_cache(filename, content)
    result = await _cache_mod.load_text_cache(filename)
    _check("文本原子写入后读取一致", result == content)


async def test_filename_validation():
    """测试文件名安全校验"""
    dangerous = ["../escape.txt", "subdir/file.json", "a\\b.txt", "", ".", ".."]
    for name in dangerous:
        try:
            _cache_mod._validate_filename(name)
            _check(f"危险文件名应拒绝: {name!r}", False)
        except ValueError:
            _check(f"危险文件名已拒绝: {name!r}", True)


async def test_get_cache_age_nonexistent():
    """测试不存在文件的缓存年龄"""
    age = _cache_mod.get_cache_age_hours("definitely_not_a_real_file_2024.xyz")
    _check("不存在文件的缓存年龄为 None", age is None)


# ==================== KEVClient 测试 ====================


async def test_kev_load_from_cache_hit():
    """测试 KEVClient.load_from_cache 命中"""
    from src.clients.kev_client import KEVClient
    from src.config import KEV_CACHE_FILE

    catalog = [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j"},
        {"cveID": "CVE-2022-22965", "vendorProject": "Spring", "product": "Spring"},
    ]
    filepath = os.path.join(_temp_dir, KEV_CACHE_FILE)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(catalog, f)
    _make_old_mtime(filepath, 0)

    client = KEVClient()
    result = await client.load_from_cache()
    _check("KEV load_from_cache 命中", result is not None)
    if result:
        _check("KEV 数据条目数正确", len(result) == 2)


async def test_kev_load_from_cache_miss():
    """测试 KEVClient.load_from_cache 未命中"""
    from src.clients.kev_client import KEVClient
    from src.config import KEV_CACHE_FILE

    # 确保文件不存在
    filepath = os.path.join(_temp_dir, KEV_CACHE_FILE)
    if os.path.exists(filepath):
        os.remove(filepath)

    client = KEVClient()
    result = await client.load_from_cache()
    _check("KEV load_from_cache 未命中返回 None", result is None)


async def test_kev_load_catalog_returns_empty():
    """测试 KEVClient.load_catalog 缓存未命中时返回空列表"""
    from src.clients.kev_client import KEVClient
    from src.config import KEV_CACHE_FILE

    filepath = os.path.join(_temp_dir, KEV_CACHE_FILE)
    if os.path.exists(filepath):
        os.remove(filepath)

    client = KEVClient()
    result = await client.load_catalog()
    _check("KEV load_catalog 未命中返回 []", result == [], f"得到 {result}")
    _check("KEV load_catalog 返回类型为 list", isinstance(result, list))


async def test_kev_fetch_and_save():
    """测试 KEVClient.fetch_and_save（mock 网络）"""
    import src.clients.kev_client as kev_mod

    # mock resilient_request
    original_request = kev_mod.resilient_request
    try:
        mock_catalog = [{"cveID": "CVE-2024-9999", "vendorProject": "Test"}]

        class MockResponse:
            status_code = 200
            def json(self):
                return {"vulnerabilities": mock_catalog}

        async def mock_request(*args, **kwargs):
            return MockResponse()

        kev_mod.resilient_request = mock_request

        from src.clients.kev_client import KEVClient

        client = KEVClient()
        result = await client.fetch_and_save()
        _check("KEV fetch_and_save 返回正确数据", result == mock_catalog)

        # 验证磁盘缓存已写入
        from src.config import KEV_CACHE_FILE
        cached = await _cache_mod.load_json_cache(KEV_CACHE_FILE)
        _check("KEV fetch_and_save 写入磁盘", cached == mock_catalog)
    finally:
        kev_mod.resilient_request = original_request


async def test_kev_fetch_and_save_disk_write_failure():
    """测试 KEVClient.fetch_and_save 磁盘写入失败仍返回数据（M-1 回归测试）"""
    import src.clients.kev_client as kev_mod

    original_request = kev_mod.resilient_request
    original_save = kev_mod.save_json_cache  # 保存 kev_client 模块命名空间中的引用
    try:
        mock_catalog = [{"cveID": "CVE-2024-9999", "vendorProject": "Test"}]

        class MockResponse:
            status_code = 200
            def json(self):
                return {"vulnerabilities": mock_catalog}

        async def mock_request(*args, **kwargs):
            return MockResponse()

        kev_mod.resilient_request = mock_request

        # mock kev_client 模块命名空间中的 save_json_cache（而非 src.cache）
        # 因为 fetch_and_save 调用的是本模块 import 的引用
        async def mock_save_fail(*args, **kwargs):
            raise OSError("磁盘写入失败（模拟）")

        kev_mod.save_json_cache = mock_save_fail

        from src.clients.kev_client import KEVClient

        client = KEVClient()
        result = await client.fetch_and_save()
        _check("KEV 磁盘写入失败仍返回数据", result == mock_catalog,
               f"期望 {mock_catalog}，得到 {result}")
    finally:
        kev_mod.resilient_request = original_request
        kev_mod.save_json_cache = original_save


# ==================== ExploitClient 测试 ====================


_CSV_CONTENT = (
    "id,file,description,date,author,type,platform,port,codes\r\n"
    "123,exploit.rb,Test Exploit CVE-2024-0001,2024-01-01,test,remote,linux,80,"
    "CVE-2024-0001\r\n"
    "456,poc.py,Another PoC,2024-02-01,foo,local,windows,,CVE-2024-0002\r\n"
)


async def test_exploit_load_from_cache_hit():
    """测试 ExploitClient.load_from_cache 命中"""
    from src.clients.exploit_client import ExploitClient
    from src.config import EXPLOITDB_CACHE_FILE

    filepath = os.path.join(_temp_dir, EXPLOITDB_CACHE_FILE)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(_CSV_CONTENT)
    _make_old_mtime(filepath, 0)

    client = ExploitClient()
    result = await client.load_from_cache()
    _check("ExploitDB load_from_cache 命中", result is not None)
    if result:
        _check("ExploitDB 条目数", len(result) == 2, f"得到 {len(result)}")
        _check("ExploitDB 第一项 edb_id", result[0].get("id") == "123")


async def test_exploit_load_from_cache_miss():
    """测试 ExploitClient.load_from_cache 未命中"""
    from src.clients.exploit_client import ExploitClient
    from src.config import EXPLOITDB_CACHE_FILE

    filepath = os.path.join(_temp_dir, EXPLOITDB_CACHE_FILE)
    if os.path.exists(filepath):
        os.remove(filepath)

    client = ExploitClient()
    result = await client.load_from_cache()
    _check("ExploitDB load_from_cache 未命中返回 None", result is None)


async def test_exploit_load_exploitdb_csv_cache_hit():
    """测试 load_exploitdb_csv 缓存命中时填充 _csv_cache"""
    from src.clients.exploit_client import ExploitClient
    from src.config import EXPLOITDB_CACHE_FILE

    filepath = os.path.join(_temp_dir, EXPLOITDB_CACHE_FILE)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(_CSV_CONTENT)
    _make_old_mtime(filepath, 0)

    client = ExploitClient()
    await client.load_exploitdb_csv()
    _check("load_exploitdb_csv 命中后 _csv_cache 非空", client._csv_cache is not None)
    if client._csv_cache:
        _check("load_exploitdb_csv 条目数正确", len(client._csv_cache) == 2)


async def test_exploit_fetch_and_save():
    """测试 ExploitClient.fetch_and_save（mock 网络）"""
    import src.clients.exploit_client as exploit_mod

    original_request = exploit_mod.resilient_request
    try:
        class MockResponse:
            status_code = 200
            @property
            def text(self):
                return _CSV_CONTENT

        async def mock_request(*args, **kwargs):
            return MockResponse()

        exploit_mod.resilient_request = mock_request

        from src.clients.exploit_client import ExploitClient

        client = ExploitClient()
        await client.fetch_and_save()
        _check("fetch_and_save 后 _csv_cache 非空", client._csv_cache is not None)
        if client._csv_cache:
            _check("fetch_and_save 条目数", len(client._csv_cache) == 2)

        # 验证磁盘缓存已写入
        from src.config import EXPLOITDB_CACHE_FILE
        cached_text = await _cache_mod.load_text_cache(EXPLOITDB_CACHE_FILE)
        _check("fetch_and_save 磁盘缓存写入", cached_text is not None)
        if cached_text:
            _check("磁盘缓存内容一致", "CVE-2024-0001" in cached_text)
    finally:
        exploit_mod.resilient_request = original_request


async def test_exploit_fetch_and_save_disk_write_failure():
    """测试 ExploitClient.fetch_and_save 磁盘写入失败仍填充 _csv_cache（M-2 回归测试）"""
    import src.clients.exploit_client as exploit_mod

    original_request = exploit_mod.resilient_request
    original_save = exploit_mod.save_text_cache  # 保存 exploit_client 模块命名空间中的引用
    try:
        class MockResponse:
            status_code = 200
            @property
            def text(self):
                return _CSV_CONTENT

        async def mock_request(*args, **kwargs):
            return MockResponse()

        exploit_mod.resilient_request = mock_request

        # mock exploit_client 模块命名空间中的 save_text_cache（而非 src.cache）
        # 因为 fetch_and_save 调用的是本模块 import 的引用
        async def mock_save_fail(*args, **kwargs):
            raise OSError("磁盘写入失败（模拟）")

        exploit_mod.save_text_cache = mock_save_fail

        from src.clients.exploit_client import ExploitClient

        client = ExploitClient()
        await client.fetch_and_save()
        _check("ExploitDB 磁盘写入失败仍填充 _csv_cache",
               client._csv_cache is not None)
        if client._csv_cache:
            _check("ExploitDB 磁盘写入失败条目数正确",
                   len(client._csv_cache) == 2,
                   f"得到 {len(client._csv_cache)}")
    finally:
        exploit_mod.resilient_request = original_request
        exploit_mod.save_text_cache = original_save


# ==================== 运行全部测试 ====================


async def main():
    """运行所有缓存测试。"""
    print("=" * 60)
    print("磁盘缓存层测试 —— tests/check_cache.py")
    print("=" * 60)

    print("\n── 基础缓存读写 ──")
    await test_json_cache_hit()
    await test_json_cache_miss()
    await test_json_cache_corrupted()
    await test_json_cache_stale()
    await test_text_cache_hit()
    await test_text_cache_miss()
    await test_atomic_write_json()
    await test_atomic_write_text()
    await test_filename_validation()
    await test_get_cache_age_nonexistent()

    print("\n── KEVClient 缓存 ──")
    await test_kev_load_from_cache_hit()
    await test_kev_load_from_cache_miss()
    await test_kev_load_catalog_returns_empty()
    await test_kev_fetch_and_save()
    await test_kev_fetch_and_save_disk_write_failure()

    print("\n── ExploitClient 缓存 ──")
    await test_exploit_load_from_cache_hit()
    await test_exploit_load_from_cache_miss()
    await test_exploit_load_exploitdb_csv_cache_hit()
    await test_exploit_fetch_and_save()
    await test_exploit_fetch_and_save_disk_write_failure()

    # 总结
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
