"""启动性能测量脚本

测量 app_lifespan 从进入到 yield 的耗时（即生命周期就绪时间），
验证修复后不再因网络下载阻塞启动。

测量范围说明:
- 本脚本测量的是 app_lifespan 上下文管理器中 yield 之前的耗时
  （仅本地磁盘 I/O + 内存操作，不包含网络请求）
- 后台刷新（网络下载）在 yield 之后异步执行，不阻塞启动
- 完整服务启动 = 模块导入 + 工具注册 + app_lifespan + 传输层绑定

用法:
    # 冷启动（无缓存）—— 单次
    python scripts/measure_startup.py --mode cold
    
    # 热启动（有缓存）—— 单次
    python scripts/measure_startup.py --mode hot
    
    # 冷+热各测 10 次取统计值
    python scripts/measure_startup.py --mode both --repeat 10
    
    # 后台刷新验证
    python scripts/measure_startup.py --mode verify_bg
"""

import argparse
import asyncio
import json
import logging
import os
import shutil
import statistics
import sys
import time

# 推导项目根目录并加入 sys.path
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _project_root)

# 让 src.server 的 import 使用自己的日志配置（不做全局压制）
# 但禁止 propagate 到 root logger，避免干扰测量脚本的输出
logging.getLogger("src").setLevel(logging.WARNING)


async def measure_lifespan_yield() -> float:
    """测量 app_lifespan 从进入到 yield 的耗时（秒）。

    通过直接调用 app_lifespan 上下文管理器来精确测量 yield 前耗时。
    这是服务生命周期中最关键的性能瓶颈点。
    """
    from src.server import mcp, app_lifespan

    t0 = time.perf_counter()
    async with app_lifespan(mcp) as ctx:
        elapsed = time.perf_counter() - t0
        return elapsed


async def run_cold_start() -> float:
    """冷启动：缓存目录不存在 -> load_from_cache 返回 None -> 空数据就绪"""
    from src.config import CACHE_DIR

    if os.path.exists(CACHE_DIR):
        shutil.rmtree(CACHE_DIR, ignore_errors=True)

    return await measure_lifespan_yield()


async def run_hot_start_with_data(kev_data: list, csv_content: str) -> float:
    """热启动：用指定缓存文件预填充，测量 yield 耗时。"""
    from src.config import CACHE_DIR, KEV_CACHE_FILE, EXPLOITDB_CACHE_FILE

    os.makedirs(CACHE_DIR, exist_ok=True)

    kev_path = os.path.join(CACHE_DIR, KEV_CACHE_FILE)
    with open(kev_path, "w", encoding="utf-8") as f:
        json.dump(kev_data, f)

    exploit_path = os.path.join(CACHE_DIR, EXPLOITDB_CACHE_FILE)
    with open(exploit_path, "w", encoding="utf-8") as f:
        f.write(csv_content)

    return await measure_lifespan_yield()


async def run_hot_start_small() -> float:
    """热启动（小样本 2 条 KEV + 2 行 CSV）"""
    kev_data = [
        {"cveID": "CVE-2021-44228", "vendorProject": "Apache", "product": "Log4j",
         "vulnerabilityName": "Log4j RCE", "dateAdded": "2021-12-10",
         "shortDescription": "Apache Log4j2 RCE", "requiredAction": "Apply updates",
         "dueDate": "2022-01-10", "notes": ""},
        {"cveID": "CVE-2022-22965", "vendorProject": "Spring", "product": "Spring Framework",
         "vulnerabilityName": "Spring4Shell", "dateAdded": "2022-04-01",
         "shortDescription": "Spring Framework RCE", "requiredAction": "Apply updates",
         "dueDate": "2022-04-22", "notes": ""},
    ]
    csv_content = (
        "id,file,description,date,author,type,platform,port,codes\r\n"
        "123,exploit.rb,Test Exploit CVE-2024-0001,2024-01-01,test,remote,linux,80,"
        "CVE-2024-0001\r\n"
        "456,poc.py,Another PoC,2024-02-01,foo,local,windows,,CVE-2024-0002\r\n"
    )
    return await run_hot_start_with_data(kev_data, csv_content)


async def run_hot_start_real_scale() -> float:
    """热启动（真实规模缓存：KEV ~1644 条 + 真实 CSV 部分）"""
    from src.config import CACHE_DIR, KEV_CACHE_FILE, EXPLOITDB_CACHE_FILE

    # 先尝试获取真实 KEV 数据
    kev_path = os.path.join(CACHE_DIR, KEV_CACHE_FILE)
    if not os.path.exists(kev_path):
        # 缓存不存在，下载一份
        try:
            from src.clients.kev_client import KEVClient
            client = KEVClient()
            catalog = await client.fetch_and_save()
            if not catalog:
                raise RuntimeError("KEV fetch returned empty")
        except Exception as e:
            # 降级：用小样本
            print(f"  [WARN] 无法获取真实 KEV 数据 ({e})，使用小样本替代")
            return await run_hot_start_small()

    return await measure_lifespan_yield()


def _cleanup_cache():
    """清理缓存目录"""
    from src.config import CACHE_DIR

    if os.path.exists(CACHE_DIR):
        shutil.rmtree(CACHE_DIR, ignore_errors=True)


def print_stats(label: str, values: list[float]):
    """打印统计信息"""
    if not values:
        return
    avg = statistics.mean(values)
    print(f"\n  {label} ({len(values)} 次测量):")
    print(f"    最小值: {min(values):.4f} 秒 ({min(values) * 1000:.2f} 毫秒)")
    print(f"    最大值: {max(values):.4f} 秒 ({max(values) * 1000:.2f} 毫秒)")
    print(f"    平均值: {avg:.4f} 秒 ({avg * 1000:.2f} 毫秒)")
    if len(values) > 1:
        print(f"    标准差: {statistics.stdev(values):.6f} 秒")
    print(f"    中位数: {statistics.median(values):.4f} 秒 ({statistics.median(values) * 1000:.2f} 毫秒)")
    print(f"    原始值: {[f'{v*1000:.3f}ms' for v in values]}")


def main():
    parser = argparse.ArgumentParser(description="启动性能测量脚本")
    parser.add_argument(
        "--mode", choices=["cold", "hot", "both", "verify_bg", "hot_real"],
        default="both",
        help="cold=冷启动, hot=热启动(小样本), both=两者, "
             "verify_bg=后台刷新验证, hot_real=真实规模热启动"
    )
    parser.add_argument(
        "--repeat", type=int, default=1,
        help="重复测量次数（默认 1，推荐 10）"
    )
    parser.add_argument(
        "--no-cleanup", action="store_true",
        help="不自动清理缓存目录（用于调试）"
    )
    args = parser.parse_args()

    print("=" * 70)
    print("  启动性能测量 — touful-vuln-search-mcp")
    print(f"  报告时间: 2026-07-16")
    print(f"  Python: {sys.version.split()[0]}")
    print("=" * 70)
    print()
    print("  测量说明:")
    print("  · 测量范围: app_lifespan 从进入到 yield 的耗时")
    print("  · 不含: 模块导入、工具注册、传输层绑定")
    print("  · yield 前仅有本地磁盘 I/O，无网络请求")
    print()

    cold_results: list[float] = []
    hot_results: list[float] = []

    if args.mode in ("cold", "both"):
        print("-" * 70)
        print("  [阶段 1] 冷启动测量（cache 目录不存在）")
        print("-" * 70)
        for i in range(args.repeat):
            elapsed = asyncio.run(run_cold_start())
            cold_results.append(elapsed)
            if args.repeat > 1:
                print(f"    第 {i+1}/{args.repeat} 次: {elapsed*1000:.3f} ms")
        print_stats("冷启动", cold_results)

    if args.mode in ("hot", "both"):
        print()
        print("-" * 70)
        print("  [阶段 2] 热启动测量（小样本缓存: 2 条 KEV + 2 行 CSV）")
        print("-" * 70)
        for i in range(args.repeat):
            elapsed = asyncio.run(run_hot_start_small())
            hot_results.append(elapsed)
            if args.repeat > 1:
                print(f"    第 {i+1}/{args.repeat} 次: {elapsed*1000:.3f} ms")
        print_stats("热启动（小样本）", hot_results)

    if args.mode == "hot_real":
        print()
        print("-" * 70)
        print("  [阶段 2] 热启动测量（真实规模缓存: ~1644 条 KEV）")
        print("-" * 70)
        for i in range(args.repeat):
            elapsed = asyncio.run(run_hot_start_real_scale())
            hot_results.append(elapsed)
            if args.repeat > 1:
                print(f"    第 {i+1}/{args.repeat} 次: {elapsed*1000:.3f} ms")
        print_stats("热启动（真实规模）", hot_results)

    if args.mode == "verify_bg":
        print()
        print("-" * 70)
        print("  [阶段 3] 后台刷新可观测性验证")
        print("-" * 70)
        # 使用冷启动触发后台刷新
        asyncio.run(run_cold_start_verify_bg())

    if not args.no_cleanup:
        _cleanup_cache()

    print()
    print("=" * 70)
    print("  测量完成")
    print("=" * 70)


async def run_cold_start_verify_bg():
    """冷启动并观察后台刷新日志"""
    import io
    from src.server import mcp, app_lifespan

    _log = logging.getLogger("src.server")
    _log.setLevel(logging.INFO)
    capture = io.StringIO()
    sh = logging.StreamHandler(capture)
    sh.setLevel(logging.INFO)
    sh.setFormatter(logging.Formatter("%(message)s"))
    _log.addHandler(sh)

    t0 = time.perf_counter()
    async with app_lifespan(mcp) as ctx:
        yield_elapsed = time.perf_counter() - t0
        print(f"  app_lifespan yield 耗时: {yield_elapsed*1000:.3f} ms")
        # yield 后等待 3 秒，让后台任务完成或打印日志
        await asyncio.sleep(3.0)
    total_elapsed = time.perf_counter() - t0

    _log.removeHandler(sh)

    logs = capture.getvalue()
    print(f"  总耗时 (含后台等待): {total_elapsed:.3f} 秒")
    print()
    print("  === 后台刷新日志 ===")
    for line in logs.splitlines():
        if line.strip():
            print(f"    {line}")
    print("  ===================")
    print()

    # 分析结果
    has_kev_done = "KEV 后台刷新完成" in logs
    has_exploit_done = "Exploit-DB 后台刷新完成" in logs
    has_kev_fail = "KEV 后台刷新失败" in logs
    has_exploit_fail = "Exploit-DB 后台刷新失败" in logs

    print("  后台刷新状态:")
    sys.stdout.flush()
    if has_kev_done:
        print("[OK] KEV 后台刷新成功")
    elif has_kev_fail:
        print("[WARN] KEV 后台刷新失败")
    else:
        print("[INFO] KEV 后台刷新未完成或被取消")
    if has_exploit_done:
        print("[OK] Exploit-DB 后台刷新成功")
    elif has_exploit_fail:
        print("[WARN] Exploit-DB 后台刷新失败")
    else:
        print("[INFO] Exploit-DB 后台刷新未完成或被取消")


if __name__ == "__main__":
    main()
