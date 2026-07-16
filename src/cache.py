"""通用磁盘缓存工具

提供 JSON/文本缓存的读写、新鲜度检查与原子写入，
服务于 KEV 和 Exploit-DB 的本地磁盘缓存层。
"""

import json
import logging
import os
import re
import time
import uuid

from src.config import CACHE_DIR

logger = logging.getLogger(__name__)

# 仅允许字母、数字、下划线、短横线、点号作为安全文件名
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_\-\.]+$")


def _validate_filename(filename: str) -> None:
    """校验缓存文件名安全性，防止路径穿越攻击。

    Args:
        filename: 缓存文件名（不含路径）。

    Raises:
        ValueError: 文件名含非法字符或路径分隔符。
    """
    if not filename or not isinstance(filename, str):
        raise ValueError(f"缓存文件名必须为非空字符串，实际: {filename!r}")
    # 拒绝纯点号和双点号（路径穿越常用 payload）
    if filename in (".", ".."):
        raise ValueError(f"缓存文件名不允许为 '.' 或 '..': {filename!r}")
    if not _SAFE_FILENAME_RE.match(filename):
        raise ValueError(
            f"缓存文件名包含非法字符: {filename!r}，"
            "仅允许字母、数字、下划线、短横线、点号"
        )


def _ensure_cache_dir() -> None:
    """确保缓存目录存在（幂等操作）。"""
    os.makedirs(CACHE_DIR, exist_ok=True)


async def load_json_cache(filename: str):
    """从磁盘读取 JSON 缓存。

    Args:
        filename: 缓存文件名（纯文件名，如 "kev_catalog.json"）。

    Returns:
        解析后的 dict 或 list；文件不存在/损坏/JSON 解析失败时返回 None。
    """
    _validate_filename(filename)
    filepath = os.path.join(CACHE_DIR, filename)
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("JSON 缓存读取失败 %s: %s", filename, e)
        return None


async def save_json_cache(filename: str, data) -> None:
    """原子写入 JSON 缓存。

    先写入临时文件（同目录 .tmp 随机后缀），
    再通过 os.replace 原子替换为目标文件，防止读到半截文件。

    Args:
        filename: 缓存文件名（纯文件名）。
        data:  要写入的数据（dict 或 list）。

    Raises:
        ValueError: 文件名非法。
        OSError: 磁盘写入失败。
    """
    _validate_filename(filename)
    _ensure_cache_dir()
    tmp_name = f".{filename}.{uuid.uuid4().hex[:8]}.tmp"
    tmp_path = os.path.join(CACHE_DIR, tmp_name)
    target = os.path.join(CACHE_DIR, filename)
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp_path, target)
    except Exception:
        # 清理临时文件（尽力而为）
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


async def load_text_cache(filename: str) -> str | None:
    """从磁盘读取文本缓存（CSV 等纯文本格式）。

    Args:
        filename: 缓存文件名（纯文件名）。

    Returns:
        文件内容字符串；文件不存在或读取失败时返回 None。
    """
    _validate_filename(filename)
    filepath = os.path.join(CACHE_DIR, filename)
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return None
    except OSError as e:
        logger.warning("文本缓存读取失败 %s: %s", filename, e)
        return None


async def save_text_cache(filename: str, text: str) -> None:
    """原子写入文本缓存。

    机制同 save_json_cache，先写临时文件再 os.replace 原子替换。

    Args:
        filename: 缓存文件名（纯文件名）。
        text:    要写入的文本内容。

    Raises:
        ValueError: 文件名非法。
        OSError: 磁盘写入失败。
    """
    _validate_filename(filename)
    _ensure_cache_dir()
    tmp_name = f".{filename}.{uuid.uuid4().hex[:8]}.tmp"
    tmp_path = os.path.join(CACHE_DIR, tmp_name)
    target = os.path.join(CACHE_DIR, filename)
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp_path, target)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def get_cache_age_hours(filename: str) -> float | None:
    """获取缓存文件距今小时数。

    Args:
        filename: 缓存文件名（纯文件名）。

    Returns:
        距今小时数（float）；文件不存在返回 None。
    """
    _validate_filename(filename)
    filepath = os.path.join(CACHE_DIR, filename)
    try:
        mtime = os.path.getmtime(filepath)
        return (time.time() - mtime) / 3600.0
    except OSError:
        return None


def is_cache_fresh(filename: str, ttl_hours: int) -> bool:
    """检查缓存是否在有效期内。

    Args:
        filename:  缓存文件名（纯文件名）。
        ttl_hours: 缓存有效期（小时）。

    Returns:
        True 表示缓存存在且未过期，False 表示过期或不存在。
    """
    age = get_cache_age_hours(filename)
    if age is None:
        return False
    return age < ttl_hours
