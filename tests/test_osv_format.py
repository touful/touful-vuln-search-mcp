"""测试 _format_osv_vuln 函数的边界条件"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# 从 server.py 提取 _format_osv_vuln 函数
with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'src', 'server.py'), 'r', encoding='utf-8') as f:
    code = f.read()

func_start = code.index('def _format_osv_vuln')
lines = code[func_start:].split('\n')

func_lines = []
for line in lines:
    if line.startswith('def _format_osv_vuln') and func_lines:
        break
    if not func_lines and not line.startswith('def _format_osv_vuln'):
        continue
    func_lines.append(line.rstrip())
    if func_lines and line.strip() == '' and len(func_lines) > 3:
        # Check if next non-empty line is top-level
        remaining = lines[len(func_lines):]
        for rl in remaining:
            if rl.strip() and not rl.startswith(' ') and not rl.startswith('\t') and not rl.startswith('#'):
                break
        else:
            continue
        # Actually just collect until we hit another top-level def
        # Simpler: collect until empty line at top level
        pass

# Simpler approach: collect all lines until next top-level def/comment block
func_lines = []
in_func = False
for line in lines:
    if line.startswith('def _format_osv_vuln'):
        in_func = True
    if in_func:
        func_lines.append(line)
        # Stop at next top-level definition (non-indented, non-empty, non-comment, not "def _format_osv_vuln")
        if len(func_lines) > 1 and line.strip() == '':
            # Look ahead - is next non-empty line top-level?
            idx = lines.index(line)
            for future_line in lines[idx+1:]:
                if not future_line.strip():
                    continue
                if not future_line.startswith(' ') and not future_line.startswith('\t'):
                    # This is a top-level line, end of our function
                    if future_line.strip().startswith('#'):
                        continue  # comment blocks could be after function
                    in_func = False
                break
        if not in_func:
            break

# Actually let me just find the end by looking for the # ========== that follows
# The function is between _CVE_ID_PATTERN and # ========== 生命周期管理
func_end = None
for i, line in enumerate(lines):
    if i > 0 and line.strip().startswith('# ========== 生命周期管理'):
        func_end = i - 1
        break

# Get all function lines
func_lines = []
started = False
blank_count = 0
for i, line in enumerate(lines):
    if i > (func_end or 9999):
        break
    if line.startswith('def _format_osv_vuln'):
        started = True
    if started:
        func_lines.append(line)

print(f"Extracted {len(func_lines)} lines for _format_osv_vuln")

# Execute the function
exec('\n'.join(func_lines))

# Test 1: Normal vuln with all fields
print("=" * 60)
print("测试 1: 完整漏洞数据（所有字段都存在）")
test1 = {
    "id": "GHSA-29mw-wpgm-hmr9",
    "summary": "lodash 中存在原型污染漏洞",
    "details": "Lodash versions prior to 4.17.21 are vulnerable to prototype pollution via the defaultsDeep function.",
    "aliases": ["CVE-2020-28500"],
    "modified": "2025-09-29T21:12:31Z",
    "published": "2022-01-06T20:30:46Z",
    "references": [
        {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-29mw-wpgm-hmr9"},
        {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-28500"},
    ],
    "affected": [{
        "package": {"name": "lodash", "ecosystem": "npm", "purl": "pkg:npm/lodash"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
        "versions": [],
    }],
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"}],
    "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-1333"]},
}
r1 = _format_osv_vuln(test1)
print(r1)
assert "GHSA-29mw-wpgm-hmr9" in r1, "FAIL: 缺少 ID"
assert "CVE-2020-28500" in r1, "FAIL: 缺少别名"
assert "2022-01-06" in r1, "FAIL: 日期格式不对"
assert "2025-09-29" in r1, "FAIL: 修改日期格式不对"
assert "npm:lodash" in r1, "FAIL: 缺少包信息"
assert "4.17.21" in r1, "FAIL: 缺少修复版本"
assert "CWE-1333" in r1, "FAIL: 缺少 CWE"
assert "CVSS:3.1" in r1, "FAIL: 缺少 CVSS 评分"
print("[PASS] 测试 1 通过\n")

# Test 2: Empty aliases
print("=" * 60)
print("测试 2: aliases 为空列表")
test2 = {
    "id": "GHSA-xxxx-xxxx-xxxx",
    "summary": "测试漏洞",
    "details": "",
    "aliases": [],
    "modified": "2024-01-01T00:00:00Z",
    "published": "2023-06-15T00:00:00Z",
    "references": [],
    "affected": [],
    "severity": [],
    "database_specific": {},
}
r2 = _format_osv_vuln(test2)
print(r2)
assert "无" in r2 and "别名" in r2, "FAIL: 别名应显示无"
assert "无受影响包信息" in r2, "FAIL: 应显示无受影响包信息"
assert "无参考链接" in r2, "FAIL: 应显示无参考链接"
assert "N/A" in r2, "FAIL: 严重程度应为 N/A"
# 验证没有崩溃
print("[PASS] 测试 2 通过\n")

# Test 3: severity from database_specific, details > 500 chars
print("=" * 60)
print("测试 3: severity 从 database_specific 获取 & details 超长截断")
test3 = {
    "id": "GHSA-test-long",
    "summary": "超长详情测试",
    "details": "A" * 800,
    "aliases": [],
    "modified": "2025-01-01T00:00:00Z",
    "published": "2025-01-01T00:00:00Z",
    "references": [{"type": "WEB", "url": "https://example.com"}],
    "affected": [],
    "severity": [],
    "database_specific": {"severity": "MEDIUM", "cwe_ids": []},
}
r3 = _format_osv_vuln(test3)
print(r3)
assert "MEDIUM" in r3, "FAIL: 应从 database_specific 获取 severity"
assert "..." in r3, "FAIL: 超长 details 应截断"
assert len(r3.split("**详情**: ")[1]) <= 503, "FAIL: details 超过 500 字符"  # 500 + "..."
print("[PASS] 测试 3 通过\n")

# Test 4: No ranges but has versions
print("=" * 60)
print("测试 4: ranges 为空但有 versions（列出具体版本）")
test4 = {
    "id": "GHSA-test-versions",
    "summary": "版本列表测试",
    "details": "Test",
    "aliases": [],
    "modified": "2024-01-01T00:00:00Z",
    "published": "2024-01-01T00:00:00Z",
    "references": [],
    "affected": [{
        "package": {"name": "test-pkg", "ecosystem": "PyPI", "purl": "pkg:pypi/test-pkg"},
        "ranges": [],
        "versions": ["1.0.0", "1.0.1", "1.0.2"],
    }],
    "severity": [],
    "database_specific": {},
}
r4 = _format_osv_vuln(test4)
print(r4)
assert "1.0.0" in r4, "FAIL: 应显示具体版本"
assert "1.0.1" in r4, "FAIL: 应显示具体版本"
print("[PASS] 测试 4 通过\n")

# Test 5: Versions > 10
print("=" * 60)
print("测试 5: versions 超过 10 个应截断")
test5 = {
    "id": "GHSA-test-many-versions",
    "summary": "多版本测试",
    "details": "Test",
    "aliases": [],
    "modified": "2024-01-01T00:00:00Z",
    "published": "2024-01-01T00:00:00Z",
    "references": [],
    "affected": [{
        "package": {"name": "test-pkg", "ecosystem": "npm", "purl": "pkg:npm/test-pkg"},
        "ranges": [],
        "versions": [f"1.0.{i}" for i in range(15)],
    }],
    "severity": [],
    "database_specific": {},
}
r5 = _format_osv_vuln(test5)
print(r5)
assert "及更多" in r5, "FAIL: 超过 10 个版本应显示 '...及更多'"
print("[PASS] 测试 5 通过\n")

# Test 6: ECOSYSTEM range type (R-01 修复验证)
print("=" * 60)
print("测试 6: ECOSYSTEM 范围类型（如 PyPI 生态常用）")
test6 = {
    "id": "GHSA-test-ecosystem",
    "summary": "ECOSYSTEM 范围类型测试",
    "details": "Test",
    "aliases": [],
    "modified": "2024-01-01T00:00:00Z",
    "published": "2024-01-01T00:00:00Z",
    "references": [],
    "affected": [{
        "package": {"name": "requests", "ecosystem": "PyPI", "purl": "pkg:pypi/requests"},
        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.31.0"}]}],
        "versions": [],
    }],
    "severity": [],
    "database_specific": {},
}
r6 = _format_osv_vuln(test6)
print(r6)
assert ">= 0" in r6, "FAIL: ECOSYSTEM 范围应显示 introduced 版本"
assert "2.31.0" in r6, "FAIL: ECOSYSTEM 范围应显示 fixed 版本"
assert "版本范围未知" not in r6, "FAIL: ECOSYSTEM 范围不应被跳过"
print("[PASS] 测试 6 通过\n")

# Test 7: GIT range type (R-01 修复验证)
print("=" * 60)
print("测试 7: GIT 范围类型（Go 生态常用）")
test7 = {
    "id": "GHSA-test-git",
    "summary": "GIT 范围类型测试",
    "details": "Test",
    "aliases": [],
    "modified": "2024-01-01T00:00:00Z",
    "published": "2024-01-01T00:00:00Z",
    "references": [],
    "affected": [{
        "package": {"name": "golang.org/x/net", "ecosystem": "Go", "purl": "pkg:golang/golang.org/x/net"},
        "ranges": [{"type": "GIT", "events": [{"introduced": "0"}, {"fixed": "0.17.0"}]}],
        "versions": [],
    }],
    "severity": [],
    "database_specific": {},
}
r7 = _format_osv_vuln(test7)
print(r7)
assert ">= 0" in r7, "FAIL: GIT 范围应显示 introduced 版本"
assert "0.17.0" in r7, "FAIL: GIT 范围应显示 fixed 版本"
assert "版本范围未知" not in r7, "FAIL: GIT 范围不应被跳过"
print("[PASS] 测试 7 通过\n")

# Test 8: CVSS_V4 severity (R-03 修复验证)
print("=" * 60)
print("测试 8: CVSS_V4 严重程度评分")
test8 = {
    "id": "GHSA-test-cvssv4",
    "summary": "CVSS_V4 测试",
    "details": "Test",
    "aliases": [],
    "modified": "2024-01-01T00:00:00Z",
    "published": "2024-01-01T00:00:00Z",
    "references": [],
    "affected": [],
    "severity": [{"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}],
    "database_specific": {},
}
r8 = _format_osv_vuln(test8)
print(r8)
assert "CVSS:4.0" in r8, "FAIL: 应显示 CVSS_V4 评分"
print("[PASS] 测试 8 通过\n")

# Test 9: severity 列表存在但无匹配类型 → 回退到 database_specific (R-03 修复验证)
print("=" * 60)
print("测试 9: severity 列表有值但无 CVSS_V3/V4 → 回退到 database_specific")
test9 = {
    "id": "GHSA-test-fallback",
    "summary": "severity fallback 测试",
    "details": "Test",
    "aliases": [],
    "modified": "2024-01-01T00:00:00Z",
    "published": "2024-01-01T00:00:00Z",
    "references": [],
    "affected": [],
    "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}],
    "database_specific": {"severity": "CRITICAL", "cwe_ids": ["CWE-79"]},
}
r9 = _format_osv_vuln(test9)
print(r9)
assert "CRITICAL" in r9, "FAIL: 应回退到 database_specific.severity"
assert "CWE-79" in r9, "FAIL: 应显示 CWE"
print("[PASS] 测试 9 通过\n")

# Test 10: last_affected 事件 (R-04 修复验证)
print("=" * 60)
print("测试 10: last_affected 事件类型")
test10 = {
    "id": "GHSA-test-lastaffected",
    "summary": "last_affected 测试",
    "details": "Test",
    "aliases": [],
    "modified": "2024-01-01T00:00:00Z",
    "published": "2024-01-01T00:00:00Z",
    "references": [],
    "affected": [{
        "package": {"name": "test-lib", "ecosystem": "npm", "purl": "pkg:npm/test-lib"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"last_affected": "2.5.0"}]}],
        "versions": [],
    }],
    "severity": [],
    "database_specific": {},
}
r10 = _format_osv_vuln(test10)
print(r10)
assert "<= 2.5.0" in r10, "FAIL: 应显示 last_affected 版本"
assert ">= 1.0.0" in r10, "FAIL: 应显示 introduced 版本"
print("[PASS] 测试 10 通过\n")

# Test 11: limit 事件 (R-04 修复验证)
print("=" * 60)
print("测试 11: limit 事件类型")
test11 = {
    "id": "GHSA-test-limit",
    "summary": "limit 事件测试",
    "details": "Test",
    "aliases": [],
    "modified": "2024-01-01T00:00:00Z",
    "published": "2024-01-01T00:00:00Z",
    "references": [],
    "affected": [{
        "package": {"name": "test-lib2", "ecosystem": "Maven", "purl": "pkg:maven/test-lib2"},
        "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"limit": "3.0.0"}]}],
        "versions": [],
    }],
    "severity": [],
    "database_specific": {},
}
r11 = _format_osv_vuln(test11)
print(r11)
assert "< 3.0.0" in r11, "FAIL: 应显示 limit 版本"
assert ">= 0" in r11, "FAIL: 应显示 introduced 版本"
print("[PASS] 测试 11 通过\n")

print("=" * 60)
print("全部测试通过!")
