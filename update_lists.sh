#!/bin/bash
set -euo pipefail

# ============================================================
# 配置
# ============================================================
DIR="rules"
BLOCK_OUT="./$DIR/blocklists.txt"
ALLOW_OUT="./$DIR/allowlists.txt"

# 创建输出目录
mkdir -p "./$DIR"

# ============================================================
# 工具函数
# ============================================================
count_lines() {
    local file="$1"
    if [[ -f "$file" ]]; then
        wc -l < "$file" | tr -d ' '
    else
        echo "0"
    fi
}

# Cleanup on exit
trap 'echo "Script interrupted."; exit 1' INT TERM

# ============================================================
# 统计清空前数量
# ============================================================
l1=$(count_lines "$BLOCK_OUT")
l2=$(count_lines "$ALLOW_OUT")
echo "清空前：黑名单 ${l1} 条，白名单 ${l2} 条"

# 清空文件
> "$BLOCK_OUT"
> "$ALLOW_OUT"

# ============================================================
# 域名提取函数
# ============================================================
extract_domains() {
    awk '{
        # 跳过空行和注释
        if (/^[[:space:]]*$/ || /^[!#]/) next

        line = tolower($0)

        # 处理白名单规则 (@@||) 和黑名单规则 (||)
        sub(/^@@\|\|?/, "", line)
        sub(/^\|\|?/, "", line)

        # 去除修饰符和注释
        sub(/\^.*/, "", line)
        sub(/[#!].*/, "", line)
        sub(/\/.*/, "", line)
        sub(/:.*/, "", line)

        # 处理 hosts 格式 (如 0.0.0.0 domain.com)
        sub(/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+/, "", line)

        # 去除首尾空白
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)

        # 验证域名格式并去重
        if (line ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/ \
            && !seen[line]++) {
            print line
        }
    }'
}

# ============================================================
# 通用 curl 参数
# ============================================================
CURL_OPTS=(
    -fsSL
    --max-time 60
    --retry 3
    --retry-delay 5
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    -H "Accept: text/plain, */*;q=0.1"
    -H "Accept-Language: en-US,en;q=0.9"
    -H "Referer: https://google.com"
)

# ============================================================
# 下载黑名单
# ============================================================
echo ""
echo "=========================================="
echo "Downloading blocklists..."
echo "=========================================="

BLOCK_URLS=(
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AWAvenue_Ads_Rule.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Mobile_Ads_filter.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Chinese_filter.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Base_filter.txt"
    "https://raw.gitcode.com/rssv/qy-Ads-Rule/raw/main/black.txt"
    "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt"
    "https://nginx-adg.iepose.cn/list/3318.txt"
)

# 逐个下载，失败跳过而不中断整体
{
    for url in "${BLOCK_URLS[@]}"; do
        echo "  -> Fetching: $url" >&2
        curl "${CURL_OPTS[@]}" "$url" 2>/dev/null || echo "  [WARN] Failed: $url" >&2
    done
} | extract_domains > "$BLOCK_OUT"

l1=$(count_lines "$BLOCK_OUT")
echo "黑名单下载完成：${l1} 条"

# ============================================================
# 下载白名单
# ============================================================
echo ""
echo "=========================================="
echo "Downloading allowlists..."
echo "=========================================="

ALLOW_URLS=(
    "https://cdn.jsdelivr.net/gh/Zisbusy/AdGuardHome-Rules@main/Rules/whitelist.txt"
    "https://nginx-adg.iepose.cn/list/3318_bai.txt"
)

{
    for url in "${ALLOW_URLS[@]}"; do
        echo "  -> Fetching: $url" >&2
        curl "${CURL_OPTS[@]}" "$url" 2>/dev/null || echo "  [WARN] Failed: $url" >&2
    done
} | extract_domains > "$ALLOW_OUT"

l2=$(count_lines "$ALLOW_OUT")
echo "白名单下载完成：${l2} 条"

# ============================================================
# 最终统计
# ============================================================
echo ""
echo "=========================================="
echo "✅ 完成！"
echo "   黑名单：${l1} 条 -> $BLOCK_OUT"
echo "   白名单：${l2} 条 -> $ALLOW_OUT"
echo "=========================================="
