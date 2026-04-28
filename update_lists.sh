#!/bin/bash
set -euo pipefail

DIR="rules"
BLOCK_OUT="./$DIR/blocklists.txt"
ALLOW_OUT="./$DIR/allowlists.txt"
BLOCK_TMP="/tmp/blocklists.tmp"
ALLOW_TMP="/tmp/allowlists.tmp"

mkdir -p "./$DIR"

trap 'rm -f "$BLOCK_TMP" "$ALLOW_TMP"' INT TERM EXIT

count_lines() {
    [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo "0"
}

# 统计旧数据
l1=$(count_lines "$BLOCK_OUT")
l2=$(count_lines "$ALLOW_OUT")
echo "清空前：黑名单 ${l1} 条，白名单 ${l2} 条"

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
extract_domains() {
    local mode="${1:-block}"
    awk -v mode="$mode" '{
        if (/^[[:space:]]*$/ || /^[!#]/) next
        line = tolower($0)

        # 判断是否是白名单规则 (@@开头)
        is_allow = (line ~ /^@@/)

        # 黑名单模式：跳过 @@ 白名单规则
        if (mode == "block" && is_allow) next

        # 白名单模式：跳过非 @@ 规则（黑名单语法不放入白名单）
        # 如果你希望白名单文件里的普通域名也保留，注释掉下面这行
        if (mode == "allow" && !is_allow) next

        # 去掉前缀 @@|| @@| || |
        sub(/^@@\|\|?/, "", line)
        sub(/^\|\|?/, "", line)

        # 去掉修饰符（^ 及其后面所有内容，包括 $important 等）
        sub(/\^.*/, "", line)
        sub(/\$.*/, "", line)   # ← 新增：处理没有 ^ 直接跟 $ 的情况
        sub(/[#!].*/, "", line)
        sub(/\/.*/, "", line)
        sub(/:.*/, "", line)

        # 处理 hosts 格式
        sub(/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+/, "", line)

        # 去除首尾空白
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)

        # 验证域名格式并去重
        if (line ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/ \
            && !seen[line]++) print line
    }'
}

# ============================================================
# 下载黑名单 → 写入临时文件
# ============================================================
echo "Downloading blocklists..."
BLOCK_URLS=(
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AWAvenue_Ads_Rule.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Mobile_Ads_filter.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Chinese_filter.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Base_filter.txt"
    "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt"
    # "https://nginx-adg.iepose.cn/list/3318.txt"
)

{
    for url in "${BLOCK_URLS[@]}"; do
        echo "  -> $url" >&2
        curl "${CURL_OPTS[@]}" "$url" 2>/dev/null \
            || echo "  [WARN] Failed: $url" >&2
    done
} | extract_domains  "block"  > "$BLOCK_TMP"  # ← 写临时文件
cat ./rules/hei.txt >> "$BLOCK_TMP" # 把自定义的黑名单加进去
# ============================================================
# 下载白名单 → 写入临时文件
# ============================================================
echo "Downloading allowlists..."
ALLOW_URLS=(
   "https://mirror.ghproxy.com/https://raw.githubusercontent.com/BlueSkyXN/AdGuardHomeRules/master/ok.txt"
    "https://cdn.jsdelivr.net/gh/Zisbusy/AdGuardHome-Rules@main/Rules/whitelist.txt"
    # "https://nginx-adg.iepose.cn/list/3318_bai.txt"
    "https://raw.githubusercontent.com/juju-0211/AdGuardHome-/main/%E7%99%BD%E5%90%8D%E5%8D%95.txt"
    "https://raw.githubusercontent.com/mphin/adguardhome_rules/main/Allowlist.txt"
    "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/whitelist.txt"
    
)

{
    for url in "${ALLOW_URLS[@]}"; do
        echo "  -> $url" >&2
        curl "${CURL_OPTS[@]}" "$url" 2>/dev/null \
            || echo "  [WARN] Failed: $url" >&2
    done
} | extract_domains "allow"  > "$ALLOW_TMP"  # ← 写临时文件
cat ./rules/bai.txt >> "$ALLOW_TMP"

# ============================================================
# 对比是否有变化，有变化才替换
# ============================================================
CHANGED=false

if ! diff -q "$BLOCK_TMP" "$BLOCK_OUT" > /dev/null 2>&1; then
    mv "$BLOCK_TMP" "$BLOCK_OUT"
    echo "✅ 黑名单已更新"
    CHANGED=true
else
    echo "⏭️  黑名单无变化，跳过"
fi

if ! diff -q "$ALLOW_TMP" "$ALLOW_OUT" > /dev/null 2>&1; then
    mv "$ALLOW_TMP" "$ALLOW_OUT"
    echo "✅ 白名单已更新"
    CHANGED=true
else
    echo "⏭️  白名单无变化，跳过"
fi

# ============================================================
# 输出最终统计
# ============================================================
l1=$(count_lines "$BLOCK_OUT")
l2=$(count_lines "$ALLOW_OUT")

echo ""
echo "=========================================="
echo "黑名单：${l1} 条 -> $BLOCK_OUT"
echo "白名单：${l2} 条 -> $ALLOW_OUT"

if [[ "$CHANGED" == "true" ]]; then
    echo "📦 内容有变化，将触发 Push"
else
    echo "🔕 内容无变化，不会触发 Push"
fi
echo "=========================================="
