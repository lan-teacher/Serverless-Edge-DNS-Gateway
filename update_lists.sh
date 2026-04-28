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

# ============================================================
# extract_domains <mode>
#
# mode=block_src：来源是黑名单列表
#   - @@||domain^ → 提取到白名单(stdout 行首加 ALLOW:)
#   - ||domain^   → 提取到黑名单
#   - 纯域名/hosts → 提取到黑名单
#   - 其他复杂规则（含 * / [] 等）→ 丢弃
#
# mode=allow_src：来源是白名单列表
#   - @@||domain^ → 提取到白名单
#   - ||domain^   → 提取到白名单（黑名单写法出现在白名单文件里，视为白名单意图）
#   - 纯域名/hosts → 提取到白名单
#   - 其他复杂规则 → 丢弃
#
# 输出格式：
#   BLOCK:<domain>   → 进黑名单
#   ALLOW:<domain>   → 进白名单
# ============================================================
extract_domains() {
    local mode="$1"   # block_src | allow_src
    awk -v mode="$mode" '
    function clean(s,    tmp) {
        tmp = s
        # 去掉修饰符（^ 及其后所有内容）
        sub(/\^.*/, "", tmp)
        # 去掉 $ 修饰符
        sub(/\$.*/, "", tmp)
        # 去掉行内注释
        sub(/[#!].*/, "", tmp)
        # 去掉路径
        sub(/\/.*/, "", tmp)
        # 去掉端口
        sub(/:.*/, "", tmp)
        # 去除首尾空白
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", tmp)
        return tmp
    }
    function is_valid(d) {
        # 合法域名：仅字母数字和连字符，至少两级，无通配符
        return (d ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/)
    }
    {
        # 跳过空行
        if (/^[[:space:]]*$/) next
        # 跳过纯注释行
        if (/^[[:space:]]*[#!]/) next

        line = tolower($0)

        # ── 情形1：白名单规则 @@||domain^ 或 @@|domain
        if (line ~ /^@@\|/) {
            sub(/^@@\|\|?/, "", line)
            domain = clean(line)
            if (is_valid(domain) && !seen_allow[domain]++)
                print "ALLOW:" domain
            next
        }

        # ── 情形2：黑名单规则 ||domain^ 或 |domain
        if (line ~ /^\|/) {
            sub(/^\|\|?/, "", line)
            domain = clean(line)
            if (!is_valid(domain)) next
            if (mode == "block_src") {
                if (!seen_block[domain]++) print "BLOCK:" domain
            } else {
                # 白名单文件里的 || 规则 → 视为白名单意图
                if (!seen_allow[domain]++) print "ALLOW:" domain
            }
            next
        }

        # ── 情形3：hosts 格式（0.0.0.0 domain 或 127.0.0.1 domain）
        if (line ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]/) {
            sub(/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]+/, "", line)
            domain = clean(line)
            if (!is_valid(domain)) next
            if (mode == "block_src") {
                if (!seen_block[domain]++) print "BLOCK:" domain
            } else {
                if (!seen_allow[domain]++) print "ALLOW:" domain
            }
            next
        }

        # ── 情形4：纯域名（无前缀）
        # 跳过包含通配符、路径、IP等复杂规则
        if (line ~ /[*\[\]\/\\@]/) next
        if (line ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next  # 纯IP跳过

        domain = clean(line)
        if (!is_valid(domain)) next

        if (mode == "block_src") {
            if (!seen_block[domain]++) print "BLOCK:" domain
        } else {
            if (!seen_allow[domain]++) print "ALLOW:" domain
        }
    }
    '
}

# ============================================================
# 下载黑名单源
# ============================================================
echo ""
echo "=========================================="
echo "Downloading blocklists..."

BLOCK_URLS=(
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AWAvenue_Ads_Rule.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Mobile_Ads_filter.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Chinese_filter.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Base_filter.txt"
    "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt"
)

# 临时存放从黑名单源里提取出来的白名单条目
ALLOW_FROM_BLOCK_TMP="/tmp/allow_from_block.tmp"
> "$ALLOW_FROM_BLOCK_TMP"

> "$BLOCK_TMP"

for url in "${BLOCK_URLS[@]}"; do
    echo "  -> $url"
    content=$(curl "${CURL_OPTS[@]}" "$url" 2>/dev/null) || { echo "  [WARN] Failed: $url"; continue; }
    echo "$content" | extract_domains "block_src" | while IFS= read -r tagged; do
        prefix="${tagged%%:*}"
        domain="${tagged#*:}"
        if [[ "$prefix" == "BLOCK" ]]; then
            echo "$domain"
        elif [[ "$prefix" == "ALLOW" ]]; then
            # @@规则写入白名单暂存
            echo "$domain" >> "$ALLOW_FROM_BLOCK_TMP"
        fi
    done >> "$BLOCK_TMP"
done

# 追加自定义黑名单
if [[ -f ./rules/hei.txt ]]; then
    echo "  -> ./rules/hei.txt (custom)"
    cat ./rules/hei.txt | extract_domains "block_src" | grep "^BLOCK:" | sed 's/^BLOCK://' >> "$BLOCK_TMP"
fi

# ============================================================
# 下载白名单源
# ============================================================
echo ""
echo "Downloading allowlists..."

ALLOW_URLS=(
    "https://raw.githubusercontent.com/Menghuibanxian/AdguardHome/main/White.txt"
    "https://cdn.jsdelivr.net/gh/Zisbusy/AdGuardHome-Rules@main/Rules/whitelist.txt"
    "https://raw.githubusercontent.com/juju-0211/AdGuardHome-/main/%E7%99%BD%E5%90%8D%E5%8D5.txt"
    "https://raw.githubusercontent.com/mphin/adguardhome_rules/main/Allowlist.txt"
    "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/whitelist.txt"
)

> "$ALLOW_TMP"

for url in "${ALLOW_URLS[@]}"; do
    echo "  -> $url"
    content=$(curl "${CURL_OPTS[@]}" "$url" 2>/dev/null) || { echo "  [WARN] Failed: $url"; continue; }
    echo "$content" | extract_domains "allow_src" | sed 's/^ALLOW://' >> "$ALLOW_TMP"
done

# 追加自定义白名单
if [[ -f ./rules/bai.txt ]]; then
    echo "  -> ./rules/bai.txt (custom)"
    cat ./rules/bai.txt | extract_domains "allow_src" | sed 's/^ALLOW://' >> "$ALLOW_TMP"
fi

# 追加从黑名单源里提取的 @@ 白名单
if [[ -s "$ALLOW_FROM_BLOCK_TMP" ]]; then
    echo "  -> 合并黑名单源中提取的 @@ 白名单 ($(wc -l < "$ALLOW_FROM_BLOCK_TMP") 条)"
    cat "$ALLOW_FROM_BLOCK_TMP" >> "$ALLOW_TMP"
fi

rm -f "$ALLOW_FROM_BLOCK_TMP"

# ============================================================
# 去重排序
# ============================================================
echo ""
echo "去重排序中..."
sort -u "$BLOCK_TMP" -o "$BLOCK_TMP"
sort -u "$ALLOW_TMP" -o "$ALLOW_TMP"

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
