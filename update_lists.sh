#!/bin/bash
set -euo pipefail

DIR="rules"
BLOCK_OUT="./$DIR/blocklists.txt"
ALLOW_OUT="./$DIR/allowlists.txt"
BLOCK_TMP="/tmp/blocklists.tmp"
ALLOW_TMP="/tmp/allowlists.tmp"
ALLOW_FROM_BLOCK_TMP="/tmp/allow_from_block.tmp"

mkdir -p "./$DIR"
trap 'rm -f "$BLOCK_TMP" "$ALLOW_TMP" "$ALLOW_FROM_BLOCK_TMP"' INT TERM EXIT

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
    -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    -H "Accept: text/plain, _/_;q=0.1"
    -H "Accept-Language: en-US,en;q=0.9"
    -H "Referer: https://google.com"
)

# ============================================================
# 安全下载函数：校验 HTTP 状态码 + 内容是否像规则文件
# ============================================================
safe_curl() {
    local url="$1"
    local tmp_body
    tmp_body=$(mktemp /tmp/curl_body.XXXXXX)
    local http_code
    
    http_code=$(curl "${CURL_OPTS[@]}" \
        --write-out "%{http_code}" \
        --output "$tmp_body" \
        "$url" 2>/dev/null) || {
            rm -f "$tmp_body"
            return 1
        }
        
    if [[ ! "$http_code" =~ ^2 ]]; then
        echo "  [WARN] HTTP ${http_code}: $url" >&2
        rm -f "$tmp_body"
        return 1
    fi
    
    local size
    size=$(wc -c < "$tmp_body" | tr -d ' ')
    if [[ "$size" -lt 100 ]]; then
        echo "  [WARN] 内容过小(${size}字节，疑似空文件): $url" >&2
        rm -f "$tmp_body"
        return 1
    fi
    
    local first_line
    first_line=$(head -c 200 "$tmp_body" | tr '[:upper:]' '[:lower:]')
    if echo "$first_line" | grep -qE '<!doctype html|<html'; then
        echo "  [WARN] 返回 HTML 页面（疑似被重定向到登录/错误页）: $url" >&2
        rm -f "$tmp_body"
        return 1
    fi
    cat "$tmp_body"
    rm -f "$tmp_body"
    return 0
}

# ============================================================
# 提取规则函数
# ============================================================
extract_domains() {
    local mode="$1"
    awk -v mode="$mode" '
    function clean(s,    tmp) {
        tmp = s
        sub(/\^.*/, "", tmp)
        sub(/\$.*/, "", tmp)
        sub(/[#!].*/, "", tmp)
        sub(/\/.*/, "", tmp)
        sub(/:.*/, "", tmp)
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", tmp)
        return tmp
    }
    function is_valid(d) {
        return (d ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/)
    }
    {
        sub(/\r$/, "") # 核心修复: 去除 Windows 换行符，防止域名后接不可见字符
        if (/^[[:space:]]*$/) next
        if (/^[[:space:]]*[#!]/) next
        line = tolower($0)
        
        # 情形1：白名单规则 @@||domain^
        if (line ~ /^@@\|/) {
            sub(/^@@\|\|?/, "", line)
            domain = clean(line)
            if (is_valid(domain) && !seen_allow[domain]++)
                print "ALLOW:" domain
            next
        }
        
        # 情形2：黑名单规则 ||domain^
        if (line ~ /^\|/) {
            sub(/^\|\|?/, "", line)
            domain = clean(line)
            if (!is_valid(domain)) next
            if (mode == "block_src") {
                if (!seen_block[domain]++) print "BLOCK:" domain
            } else {
                if (!seen_allow[domain]++) print "ALLOW:" domain
            }
            next
        }
        
        # 情形3：hosts 格式
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
        
        # 情形4：纯域名
        if (line ~ /[*\[\]\/\\@]/) next
        if (line ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/) next
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
# 通用下载处理函数
# ============================================================
process_urls() {
    local mode="$1"
    local b_tmp="$2"
    local a_tmp="$3"
    shift 3
    local urls=("$@")
    
    for url in "${urls[@]}"; do
        echo "  -> $url"
        local content
        if content=$(safe_curl "$url"); then
            local block_count=0 allow_count=0
            while IFS= read -r tagged; do
                prefix="${tagged%%:*}"
                domain="${tagged#*:}"
                if [[ "$prefix" == "BLOCK" ]]; then
                    echo "$domain" >> "$b_tmp"
                    (( block_count++ )) || true
                elif [[ "$prefix" == "ALLOW" ]]; then
                    echo "$domain" >> "$a_tmp"
                    (( allow_count++ )) || true
                fi
            done < <(echo "$content" | extract_domains "$mode")
            echo "     ✓ 提取到 黑名单:${block_count} | 白名单:${allow_count}"
        else
            echo "  [报错] 下载失败: $url"
        fi
    done
}

# ============================================================
# 1. 黑名单源处理
# ============================================================
echo ""
echo "=========================================="
echo "开始下载并处理黑名单 blocklists..."
  #  "https://big.oisd.nl"
  #  "https://raw.githubusercontent.com/ppfeufer/adguard-filter-list/refs/heads/master/blocklist"
 #        "https://raw.githubusercontent.com/qq5460168/666/master/rules.txt"
BLOCK_URLS=(
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt"
    "https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt"
    "https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AWAvenue_Ads_Rule.txt"
    "https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt"
    "https://raw.githubusercontent.com/790953214/qy-Ads-Rule/main/black.txt"
    "https://raw.githubusercontent.com/afwfv/DD-AD/main/rule/DD-AD.txt"
    "https://raw.githubusercontent.com/2Gardon/SM-Ad-FuckU-hosts/master/SMAdHosts"
    "https://raw.githubusercontent.com/damengzhu/banad/main/jiekouAD.txt"
)

> "$BLOCK_TMP"
> "$ALLOW_FROM_BLOCK_TMP"

process_urls "block_src" "$BLOCK_TMP" "$ALLOW_FROM_BLOCK_TMP" "${BLOCK_URLS[@]}"
echo "追加黑名单"
cat ./rules/hei.txt >> $BLOCK_TMP

# ============================================================
# 2. 白名单源处理
# ============================================================
echo ""
echo "=========================================="
echo "开始下载并处理白名单 allowlists..."

ALLOW_URLS=(
    "https://raw.githubusercontent.com/Menghuibanxian/AdguardHome/main/White.txt"
    "https://cdn.jsdelivr.net/gh/Zisbusy/AdGuardHome-Rules@main/Rules/whitelist.txt"
    "https://raw.githubusercontent.com/juju-0211/AdGuardHome-/main/白名单.txt"
    "https://raw.githubusercontent.com/mphin/adguardhome_rules/main/Allowlist.txt"
    "https://raw.githubusercontent.com/Zisbusy/AdGuardHome-Rules/main/Rules/whitelist.txt"
)

> "$ALLOW_TMP"
process_urls "allow_src" "/dev/null" "$ALLOW_TMP" "${ALLOW_URLS[@]}"

echo "追加白名单"
cat ./rules/bai.txt >> $ALLOW_TMP


if [[ -s "$ALLOW_FROM_BLOCK_TMP" ]]; then
    echo "  -> 追加从黑名单源提取的 @@ 白名单 ($(wc -l < "$ALLOW_FROM_BLOCK_TMP" | tr -d ' ') 条)"
    cat "$ALLOW_FROM_BLOCK_TMP" >> "$ALLOW_TMP"
fi

# ============================================================
# 3. 精确去重与交叉冲突剔除
# ============================================================
echo ""
echo "正在进行去重与交叉对比隔离..."

# 先对两个文件进行完全精确的去重
sort -u "$BLOCK_TMP" -o "$BLOCK_TMP"
sort -u "$ALLOW_TMP" -o "$ALLOW_TMP"

# 如果一个域名同时出现在黑白名单里，直接把它从黑名单删了（节约Cloudflare内存）
# 使用 comm -23 提取在 黑名单(1) 有且不在 白名单(2) 的内容
mv "$BLOCK_TMP" "$BLOCK_TMP.uncleaned"
comm -23 "$BLOCK_TMP.uncleaned" "$ALLOW_TMP" > "$BLOCK_TMP"
rm -f "$BLOCK_TMP.uncleaned"


# ============================================================
# 4. 对比是否有变化
# ============================================================
CHANGED=false
if ! diff -q "$BLOCK_TMP" "$BLOCK_OUT" > /dev/null 2>&1; then
    mv "$BLOCK_TMP" "$BLOCK_OUT"
    echo "✅ 黑名单已更新"
    CHANGED=true
else
    echo "⏭️  黑名单无变化，跳过更新"
fi

if ! diff -q "$ALLOW_TMP" "$ALLOW_OUT" > /dev/null 2>&1; then
    mv "$ALLOW_TMP" "$ALLOW_OUT"
    echo "✅ 白名单已更新"
    CHANGED=true
else
    echo "⏭️  白名单无变化，跳过更新"
fi

# ============================================================
# 5. 最终统计
# ============================================================
l1=$(count_lines "$BLOCK_OUT")
l2=$(count_lines "$ALLOW_OUT")
echo ""
echo "=========================================="
echo "🎯 最终处理结果："
echo "黑名单：${l1} 条 -> $BLOCK_OUT"
echo "白名单：${l2} 条 -> $ALLOW_OUT"
if [[ "$CHANGED" == "true" ]]; then
    echo "📦 内容有变化，准备提交 Push"
else
    echo "🔕 内容无变化"
fi
echo "=========================================="
