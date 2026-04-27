#!/bin/bash

# Định nghĩa đường dẫn tương đối trong Github Workspace
DIR="rules"
BLOCK_OUT="./$DIR/blocklists.txt"
ALLOW_OUT="./$DIR/allowlists.txt"
BLOCK_TMP="/tmp/blocklists.tmp"
ALLOW_TMP="/tmp/allowlists.tmp"

# Tạo thư mục rules nếu chưa có
mkdir -p "./$DIR"
l1=`wc -l ./$DIR/blocklists.txt| awk {'pring $1'}`
l2=`wc -l ./$DIR/allowlists.txt| awk {'pring $1'}`
echo > ${BLOCK_OUT}
echo > ${ALLOW_OUT}
# Cleanup khi script exit
trap "rm -f $BLOCK_TMP $ALLOW_TMP; exit" INT TERM EXIT
echo "清空前当前黑名单${l1}条,白名单${l2}条"

extract_domains() {
  awk '{
    if (/^[[:space:]]*$/ || /^[!#]/) next
    line = tolower($0)
    sub(/^@@\|\|?/, "", line)
    sub(/^\|\|?/, "", line)
    sub(/\^.*/, "", line)
    sub(/[#!].*/, "", line)
    sub(/\/.*/, "", line)
    sub(/:.*/, "", line)
    sub(/^[0-9.]+[[:space:]]+/, "", line)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
    if (line ~ /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/ && !seen[line]++) print line
  }'
}

echo "Downloading and processing blocklists..."
curl -fsSL  --max-time 60 \
   -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -H "Accept: text/plain, */*;q=0.1" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Referer: https://google.com" \
https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt \
https://raw.githubusercontent.com/Cats-Team/AdRules/main/dns.txt \
https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AWAvenue_Ads_Rule.txt \
https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Mobile_Ads_filter.txt \
https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Chinese_filter.txt \
https://ghfast.top/https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/AdGuard_Base_filter.txt \
https://raw.gitcode.com/rssv/qy-Ads-Rule/raw/main/black.txt \
https://raw.githubusercontent.com/2771936993/HG/main/hg1.txt \
https://nginx-adg.iepose.cn/list/3318.txt \
| extract_domains > "$DIR/blocklists.txt"

echo "Downloading and processing allowlists..."
curl -fsSL  --max-time 60 \
  -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)" \
  -H "Accept: text/plain, */*;q=0.1" \
  -H "Accept-Language: en-US,en;q=0.9" \
  -H "Referer: https://google.com" \
https://cdn.jsdelivr.net/gh/Zisbusy/AdGuardHome-Rules@main/Rules/whitelist.txt \
https://nginx-adg.iepose.cn/list/3318_bai.txt \
| extract_domains > "$DIR/allowlists.txt"

# Di chuyển file tmp vào thư mục đích
#mv "$BLOCK_TMP" "$BLOCK_OUT"
#mv "$ALLOW_TMP" "$ALLOW_OUT"
l1=`wc -l ./$DIR/blocklists.txt| awk {'pring $1'}`
l2=`wc -l ./$DIR/allowlists.txt| awk {'pring $1'}`
echo "当前黑名单${l1}条,白名单${l2}条"
echo "Done. Files saved to $BLOCK_OUT and $ALLOW_OUT"
