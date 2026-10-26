#!/usr/bin/env bash
# verify_wsl.sh の uv の判定（uv_verdict）の試験。通信しない。Test-Helpers.ps1 の Get-AuditUvVerdict と同じ入力で同じ答えになること
# 使い方: bash test_verify_wsl.sh（6.2 の手順0）
set -u
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# verify_wsl.sh は読み込むと通信を始めるので、判定に使う2つの関数だけを取り出す
src=$(sed -n '/^strip_url(){/,/; }$/p; /^uv_verdict(){/,/^}$/p' "$KIT/verify_wsl.sh")
eval "$src"
passed=0; failed=0
for f in strip_url uv_verdict; do
  if ! declare -F "$f" >/dev/null; then echo "FAIL: $f を verify_wsl.sh から取り出せない"; exit 1; fi
done
check(){ # 期待値 名前 出力
  local got; got=$(UV_NATIVE_TLS= uv_verdict "$3" "$uu"); got=${got%%$'\t'*}
  if [ "$got" = "$1" ]; then passed=$((passed+1)); else failed=$((failed+1)); echo "FAIL: $2 expected=[$1] actual=[$got]"; fi; }

uu=https://t.example/
nl=$'\n'; bar=$'\xe2\x94\x82'
get="DEBUG Sending fresh GET request for: https://t.example/emudhra-probe-x/$nl"
fail="error: Failed to fetch: \`https://t.example/emudhra-probe-x/\`$nl  Caused by: error sending request for url (https://t.example/emudhra-probe-x/)$nl  Caused by: client error (Connect)$nl  Caused by: invalid peer certificate: "
old="DEBUG uv 0.7.14 (e7f596711 2025-06-23)${nl}DEBUG No cache entry for: https://t.example/emudhra-probe-x/${nl}DEBUG No netrc file found$nl"
ct='error: Unsupported `Content-Type` "text/plain" for '
check REJECT 'uv: unknown issuer' "$get${fail}UnknownIssuer"
check REJECT 'uv: revoked (native TLS)' "$get${fail}Revoked"
# uv 0.13.5（UV_NATIVE_TLS なし、v2.11.6）: 自前の証明書一覧が経路を不信頼とする
check REJECT 'uv 0.13: distrusted (own root list)' "$get${fail}Other(OtherError(CertDistrusted))"
check UNKNOWN 'uv 0.13: another Other(...) reason' "$get${fail}Other(OtherError(SomethingElse))"
check UNKNOWN 'uv 0.13: Other(...) of another shape' "$get${fail}Other(Unexpected)"
check UNKNOWN 'uv 0.13: Other(OtherError(UnknownIssuer)) is not unwrapped' "$get${fail}Other(OtherError(UnknownIssuer))"
check UNKNOWN 'uv 0.13: Other(OtherError(Revoked)) is not unwrapped' "$get${fail}Other(OtherError(Revoked))"
check UNKNOWN 'uv 0.13: distrusted with a suffix' "$get${fail}Other(OtherError(CertDistrusted))_x"
check UNKNOWN 'uv 0.13: distrusted in another case' "$get${fail}Other(OtherError(certdistrusted))"
check REJECT 'uv 0.13: distrusted, then more lines' "$get${fail}Other(OtherError(CertDistrusted))$nl${nl}hint: x"
check UNKNOWN 'uv 0.13: distrusted and expired' "$get${fail}Other(OtherError(CertDistrusted))$nl  cause: invalid peer certificate: Expired"
check UNKNOWN 'uv: expired' "$get${fail}Expired"
check UNKNOWN 'uv: name' "$get${fail}NotValidForName"
# uv 0.11.4: 改行して罫線（U+2502）を挟んで URL を書く
wrapped="  Caused by: client error (Connect)$nl  Caused by: invalid peer certificate: UnknownIssuer$nl  x Request failed after 3 retries in 11.1s$nl  |-> Failed to fetch:$nl  $bar   \`https://t.example/emudhra-probe-x/\`$nl  |-> error sending request for url$nl  $bar   (https://t.example/emudhra-probe-x/)$nl  |-> client error (Connect)$nl  \\-> invalid peer certificate: UnknownIssuer"
check REJECT 'uv 0.11: wrapped URL, unknown issuer' "$get$wrapped"
check UNKNOWN 'uv 0.11: wrapped URL, expired' "$get${wrapped//UnknownIssuer/Expired}"
check UNKNOWN 'uv 0.11: wrapped, another URL' "$get${wrapped//(https:\/\/t.example\//(https://other.example/}"
# uv 0.12.22 on Linux: Failed to fetch は囲まず cause: の行、Content-Type は囲む
linux="error: Failed to fetch: https://t.example/emudhra-probe-x/$nl  cause: error sending request for url (https://t.example/emudhra-probe-x/)$nl  cause: client error (Connect)$nl  cause: invalid peer certificate: UnknownIssuer$nl${nl}hint: Consider enabling use of system TLS certificates with the \`--system-certs\` command-line flag"
check REJECT 'uv 0.12.22 (Linux): no backticks, unknown issuer' "$get$linux"
check UNKNOWN 'uv 0.12.22 (Linux): expired' "$get${linux//UnknownIssuer/Expired}"
check UNKNOWN 'uv 0.12.22 (Linux): another URL failed' "$get${linux//fetch: https:\/\/t.example\//fetch: https://other.example/}"
check ACCEPT 'uv 0.12.22 (Linux): target answered, URL in backticks' "$get$ct\`https://t.example/emudhra-probe-x/\`. Expected JSON or HTML."
check UNKNOWN 'uv 0.12.22 (Linux): another host answered, URL in backticks' "$get$ct\`https://other.example/emudhra-probe-x/\`. Expected JSON or HTML."
check ACCEPT 'uv: target answered' "${get}${ct}https://t.example/emudhra-probe-x/. Expected JSON or HTML."
check ACCEPT 'uv: 404 from the index' "$get  x No solution found when resolving dependencies:$nl  Because emudhra-probe-x was not found in the package registry and you require"
check UNKNOWN 'uv: not found without a request to the target' "  x No solution found when resolving dependencies:$nl  Because emudhra-probe-x was not found in the package registry and you require"
check ACCEPT 'uv (old): the target answered (no GET line)' "DEBUG uv 0.9.17$nl${ct}https://t.example/emudhra-probe-x/. Expected JSON or HTML."
check UNKNOWN 'uv: target and another index asked, generic not found' "${get}DEBUG Sending fresh GET request for: https://other.example/simple/emudhra-probe-x/$nl  Because emudhra-probe-x was not found in the package registry"
check UNKNOWN 'uv: another index asked, target answered' "${get}DEBUG Sending fresh GET request for: https://other.example/simple/emudhra-probe-x/$nl${ct}https://t.example/emudhra-probe-x/. Expected JSON or HTML."
check ACCEPT 'uv: other DEBUG lines do not count' "${get}DEBUG Using request timeout of 30s${nl}DEBUG Acquired lock for \`C:\\x\`$nl  Because emudhra-probe-x was not found in the package registry"
check UNKNOWN 'uv (old): not found after only "No cache entry"' "$old  x No solution found when resolving dependencies:$nl  Because emudhra-probe-x${nl}      was not found in the package registry and you require"
check UNKNOWN 'uv (old): target and another index, generic not found' "${old}DEBUG No cache entry for: https://other.example/simple/emudhra-probe-x/$nl  Because emudhra-probe-x was not found in the package registry"
check UNKNOWN 'uv (old): another host answered' "$old${ct}https://other.example/emudhra-probe-x/. Expected JSON or HTML."
check REJECT 'uv (old): unknown issuer' "$old${fail}UnknownIssuer"
check UNKNOWN 'uv: another index failed' "error: Failed to fetch: \`https://other.example/x/\`$nl  Caused by: invalid peer certificate: UnknownIssuer"
check UNKNOWN 'uv: DNS failure' "error: Failed to fetch: \`https://t.example/x/\`$nl  Caused by: dns error"
check UNKNOWN 'uv: redirect target rejected' "${get}error: Failed to fetch: \`https://t.example/emudhra-probe-x/\`$nl  Caused by: error sending request for url (https://redirected.example/x/)$nl  Caused by: invalid peer certificate: UnknownIssuer"
check UNKNOWN 'uv: target and another URL in the error' "$get${fail}UnknownIssuer$nl  Caused by: error sending request for url (https://redirected.example/x/)"
check UNKNOWN 'uv: redirect to a host that starts with the target name' "${get}error: Failed to fetch: \`https://t.example/emudhra-probe-x/\`$nl  Caused by: error sending request for url (https://t.example.other.example/pkg/)$nl  Caused by: invalid peer certificate: UnknownIssuer"
check UNKNOWN 'uv: same host, other port' "${get}error: Failed to fetch: \`https://t.example/emudhra-probe-x/\`$nl  Caused by: error sending request for url (https://t.example:8443/x/)$nl  Caused by: invalid peer certificate: UnknownIssuer"
if [ "$failed" -gt 0 ]; then echo "FAILED: $failed / $((passed+failed))"; exit 1; fi
echo "PASS: $passed uv cases; no network."
