#!/usr/bin/env bash
# eMudhra 検証（WSL / Linux 側）。外部 HTTPS 通信のみ。インストール・設定変更はしない。
# 使い方: bash verify_wsl.sh [--known-tls-inspection]
# 前提: 3.3 の棚卸し（~/emudhra-audit/venv-inventory.tsv, conda-prefixes.txt）が完了していること
set -u
KIT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out=~/emudhra-audit; mkdir -p "$out"
INSPECT=no; [ "${1:-}" = "--known-tls-inspection" ] && INSPECT=yes

CTRL_URL=https://www.google.com/
T1=https://dv-g3b-emudhra.we-have-a-problem.com/
T2=https://dv-g3b-aaa-emudhra.we-have-a-problem.com/
CTRL=CONTROL                     # 集計上の対照ラベル（全ツール共通）
rows="$out/verify-wsl.tsv"; : > "$rows"
SYSPY=$(command -v python3) || { echo "python3 が無いので集計できません" >&2; exit 1; }

# TLS 検査プロキシの自動検出: 対照サイトの証明書発行者が Google Trust Services でなければ、経路上で証明書が差し替えられている
# （プロキシの CA を信頼している端末では対照が通り、テストホストだけ失敗するので「偽の FIXED」になる）
ctrl_issuer=$("$SYSPY" - <<'PY' 2>/dev/null
import socket, ssl
ctx = ssl.create_default_context()
try:
    with socket.create_connection(('www.google.com', 443), timeout=15) as s:
        with ctx.wrap_socket(s, server_hostname='www.google.com') as t:
            print(dict(x[0] for x in t.getpeercert()['issuer']).get('organizationName', '?'))
except Exception as e:
    print('ERROR:' + type(e).__name__)
PY
)
echo "対照サイトの証明書発行者: ${ctrl_issuer:-?}"
case "$ctrl_issuer" in
  "Google Trust Services"*) ;;
  *) echo "警告: 証明書が差し替えられている可能性（TLS 検査プロキシ等）。全件 UNKNOWN 扱いにします" >&2; INSPECT=yes ;;
esac

# native: WSL 側の実体があるときだけ真。PATH の先、またはリンクを解決した先が /mnt/ 配下（Windows 側の node.exe や npm など）なら
# Windows 側で判定するので、ここでは測らずに理由を表示する（例: Windows 側の Node に入っている npm）。
# Linux 側のラッパースクリプトが中で Windows 側を呼ぶ場合は見分けられない（3.3 の一覧で目で確認する）
native(){ local p r; p=$(command -v "$1") || return 1; r=$(readlink -f -- "$p" 2>/dev/null) || r=$p
  case "$p|$r" in /mnt/*|*"|/mnt/"*) echo "skip $1: Windows 側の実体 ($p -> $r)。Windows 側の 6.1 で判定" >&2; return 1 ;; esac; }

strip_url(){ # 診断文から要求 URL とホスト名を除く（revoked.badssl.com のようにホスト名に判定語が入ることがある）
  local text=$1 url=$2 host; host=${url#https://}; host=${host%%/*}
  text=${text//"$url"/<url>}; text=${text//"${url%/}"/<url>}; printf '%s' "${text//"$host"/<host>}"; }

rec(){ # tool target verdict detail（verdict は ACCEPT/REJECT/UNKNOWN/NONE のいずれか）
  local v="$3"; [ "$INSPECT" = yes ] && v=UNKNOWN
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$v" "$(printf '%s' "$4" | tr '\t\r\n' '   ' | head -c 200)" >> "$rows"; }

# ---------- curl ----------
# rc 60 かつ「発行者不明 / 自己署名チェーン / 失効」のみ REJECT。期限切れ・名前不一致は先に除外。47 はリダイレクト上限 = TLS 成立
curl_one(){ local label=$1 url=$2 e rc
  e=$(curl -sS --max-time 15 --max-redirs 0 -o /dev/null "$url" 2>&1 </dev/null); rc=$?; e=$(strip_url "$e" "$url")
  if [ $rc -eq 0 ] || [ $rc -eq 47 ]; then rec curl "$label" ACCEPT "rc=$rc"
  elif [ $rc -eq 60 ] && printf '%s' "$e" | grep -qiE 'expired|not yet valid|does not match|subject alternative name|no alternative'; then rec curl "$label" UNKNOWN "rc=60 not related: $e"
  elif [ $rc -eq 60 ] && printf '%s' "$e" | grep -qiE 'unable to get local issuer|self[- ]signed certificate in certificate chain|revoked'; then rec curl "$label" REJECT "rc=60 $e"
  else rec curl "$label" UNKNOWN "rc=$rc $e"; fi; }
if native curl; then curl_one "$CTRL" "$CTRL_URL"; curl_one "$T1" "$T1"; curl_one "$T2" "$T2"; fi

# ---------- wget ----------（rc 5 = SSL 検証失敗、8 = サーバーエラー応答 = TLS 成立）
wget_one(){ local label=$1 url=$2 e rc
  e=$(wget -T 15 --max-redirect=0 -O /dev/null "$url" 2>&1 </dev/null); rc=$?; e=$(strip_url "$e" "$url")
  if [ $rc -eq 0 ] || [ $rc -eq 8 ]; then rec wget "$label" ACCEPT "rc=$rc"
  elif [ $rc -eq 5 ] && printf '%s' "$e" | grep -qiE 'expired|not yet|does not match'; then rec wget "$label" UNKNOWN "rc=5 not related"
  elif [ $rc -eq 5 ] && printf '%s' "$e" | grep -qiE 'unable to locally verify the issuer|issuer is not trusted|self-signed|revoked'; then rec wget "$label" REJECT "rc=5"
  else rec wget "$label" UNKNOWN "rc=$rc $(printf '%s' "$e" | tail -1)"; fi; }
if native wget; then wget_one "$CTRL" "$CTRL_URL"; wget_one "$T1" "$T1"; wget_one "$T2" "$T2"; fi

# ---------- Git（テスト先は Git リポジトリではない。TLS が通れば HTTP レベルの失敗 = ACCEPT） ----------
# git_tls_reason: GnuTLS 版 git（Ubuntu）は理由を言わない「server certificate verification failed」しか出さない。
# git と同じ条件に近い場合だけ openssl で理由を確かめる:
# - git が実際に読んだ CA の場所を使う（エラーの CAfile、または GIT_CURL_VERBOSE の「found N certificates in <場所>」。分からなければ確かめない）。
#   場所がディレクトリなら、中のファイルをすべて1つにまとめて -CAfile で渡す（openssl の -CApath はハッシュ名のリンクで探すので、
#   リンクが欠けていると GnuTLS が読んだ証明書と食い違う）
# - プロキシ設定が無い（あれば openssl の直結では git の経路を再現できない）
# openssl の verify error が「発行者不明(2,20) / 自己署名チェーン(19) / 失効(23)」だけのときに REJECT。
# 期限切れ・名前不一致など他の番号が1つでも出たら UNKNOWN
git_tls_reason(){ local t=$1 e=$2 ca h proxy o orc nums n final bundle f ctrl crc ok
  proxy="$(git config --get-urlmatch http.proxy "$t" 2>/dev/null)${https_proxy:-}${HTTPS_PROXY:-}${all_proxy:-}${ALL_PROXY:-}"
  if [ -n "$proxy" ]; then rec git "$t" UNKNOWN "gnutls: verification failed; proxy configured, openssl cross-check skipped"; return; fi
  command -v openssl >/dev/null || { rec git "$t" UNKNOWN "gnutls: verification failed; openssl not found"; return; }
  ca=$(printf '%s' "$e" | sed -n 's/.*CAfile: \([^ ]*\).*/\1/p' | head -1)
  if [ -z "$ca" ] || [ "$ca" = none ] || [ ! -e "$ca" ]; then
    ca=$(GIT_CURL_VERBOSE=1 GIT_TERMINAL_PROMPT=0 timeout 60 git -c http.followRedirects=false ls-remote "$t" 2>&1 </dev/null \
         | sed -n 's/.*found [0-9]* certificates in \([^ ]*\).*/\1/p' | head -1)
  fi
  if [ ! -f "$ca" ] && [ ! -d "$ca" ]; then rec git "$t" UNKNOWN "gnutls: verification failed; CA location not reported"; return; fi
  bundle=$(mktemp) || { rec git "$t" UNKNOWN "gnutls: verification failed; mktemp failed"; return; }
  # 1ファイルでも読めなければ集合が欠けるので確かめない（欠けると本来の理由が 20 に変わり、偽の REJECT になりうる）
  ok=yes
  if [ -f "$ca" ]; then cat -- "$ca" > "$bundle" || ok=no
  else for f in "$ca"/*; do if [ -f "$f" ]; then { cat -- "$f" && echo; } >> "$bundle" || { ok=no; break; }; fi; done; fi   # -f はリンク先を見る
  if [ "$ok" != yes ] || [ ! -s "$bundle" ]; then rm -f "$bundle"; rec git "$t" UNKNOWN "gnutls: verification failed; could not read every file in $ca"; return; fi
  h=${t#https://}; h=${h%%/*}
  o=$(timeout 20 openssl s_client -connect "$h:443" -servername "$h" -verify_hostname "$h" -CAfile "$bundle" -no-CApath -no-CAstore </dev/null 2>&1); orc=$?
  # 対照: 同じまとめファイルで対照サイトが検証に通ること（まとめ方が壊れていると全ホストが 20 になり、偽の REJECT になる）
  ctrl=$(timeout 20 openssl s_client -connect www.google.com:443 -servername www.google.com -verify_hostname www.google.com -CAfile "$bundle" -no-CApath -no-CAstore </dev/null 2>&1); crc=$?
  rm -f "$bundle"
  ctrl=$(printf '%s\n' "$ctrl" | grep -m1 'Verify return code' | sed 's/^ *//')
  if [ $crc -ne 0 ]; then rec git "$t" UNKNOWN "gnutls: verification failed; openssl control incomplete (rc=$crc)"; return; fi
  case "$ctrl" in "Verify return code: 0 "*) ;; *) rec git "$t" UNKNOWN "gnutls: verification failed; openssl control with same CA failed: ${ctrl:-no result}"; return ;; esac
  nums=$(printf '%s\n' "$o" | grep -oE 'verify error:num=[0-9]+' | cut -d= -f2 | sort -un | tr '\n' ' ')
  final=$(printf '%s\n' "$o" | grep -m1 'Verify return code' | sed 's/^ *//')
  # 検証を最後まで終えた結果だけを使う（タイムアウト・異常終了・最終結果なしは途中までの結果なので UNKNOWN）
  if [ $orc -ne 0 ] || [ -z "$final" ]; then rec git "$t" UNKNOWN "gnutls: verification failed; openssl incomplete (rc=$orc) errors=[$nums]"; return; fi
  if [ -z "$nums" ]; then rec git "$t" UNKNOWN "gnutls: verification failed; openssl ($ca) no verify error: ${final:-no result}"; return; fi
  for n in $nums; do case $n in 2|19|20|23) ;; *) rec git "$t" UNKNOWN "gnutls: verification failed; openssl ($ca) errors=[$nums] $final"; return ;; esac; done
  rec git "$t" REJECT "gnutls: verification failed; openssl same CA ($ca), direct, errors=[$nums] $final"; }
if native git; then
  e=$(GIT_TERMINAL_PROMPT=0 timeout 60 git -c http.followRedirects=false ls-remote https://github.com/git/git.git HEAD 2>&1 </dev/null) && rec git "$CTRL" ACCEPT "github ls-remote ok" || rec git "$CTRL" UNKNOWN "control failed"
  for t in "$T1" "$T2"; do
    e=$(GIT_TERMINAL_PROMPT=0 timeout 60 git -c http.followRedirects=false ls-remote "$t" 2>&1 </dev/null); grc=$?; e=$(strip_url "$e" "$t")
    if [ $grc -eq 124 ]; then rec git "$t" UNKNOWN "timeout"
    elif printf '%s' "$e" | grep -qiE 'expired|does not match'; then rec git "$t" UNKNOWN "not related"
    elif printf '%s' "$e" | grep -qiE 'unable to get local issuer|self[- ]signed certificate in certificate chain|revoked'; then rec git "$t" REJECT "$e"
    elif printf '%s' "$e" | grep -qiE 'server certificate verification failed'; then git_tls_reason "$t" "$e"
    elif printf '%s' "$e" | grep -qiE 'not found|404|403|not a git repository|unexpected disconnect|(<url>|<host>)/?info/refs not valid: is this a git repository\?'; then rec git "$t" ACCEPT "http-level error"
    else rec git "$t" UNKNOWN "$e"; fi
  done
fi

# ---------- Node（エラーコードの許可リスト） ----------
if native node; then
  cat > "$out/nodetest.js" <<'JS'
const url = process.argv[2];
const REJECT = new Set(['UNABLE_TO_GET_ISSUER_CERT_LOCALLY','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','CERT_REVOKED','UNABLE_TO_GET_ISSUER_CERT']);
fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(15000) })
  .then(r => console.log('ACCEPT\thttp ' + r.status))
  .catch(e => { const c = e.cause || e; const code = c.code || c.name;
    console.log((REJECT.has(code) ? 'REJECT' : 'UNKNOWN') + '\t' + code); });
JS
  for pair in "$CTRL $CTRL_URL" "$T1 $T1" "$T2 $T2"; do
    set -- $pair; r=$(timeout 30 node "$out/nodetest.js" "$2" </dev/null 2>&1 | head -1)
    case "$r" in ACCEPT*|REJECT*|UNKNOWN*) rec node "$1" "${r%%	*}" "${r#*	}" ;; *) rec node "$1" UNKNOWN "$r" ;; esac
  done
fi

# ---------- uv（インデックスの URL をテストホストに向け、ランダムな名前を --dry-run で「入れたふり」。何もインストールされない） ----------
# --target の一時フォルダに向ける（システムの python3 は外部管理（PEP 668）で、そのままでは uv が拒否する）。判定は Windows の Get-AuditUvVerdict と同じ
# uv_verdict <uv -v の出力> <対象 URL>: 通信しない判定だけの関数（v2.11.5。test_verify_wsl.sh が取り出して試験する）。「判定語<TAB>理由」を出す
uv_verdict(){ local e=$1 url=$2 r other flat auth
  # 判定は Get-AuditUvVerdict と同じ: エラー行（DEBUG 以外）に対象と scheme・host・port が一致しない URL があれば接続先が不確か
  # （リダイレクト先・追加インデックス）。伏せ字にする前に比べる（文字列の置換だと t.example.other のような別ホストが対象に見える）
  auth=$(printf '%s' "$url" | sed -E 's#^(https?://[^/]+).*#\1#'); case "$auth" in *:[0-9]*) ;; https://*) auth="$auth:443" ;; esac
  # DEBUG 行は、問い合わせを表すもの（GET request for: / 古い uv の No cache entry for:）だけを含める（別インデックスへの問い合わせを見逃さない）
  other=$(printf '%s\n' "$e" | awk '!/^[[:space:]]*DEBUG / || /GET request for:|No cache entry for:/' | grep -oE 'https?://[^[:space:]`'"'"'"()<>/]+' \
    | sed -E 's#^(https://[^:]+)$#\1:443#' | grep -cvxF "$auth")
  e=$(strip_url "$e" "$url")
  # uv 0.11.x は「Failed to fetch:」の後で改行し、罫線（U+2502）を挟んで URL を書く（Get-AuditUvVerdict と同じく、空白と罫線を挟んでよい）
  flat=$(printf '%s' "$e" | tr '\n' ' ' | LC_ALL=C sed 's/\xe2\x94\x82/ /g')
  if printf '%s' "$e" | grep -qE 'Failed to fetch|invalid peer certificate|error sending request'; then
    if [ "$other" -gt 0 ]; then printf 'UNKNOWN\tanother URL in the error\n'; return; fi
    # URL をバッククオートで囲むかは uv の版で違う（v2.11.5。Linux の uv 0.12.22 は Failed to fetch では囲まず、Content-Type では囲む）
    if ! printf '%s' "$flat" | grep -qE 'Failed to fetch:[[:space:]]*`?(<url>|<host>)' || ! printf '%s' "$flat" | grep -qE 'error sending request for url[[:space:]]*\((<url>|<host>)'; then
      printf 'UNKNOWN\tfetch failed, not for the target request\n'; return; fi
    # uv 0.13.5（UV_NATIVE_TLS なし）は自前の証明書一覧で拒否し「Other(OtherError(CertDistrusted))」と書く（v2.11.6）。
    # この文字列だけを CertDistrusted に直す。ほかの Other(...)（Other(OtherError(UnknownIssuer)) も）は「Other」のままなので UNKNOWN
    # 後ろは空白か行末だけ（Get-AuditUvVerdict と同じ。大文字と小文字は区別する）
    r=$(printf '%s' "$e" | sed -E 's/invalid peer certificate: Other\(OtherError\(CertDistrusted\)\)([[:space:]]|$)/invalid peer certificate: CertDistrusted\1/g' \
      | grep -oE 'invalid peer certificate: [A-Za-z]+' | sed 's/.*: //' | sort -u | tr '\n' ' ')
    if [ -n "$r" ] && ! printf '%s' "$r" | tr ' ' '\n' | grep -vxE 'UnknownIssuer|Revoked|CertDistrusted|' >/dev/null; then printf 'REJECT\tUV_NATIVE_TLS=%s; %s\n' "${UV_NATIVE_TLS:-}" "$r"
    else printf 'UNKNOWN\tfetch failed: %s\n' "${r:-no certificate reason}"; fi
  elif [ "$other" -gt 0 ]; then printf 'UNKNOWN\tanother URL in the diagnostics\n'
  # 対象の URL を名指しした応答はそれだけで ACCEPT（v2.11.4。古い uv は Sending ... GET request を出さない）
  elif printf '%s' "$e" | grep -qE 'Unsupported `Content-Type` "[^"]*" for `?(<url>|<host>)'; then printf 'ACCEPT\tUV_NATIVE_TLS=%s\n' "${UV_NATIVE_TLS:-}"
  # URL を名指ししない not found は、対象への GET の記録があるときだけ（No cache entry は問い合わせ前の行なので根拠にしない）
  elif ! printf '%s' "$e" | grep -qE 'Sending (fresh|revalidation) GET request for: (<url>|<host>)'; then
    printf 'UNKNOWN\tno request to the target recorded\n'
  elif printf '%s' "$e" | grep -q 'was not found in the package registry'; then printf 'ACCEPT\tUV_NATIVE_TLS=%s\n' "${UV_NATIVE_TLS:-}"
  else printf 'UNKNOWN\t%s\n' "$(printf '%s' "$e" | tail -1)"; fi
}
uv_one(){ local label=$1 url=$2 e name tgt v
  name="emudhra-probe-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"; tgt=$(mktemp -d)
  e=$(timeout 120 uv -v pip install --dry-run --no-deps --only-binary :all: --no-cache --python "$SYSPY" --target "$tgt" --index-url "$url" "$name" 2>&1 </dev/null)
  rm -rf -- "$tgt"
  v=$(uv_verdict "$e" "$url"); rec uv "$label" "${v%%$'\t'*}" "${v#*$'\t'}"; }
if native uv; then uv_one "$CTRL" "$CTRL_URL"; uv_one "$T1" "$T1"; uv_one "$T2" "$T2"; fi

# ---------- Java（11 以上はキットの TlsProbe.java をコンパイルせずに実行。10 以下は単一ファイル実行が無いので UNKNOWN） ----------
if native java; then
  for pair in "$CTRL $CTRL_URL" "$T1 $T1" "$T2 $T2"; do
    set -- $pair; r=$(timeout 120 java "$KIT/TlsProbe.java" "$2" </dev/null 2>&1 | grep -m1 -E '^(ACCEPT|REJECT|UNKNOWN)'$'\t')
    case "$r" in ACCEPT*|REJECT*|UNKNOWN*) rec java "$1" "${r%%	*}" "${r#*	}" ;; *) rec java "$1" UNKNOWN "no probe result (Java 10 以下、または jdk.compiler なし)" ;; esac
  done
fi

# ---------- Python（棚卸し済みの全実体。起動不可も UNKNOWN として残す） ----------
pylist="$out/verify-pylist.txt"
{
  for p in /usr/bin/python3 /usr/local/bin/python3; do [ -e "$p" ] && echo "$p"; done
  [ -f "$out/venv-inventory.tsv" ] && awk -F'\t' 'NR>1 {print $1"/bin/python"}' "$out/venv-inventory.tsv"   # python_exec=no も含める
  [ -f "$out/conda-prefixes.txt" ] && while IFS= read -r p; do [ -n "$p" ] && echo "$p/bin/python"; done < "$out/conda-prefixes.txt"
  for v in "${PIPX_HOME:-$HOME/.local/share/pipx}"/venvs/*/bin/python "$HOME"/.local/pipx/venvs/*/bin/python; do [ -e "$v" ] && echo "$v"; done
  command -v uv >/dev/null && uv python list --only-installed --output-format json 2>/dev/null </dev/null \
    | "$SYSPY" -c 'import json,sys; [print(i["path"]) for i in json.load(sys.stdin) if i.get("path")]' 2>/dev/null
  command -v pyenv >/dev/null && for v in "$(pyenv root)"/versions/*/bin/python; do [ -e "$v" ] && echo "$v"; done
} | sort -u > "$pylist"
echo "Python 検証対象: $(wc -l < "$pylist") 件 → $pylist"

while IFS= read -r -u 3 py; do
  for pair in "$CTRL|$CTRL_URL" "$T1|$T1" "$T2|$T2"; do
    label="${pair%%|*}"; url="${pair#*|}"
    if [ -x "$py" ]; then json=$(timeout 90 "$py" "$KIT/probe_python.py" "$url" </dev/null 2>/dev/null); else json=""; fi
    "$SYSPY" "$KIT/audit_summary.py" rows "$py" "$label" <<< "$json" | while IFS=$'\t' read -r a b c d; do rec "$a" "$b" "$c" "$d"; done
  done
done 3< "$pylist"

# ---------- 集計 ----------
"$SYSPY" "$KIT/audit_summary.py" summary "$rows" "$CTRL" "$T1" "$T2" | tee "$out/verify-wsl-summary.tsv" | { command -v column >/dev/null && column -t -s $'\t' || cat; }
[ "$INSPECT" = yes ] && echo "TLS 検査プロキシ申告あり: 全件 UNKNOWN 扱い（FIXED は出さない）"
echo "NONE（モジュール未導入）の経路は FIXED にならない。stdlib-ssl が VULNERABLE の Python は残件"
