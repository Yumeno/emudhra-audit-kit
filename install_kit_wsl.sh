#!/usr/bin/env bash
# Windows 側に Install-Kit.ps1 で配置したキットを、WSL の作業フォルダへコピーする（ディストリごと、通常ユーザー）。
# 使い方: bash /mnt/c/Users/<Windowsユーザー>/emudhra-audit/kit/install_kit_wsl.sh [配置先]
#   配置先の既定は ~/emudhra-audit/kit。監査結果は ~/emudhra-audit に出力され、キットとは分かれる。
# コピーした内容を KIT_VERSION.txt の SHA256 と照合してから配置する。改行コードは変換しない（.sh/.py に CR が含まれていれば中止）。
# 同じ配置先への同時実行は想定しない。配置先は WSL 側のファイルシステム（/mnt/ 配下は不可）。
set -euo pipefail
die() { echo "中止: $*" >&2; exit 1; }
MARKER=KIT_VERSION.txt
# Install-Kit.ps1 の $KitFiles と同じ集合。KIT_VERSION.txt の一覧はこれと完全一致すること
KIT_FILES="emudhra-runbook.md Test-Emudhra.Helpers.ps1 Invoke-Verification.ps1 Test-Helpers.ps1 probe_python.py test_probe_python.py TlsProbe.java test_verify_wsl.sh verify_wsl.sh audit_summary.py install_kit_wsl.sh Replace-GitBrotli.ps1 Invoke-CiAudit.ps1"

SRC="$(realpath -e -- "$(dirname "${BASH_SOURCE[0]}")")"
DEST="$(realpath -m -- "${1:-$HOME/emudhra-audit/kit}")"   # シンボリックリンクを解決した実体パスで比較する
OUTROOT="$(realpath -m -- "$HOME/emudhra-audit")"
PARENT="$(dirname "$DEST")"

[ -f "$SRC/$MARKER" ] || die "$SRC に $MARKER が無い。Windows 側で Install-Kit.ps1 を先に実行すること"
[ "$DEST" != / ] && [ "$PARENT" != / ] || die "配置先が浅すぎる ($DEST)"
[ "$DEST" != "$OUTROOT" ] || die "配置先が監査結果のフォルダそのもの ($DEST)"
case "$DEST/" in /mnt/*) die "配置先は WSL 側のファイルシステムにすること（/mnt/ 配下は不可: $DEST）" ;; esac
case "$DEST/" in "$SRC/"*) die "配置先がキットの配置元の中にある ($DEST)" ;; esac
case "$SRC/" in "$DEST/"*) die "配置元が配置先の中にある ($SRC)" ;; esac
d="$DEST"
while [ "$d" != / ]; do
  [ ! -e "$d/.git" ] || die "配置先が git の作業ツリーの中にある ($d)"
  d="$(dirname "$d")"
done

# KIT_VERSION.txt の "# sha256" から最初の空行までを一覧とし、各行を厳密に検証する
list="$(awk 'f && /^$/ {exit} f {print} /^# sha256$/ {f=1}' "$SRC/$MARKER")"
[ -n "$list" ] || die "$MARKER にファイル一覧が無い"
names=""; count=0
while IFS= read -r line; do
  [[ "$line" =~ ^[0-9a-f]{64}\ \ ([A-Za-z0-9._-]+)$ ]] || die "$MARKER の一覧に不正な行: '$line'"
  case " $KIT_FILES " in *" ${BASH_REMATCH[1]} "*) ;; *) die "$MARKER の一覧にキット外のファイル: ${BASH_REMATCH[1]}" ;; esac
  case " $names " in *" ${BASH_REMATCH[1]} "*) die "$MARKER の一覧に重複: ${BASH_REMATCH[1]}" ;; esac
  names="$names ${BASH_REMATCH[1]}"; count=$((count+1))
done <<< "$list"
[ "$count" -eq "$(wc -w <<< "$KIT_FILES")" ] || die "$MARKER の一覧がキットのファイル集合と一致しない（$count 件）"

# 空か、キットのファイルと $MARKER だけのフォルダだけを置き換える（監査結果の誤上書き防止）
if [ -L "$DEST" ] || { [ -e "$DEST" ] && [ ! -d "$DEST" ]; }; then die "配置先がフォルダではない ($DEST)"; fi
if [ -d "$DEST" ]; then
  # 改行区切りの列挙（ls）は改行を含む名前で分割されるので、glob で 1 項目ずつ取り出して名前を分割せず検査する
  [ -r "$DEST" ] && [ -x "$DEST" ] || die "$DEST の内容を列挙できない"   # 読めないと glob は黙って空になる
  shopt -s dotglob nullglob; items=("$DEST"/*); shopt -u dotglob nullglob
  if [ "${#items[@]}" -gt 0 ]; then
    [ -f "$DEST/$MARKER" ] && [ ! -L "$DEST/$MARKER" ] || die "$DEST は空でなく $MARKER も無いので上書きしない"
    for item in "${items[@]}"; do
      e="${item##*/}"
      # 空白・改行を含む名前は下の空白区切り照合で隣り合う2名に一致しうるので、先に形式で弾く
      [[ "$e" =~ ^[A-Za-z0-9._-]+$ ]] || die "$DEST にキット以外のもの: $(printf '%q' "$e")（先に移動すること）"
      # __pycache__（キットの Python テストを配置先で実行するとできる）は、中身が通常の *.pyc だけなら許す
      if [ "$e" = __pycache__ ] && [ -d "$item" ] && [ ! -L "$item" ]; then
        bad=$(find "$item" -mindepth 1 \( ! -type f -o ! -name '*.pyc' \) -print -quit) || die "$item を検査できない"
        [ -z "$bad" ] || die "$DEST/__pycache__ に .pyc 以外のもの: $(printf '%q' "$bad")"
        continue
      fi
      case " $KIT_FILES $MARKER " in
        *" $e "*) [ -f "$item" ] && [ ! -L "$item" ] || die "$DEST にキット以外のもの: $e" ;;
        *) die "$DEST にキット以外のもの: '$e'（先に移動すること）" ;;
      esac
    done
  fi
fi
for b in "$PARENT"/.kit-old-*; do
  if [ -e "$b" ]; then echo "警告: 以前のキットの退避が残っている（中断した実行?）: $b" >&2; fi
done

mkdir -p "$PARENT"
stage="$(mktemp -d "$PARENT/.kit-stage-XXXXXX")"
trap 'rm -rf "$stage"' EXIT
n=0
while IFS= read -r line; do
  hash=${line%%  *}; name=${line#*  }
  cp -- "$SRC/$name" "$stage/$name"
  actual=$(sha256sum -- "$stage/$name" | cut -d' ' -f1)
  [ "$actual" = "$hash" ] || die "SHA256 不一致 $name (期待 $hash / 実際 $actual)"
  case "$name" in *.sh|*.py)
    if grep -q $'\r' "$stage/$name"; then die "$name に CRLF。リポジトリの .gitattributes / core.autocrlf を確認"; fi ;;
  esac
  n=$((n+1))
done <<< "$list"
# 元の記録（空行で終わる一覧まで）を引き継ぎ、WSL 側の記録を空行の後に足す（再配布時も一覧は空行で終わる）
awk 'f && /^$/ {exit} {print} /^# sha256$/ {f=1}' "$SRC/$MARKER" > "$stage/$MARKER"
. /etc/os-release 2>/dev/null || true
printf '\n# wsl\nwsl_installed_at=%s\nwsl_distro=%s\nwsl_source=%s\n' "$(date -Is)" "${PRETTY_NAME:-unknown}" "$SRC" >> "$stage/$MARKER"
chmod 644 "$stage"/*   # /mnt/c 由来の 777 を引き継がない
chmod +x "$stage/verify_wsl.sh" "$stage/install_kit_wsl.sh"
chmod 755 "$stage"     # mktemp -d は 700

# 退避 → 配置 → 失敗時は復元（mv -T は配置先の中へ入れ子にしない。配置先が空でないフォルダなら失敗、空フォルダなら置き換える）
backup=""
if [ -e "$DEST" ]; then backup="$(mktemp -u "$PARENT/.kit-old-XXXXXX")"; mv -T -- "$DEST" "$backup"; fi
if ! mv -T -- "$stage" "$DEST"; then
  if [ -z "$backup" ]; then die "配置に失敗（以前のキットは無し）"; fi
  if [ ! -e "$DEST" ] && mv -T -- "$backup" "$DEST"; then die "配置に失敗（以前のキットは復元済み）"; fi
  die "配置に失敗。以前のキットは $backup に退避したまま（手動で戻すこと）"
fi
trap - EXIT
[ -z "$backup" ] || rm -rf -- "$backup" || echo "警告: 以前のキットの退避を削除できない: $backup" >&2

echo "キットを配置: $DEST ($n ファイル)"
grep -E '^(commit|dirty)=' "$DEST/$MARKER"
