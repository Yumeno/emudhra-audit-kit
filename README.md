# eMudhra 中間CA鍵漏えい 対応監査キット

Windows 10/11 + WSL2 の開発用 PC を、1台ずつ点検・対処・検証するための手順書とスクリプト一式です。
手順書 `emudhra-runbook.md` を Claude Code に渡して進めることを想定しています。

> **ご利用の前に**
>
> - このキットの運用実績は、限られた環境だけです。**あくまで参考として**扱い、
>   スクリプトの中の処理を確かめたうえで、ご自分の環境で試してから使ってください。
> - Python 本体（CPython）の標準の `ssl` モジュールの修正（CVE-2026-115557）は 3.11〜3.15 に取り込まれていますが、
>   2026-10-26 未明の時点では、修正を含むリリースのバイナリはまだ出ていません。もう少し待てば出るはずです
>   （ただし 3.11・3.12（と 3.13）はセキュリティ修正だけの時期で、python.org の Windows インストーラーは通常出ません。
>   ほかの配布やアプリの配布元の対応を確かめてください。手順書 8章）。
> - それまでの対処（手順書 5.3）: certifi を使う経路は certifi を更新します。標準の `ssl` は certifi の更新だけでは直らないので、
>   更新した証明書ファイルをコードで指定するか、truststore を起動時に組み込んで Windows の判定を使わせます。
>   修正を含む配布が出たら Python ごと更新し、検証をやり直してください。

## 何をするものか

2026-10 に、インドの認証局 eMudhra の中間 CA 証明書の秘密鍵が、公開されている証明書から復元できると分かりました
（証明書は 2025-04 に作られ、その時点から復元できる状態でした）。ブラウザーと OS は失効の配信で対処済みですが、
**自前の証明書一覧を持つソフト**（Python・certifi・pip・uv・Node・Git・curl・Java・Electron のアプリ・アプリに同梱された
Python など）は、それぞれ更新しないと、この鍵で作られた偽の証明書を受け入れてしまう可能性があります。

このキットは、同じ時期に公表された次の問題もまとめて扱います。

- Brotli の脆弱性（CVE-2026-111497）と Pillow 13.0.0 の修正（Git やアプリに同梱されたライブラリの版を照合する）
- CI / サプライチェーン攻撃の痕跡（GhostAction 型のシークレットの持ち出し、LiteLLM 1.107.0、npm の tensorlake 0.5.144）

対象にしていないもの（macOS、WSL 以外の Linux、Docker のイメージの中、VM のゲスト、ほかのユーザー、スマートフォン、
ネットワーク機器、GitHub 以外の CI など）は手順書の 0.1 にまとめてあります。

## 仕組み

### 進め方の原則

```
① 読み取りだけの棚卸し → ② 対象と変更内容の提示（承認待ち） → ③ 承認したものだけ更新 → ④ 実際の経路で検証
```

- 一括更新（`winget upgrade --all` など）はしません。更新・設定の変更・削除は、1件ずつ承認を取ってから行います。
- 変更はすべて `$HOME\emudhra-audit\changes.log` に記録します（対象のパス・前後の版・結果・戻し方）。
- 監査結果はその PC の作業フォルダにだけ置き、リポジトリにも外部のサービスにも入れません。

### 判定の仕方（実際に接続して確かめる）

版の番号だけで「対策済み」とは判断せず、各ソフトの実際の通信経路で次の3つのサイトに接続して確かめます。

| 接続先 | 役割 | 期待する結果 |
|---|---|---|
| `www.google.com` | 対照（正常なサイト） | ACCEPT（つながる） |
| `dv-g3b-emudhra.we-have-a-problem.com` | 問題の中間 CA を使ったテスト用ホスト（基本の経路） | REJECT（拒否する） |
| `dv-g3b-aaa-emudhra.we-have-a-problem.com` | 同じ中間 CA の Sectigo の相互署名の経路 | REJECT |

- 1回ごとの結果は **ACCEPT / REJECT / UNKNOWN** の3つに分けます。通信の失敗をまとめて「拒否できた」とは数えません。
  失敗の理由（証明書の期限切れ、名前の不一致など本件と関係ないもの）を見て、関係ないものは UNKNOWN にします。
- ツール・経路ごとに、**対照が ACCEPT 1件・テスト用ホスト2つがそれぞれ REJECT 1件**のときだけ **FIXED**（対策済み）です。
- 対照がちょうど1件で ACCEPT か UNKNOWN、テスト用ホスト2つの結果がそれぞれ1件そろっていて、どちらかが ACCEPT なら **VULNERABLE**（未対策）です。
- それ以外（対照が REJECT、結果が欠けている・重なっている・判定できない）は **UNKNOWN** です。
  そのモジュールが入っていないだけの経路（結果が NONE）は **N/A** です。
- Python は「実体のパス × 標準の ssl / certifi / requests」の経路ごとに判定します。
- 対照サイトの証明書の発行者が Google Trust Services でなければ、ウイルス対策ソフトやプロキシが通信を検査して証明書を
  差し替えています。このときは「偽の FIXED」が出るので、FIXED とは報告しません。
- Windows（PowerShell）と WSL（bash）の集計は、同じ規則で書いた2つの実装（`Get-AuditSummary` と `audit_summary.py`）で行います。

### リポジトリと作業フォルダを分ける

監査結果がリポジトリに混ざらないように、キットは作業フォルダへコピーしてから使います。リポジトリのフォルダでは監査を実行しません。

```
<リポジトリ>\                     編集・コミット用
  Install-Kit.ps1  →  $HOME\emudhra-audit\kit\     Windows 側のキット（KIT_VERSION.txt にコミットと SHA256）
                      $HOME\emudhra-audit\*        Windows 側の監査結果（changes.log など）
  WSL: install_kit_wsl.sh  →  ~/emudhra-audit/kit/  （Windows 側のキットからコピーし、SHA256 を照合してから配置）
                              ~/emudhra-audit/*     WSL 側の監査結果
```

## ファイル構成

| ファイル | 役割 |
|---|---|
| `emudhra-runbook.md` | 手順書。背景、Claude Code への指示、棚卸し・判定・対処・検証・報告の手順、修正版の一覧と一次資料 |
| `Install-Kit.ps1` | キットを Windows の作業フォルダ（既定 `$HOME\emudhra-audit\kit`）へ配置し、コミットとファイルの SHA256 を `KIT_VERSION.txt` に記録する |
| `install_kit_wsl.sh` | Windows 側に配置したキットを WSL の作業フォルダ（既定 `~/emudhra-audit/kit`）へ、SHA256 を照合してコピーする（ディストリごと） |
| `Test-Emudhra.Helpers.ps1` | Windows 側の判定と集計の関数（Windows の証明書ストアでの直接判定、curl / Git / uv / pip などの出力の判定、走査の補助） |
| `Invoke-Verification.ps1` | Windows 側の検証の入口。Python の実体の一覧を受け取り、経路ごとに判定して `verify-python.json` などに書き出す |
| `probe_python.py` | 1つの Python で、標準の ssl / certifi / requests の3経路を1つの URL について判定する（Windows・WSL 共通。何もインストールしない） |
| `TlsProbe.java` | Java 11 以上の既定の信頼で判定する（コンパイル不要の単一ファイル実行） |
| `verify_wsl.sh` | WSL 側の検証（Python・curl・Git・Node・uv など） |
| `audit_summary.py` | WSL 側の集計（`Get-AuditSummary` と同じ規則） |
| `Replace-GitBrotli.ps1` | Git for Windows / PortableGit / MinGit の古い libbrotli を MSYS2 の 1.2.1 に差し替える。`-Check` で確認だけ（権限不要）。元の DLL は退避する。管理者の PowerShell で実行するのは Program Files の中の Git だけで、ユーザーのフォルダにある Git（PortableGit・MinGit）は通常の PowerShell で実行する（手順書 5.11） |
| `Invoke-CiAudit.ps1` | GitHub のアカウントと所属組織の全リポジトリを、CI の攻撃の痕跡と危ない設定について読み取りだけで調べる（`gh` の GET のみ。シークレットの値は読まない） |
| `Test-Helpers.ps1` | Windows 側のキットのテスト（外部に通信しない）。`-PythonPath` を付けると Python の部分も試す |
| `test_probe_python.py` | `probe_python.py` と `audit_summary.py` のテスト（外部に通信しない） |
| `test_verify_wsl.sh` | `verify_wsl.sh` の uv の判定のテスト（外部に通信しない。Windows 側と同じ入力で同じ答えになるか） |
| `.gitattributes` | 改行を LF に固定する（bash と Python のスクリプトに CR が入ると WSL で動かないため） |

## 使い方

細かい手順と注意は手順書にあります。ここでは流れだけを示します。

### 1. 準備（ユーザーが行う）

1. Git の HTTPS の検証を Windows の証明書ストアにそろえる（`git config --get http.sslBackend` が `schannel`）。手順書 1.1。
2. 必要なら GitHub CLI（`gh`）を入れてログインする。
3. このリポジトリを clone する。
4. キットを作業フォルダに配置する。

   ```powershell
   powershell.exe -NoProfile -File <clone したフォルダ>\Install-Kit.ps1
   Get-Content "$HOME\emudhra-audit\kit\KIT_VERSION.txt" -TotalCount 2   # dirty=no を確かめる
   ```

   WSL も点検するなら、ディストリごとに次を実行します。

   ```powershell
   wsl -d <ディストリ> -- bash /mnt/c/Users/<Windowsのユーザー名>/emudhra-audit/kit/install_kit_wsl.sh
   ```

### 2. Claude Code に依頼する

キットのフォルダ（`$HOME\emudhra-audit\kit`）で Claude Code を起動し、手順書 1章の「Claude Code への実行指示」をそのまま渡します。
Claude Code は次の順で進め、変更の前には必ず承認を求めます。

| 段階 | 手順書 | 内容 |
|---|---|---|
| 着手前 | 1.1 | Claude Code の版、キットのテスト（`Test-Helpers.ps1`）、通信の検査の有無、Windows の証明書ストアの直接判定（FIXED でなければ止まる） |
| 棚卸し | 3.1〜3.3b | Windows・全ドライブの venv や同梱ランタイム・WSL を読み取りだけで調べる。サプライチェーン攻撃の痕跡もここで見る |
| GitHub | 3.4 | `Invoke-CiAudit.ps1` で CI を調べる（アカウントごとに1回、どれか1台で） |
| 判定 | 4 | 「対策済み / 要更新 / 判定不能 / 対象外」に分け、更新の計画を示して承認を待つ |
| 対処 | 5 | 承認したものだけを更新する（Git の Brotli の差し替えは `Replace-GitBrotli.ps1`） |
| 検証 | 6 | 実際の経路で3つのサイトに接続して判定する（6.1 Windows、6.2 WSL）。6.4 で Brotli・Pillow・固めたアプリの版を照合する |
| 報告 | 7 | テンプレートで PC ごとの報告書を作る（作業フォルダに置き、リポジトリには入れない） |

### 3. キットを直すとき

1. リポジトリで編集し、テスト（`powershell.exe -NoProfile -File .\Test-Helpers.ps1`、`python -B -m unittest test_probe_python`、
   WSL で `bash test_verify_wsl.sh`）を通す。
2. レビューを受けてからコミットし、手順書の先頭の版を書き換える。
3. 各 PC で `Install-Kit.ps1`（と WSL の `install_kit_wsl.sh`）を実行し直して配置する。

## 注意

- 修正版の番号は手順書を書いた時点のものです。実行の前に、対応情報サイト（https://emudhra.we-have-a-problem.com/ 。
  eMudhra の公式ではなく、コミュニティが運営）と各ベンダーの告知で確かめ直してください。
- 監査結果（棚卸しの一覧、検証の結果、報告書、`changes.log`）は、このリポジトリにコミットしないでください。
- このキットは無保証です。更新や差し替えは、内容を確かめたうえで自分の判断で行ってください。

## ライセンス

MIT License（`LICENSE` を参照）。
