# eMudhra 中間CA秘密鍵漏えい 対応手順書（Windows + WSL 開発機向け）v2.12.8

公開: 2026-10-26（v2.12.8）
同梱キット（このファイルと同じフォルダ）:

**キットはリポジトリから作業フォルダへ配置して使う。リポジトリのフォルダでは監査を実行しない**（監査結果がリポジトリに混入するのを防ぐ）。

```
<リポジトリ>\                  編集・コミット・push 用
  Install-Kit.ps1  →  $HOME\emudhra-audit\kit\   実行用キット（KIT_VERSION.txt に commit / SHA256）
                      $HOME\emudhra-audit\*      Windows 側の監査結果（changes.log 等）
  WSL: install_kit_wsl.sh → ~/emudhra-audit/kit/ （Windows 側の kit からコピーし、SHA256 照合後に配置）
                            ~/emudhra-audit/*    WSL 側の監査結果
```

| ファイル | 用途 | 出所 |
|---|---|---|
| `Test-Emudhra.Helpers.ps1` / `Invoke-Verification.ps1` | Windows 検証（Python 経路別、Windows ストア直接） | GPT 提供の差し替え案を採用 |
| `probe_python.py` | 各 Python 実体の stdlib-ssl / certifi / requests を判定（Windows・WSL 共通） | 同上 |
| `Test-Helpers.ps1` / `test_probe_python.py` | キット自体のテスト（外部通信なし） | 同上 |
| `TlsProbe.java` | Java 11 以上の既定の信頼で判定（コンパイル不要の単一ファイル実行。Windows・WSL 共通） | Claude 作成（v2.9） |
| `verify_wsl.sh` / `audit_summary.py` | WSL 検証と集計（`Get-AuditSummary` と同一ロジック） | Claude 作成 |
| `test_verify_wsl.sh` | verify_wsl.sh の uv の判定の試験（外部通信なし。`Get-AuditUvVerdict` と同じ入力） | Claude 作成（v2.11.5） |
| `Install-Kit.ps1` / `install_kit_wsl.sh` | キットを作業フォルダへ配置（Install-Kit.ps1 はリポジトリ側でのみ使い、kit には含めない） | Claude 作成（v2.7） |
| `Replace-GitBrotli.ps1` | Git for Windows / PortableGit / MinGit の libbrotli を MSYS2 1.2.1 に差し替え（5.11。管理者の PowerShell。`-Check` は権限不要） | Claude 作成（v2.11。v2.12 で MinGit 型に対応） |
| `Invoke-CiAudit.ps1` | GitHub のアカウントと所属組織の全リポジトリを、CI の攻撃の痕跡と危ない設定について読み取りだけで調べる（3.4。アカウントごとに1回） | Claude 作成（v2.12.2） |

テスト状況: キットのテスト（Test-Helpers.ps1、test_probe_python.py、test_verify_wsl.sh）は外部に通信せずに動く。環境は PC ごとに違うので、使う前に各 PC で 6.1 の手順0（キットのテスト）を必ず通すこと。通信や実物の環境を要する部分（TlsProbe.java の接続、Replace-GitBrotli.ps1 の差し替え、Invoke-CiAudit.ps1 など）は自動のテストに含まれていないので、初めて使うときは結果を目で確かめる。
対象: Windows 10/11 + WSL2 の開発用PC（複数台）（対象にしていないものは 0.1）
想定実行者: Claude Code（メイン: Opus/Fable、棚卸し・検証: Sonnet サブエージェント）

## 0. 背景と方針

- インド認証局 eMudhra の中間CA証明書8件（TLS用6、コード署名用2）の秘密鍵が公開証明書から復元可能だった。**証明書は 2025-04 に作られ、作られた時点から**鍵の作り方を誤っていて、誰でも復元できる状態だった（弱点のあった期間は 2025-04 から各ソフトが対処するまで）。
  2026-10-17 に研究者が報告し Chrome / Firefox が同日ブロック、10-19 に各社の信頼リストへ開示、Microsoft 10-20 にブロック、CA（eMudhra と、相互署名した Sectigo）も失効させた。
  Apple は 10-19 から設定データの自動更新で TLS 用の中間 12 件（emSign の下の 6 件と、Sectigo の AAA Certificate Services の下の相互署名 6 件）をブロックし、
  10-23 には emSign のルートもブロックした（[Apple: About the compromised eMudhra intermediate CAs](https://support.apple.com/en-us/149555)、2026-10-23。
  対応情報サイトは Apple を 10-22 と書いているが、一次資料の Apple の記載を採る）。macOS のコマンドラインツール（curl / git / python3 など、`/etc/ssl/cert.pem` を読むもの）は、Apple の今後の更新まで受け入れうる（この手順書は macOS を対象にしていない）。
  実際の悪用は未確認。CT ログにこの期間の該当中間の証明書は無く、CT を確かめるブラウザーは攻撃され得なかったとされる。CT を確かめないソフト（言語ランタイム・パッケージマネージャー・Git など）は対象外。
- ブラウザ・OS は失効配信で対処済み。**失効情報を取り込まない独自CAバンドル持ちのソフト**（言語ランタイム、パッケージマネージャー、Git、Electron、Claude Code 自身など）は個別更新が必要。
- 情報源: https://emudhra.we-have-a-problem.com/ （Dennis Jackson 氏らコミュニティ運営の対応情報サイト。**eMudhra 公式ではない**。修正版表・テストホスト・Windows用ブロックスクリプトあり）
- 修正版の根拠は各ベンダーの告知を一次資料とし、セクション4の表にリンクする。数値は変動するので実行前に再確認する。

**作業原則（この順序を崩さない）**

```
① 読取り専用の棚卸し  → ② 対象と変更内容の提示（承認待ち）  → ③ 承認済み対象のみ更新  → ④ 実利用経路で検証（3値判定）
```

- 更新は**本件の影響対象に限定**する。`winget upgrade --all` 等の一括更新は使わない。
- 既存のメジャーバージョン内で修正版へ上げる。メジャー移行（Node 20→24 等）は別判断。
- ComfyUI / Stability Matrix / Forge / Automatic1111 等のアプリ管理 Python 環境は、**certifi だけを対象**にし、依存関係の一括更新はしない。更新後はアプリ起動を確認する。
- 棚卸し段階では管理者権限・root で未知の python を起動しない（起動確認は通常ユーザー権限）。
- 変更ごとに「対象パス・変更前後の版・結果・ログ」を記録する（セクション7）。

### 0.1 対象範囲と、対象にしていないもの（v2.12.3）

**この手順書とキットが調べるもの**: Windows 10 / 11 の PC と、その上の WSL2 の Ubuntu / Debian 系のディストリ。加えて、GitHub のアカウントと所属組織のリポジトリ（3.4、サーバー側）。
- 走査する場所: Windows は 3.2 が選んだ固定ドライブ（`drives-scanned.txt`。リムーバブルの USB メモリ・SD カード・ネットワークドライブは含まない）を、
  実行したユーザーの権限で。WSL は通常ユーザーの権限で Linux のファイルシステム（`/mnt` の Windows 側は除く）
- 走査で見るもの: 全ファイルの中身ではなく、決まった名前・場所のもの（python.exe・pyvenv.cfg・git / curl / uv / node / java などの exe・cacert.pem・
  Brotli を抱える DLL・サプライチェーン攻撃の痕跡の候補など）。リンクはたどらない。Windows・`node_modules`・`.git`・`__pycache__`・`site-packages`・`Lib`・
  `pkgs`・`Temp` には降りない（`site-packages` / `Lib` / `node_modules` は直下の決まった名前だけ見る）。読めなかった場所は走査エラー・未走査リンクに残る
- 実測するもの: 6.1 の一覧（ユーザーが確認したもの）にある Python・ツールだけ。それ以外のアプリは、版の照合（6.4）で分かる範囲だけ

**対象にしていないもの**（報告書の「未探索」に必ず書く）と、対象にする場合に足すもの:

| 対象にしていないもの | キットがしないこと | 対象にするなら必要な追加 |
|---|---|---|
| **macOS** | 何も調べない。Apple は Safari・メール・システムの仕組みを使うアプリを自動で守るが（2026-10-19 から中間 12 件、10-23 にルート。[HT 149555](https://support.apple.com/en-us/149555)）、`/etc/ssl/cert.pem` を読むコマンドラインツール（curl / git / python3 / ruby / perl / openssl。Xcode Command Line Tools を含む）は Apple の今後の更新まで受け入れうる | macOS 用の棚卸しと実測（zsh / bash）: `/etc/ssl/cert.pem` に emSign と AAA Certificate Services のルートが残っているかの確認と、Apple の手順による削除（管理者権限・バックアップ・macOS の更新で元に戻る）。Homebrew（`ca-certificates`・`openssl@3`・curl・python・node）、pyenv / conda / venv の certifi、Node、Java の cacerts、Git、uv、Docker Desktop for Mac、Electron アプリ、アプリ同梱の cacert.pem・PyInstaller 等。テストホストへの実測（3.3 / 6.2 の bash の多くは流用できるが、パス・`stat`・`find` の違いを直す） |
| **WSL 以外の Linux**（実機・VM・サーバー） | 3.3 / 3.3b / 6.2（verify_wsl.sh）は WSL の Ubuntu / Debian 系を前提にしている。`/mnt` を Windows のドライブとみなして外す、ca-certificates の修正版の表が Ubuntu / Debian だけ、root でしか読めない場所・他のユーザーのホームを見ない | ディストリごとの ca-certificates の修正版（RHEL / Fedora / Rocky の `ca-certificates` と `update-ca-trust`、Arch、SUSE、Alpine は 4章に一部）と 4章の表の追加。`/mnt` を外す処理の見直し（実機では普通のマウント）。root で見る範囲（`/opt`・`/usr/local`・`/srv`・他のユーザー）は方針（root で未知の python を起動しない）と合わせて、読むだけの棚卸しにする。systemd のサービスで動く Python / Node / Java、Snap・Flatpak（それぞれのランタイムが証明書を持つ）、AppImage（同梱）。OS の libbrotli は USN / ディストリの告知で確認。本番サーバーは、変更の承認の流れを別に決める |
| **Ubuntu / Debian 系以外の WSL のディストリ**（Fedora・Arch・Alpine・openSUSE など） | 3.3 / 6.2 の ca-certificates の判定と修正版の表は Ubuntu / Debian だけ | 上の「WSL 以外の Linux」と同じ追加。`wsl -l -v` の全ディストリについて、実施した・しなかったを報告書に書く |
| **独自の TLS と証明書一覧を組み込んだアプリ**（形式を問わない） | 一般には見つけられない。Electron・Bun・Python・Node・Java・uv・Git など、キットが知っている部品だけ判定する | 4章の表にあるもの（Flutter / Dart、Firestore の SDK、Go の `x509roots/fallback`、Rust の `webpki-roots` など）は版を確かめる。それ以外は開発元の告知・修正版を確かめ、必要ならアプリの通信をテストホストに向けて実測する。自分のプロジェクトは依存の版を確かめ、作り直して配布し直す |
| **Docker のコンテナ・イメージ** | 5.8 は Dockerfile / compose の FROM と Docker Desktop の版を見るだけ。イメージの中・動いているコンテナの中は実測しない | イメージごとに中で 6.2 相当の実測（または ca-certificates・certifi・Node の版を読む）、再ビルドと再作成。レジストリにある自作イメージも対象にするかを決める |
| **この PC の中の仮想マシン**（Hyper-V / VirtualBox / VMware のゲスト） | 仮想ディスクの中は見ない（3.2 は仮想ディスクのファイルとして見えるだけ） | ゲストの OS ごとに、この手順書（Windows / Linux / macOS の該当部分）を中で実行する |
| **同じ PC の他のユーザー・管理者だけが読める場所** | 3.2 は実行したユーザーの権限で走査する。読めない場所は走査エラーに残るだけ | ユーザーごとに実行する。管理者で読むだけの走査をするなら、未知の python を起動しない方針のまま、ファイルを読むだけの処理に分ける |
| **接続していないドライブ・リムーバブル媒体・ネットワークドライブ・クラウドにだけあるファイル** | 走査の時点でつながっていない固定ドライブ、USB メモリ・SD カード（リムーバブル）、ネットワークドライブ・共有フォルダ、OneDrive 等のオンデマンドのファイルは見ない | 固定ドライブ（外付けの HDD を含む）は、つないでから 3.2 をやり直す（v2.11 から前回との差分が出る）。Get-Partition に出ない固定ドライブは、確かめてから 3.2 の `$includeDrives` に書く（外した理由は `drives-not-scanned.txt`）。リムーバブルの媒体とネットワークの場所は、今のキットでは `$includeDrives` に書いても走査しないので、対象にするなら 3.2 の走査の根を足す処理を加える（クラウドの同期フォルダを開かない方針と両立させる）。クラウドのものは同期してから |
| **iPhone / iPad** | 調べない | OS 側は作業不要（Apple が設定データの自動更新で対処。OS を最新にし、ネットにつながっていればよい）。ただし**アプリ独自の証明書一覧**は別で、Apple の対処が効かない（例: Cloud Firestore の SDK を使うアプリ。4章）。アプリを最新にし、自分で配布しているアプリは SDK を上げて配布し直す |
| **Android の端末** | 調べない | OS とシステムの更新（Android 14 以降は証明書の一覧が Google Play 経由で更新される）を確認。古い端末は機種の更新の有無を確認。独自の証明書一覧を持つアプリは開発元の対応を待つ |
| **ルーター・NAS・プリンター・スマート家電など** | 調べない | 各機器のファームウェアの更新を確認（独自の証明書一覧を持つ）。管理画面で HTTPS の外部接続を使う機能があれば、更新までは使わない |
| **GitHub 以外の Git ホスティング・CI**（GitLab、Bitbucket、Azure DevOps、自前の Jenkins など） | 3.4 は GitHub だけ | それぞれの API で 3.4 と同じ確認（ワークフロー・パイプラインの中身、実行履歴と起動者、シークレットの名前、Webhook、デプロイキー）。GitLab は同時期に脆弱性の修正もある（GitLab の告知を確認） |
| **もらった・ダウンロードした単一 exe 型のアプリ**（PyInstaller の onefile 等） | 中の部品を見ない（v2.10.1 からの方針。自分の開発環境の dist だけ調べる） | 全 exe の末尾を読む判定に戻す（ウイルス対策の検査とクラウドのファイルで極端に遅くなる）か、開発元に依存の版を問い合わせる |
| **Java 10 以前の実測** | 版を読むだけで UNKNOWN にする（TlsProbe.java は Java 11 以上） | Java 6 / 7 でも動く実測プログラム（HttpsURLConnection でテストホストにつなぐ）を足す。`cacerts` の中身（emSign / AAA Certificate Services のルートの有無）は参考にしかならない（JSSE は `javax.net.ssl.trustStore` の指定・`jssecacerts`・`cacerts` の順に選び、アプリ独自の TrustManager もありうる）。実測できるまでは UNKNOWN のまま |
| **コード署名用の中間 2 件で署名されたファイル** | 探さない（Windows は信頼しない一覧で拒否、Apple は元々信頼しない） | Authenticode 署名の連鎖に EM のコード署名用の中間を含む exe / dll / msi を探す処理を足す |
| **ブラウザーそのもの**（Chrome / Edge / Firefox / Safari） | Brotli の版の照合（6.4）以外は見ない（各社が 10-17〜10-20 に対処済み） | 自動更新が止まっていないか（古い Firefox ESR、管理ポリシーで更新を止めた端末）を確認する |

## 1. Claude Code への実行指示

```
この手順書 emudhra-runbook.md に従って、このPCの Windows 側と WSL 側を点検してください。

役割分担:
- セクション3「棚卸し」とセクション6「検証」は sonnet のサブエージェントに委譲すること。
  3.1 Windows、3.2 venv網羅探索、3.3 WSL（ディストリごと）は別サブエージェントで並列実行してよい。
  3.3b（WSL へ Windows 側一覧を取り込む）は 3.2 の完了後に実行すること。未完了なら「未取込」を残件にし、黙って省略しない。
- 検証（セクション6）は同梱キットのスクリプトで行う。手順0のキット自体のテストが通らなければ検証に進まず報告すること。
  サブエージェントからは結果ファイルのパスと要約表だけ受け取ること。
- セクション4「判定」、セクション5「対応計画の提示と実行」、セクション7「報告」はあなた自身が行うこと。
  判断材料が足りなければ結果ファイル（venv-inventory.csv 等）を直接読むこと。

進め方:
0. セクション1.1の着手前チェックを最初に行う（Claude Code 版の確認、Windows ストア直接判定）。
   Windows ストア直接判定が FIXED でなければ、棚卸しに進まず報告すること
1. 棚卸し結果を表で報告（読取り専用。この段階で何も変更しない）
2. セクション4に照らし、「対策済み／要更新／判定不能／対象外」に分類。
   要更新の各項目について「対象の絶対パス・現在版・更新後版・更新方法・影響範囲」を一覧にして私の承認を待つ
3. 承認された項目だけセクション5の手順で更新。venv は更新対象数と一覧を先に提示
4. セクション6の検証をサブエージェントに実行させ、セクション7のテンプレートで報告

制約:
- 一括更新コマンド（winget upgrade --all, choco upgrade all, scoop update *, pipx upgrade-all, pip install -U 以外の依存一括更新）は使わない
- 破壊的操作（venv削除、git/npm/conda の設定変更、環境変数の永続設定、Node のメジャー変更、conda base 更新）は個別に確認を取る
- 壊れた venv は削除せず一覧化のみ
- エラー出力を破棄しない（2>$null / Out-Null / 2>/dev/null で更新ログを捨てない）
- 修正版の番号は作成時点のもの。実行前に https://emudhra.we-have-a-problem.com/ と各ベンダー告知で再確認し、差異を報告
- 想定外の構成（複数の Python 配布、GPO 停止、TLS 検査プロキシ、アプリ管理環境）は推測で進めず質問する
- 検証で TLS 検査（対照サイトの発行者が Google Trust Services 以外）が検出されたら、結果を FIXED と報告しない
- 実施していないテストを実施済みと書かない。UNKNOWN と未探索領域は残件として報告する
```

### 1.1 着手前チェック

キットは公開リポジトリで配布する: https://github.com/Yumeno/emudhra-audit-kit
clone・push に使う Git / gh は、どちらも Windows の証明書ストアで検証する前提にそろえる。

**ユーザーが行う（Claude Code 起動前）**

1. Git の HTTPS バックエンドを確認する（PowerShell）

   ```powershell
   git --version
   git config --show-origin --show-scope --get-all http.sslBackend   # 設定元ごとの値
   git config --get http.sslBackend                                  # 有効値（最後に効くもの）
   ```

   有効値が `schannel` なら OK。`openssl` または空なら設定する（元に戻すときは `--unset`）:

   ```powershell
   git config --global http.sslBackend schannel
   git config --get http.sslBackend   # schannel になったことを確認
   ```

   Git 本体の更新が必要な場合は 5.2 の注意（Git Bash 以外のシェルから実行）に従う。
2. gh が未導入なら導入してログインする（`gh auth login` は対話が必要なので、別ウィンドウの PowerShell で）

   ```powershell
   winget install --id GitHub.cli -e
   gh auth login -h github.com -p https -w
   gh auth setup-git
   ```

3. キットを取得する: `git clone https://github.com/Yumeno/emudhra-audit-kit.git`
   （`.gitattributes` で LF 固定）
   - Windows 本体の判定前に clone することになるが、github.com の証明書は eMudhra 系ではなく、悪用には経路上の能動的な改ざんが必要なためリスクは低い。厳密にするなら、ブラウザ（Chrome / Edge は CRLSets で対策済み）で GitHub にログインして ZIP を取得し、判定後に clone し直す
4. キットを作業フォルダへ配置する（リポジトリのフォルダでは監査を実行しない）

   ```powershell
   powershell.exe -NoProfile -File <clone したフォルダ>\Install-Kit.ps1   # → $HOME\emudhra-audit\kit
   Get-Content "$HOME\emudhra-audit\kit\KIT_VERSION.txt" -TotalCount 2   # commit / dirty を報告に記録
   ```

   配置先は、空のフォルダか、`KIT_VERSION.txt` とキットのファイルだけを含むフォルダのときだけ置き換える。それ以外のもの（監査結果など）が入っていれば中止する。監査結果のフォルダ（`$HOME\emudhra-audit`）そのもの、git の作業ツリーの中、ジャンクション／シンボリックリンクを含むパスも拒否する。置き換えは旧キットを退避してから行い、失敗時は元に戻す。`dirty=yes`（未コミットの変更あり）で配置した場合は報告に明記する

**Claude Code が最初に行う（棚卸しより前）**

1. Claude Code の版を確認する（5.1。修正版以降でなければ先に更新して再起動）
2. キットのテスト（Windows PowerShell 5.1。外部通信なし）
3. TLS 検査の検出と Windows ストア直接判定。結果は `verify-windows-trust.json`

   ```powershell
   Set-Location "$HOME\emudhra-audit\kit"
   powershell.exe -NoProfile -File .\Test-Helpers.ps1; if ($LASTEXITCODE -ne 0) { throw 'helper tests failed' }
   $req = [Net.WebRequest]::Create('https://www.google.com/'); $req.Timeout = 15000
   try { $req.GetResponse().Close(); $issuer = $req.ServicePoint.Certificate.Issuer } catch { $issuer = "ERROR: $($_.Exception.Message)" }
   "対照サイトの証明書発行者: $issuer"
   # PowerShell 7（pwsh）では ServicePoint.Certificate が空になる。この手順は Windows PowerShell 5.1（powershell.exe）で実行する
   if (-not $issuer) { throw '発行者を読めない。PowerShell 7 では空になるので、Windows PowerShell 5.1（powershell.exe）で実行し直す' }
   if ($issuer -notmatch 'O=Google Trust Services') { throw 'TLS 検査の可能性。判定せず報告' }
   . .\Test-Emudhra.Helpers.ps1
   $out = "$HOME\emudhra-audit"; New-Item -ItemType Directory -Force $out | Out-Null
   $w = Invoke-AuditWindowsTlsSet
   Write-AuditUtf8 -Path "$out\verify-windows-trust.json" -Text (ConvertTo-Json -InputObject $w -Depth 8)
   $w.Rows | ForEach-Object { "$($_.Target) => $($_.Verdict) | $($_.Detail)" }
   $w.Summary | Format-Table -AutoSize
   ```

   - FIXED（対照 ACCEPT・2ホスト REJECT、selfcheck=PASS）なら、Git(schannel) / gh / winget の土台は対策済みとして棚卸しへ進む
   - FIXED 以外なら棚卸しに進まずユーザーに報告する（GPO の自動更新停止、オフライン、TLS 検査等を疑う。5.6 の対処は承認後）
   - Disallowed ストアの列挙で eMudhra が 0 件でも、それだけで未対策と判定しない（3.1 の注意）
   - **TLS 検査が一部の経路だけのことがある**（例: ウイルス対策ソフトによっては .NET の経路だけを検査し、Python / node / curl / git は本来の発行者のまま）。発行者が違って止まったら、6.1 手順3 の前に、python-all.txt / tools-to-run.txt の実体で経路ごとに発行者を確かめる（自動化はしていない。v2.12.1）:
     - Python: `ssl.create_default_context()` と certifi の context で www.google.com に接続し、`getpeercert()['issuer']`。`-I` を付けるとユーザーの site-packages（Store 版の certifi はここ）が読まれないので、certifi の有無の判断には使わない
     - node: `tls.connect(...)` の `getPeerCertificate().issuer`。curl: `-w "%{certs}"` の Issuer の行
     - git: PowerShell なら `$env:GIT_CURL_VERBOSE = '1'` としてから `git -c http.sslBackend=openssl ls-remote https://github.com/git/git.git HEAD`、終わったら `Remove-Item Env:GIT_CURL_VERBOSE`（bash なら `GIT_CURL_VERBOSE=1 git ...`）（その場だけ openssl にして issuer の行を出す。github.com の本来の発行者は Sectigo）
     - uv: 発行者を出せない。既定（自前の証明書一覧）は検査用の CA を信頼しないので、検査されていれば対照が失敗して UNKNOWN になる（偽の FIXED は出ない）
     - すべて本来の発行者なら、6.1 手順3〜4 を `$inspect = $false` で、`-IncludeWindowsTrustProbe` を外して実行し（Windows ストアは curl.exe で測る）、検査のある経路は「検査ソフトが遮断（アプリ自身は判定不能）」として残す。手順から外れたことを changes.log と報告書に書く。どれかの経路が検査されていたら、その経路は UNKNOWN のまま

## 2. 全体フロー

```
[着手前]  1.1 Git schannel 確認（ユーザー）→ clone → Install-Kit.ps1 で配置 → Claude Code 版確認 → キットのテスト → Windows ストア直接判定（FIXED でなければ停止）
[棚卸し]  Windows 3.1 ─┐
          venv   3.2 ─┼─ 並列（Sonnet）→ 結果ファイル
          WSL    3.3 ─┘
          WSL    3.3b ← 3.2 完了（venv-scan.done）後
[判定]    セクション4の表で4分類 → 更新計画を提示 → 承認
[更新]    承認済みのみ（セクション5）→ 常駐プロセス再起動
[検証]    キットのテスト → TLS 検査検出 → セクション6（経路別の対照 + 2ホスト）→ 6.3 突き合わせ → セクション7報告
```

## 3. 棚卸し（読取り専用）

結果はすべて `$HOME\emudhra-audit\`（WSL: `~/emudhra-audit/`）に保存する。

### 3.1 Windows 側（PowerShell、通常ユーザー権限）

```powershell
$out = "$HOME\emudhra-audit"; New-Item -ItemType Directory -Force $out | Out-Null
. "$out\kit\Test-Emudhra.Helpers.ps1"   # 1.1 で配置済みのキット（Python 実体の列挙と Electron 版の取得に使う）
# 古い目印を先に消す（この走査が書き出しまで成功したときだけ付け直す）。あるのに消せなければ止める（古い結果を新しいものと取り違えないため）
if (Test-Path -LiteralPath "$out\electron-apps.csv.ok") { Remove-Item -LiteralPath "$out\electron-apps.csv.ok" -ErrorAction Stop }
# Start-Transcript は使わない: Windows PowerShell 5.1 ではネイティブコマンド（git、curl、python など）の出力が記録されない。
# 全体をスクリプトブロックにしてパイプで受け、画面とログの両方に出す（-Width で表の右端が切れるのも防ぐ。ログは UTF-16）
& {

# --- OS と信頼リスト ---
(Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").DisplayVersion
# GPO: 1 なら自動更新停止。0/未設定は「停止していない」だけで、受信済みの証拠ではない（実測はセクション6で）
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\SystemCertificates\AuthRoot" -ErrorAction SilentlyContinue | Select-Object DisableRootAutoUpdate
# Disallowed ストアに eMudhra / emSign が入っているか（Block スクリプト適用済みの目安）
# 注意: 自動更新で受信した不信頼は、ここに列挙されないことがある（0件でも、実測では ExplicitDistrust になることがある）。0件 = 未受信ではない。判定はセクション6の実測で
Get-ChildItem Cert:\LocalMachine\Disallowed | Where-Object { ($_.Subject + $_.Issuer + $_.FriendlyName) -match 'eMudhra|emSign|EM-DV|EM-OV|EM-EV' } | Select-Object Subject, Issuer, Thumbprint, NotAfter
# 確実な突合はトラッカーの impacted-intermediates.json の Thumbprint/SHA-256 と比較する
# TLS検査プロキシの有無（検証結果の解釈に必要）
netsh winhttp show proxy
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" | Select-Object ProxyEnable, ProxyServer
Get-Date -Format o   # 端末時刻（証明書期限判定の前提）

# --- インストール済みアプリの一覧（コマンド名で探すと漏れるものを拾う） ---
# コマンド名の確認だけだと、svn を PATH に入れない SVN クライアント、PATH に無いシェルがある GitHub CLI、古い Java を同梱するアプリなどを
# 見落とす。一覧を目で見て、通信するアプリ（独自の TLS や Java・Python・node を同梱するもの）を拾う
$uninstall = Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*","HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue
$uninstall | Where-Object DisplayName | Select-Object DisplayName, DisplayVersion, Publisher, InstallLocation, InstallDate |
  Sort-Object DisplayName, DisplayVersion -Unique | Export-Csv "$out\installed-apps.csv" -NoTypeInformation -Encoding UTF8
"インストール済みアプリ: $(@(Import-Csv "$out\installed-apps.csv").Count) 件 → installed-apps.csv"

# --- パッケージマネージャー本体（Windowsストア使用のため本体はOK。導入物の棚卸しに使う） ---
winget --version; winget list --source winget 2>$null | Out-File "$out\winget-list.txt"
choco --version 2>$null; choco list 2>$null | Out-File "$out\choco-list.txt"
scoop --version 2>$null; scoop list 2>$null | Out-File "$out\scoop-list.txt"

# --- Git: 実体ごとに、設定元まで含めて ---
where.exe git
git --version
# TLS 関連キーだけを許可リストで問い合わせる（全 http.* を列挙しない＝extraHeader 等の値をそもそも取得しない）。
# URL スコープのキー名に user:pass が入るケースも保存前に伏せる
$gitTls = git config --show-origin --show-scope --get-regexp '^http(\..*)?\.(sslbackend|sslcainfo|sslcapath|sslverify)$' 2>$null
@($gitTls) | ForEach-Object { ([string]$_) -replace '://[^/@\s]+@','://<redacted>@' } | Out-File "$out\git-config.txt" -Encoding utf8
Get-Content "$out\git-config.txt"      # sslverify false が出たら要是正
# extraHeader は「設定の有無」だけ（キー名のみ取得、値は取得しない）
git config --name-only --get-regexp 'extraheader$' 2>$null | ForEach-Object { ([string]$_) -replace '://[^/@\s]+@','://<redacted>@' }
Get-ChildItem Env: | Where-Object Name -match 'GIT_SSL'
# 主要リポジトリの有効設定（代表1〜3個で）: cd <repo>; git config --get http.sslBackend; git config --get http.sslCAInfo

# --- curl: 実体ごとに ---
# PATH 上のものだけを見る。PATH 外の curl.exe（Git 同梱の mingw64\bin・ucrt64\bin の curl.exe など）は 3.2 の全ドライブ走査で拾い、6.1 で実測する
where.exe curl
foreach ($c in (where.exe curl)) { "== $c"; & $c --version | Select-Object -First 2 }
# Schannel 版は Windows ストアを使う（curl-ca-bundle.crt があっても使われない）。OpenSSL 版の判定も 6.1 の実測で（バンドルの日付では判定しない）
Get-ChildItem -Path C:\Windows\System32, C:\Windows -Filter curl-ca-bundle.crt -ErrorAction SilentlyContinue
# 証明書の参照先を変える環境変数（今のプロセスと、ユーザー・システムの永続設定）。名前は完全一致の許可リスト。
# JAVA_TOOL_OPTIONS などにはトラストストアのパスワード（-Djavax.net.ssl.trustStorePassword=...）が入りうるので、記録する前に伏せる
# NODE_OPTIONS の --use-system-ca / NODE_USE_SYSTEM_CA は Node が Windows ストアも読むようにする（読むだけで、Windows の不信頼は効かない可能性がある → 実測で）
$caVars = @('SSL_CERT_FILE','SSL_CERT_DIR','CURL_CA_BUNDLE','REQUESTS_CA_BUNDLE','PIP_CERT','NODE_EXTRA_CA_CERTS','NODE_USE_SYSTEM_CA','NODE_OPTIONS',
  'NODE_TLS_REJECT_UNAUTHORIZED','GIT_SSL_NO_VERIFY','GIT_SSL_CAINFO','GIT_SSL_CAPATH','JAVA_TOOL_OPTIONS','_JAVA_OPTIONS','JDK_JAVA_OPTIONS',
  'AWS_CA_BUNDLE','HEX_CACERTS_PATH','BUNDLE_SSL_CA_CERT','CONDA_SSL_VERIFY','UV_NATIVE_TLS','UV_SYSTEM_CERTS')
# 伏せ字は Hide-AuditSecret（キット。引用符で囲まれた値は改行を含めて引用符ごと伏せる）
foreach ($scope in 'Process','User','Machine') {
  $vars = [Environment]::GetEnvironmentVariables($scope)
  foreach ($n in $caVars) { if ($vars.Contains($n)) { "$scope $n=$(Hide-AuditSecret ([string]$vars[$n]))" } }
}
# NODE_TLS_REJECT_UNAUTHORIZED=0 や GIT_SSL_NO_VERIFY は検証そのものを切る設定。見つかったら要是正（本件以前の問題）

# --- Python 配布の棚卸し（実行はせず存在と版のみ） ---
py --list-paths 2>$null
where.exe python; where.exe python3; where.exe pip
# 各 python 実体について: 版 / pip 版 / certifi 版 / 実際の CA 参照先
# 対象は py ランチャー（レジストリ登録。アプリが登録した Astral 版なども出る）+ PATH + Microsoft Store 版 + uv 管理。
# where python だけだと PATH 外の実体が漏れる（例: PATH に入れずに入れた python.org 版、アプリが持つ CPython、Store 版）。
# venv のベースやアプリ同梱の python.exe は 3.2 の全ドライブ走査で拾い、6.1 でまとめて検証する
foreach ($p in (Get-AuditWindowsPythonCandidates)) {
  "== $p"
  & $p --version
  & $p -m pip --version 2>&1
  & $p -c "import certifi,ssl;print('certifi',certifi.__version__,certifi.where())" 2>&1
  & $p -c "import ssl;print('default_verify_paths',ssl.get_default_verify_paths())"
  (& $p -m pip config list 2>&1) -replace '://[^/@\s]+@','://***@'   # cert= 指定の有無（index-url の資格情報は伏せる）
}
uv --version 2>$null; uv python list 2>$null
pipx --version 2>$null; pipx list 2>$null
conda --version 2>$null; conda env list --json 2>$null | Out-File "$out\conda-envs.json"
conda config --show ssl_verify 2>$null   # True 以外（False やファイルのパス）なら、その設定が判定を左右する。False は要是正
pixi --version 2>$null; mise --version 2>$null

# --- アプリ管理の Python 環境（ComfyUI 等）と埋め込み Python ---
# 全ドライブ走査は 3.2 の Find-EnvMarkers が1回で行い、python-exe-found.txt（見つかった python.exe すべて）と
# app-python-dirs.txt に出力する（ここでは再走査しない）。3.1 だけ先に走らせた場合は 3.2 完了後に参照すること。

# --- Node 系 ---
where.exe node; node --version 2>$null; npm --version 2>$null
npm config get cafile 2>$null; npm config get strict-ssl 2>$null
nvm list 2>$null; fnm list 2>$null; volta list 2>$null
bun --version 2>$null; deno --version 2>$null; pnpm --version 2>$null; yarn --version 2>$null

# --- Go / Rust / Java / Composer / .NET ---
go version 2>$null; go env GOROOT 2>$null
rustup --version 2>$null; rustc --version 2>$null; cargo --version 2>$null
# Java: PATH の先頭（java -version）だけでは足りない。アプリ同梱の JRE（例: 古い IDE やデザインツールが同梱する Java 6 / 7）は
# 名前でも PATH でも見つからない。全ドライブの java.exe は 3.2 で集め（実行せずに版を読む）、6.1 で実測する
# java は JAVA_TOOL_OPTIONS 等を「(NOTE: )Picked up ...」として標準エラーに出す（トラストストアのパスワードを含みうる）。
# 出力を捕まえて伏せ字にしてから、版を示す行だけを表示する
foreach ($j in @(where.exe java 2>$null)) {
  try { $r = Invoke-AuditNativeProcess -FilePath $j -ArgumentList @('-version') -TimeoutMs 30000 } catch { "== $j : $($_.Exception.Message)"; continue }
  "== $j"; @((Hide-AuditSecret ($r.StdErr + $r.StdOut)) -split "`r?`n" | Where-Object { $_ -match '^(openjdk|java) version ' })[0]
}
composer --version 2>$null
# Composer: self-update は Composer 本体の証明書だけを直す。各プロジェクトが依存する composer/ca-bundle は別（composer.lock を見る）
#   Select-String -Path <プロジェクト>\composer.lock -Pattern '"name": "composer/ca-bundle"' -Context 0,1
dotnet --list-sdks 2>$null

# --- 対策に使うツール自身 ---
claude --version 2>$null          # Claude Code
where.exe claude 2>$null          # 導入方式（npm / native / winget）
docker --version 2>$null; docker info --format '{{.ServerVersion}}' 2>$null   # ↑は Engine 版。Desktop 本体は↓
(Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Docker Desktop" -ErrorAction SilentlyContinue).DisplayVersion
docker images --format "{{.Repository}}:{{.Tag}}@{{.ID}}" 2>$null | Out-File "$out\docker-images.txt"
docker ps --format "{{.Names}} {{.Image}}" 2>$null | Out-File "$out\docker-ps.txt"

# --- その他エコシステム ---
# Ruby / Perl: 版と設定だけ記録する。どの証明書を使うかは環境変数や gem・モジュールの組み合わせで変わるので、判定は 6.1 の実測で
# （DEFAULT_CERT_FILE はビルド時の既定値で、実際に読まれるとは限らない。Mozilla::CA は入っていても使われないことがある）
where.exe ruby; ruby --version 2>$null; gem --version 2>$null; bundle --version 2>$null
# （Windows PowerShell 5.1 は外部コマンドへの引数の中の二重引用符を落とすので、-e のコードに二重引用符を使わない）
ruby -ropenssl -e 'p OpenSSL::X509::DEFAULT_CERT_FILE, ENV[%q(SSL_CERT_FILE)]' 2>$null
where.exe perl; perl -v 2>$null | Select-String 'This is perl'
perl -MMozilla::CA -e 'print qq(Mozilla::CA $Mozilla::CA::VERSION\n)' 2>$null
# Dart / Flutter / Haskell / Elixir / Erlang
dart --version 2>&1 | Select-Object -First 1; flutter --version 2>$null | Select-Object -First 1
ghc --version 2>$null; cabal --version 2>$null | Select-Object -First 1; stack --version 2>$null
elixir --version 2>$null | Select-Object -Last 1; erl -noshell -eval 'erlang:display(erlang:system_info(otp_release)),halt().' 2>$null
# JetBrains IDE（独自 JBR 同梱 = JDK 更新では直らない。Toolbox or 各 IDE の更新で）
Get-ChildItem "$env:LOCALAPPDATA\JetBrains","$env:LOCALAPPDATA\Programs","C:\Program Files\JetBrains" -Directory -ErrorAction SilentlyContinue | Where-Object Name -match 'IntelliJ|PyCharm|WebStorm|Rider|GoLand|CLion|PhpStorm|RustRover|DataGrip|Android Studio' | Select-Object FullName
# Go 製 CLI（gh, kubectl, terraform, git-lfs, docker CLI 等）: Windows ではシステムストアを使うので本体判定に従う。Linux 上は ca-certificates 依存
gh --version 2>$null | Select-Object -First 1; kubectl version --client 2>$null | Select-Object -First 1; terraform version 2>$null | Select-Object -First 1; git-lfs version 2>$null
Get-Item "$env:ProgramFiles\GitHub CLI\gh.exe" -ErrorAction SilentlyContinue | Select-Object FullName, @{n='Version';e={$_.VersionInfo.ProductVersion}}   # PATH に無いシェル向け
# 配布済みの Go 製バイナリ（自作ツールなど）は、作ったときの Go の版で決まる。手元の go の版とは別: go version -m <exe>
# クラウド CLI（Python と certifi を同梱するものがある。判定は版と配布元の告知で。設定の CA 指定も記録）
aws --version 2>$null; aws configure get ca_bundle 2>$null
az version 2>$null; az config get core.ca_bundle 2>$null   # 実行時の REQUESTS_CA_BUNDLE も上の環境変数で確認済み
gcloud version 2>$null | Select-Object -First 1; gcloud config get core/custom_ca_certs_file 2>$null
# Rust 製 CLI で rustls+webpki-roots を内蔵するもの（fnm, volta, mise, uv 等）: 各ツールの更新で
fnm --version 2>$null; volta --version 2>$null

# --- VCS その他 ---
hg --version 2>$null | Select-Object -First 1
svn --version 2>$null | Select-Object -First 1
# TortoiseSVN の svn.exe は PATH に入らないことがある（コマンドラインツールを選んだときだけ入る）。無ければ 6.1 は画面での確認になる
Get-Item "$env:ProgramFiles\TortoiseSVN\bin\svn.exe" -ErrorAction SilentlyContinue | Select-Object FullName, @{n='Version';e={$_.VersionInfo.ProductVersion}}

# --- Electron 系と内蔵 Bun（版と内蔵 Electron 版・Bun 版） ---
# アプリ名の一覧で絞らない（周辺機器の設定ツールなど、名前から Electron と分からないものがある）。
# インストール先と LOCALAPPDATA / Program Files 配下の大きな exe（60MB 以上、深さ3まで）から「Electron/x.y.z」を探す。数十秒かかる。
# resources\app\package.json の electron 欄はビルド用スクリプトのことがある（VS Code）ので版の根拠にしない
# 同じ読み込みで「Bun vx.y.z」も拾う（Claude Code のネイティブ版や `bun build --compile` で作った CLI。Brotli の件、6.4）。
# ~/.local（Claude Code ネイティブ版）、%APPDATA%\npm、~/.bun も探す
$electronRoots = @($uninstall | ForEach-Object { $_.InstallLocation } | Where-Object { $_ }) +
  @($env:LOCALAPPDATA, $env:ProgramFiles, ${env:ProgramFiles(x86)}, "$env:USERPROFILE\.local", "$env:APPDATA\npm", "$env:USERPROFILE\.bun")
# リンク（ジャンクション等）とクラウドのプレースホルダーには降りず、クラウドにだけある exe は開かない（v2.11.3。開くとダウンロードが始まる）。
# 降りなかった・読めなかった場所は electron-scan-skipped.txt に残す（未探索として報告）
$electronSkipped = [System.Collections.Generic.List[string]]::new()
$electron = @(Find-AuditElectronApps -Root $electronRoots -Errors $electronSkipped)
Write-AuditUtf8 -Path "$out\electron-scan-skipped.txt" -Text $(if ($electronSkipped.Count) { ($electronSkipped -join "`n") + "`n" } else { '' })
"Electron 走査で降りなかった・読めなかった場所: $($electronSkipped.Count) 件 → electron-scan-skipped.txt"
$electron | Export-Csv "$out\electron-apps.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop; Write-AuditUtf8 -Path "$out\electron-apps.csv.ok" -Text "v2.10 $(Get-Date -Format o)`n"   # 6.4 が「v2.10 で走査した」ことを確かめる目印（0 件でも残る）
$electron | Format-Table -AutoSize
# 修正版は 44.9.1 / 43.8.1 / 42.11.16（4章）。同じメジャーでこれ未満、または 41 以前は要更新（ベンダー任せの残件）。
# Bun 列（内蔵 Bun の版）は 6.4 で Brotli の修正版（1.4.4）と照合する
# アプリ内更新はダウンロードしただけでは exe が入れ替わらない。アプリを終了して起動し直してから再取得する

# --- 常駐プロセス（更新後の再起動対象） ---
Get-Process | Where-Object { $_.Name -match 'node|Code|Cursor|slack|Discord|Obsidian|claude|Docker|python' } | Select-Object Name, Id, Path -Unique | Out-File "$out\running-processes.txt"

} *>&1 | Out-String -Stream -Width 400 | Tee-Object -FilePath "$out\windows-audit.log"
```

### 3.2 venv の網羅探索（Windows: 全固定ドライブ）

`pyvenv.cfg` 基準で検出（venv / virtualenv / uv / poetry / pipenv / PDM / hatch 共通）。
埋め込み Python・アプリ管理環境は 3.1 の `app-python-dirs.txt` と突き合わせる。

```powershell
$out = "$HOME\emudhra-audit"; New-Item -ItemType Directory -Force $out | Out-Null   # 3.1 と並列実行するので自前で作る
. "$out\kit\Test-Emudhra.Helpers.ps1"   # Get-AuditJavaInfo（java.exe を実行せずに版を読む）
# 前回の一覧を残す（上書きすると、再実行したときに何が増えた・消えたかが分からなくなる）。最後に差分を表示する
$lists32 = 'python-exe-found.csv','tool-exe-found.csv','java-found.csv','frozen-python-found.csv','frozen-onefile-found.csv','ca-file-found.csv','brotli-lib-found.csv','supply-chain-ioc.csv','venv-inventory.csv'
$prev32 = $null
if (@($lists32 | Where-Object { Test-Path -LiteralPath "$out\$_" }).Count) {
  $prev32 = "$out\prev-3.2-$(Get-Date -Format 'yyyyMMdd-HHmmss')"; New-Item -ItemType Directory -Path $prev32 | Out-Null
  foreach ($n in $lists32) { if (Test-Path -LiteralPath "$out\$n") { Copy-Item -LiteralPath "$out\$n" -Destination "$prev32\$n" -ErrorAction Stop } }
  "前回の一覧: $prev32"
}
# 古い目印を先に消す。あるのに消せなければ止める（古い結果を新しいものと取り違えないため）
foreach ($n in 'frozen-python-found.csv','frozen-onefile-found.csv','ca-file-found.csv','brotli-lib-found.csv','supply-chain-ioc.csv') { if (Test-Path -LiteralPath "$out\$n.ok") { Remove-Item -LiteralPath "$out\$n.ok" -ErrorAction Stop } }
# brotli-lib-found.csv と supply-chain-ioc.csv は 0 件のとき Export-Csv がファイルを作らないので、前回の中身が残らないよう先に消す（前回分は上で prev-3.2 に写してある）
foreach ($n in 'brotli-lib-found.csv','supply-chain-ioc.csv') { if (Test-Path -LiteralPath "$out\$n") { Remove-Item -LiteralPath "$out\$n" -ErrorAction Stop } }
# 走査するドライブ（v2.11.3）。DriveType=3（固定）でも、Get-Partition に出ないものは既定で外す
# （例: クラウドストレージのクライアントが作る仮想ドライブ。中のファイルを開くとダウンロードが始まりうる）。
# Get-Partition に出ない＝仮想ドライブとは限らない（ダイナミックディスクのボリューム、他社製の仮想ブロックデバイスなど）。外れた表を見て、
# 正当なローカルのボリュームと分かったら、下の $includeDrives に書いて再実行する。
# ほかに外すドライブがあれば $excludeDrives に書く（ユーザーに確かめてから）。リムーバブル（SD カード等）は走査しないので、開発環境を置いていないか確かめる。
# ドライブ文字の無いマウント（フォルダにマウントしたボリューム）は表に出ない。走査中に見つかればリンクとして降りずに venv-scan-skipped-links.txt に残る。
# 走査したドライブは drives-scanned.txt に残し、6.4 の手順9も同じドライブだけを調べる。外したドライブ（drives-not-scanned.txt）は報告書の未探索に書く
# 前回の一覧は先に消す（この 3.2 が途中で止まったとき、6.4 が古い一覧を使わないように）。あるのに消せなければ止める
foreach ($n in 'drives-scanned.txt','drives-not-scanned.txt') { if (Test-Path -LiteralPath "$out\$n") { Remove-Item -LiteralPath "$out\$n" -ErrorAction Stop } }
$excludeDrives = @()   # 例: @('X:\')
$includeDrives = @()   # Get-Partition に出ないが、手で確かめて正当なローカルのボリュームと分かったもの。例: @('E:\')
$partLetters = @(Get-Partition -ErrorAction Stop | Where-Object DriveLetter | ForEach-Object { "$($_.DriveLetter):\" })
if ($partLetters.Count -eq 0) { throw 'Get-Partition からドライブ文字を得られない（走査するドライブを決められないので止める）' }
$diskRows = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2, 3 } | ForEach-Object {
  $id = $_.DeviceID + '\'
  $why = if ($_.DriveType -eq 2) { 'removable (not scanned)' } elseif ($excludeDrives -contains $id) { 'excluded by $excludeDrives' } elseif ($partLetters -notcontains $id -and $includeDrives -notcontains $id) { 'not represented by Get-Partition (not scanned; classify manually)' } else { '' }
  [pscustomobject]@{ Drive = $id; VolumeName = $_.VolumeName; FileSystem = $_.FileSystem; Scan = (-not $why); Reason = $why } })
$diskRows | Format-Table -AutoSize | Out-String -Width 200
$drives = @($diskRows | Where-Object Scan | ForEach-Object Drive)
if ($drives.Count -eq 0) { throw '走査するドライブが無い' }
Write-AuditUtf8 -Path "$out\drives-scanned.txt" -Text (($drives -join "`n") + "`n")
$notScanned = @($diskRows | Where-Object { -not $_.Scan } | ForEach-Object { "$($_.Drive)`t$($_.VolumeName)`t$($_.Reason)" })
Write-AuditUtf8 -Path "$out\drives-not-scanned.txt" -Text $(if ($notScanned.Count) { ($notScanned -join "`n") + "`n" } else { '' })
# 降りないディレクトリ（再帰前に枝刈り）。pyvenv.cfg は venv ルート直下、conda-meta は env ルート直下にあるので
# Lib / site-packages / __pycache__ の中に降りる必要はない。
# ProgramData（Anaconda 既定の envs 置き場）と OneDrive（Documents リダイレクト先）は除外しない。
# OneDrive のオンデマンドファイルは列挙だけでは実体化されない（python.exe を起動した venv のみ取り込まれる）。
$prune = @('$Recycle.Bin','System Volume Information','Windows','node_modules','.git','__pycache__','site-packages','Lib','lib','pkgs','Temp')
$errors = [System.Collections.Generic.List[string]]::new()

function Parse-Ver([string]$v) {   # PEP 440 のサフィックス（b1 / .post1 / rc / dev）を落として [version] に
  if (-not $v) { return $null }
  $clean = ($v -replace '[^0-9.].*$','').TrimEnd('.')
  try { [version]$clean } catch { $null }
}

# 1回の走査で pyvenv.cfg（venv）と conda-meta（conda env）を両方収集
$condaFound = [System.Collections.Generic.List[string]]::new()
$skippedLinks = [System.Collections.Generic.List[string]]::new()   # 降りなかったジャンクション/シンボリックリンク（別途確認用）
$embeddedFound = [System.Collections.Generic.List[string]]::new()   # 埋め込み Python / アプリ管理フォルダ（pyvenv.cfg を持たない）
$pythonExeFound = [System.Collections.Generic.List[string]]::new()  # 見つかった python.exe すべて（アプリ同梱・venv のベースなど、py ランチャーに出ないもの）
$toolExeFound = [System.Collections.Generic.List[string]]::new()    # java.exe / keytool.exe / curl.exe / svn.exe / git.exe / uv.exe / node.exe / bun.exe（アプリ同梱の JRE・Git・uv・Node、Git 同梱の curl、TortoiseSVN など）
$pyDllDirs = [System.Collections.Generic.List[string]]::new()       # python3*.dll のあるフォルダ（python.exe が無ければ PyInstaller 等で固めたアプリ。例: フォルダ型の _internal）
$caFileFound = [System.Collections.Generic.List[string]]::new()     # cacert.pem（固めたアプリやツールが抱える証明書の一覧。6.4 で一覧ごとに実測）
$specFound = [System.Collections.Generic.List[string]]::new()       # *.spec（自分の開発環境で PyInstaller を使っている印。単一 exe 型の判定はその dist だけ）
$brotliLibFound = [System.Collections.Generic.List[string]]::new()  # Brotli を抱えるライブラリ（名前で拾う。Get-AuditBrotliLibKind。6.4 でハッシュ・版を見て判定）
$iocCandidates = [System.Collections.Generic.List[string]]::new()   # サプライチェーン攻撃の痕跡を読む候補（Get-AuditIocCandidateKind。LiteLLM 1.107.0・GhostAction 型・tensorlake。v2.12.2）
$appDirPat = '^(python_embeded|python_embedded|ComfyUI.*|StabilityMatrix.*|.*webui.*|.*forge.*|stable-diffusion.*)$'
# Python の wheel が抱えるライブラリ（<site-packages>\<パッケージ>.libs\libbrotlidec-<ハッシュ>.dll）。Lib / site-packages には降りない（$prune）ので、
# その直下の *.libs だけをここで見る。$dir は Lib または site-packages。リンクとクラウドのプレースホルダーには降りない
function Find-WheelLibs([string]$dir) {
  $sp = if ([IO.Path]::GetFileName($dir) -ieq 'site-packages') { $dir } else { Join-Path $dir 'site-packages' }
  if (-not [System.IO.Directory]::Exists($sp)) { return }
  try {
    foreach ($d in @($dir, $sp) | Select-Object -Unique) { if ((Get-Item -LiteralPath $d -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { $script:skippedLinks.Add($d); return } }
    foreach ($l in [System.IO.Directory]::EnumerateDirectories($sp)) {
      if ([IO.Path]::GetFileName($l) -notlike '*.libs') { continue }
      if ((Get-Item -LiteralPath $l -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { $script:skippedLinks.Add($l); continue }
      foreach ($f in [System.IO.Directory]::EnumerateFiles($l)) { if ((Get-AuditBrotliLibKind -Path $f) -eq 'brotli-lib') { $script:brotliLibFound.Add($f) } }
    }
  } catch { $script:errors.Add("$sp : $($_.Exception.Message)") }
}
function Find-SitePackagesIoc([string]$dir) {
  # LiteLLM 1.107.0 の痕跡: site-packages 直下の cook.pth / cook.py と litellm-1.107.0.dist-info（Lib の場合は Lib\site-packages を見る）
  # Linux 用の venv（Windows のドライブに置いたもの）は lib\python3.x\site-packages。途中のフォルダがリンクなら、たどらずに記録する
  if (Test-AuditIsLink $dir) { return }
  $sps = if ([IO.Path]::GetFileName($dir) -ieq 'site-packages') { @($dir) } else {
    @(Join-Path $dir 'site-packages') + @(try { [System.IO.Directory]::EnumerateDirectories($dir, 'python3*') | Where-Object { -not (Test-AuditIsLink $_) } | ForEach-Object { Join-Path $_ 'site-packages' } } catch { $script:errors.Add("$dir : $($_.Exception.Message)") }) }
  foreach ($sp in $sps) {
    if (-not [System.IO.Directory]::Exists($sp) -or (Test-AuditIsLink $sp) -or -not (Test-AuditCanList $sp)) { continue }
    foreach ($n in 'cook.pth','cook.py','litellm-1.107.0.dist-info') { $c = Join-Path $sp $n; if (([System.IO.File]::Exists($c) -or [System.IO.Directory]::Exists($c)) -and -not (Test-AuditIsLink $c)) { $script:iocCandidates.Add($c) } }
  }
}
function Test-AuditCanList([string]$p) {
  # 中を一覧できるか（アクセス拒否のフォルダは Exists が $false を返すだけなので、ここで確かめて未確認として記録する）
  try { $e = [System.IO.Directory]::EnumerateFileSystemEntries($p).GetEnumerator(); [void]$e.MoveNext(); $true } catch { $script:errors.Add("$p : IOC check: cannot list ($($_.Exception.Message))"); $false }
}
function Test-AuditIsLink([string]$p) {
  # リンク（ジャンクション・シンボリックリンク）なら未走査リンクに記録して $true。たどらない
  try { if ((Get-Item -LiteralPath $p -Force -ErrorAction Stop).Attributes -band [IO.FileAttributes]::ReparsePoint) { $script:skippedLinks.Add($p); return $true } } catch { $script:errors.Add("$p : $($_.Exception.Message)"); return $true }
  $false
}
function Find-EnvMarkers([string]$dir) {
  try { $items = [System.IO.Directory]::EnumerateFileSystemEntries($dir) } catch { $script:errors.Add("$dir : $($_.Exception.Message)"); return }
  foreach ($i in $items) {
    $name = [System.IO.Path]::GetFileName($i)
    if ([System.IO.Directory]::Exists($i)) {
      if ($name -ieq 'conda-meta') { $script:condaFound.Add($dir); continue }
      if ($name -imatch $appDirPat -and ((Test-Path (Join-Path $i 'python.exe')) -or $name -inotmatch '^python_embed')) { $script:embeddedFound.Add($i) }   # 記録して走査は続行（配下の venv も拾う）
      if ($name -ieq 'Lib' -or $name -ieq 'site-packages') { Find-WheelLibs $i; Find-SitePackagesIoc $i }   # 降りない代わりに *.libs と LiteLLM の痕跡だけ見る
      if ($name -ieq 'node_modules' -and -not (Test-AuditIsLink $i) -and (Test-AuditCanList $i) -and [System.IO.Directory]::Exists((Join-Path $i 'tensorlake'))) {   # 降りない代わりに直下の tensorlake だけ見る（途中がリンクならたどらない。一覧できなければ未確認）
        $tl = Join-Path $i 'tensorlake'
        if (-not (Test-AuditIsLink $tl) -and (Test-AuditCanList $tl) -and [System.IO.File]::Exists((Join-Path $tl 'package.json'))) { $script:iocCandidates.Add((Join-Path $tl 'package.json')) }
      }
      if ($prune -contains $name) { continue }
      try { if ((Get-Item -LiteralPath $i -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { $script:skippedLinks.Add($i); continue } } catch { continue }  # 循環防止。リンク先は記録して別途確認
      Find-EnvMarkers $i
    } elseif ($name -ieq 'pyvenv.cfg') { $i }
    # WindowsApps の python.exe はエイリアス（Store 版が無いとストアが開く）なので除外。Store 版は Get-AuditWindowsPythonCandidates で拾う
    elseif ($name -ieq 'python.exe' -and $dir -notmatch '\\WindowsApps(\\|$)') { $script:pythonExeFound.Add($i) }
    # git.exe / uv.exe: ポータブル版のアプリが同梱するもの（PortableGit や uv など）。インストール一覧にも PATH にも出ない
    elseif ($name -imatch '^(java|keytool|curl|svn|git|uv|node|bun|dotnet)\.exe$') { $script:toolExeFound.Add($i) }
    elseif ($name -imatch '^python3\d*\.dll$') { $script:pyDllDirs.Add($dir) }
    elseif ($name -ieq 'cacert.pem') { $script:caFileFound.Add($i) }
    # Brotli を抱えるライブラリ。先に名前の粗い絞り込み（全ファイルで関数を呼ばないため）、正確な規則は Get-AuditBrotliLibKind（共有ランタイム内の .NET の DLL は除く）
    elseif ($name -imatch '^(libbrotlidec|brotlidec|CORE_RL_brotli_|libcef\.dll|Qt[56]WebEngineCore|System\.IO\.Compression\.Native)') { if (Get-AuditBrotliLibKind -Path $i) { $script:brotliLibFound.Add($i) } }
    elseif ($name -like '*.spec') { $script:specFound.Add($i) }
    # ワークフロー・ロックファイル・.vscode\tasks.json・.claude の設定（名前で粗く絞ってから、場所の規則は Get-AuditIocCandidateKind）
    elseif ($name -imatch '\.ya?ml$|^(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|bun\.lock|tasks\.json|settings(\.local)?\.json)$') { if (Get-AuditIocCandidateKind -Path $i) { $script:iocCandidates.Add($i) } }
  }
}

$cfgs = foreach ($d in $drives) { Find-EnvMarkers $d }
$errors | Out-File "$out\venv-scan-errors.txt"
$skippedLinks | Out-File "$out\venv-scan-skipped-links.txt"   # 開発フォルダへのジャンクションがあれば、そのリンク先を $drives に追加して再走査
# Windows PowerShell 5.1 の Out-File は UTF-16LE / BOM 付きになるので、一覧は UTF-8（BOM なし）で書く
[IO.File]::WriteAllText("$out\app-python-dirs.txt", (($embeddedFound | Sort-Object -Unique) -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText("$out\python-exe-found.txt", (($pythonExeFound | Sort-Object -Unique) -join "`n") + "`n", [Text.UTF8Encoding]::new($false))   # 6.1 が参照する
# 見つかった python.exe はここでは実行しない（展開しただけのアーカイブなど、出所の分からないものも拾うため）。
# ファイル情報だけ記録し、6.1 の手順2で一覧を確認してから実行する
# 版の情報を読むとファイルを開くので、クラウドにだけあるもの（開くとダウンロードが始まる）は読まずに印を付ける
$pythonExeFound | Sort-Object -Unique | ForEach-Object { Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue } |
  Select-Object FullName, @{n='ProductVersion';e={ if (Test-AuditCloudOnly -Item $_) { '(cloud-only, not read)' } else { $_.VersionInfo.ProductVersion } }},
    @{n='CompanyName';e={ if (Test-AuditCloudOnly -Item $_) { '' } else { $_.VersionInfo.CompanyName } }}, LastWriteTime |
  Export-Csv "$out\python-exe-found.csv" -NoTypeInformation -Encoding UTF8
# java.exe / keytool.exe / curl.exe / svn.exe / git.exe / uv.exe / node.exe / bun.exe も同じく実行しない（C:\Windows は走査しないので System32 の curl.exe は 3.1 の where.exe で見る）
$toolExeFound | Sort-Object -Unique | ForEach-Object { Get-Item -LiteralPath $_ -ErrorAction SilentlyContinue } |
  Select-Object @{n='Tool';e={$_.BaseName.ToLowerInvariant()}}, FullName, @{n='ProductVersion';e={ if (Test-AuditCloudOnly -Item $_) { '(cloud-only, not read)' } else { $_.VersionInfo.ProductVersion } }},
    @{n='CompanyName';e={ if (Test-AuditCloudOnly -Item $_) { '' } else { $_.VersionInfo.CompanyName } }}, LastWriteTime |
  Export-Csv "$out\tool-exe-found.csv" -NoTypeInformation -Encoding UTF8
# Java は release ファイル（無ければファイルの版）から版を読み、cacerts の場所も記録する。11 未満はキットでは実測できない（UNKNOWN。Java 8 は修正版あり、6 / 7 などは修正の提供なし。4章）
# Get-AuditJavaInfo は release も java.exe も、クラウドにだけあるものは開かない（VersionSource = cloud-only、版は空）
@($toolExeFound | Where-Object { [IO.Path]::GetFileName($_) -ieq 'java.exe' } | Sort-Object -Unique | ForEach-Object { Get-AuditJavaInfo -JavaExe $_ }) |
  Export-Csv "$out\java-found.csv" -NoTypeInformation -Encoding UTF8
# 固めた Python のアプリ（python3*.dll はあるが python.exe が無いフォルダ）。python.exe を持たないので Python の走査に出ない。
# 中の版は 6.4 で dist-info の名前から読む（実行しない）。同じフォルダと親フォルダの exe を、何のアプリかの手がかりに記録する
@($pyDllDirs | Sort-Object -Unique | Where-Object { -not (Test-Path -LiteralPath (Join-Path $_ 'python.exe')) } | ForEach-Object {
  $dll = @(Get-ChildItem -LiteralPath $_ -Filter 'python3*.dll' -File -ErrorAction SilentlyContinue)
  $exes = @(Get-ChildItem -LiteralPath $_, (Split-Path -Parent $_) -Filter *.exe -File -ErrorAction SilentlyContinue | ForEach-Object Name | Sort-Object -Unique)
  $dllText = ($dll | ForEach-Object { if (Test-AuditCloudOnly -Item $_) { "$($_.Name) (cloud-only, not read)" } else { "$($_.Name) $($_.VersionInfo.ProductVersion)" } }) -join '; '
  [pscustomobject]@{ Dir = $_; PythonDll = $dllText; Exes = ($exes -join '; ') }
}) | Export-Csv "$out\frozen-python-found.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop; Write-AuditUtf8 -Path "$out\frozen-python-found.csv.ok" -Text "v2.10 $(Get-Date -Format o)`n"   # 6.4 が「v2.10 で走査した」ことを確かめる目印（0 件でも残る）
# PyInstaller の単一 exe 型（--onefile）: Python の DLL・拡張・cacert.pem を exe の中に持ち、起動したときに一時フォルダへ展開するので、
# 上の走査では中身が見えない。**自分の開発環境で作ったものだけを調べる**（方針。他人が作った単一 exe 型は中を直せないので、全ドライブの exe は開かない。
# 全 exe の末尾を読む方式は、ウイルス対策の検査とクラウドのファイルで極端に遅くなる）。
# 開発環境の印は PyInstaller の設定ファイル（*.spec）と、その隣の dist フォルダ。中身は読まない（書き方の違いで見逃さないため）。
# dist の下の exe だけ、末尾の目印を読む（実行しない）。PyInstaller 以外の .spec の隣に dist があっても、目印が無ければ何も記録されない。
# フォルダ型の起動用 exe にも同じ目印がある。同じフォルダか _internal に python3*.dll があるものは「形式を確定できない」として Kind で区別して残す。
# クラウドにだけあるファイル（OneDrive のオンデマンド等）は開かない（開くとダウンロードが始まる）。読めなかったものは走査エラーに残す
$onefileRows = [System.Collections.Generic.List[object]]::new()
# 同じフォルダに複数の .spec（コンソール版・GUI 版など）があっても、dist は一度だけ調べる。対応する .spec はまとめて記録する
$distSpecs = @{}
foreach ($spec in @($specFound | Sort-Object -Unique)) {
  $dist = Join-Path (Split-Path -Parent $spec) 'dist'
  if (-not (Test-Path -LiteralPath $dist -PathType Container)) { continue }
  if (-not $distSpecs.ContainsKey($dist)) { $distSpecs[$dist] = [System.Collections.Generic.List[string]]::new() }
  $distSpecs[$dist].Add($spec)
}
foreach ($dist in @($distSpecs.Keys | Sort-Object)) {
  $spec = ($distSpecs[$dist] | Sort-Object) -join '; '
  # リンク（ジャンクション等）はたどらない（dist の外の exe を開かない）。読めなかった場所と、たどらなかったリンクは走査エラーに残す
  $distExes = @(Get-AuditFilesNoLinks -Root $dist -Filter '*.exe' -Errors $errors)
  foreach ($exe in $distExes) {
    if (Test-AuditCloudOnly -Item $exe) { $errors.Add("$($exe.FullName) : onefile check: cloud-only, not read"); continue }
    $hit = $false
    try { $hit = Test-AuditPyInstallerOnefile -Path $exe.FullName } catch { $errors.Add("$($exe.FullName) : onefile check: $($_.Exception.Message)") }
    if (-not $hit) { continue }
    $dll = @(Get-ChildItem -LiteralPath $exe.DirectoryName, (Join-Path $exe.DirectoryName '_internal') -Filter 'python3*.dll' -File -ErrorAction SilentlyContinue)
    $kind = if ($dll.Count -eq 0) { 'onefile' } else { 'undetermined' }
    $onefileRows.Add([pscustomobject]@{ FullName = $exe.FullName; Kind = $kind; Spec = $spec; ProductVersion = $exe.VersionInfo.ProductVersion; CompanyName = $exe.VersionInfo.CompanyName; LastWriteTime = $exe.LastWriteTime.ToString('s') }) }
}
@($onefileRows) | Export-Csv "$out\frozen-onefile-found.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop; Write-AuditUtf8 -Path "$out\frozen-onefile-found.csv.ok" -Text "v2.10 $(Get-Date -Format o)`n"   # 6.4 が「v2.10 で走査した」ことを確かめる目印（0 件でも残る）
$errors | Out-File "$out\venv-scan-errors.txt"   # 単一 exe 型の判定で読めなかったものも、走査エラーとして残す
# 証明書の一覧ファイル（site-packages の中は降りないので、venv の certifi はここに出ない。venv は 3.2 / 6.1 の Python 判定で見る）
@($caFileFound | Sort-Object -Unique | ForEach-Object {
  # 読めなかったファイルも落とさず Error 列つきで残す（6.4 で UNKNOWN）。catch の中の $_ はエラーなので、パスは先に取っておく
  $caPath = $_
  try { $fi = Get-Item -LiteralPath $caPath -ErrorAction Stop
        if (Test-AuditCloudOnly -Item $fi) { throw 'cloud-only (not downloaded; open it to fetch, then rerun)' }
        [pscustomobject]@{ FullName = $caPath; Length = $fi.Length; LastWriteTime = $fi.LastWriteTime.ToString('s'); Sha256 = (Get-FileHash -LiteralPath $caPath -ErrorAction Stop).Hash.ToLowerInvariant(); Error = '' } }
  catch { [pscustomobject]@{ FullName = $caPath; Length = ''; LastWriteTime = ''; Sha256 = ''; Error = $_.Exception.Message } }
}) | Export-Csv "$out\ca-file-found.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop; Write-AuditUtf8 -Path "$out\ca-file-found.csv.ok" -Text "v2.10 $(Get-Date -Format o)`n"   # 6.4 が「v2.10 で走査した」ことを確かめる目印（0 件でも残る）

# Brotli を抱えるライブラリ（v2.12）。名前だけで拾い、中身は読まない。読むのはファイル情報と版のリソースだけで、クラウドにだけあるファイルとリンクは開かない（Note に残る）。
# Kind: brotli-lib（libbrotlidec*.dll / brotlidec.dll / CORE_RL_brotli_.dll。Git 同梱・アプリ同梱・Python の wheel 同梱）、cef（libcef.dll）、qtwebengine（Qt5/Qt6WebEngineCore.dll）、
# dotnet-native（共有ランタイムの外にある System.IO.Compression.Native.dll = 単体配布の .NET アプリ。ネイティブの Brotli はこの DLL）。curl -V に出ないので 6.4 でハッシュ・版を見る
@($brotliLibFound | Sort-Object -Unique | ForEach-Object { Get-AuditBrotliLibRow -Path $_ }) |
  Export-Csv "$out\brotli-lib-found.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop; Write-AuditUtf8 -Path "$out\brotli-lib-found.csv.ok" -Text "v2.12 $(Get-Date -Format o)`n"   # 6.4 が「v2.12 で走査した」ことを確かめる目印（0 件でも残る）

# サプライチェーン攻撃の痕跡（v2.12.2）: LiteLLM 1.107.0（cook.pth / cook.py）、GhostAction 型のワークフロー（攻撃者の文字列・全シークレットの書き出し）、
# tensorlake 0.5.144（ChainDrop。ロックファイル・node_modules・.claude の設定・フォルダを開くと動く .vscode のタスク）。判定は Get-AuditIocFinding。
# 読むのは候補のテキストだけ（50 MB まで）で、実行しない。クラウドにだけあるファイルとリンクは開かない（走査エラーに残す）。
# HIGH = 公表された痕跡と一致（すぐ相談。鍵・トークンの無効化が要る）、CHECK = 正当なこともある（誰が追加したか・版を確かめる）
$iocRows = foreach ($c in @($iocCandidates | Sort-Object -Unique)) {
  try {
    $text = ''
    if ([System.IO.File]::Exists($c)) {
      $fi = Get-Item -LiteralPath $c -Force
      # クラウドにだけあるもの・リンクは読まない。OneDrive をやめたフォルダのように、クラウドの印だけが残って中身がローカルにあるファイルは読む（v2.12.7）
      $skip = Get-AuditReadSkipReason -Item $fi
      if ($skip) { $errors.Add("$c : IOC check: $skip, not read"); continue }
      if ($fi.Length -le 50MB) { $text = [IO.File]::ReadAllText($c) } else { $errors.Add("$c : IOC check: larger than 50 MB, not read"); continue }
    }
    Get-AuditIocFinding -Path $c -Text $text
  } catch { $errors.Add("$c : IOC check: $($_.Exception.Message)") }
}
@($iocRows | Where-Object { $_ }) | Export-Csv "$out\supply-chain-ioc.csv" -NoTypeInformation -Encoding UTF8 -ErrorAction Stop
Write-AuditUtf8 -Path "$out\supply-chain-ioc.csv.ok" -Text "v2.12.2 $(Get-Date -Format o) candidates=$(@($iocCandidates | Sort-Object -Unique).Count)`n"
$errors | Out-File "$out\venv-scan-errors.txt"   # IOC の確認で読めなかったものも走査エラーに足す

$inventory = foreach ($cfg in $cfgs) {
  $root = Split-Path $cfg
  $pyWin = Join-Path $root 'Scripts\python.exe'
  $pyLin = Join-Path $root 'bin\python'
  $kind = if (Test-Path $pyWin) { 'windows' } elseif (Test-Path $pyLin) { 'linux' } else { 'unknown' }
  $pyExec = $null; $pyVer = ''; $pyErr = ''; $pip = ''; $cert = ''; $certPath = ''; $req = ''
  if ($kind -eq 'windows') {
    $pyVer = (& $pyWin --version 2>&1 | Out-String).Trim(); $pyExec = ($LASTEXITCODE -eq 0)
    if (-not $pyExec) { $pyErr = $pyVer }
    else {
      $pip  = (& $pyWin -m pip --version 2>&1 | Out-String).Trim() -replace '^pip (\S+).*','$1'
      if ($LASTEXITCODE -ne 0) { $pip = 'none' }
      $c = (& $pyWin -c "import certifi;print(certifi.__version__);print(certifi.where())" 2>&1 | Out-String).Trim() -split "`n"
      if ($LASTEXITCODE -eq 0) { $cert = $c[0].Trim(); $certPath = $c[1].Trim() } else { $cert = 'none' }
      & $pyWin -c "import requests" 2>$null; $req = if ($LASTEXITCODE -eq 0) { 'yes' } else { 'no' }
    }
  }
  # 要更新の判定は先に計算する（$( ) の中で代入すると代入の結果も出力されて配列になり、常に真になる。v2.10.1 までの不具合）
  $needCert = $false; if ($cert -and $cert -ne 'none') { $cv = Parse-Ver $cert; $needCert = if ($cv) { $cv -lt [version]'2026.10.19' } else { $true } }
  $needPip = $false; if ($pip -and $pip -ne 'none') { $pv = Parse-Ver $pip; $needPip = if ($pv) { $pv -lt [version]'26.2.2' } else { $true } }
  $home_ = (Select-String -Path $cfg -Pattern '^home\s*=\s*(.+)$' | ForEach-Object { $_.Matches[0].Groups[1].Value })
  $appManaged = ($root -match 'ComfyUI|StabilityMatrix|webui|forge|automatic1111' )
  [PSCustomObject]@{
    venv          = $root
    kind          = $kind
    python        = $(if ($kind -eq 'windows') { $pyWin } elseif ($kind -eq 'linux') { $pyLin } else { '' })
    base_python   = $home_
    app_managed   = $appManaged
    python_exec   = $pyExec
    python_ver    = $pyVer
    python_err    = $pyErr
    pip           = $pip
    certifi       = $cert
    certifi_path  = $certPath
    requests      = $req
    # 対象コンポーネント別フラグ（どれか True なら更新候補）
    need_certifi  = $needCert
    need_pip      = $needPip
    ca_path_check = ($cert -eq 'none')   # certifi 無し = 対象外ではなく「CA利用経路を確認」
  }
}
$inventory | Export-Csv "$out\venv-inventory.csv" -NoTypeInformation -Encoding UTF8
$inventory | Format-Table venv, kind, app_managed, python_exec, pip, certifi, need_certifi, need_pip, ca_path_check -AutoSize
# 件数は @() で数える（Windows PowerShell 5.1 では、1件だけ当てはまったオブジェクトの .Count が空になる）
"検出: $(@($inventory).Count) / windows: $(@($inventory|? kind -eq windows).Count) / linux(WSL用): $(@($inventory|? kind -eq linux).Count) / unknown: $(@($inventory|? kind -eq unknown).Count)"
"need_certifi: $(@($inventory|? need_certifi).Count) / need_pip: $(@($inventory|? need_pip).Count) / ca_path_check: $(@($inventory|? ca_path_check).Count) / python起動不可: $(@($inventory|? {$_.kind -eq 'windows' -and -not $_.python_exec}).Count)"
"走査エラー: $($errors.Count) 件 / 未走査リンク: $($skippedLinks.Count) 件 / Brotli ライブラリ: $(@($brotliLibFound | Sort-Object -Unique).Count) 件（brotli-lib-found.csv）"
$iocList = @($iocRows | Where-Object { $_ })
"サプライチェーン攻撃の痕跡: 候補 $(@($iocCandidates | Sort-Object -Unique).Count) 件を確認 / HIGH $(@($iocList | Where-Object Level -eq 'HIGH').Count) / CHECK $(@($iocList | Where-Object Level -eq 'CHECK').Count)（supply-chain-ioc.csv）"
$iocList | ForEach-Object { "  $($_.Level) $($_.What): $($_.FullName) $($_.Detail)" }
if (@($iocList | Where-Object Level -eq 'HIGH').Count) { Write-Warning 'HIGH の痕跡がある。そのプログラムを使わず、ネットから切り離すかを相談する（鍵・トークンの無効化、CI のシークレットの入れ替えが要る）' }
# 前回との差分（場所の列で比べる: FullName / Dir / Java / venv。6.1 手順2 の一覧確認は、ここで増えたものを中心に見る）
function Get-Key32([string]$f) {
  if (-not (Test-Path -LiteralPath $f)) { return @() }
  $rows = @(Import-Csv -LiteralPath $f -Encoding UTF8); if ($rows.Count -eq 0) { return @() }
  $col = @('FullName','Dir','Java','venv' | Where-Object { $rows[0].PSObject.Properties.Name -contains $_ })[0]
  if (-not $col) { $col = @($rows[0].PSObject.Properties)[0].Name }
  $rows | ForEach-Object { $_.$col }
}
if ($prev32) {
  foreach ($n in $lists32) {
    $old = @(Get-Key32 "$prev32\$n")
    $new = @(Get-Key32 "$out\$n")
    $added = @($new | Where-Object { $old -notcontains $_ } | Sort-Object -Unique); $gone = @($old | Where-Object { $new -notcontains $_ } | Sort-Object -Unique)
    "{0}: 前回 {1} → 今回 {2}（増 {3} / 減 {4}）" -f $n, $old.Count, $new.Count, $added.Count, $gone.Count
    $added | ForEach-Object { "  + $_" }; $gone | ForEach-Object { "  - $_" }
  }
}
# kind=linux の一覧を WSL 側に渡す（3.3b で読む）。Windows PowerShell 5.1 の Out-File は UTF-16LE / BOM 付きになるので使わない
$linuxList = @($inventory | Where-Object kind -eq 'linux' | ForEach-Object { $_.venv } | Sort-Object -Unique)
[IO.File]::WriteAllText("$out\venv-linux-on-windows.txt", $(if ($linuxList.Count) { ($linuxList -join "`n") + "`n" } else { '' }), [Text.UTF8Encoding]::new($false))
# 完了マーカー（3.3b はこれが無ければ取り込まない）。全出力の書き込み後に最後に作る
[IO.File]::WriteAllText("$out\venv-scan.done", (Get-Date -Format o), [Text.UTF8Encoding]::new($false))
```

解釈:
- `kind=linux` は Windows 側ドライブに置かれた WSL 用 venv。`venv-linux-on-windows.txt`（UTF-8 BOM なし）に出力し、**3.2 完了後に** 3.3b で WSL 側から `/mnt/<drive>/...` に変換して取り込む。
- `brotli-lib-found.csv`（v2.12）: Brotli を抱えるライブラリを名前で拾った一覧（Kind = brotli-lib / cef / qtwebengine / dotnet-native。CloudOnly = True と Note のある行は中を読んでいない）。判定は 6.4 手順8b。**この走査は名前だけなので、名前を変えて同梱された DLL や、静的に取り込んだ Brotli（exe の中）は拾えない**（報告書の未探索に書く）。`.ok` の目印が無い（v2.11 以前の 3.2）と、6.4 はこの範囲を未探索として UNKNOWN に残す
- `python_exec=False` は起動不可（ベース Python 消失など）。**削除候補ではなく「起動不可」として報告**。pip 無し（`pip=none`）は正常な venv でもあり得るので、起動可否と混同しない。
- `certifi=none` は ImportError。それ以外の実行失敗（権限、DLL 欠落等）は `python_err` に残し UNKNOWN 扱いにする。
- **Python 標準ライブラリ `ssl` は Windows でも検証に OpenSSL を使う。** Windows の ROOT ストアから信頼ルートを読み込むだけで、Schannel の検証や Disallowed ストアは参照しない。つまり **Windows 本体が対策済みでも、`urllib` / `http.client` / certifi を使わない `ssl` 直接利用は未対策のまま**になりうる（eMudhra 中間の上位ルート emSign / Comodo AAA は ROOT ストアに残っているため）。これはセクション6で `stdlib-ssl` として独立に実測し、ACCEPT なら残件として扱う（対処はセクション5.3 末尾）。
- `ca_path_check=True`（certifi 無し）は「対応不要」ではない。上記のとおり標準 `ssl` 経路が未対策の可能性があり、独自バンドルを `cafile=` で指定するコードや httpx/aiohttp 独自設定も別途確認。
- `app_managed=True`（ComfyUI 等）は certifi のみ更新し、他は触らない。
- 埋め込み Python（`python_embeded\python.exe`）は 3.1 の一覧から個別に `python.exe -m pip --version` / certifi 版を確認（pip 無しの構成も多い）。

conda env（孤立 prefix 含む）:

```powershell
$condaJson = Get-Content "$out\conda-envs.json" -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
$known = @($condaJson.envs)
$condaPrefixes = ($known + $condaFound) | Sort-Object -Unique   # $condaFound は上の走査で収集済み
$condaPrefixes | Out-File "$out\conda-prefixes.txt"
$condaInv = foreach ($p in $condaPrefixes) {   # foreach 文は直接パイプできないので変数に受ける
  $cert = (Get-ChildItem "$p\conda-meta" -Filter 'certifi-*.json' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1).Name -replace 'certifi-([\d.]+)-.*','$1'
  $cac  = (Get-ChildItem "$p\conda-meta" -Filter 'ca-certificates-*.json' -ErrorAction SilentlyContinue | Sort-Object Name | Select-Object -Last 1).Name -replace 'ca-certificates-([\d.]+)-.*','$1'
  [PSCustomObject]@{ prefix = $p; listed = ($known -contains $p); certifi = $cert; ca_certificates = $cac }
}
$condaInv | Format-Table -AutoSize
$condaInv | Export-Csv "$out\conda-inventory.csv" -NoTypeInformation -Encoding UTF8
```

### 3.3 WSL 側（bash、ディストリごと、通常ユーザー）

```bash
out=~/emudhra-audit; mkdir -p "$out"; exec > >(tee "$out/wsl-audit.log") 2>&1
. /etc/os-release; echo "$PRETTY_NAME"; date -Is

# ca-certificates: 日付文字列では判定不可（バックポート）。修正版と dpkg --compare-versions で比較する
dpkg -l ca-certificates curl wget openssl git 2>/dev/null | grep '^ii'
cur=$(dpkg-query -W -f='${Version}' ca-certificates 2>/dev/null)
case "$VERSION_ID" in
  22.04) fix=20260816ubuntu0.22.04.1 ;; 24.04) fix=20260816ubuntu0.24.04.1 ;;
  26.04) fix=20260816ubuntu0.26.04.1 ;; 26.10) fix=20260816ubuntu0.26.10.1 ;;
  12) fix=20250419~deb12u2 ;; 13) fix=20250419+deb13u1 ;; *) fix= ;;
esac
if [ -n "$fix" ]; then dpkg --compare-versions "$cur" ge "$fix" && echo "ca-certificates: FIXED ($cur >= $fix)" || echo "ca-certificates: NEEDS UPDATE ($cur < $fix)"; else echo "ca-certificates: 修正版未確認(VERSION_ID=$VERSION_ID) → トラッカー参照"; fi
apt-cache policy ca-certificates | head -5

# Python（システム / ユーザー導入 / pipx / uv を分けて）
for p in /usr/bin/python3 /usr/local/bin/python3 ~/.local/bin/python3; do
  [ -x "$p" ] || continue; echo "== $p"; "$p" --version
  "$p" -m pip --version 2>&1
  "$p" -c "import certifi;print('certifi',certifi.__version__,certifi.where())" 2>&1
  "$p" -c "import ssl;print(ssl.get_default_verify_paths())"
done
dpkg -l python3-certifi python3-pip 2>/dev/null | grep '^ii'    # apt 管理分
uv --version 2>/dev/null; uv python list 2>/dev/null
pipx --version 2>/dev/null; pipx list 2>/dev/null
conda --version 2>/dev/null && conda env list --json > "$out/conda-envs.json"
pixi --version 2>/dev/null; mise --version 2>/dev/null

node --version 2>/dev/null; npm --version 2>/dev/null; npm config get cafile 2>/dev/null
bun --version 2>/dev/null; deno --version 2>/dev/null
go version 2>/dev/null; rustup --version 2>/dev/null; cargo --version 2>/dev/null
java -version 2>&1 | grep -E '^(openjdk|java) version ' | head -1   # 版の行だけ（「Picked up JAVA_TOOL_OPTIONS: ...」等はパスワードを含みうる）
composer --version 2>/dev/null; dotnet --list-sdks 2>/dev/null
hg --version 2>/dev/null | head -1; svn --version 2>/dev/null | head -1
ruby --version 2>/dev/null; gem --version 2>/dev/null; ruby -ropenssl -e 'puts OpenSSL::X509::DEFAULT_CERT_FILE' 2>/dev/null   # apt の ruby はシステムストア
perl -MMozilla::CA -e 'print "Mozilla::CA $Mozilla::CA::VERSION\n"' 2>/dev/null   # 入っていれば 20261020 以降
dart --version 2>&1 | head -1; ghc --version 2>/dev/null; stack --version 2>/dev/null
elixir --version 2>/dev/null | tail -1; mix hex.info 2>/dev/null | head -3   # castore 1.0.22 / erlang certifi は pending
gh --version 2>/dev/null | head -1; kubectl version --client 2>/dev/null | head -1; terraform version 2>/dev/null | head -1
claude --version 2>/dev/null; which claude
ls -l ~/.local/bin/claude ~/.local/share/claude/versions 2>/dev/null   # PATH に入っていない ~/.local/bin に古い版が残ることがある（which では出ない。v2.12.1）
docker --version 2>/dev/null
# PATH の先が /mnt/ 配下のものは Windows 側の実体（例: Windows 側の npm）。WSL の結果に数えず、Windows 側で判定する（verify_wsl.sh も測らない）
for c in node npm npx pnpm yarn bun deno git curl wget python3 pip3 java svn gh aws az gcloud; do p=$(command -v "$c") && echo "$c -> $p"; done
# ユーザーのホームに入るバージョン管理ツール（それぞれ別のランタイムと証明書を持ちうる）
ls -d ~/.nvm ~/.volta ~/.fnm ~/.pyenv ~/.rbenv ~/.asdf ~/.sdkman ~/.cargo ~/.rustup ~/.local/share/mise 2>/dev/null

# 証明書の参照先を変える環境変数（名前は完全一致）。値に秘密らしい指定（password= 等）が1つでもあれば、値全体を伏せる
# （引数全体を引用符で囲む形や改行を含む形まで sed で正しく切り出すのは難しいため）。URL の資格情報も伏せる。表示は改行を空白にして1行
for n in SSL_CERT_FILE SSL_CERT_DIR CURL_CA_BUNDLE REQUESTS_CA_BUNDLE PIP_CERT NODE_EXTRA_CA_CERTS NODE_USE_SYSTEM_CA NODE_OPTIONS \
         NODE_TLS_REJECT_UNAUTHORIZED GIT_SSL_NO_VERIFY GIT_SSL_CAINFO GIT_SSL_CAPATH JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS \
         AWS_CA_BUNDLE HEX_CACERTS_PATH BUNDLE_SSL_CA_CERT CONDA_SSL_VERIFY UV_NATIVE_TLS UV_SYSTEM_CERTS; do
  [ -n "${!n+x}" ] || continue
  if printf '%s' "${!n}" | grep -qiEz '(password|passwd|pwd|token|secret|key)[^[:space:]=]*[[:space:]]*[=:]'; then
    printf '%s=<redacted: contains a secret-like option>\n' "$n"
  else
    printf '%s=%s\n' "$n" "$(printf '%s' "${!n}" | sed -zE 's#://[^/@[:space:]]+@#://<redacted>@#g' | tr '\n' ' ')"
  fi
done
# Git: TLS キーのみ許可リストで取得し、保存前に URL 内の資格情報を伏せる（全 http.* は列挙しない）
git config --show-origin --show-scope --get-regexp '^http(\..*)?\.(sslbackend|sslcainfo|sslcapath|sslverify)$' 2>/dev/null | sed -E 's#://[^/@[:space:]]+@#://<redacted>@#g'
git config --name-only --get-regexp 'extraheader$' 2>/dev/null | sed -E 's#://[^/@[:space:]]+@#://<redacted>@#g'   # 有無のみ（値は取得しない）

# venv 網羅探索（Linux FS 全体 + /mnt 配下の Linux 用 venv。root は使わない）
find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -name node_modules -o -name .git \) -prune -o \
  -name pyvenv.cfg -type f -print 2>"$out/venv-scan-errors.txt" | sort > "$out/venv-inventory.txt"
# venv の詳細（版・要更新判定）は 3.3b で、Windows 側の一覧取り込み後にまとめて作る

# サプライチェーン攻撃の痕跡（v2.12.2。3.2 の Get-AuditIocFinding と同じ規則。読むだけで実行しない。50 MB を超えるファイルは読まない）
# HIGH = 公表された痕跡（侵害された版・攻撃者の文字列）と一致（すぐ相談）、CHECK = 正当なこともある（誰が追加したか・版を確かめる）
# 読むのは実ファイルだけ（find は既定でリンクをたどらず、-type f / -type d はリンクに当たらない）。site-packages と node_modules は
# 見つけた所で直下だけを見て、その先には降りない（大きな依存ツリーを全部たどらないため）
ioc='AKIA_CTX_START|c=monami|193\.32\.204\.199|45\.139\.104\.115|170\.39\.218\.2|oast\.fun'
: > "$out/ioc-scan-errors-wsl.txt"   # 読めなかった場所（権限など）。未確認として件数を出す
{
  find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -name .git \) -prune -o \
    \( -name node_modules -o -name site-packages \) -type d -prune -print 2>>"$out/ioc-scan-errors-wsl.txt" |
    while IFS= read -r d; do
      if [ ! -r "$d" ] || [ ! -x "$d" ]; then printf '%s : not readable\n' "$d" >> "$out/ioc-scan-errors-wsl.txt"; continue; fi   # 中を見られない（権限）＝未確認
      case "$d" in
        */node_modules)
          if [ -d "$d/tensorlake" ] && [ ! -L "$d/tensorlake" ]; then
            if [ ! -r "$d/tensorlake" ] || [ ! -x "$d/tensorlake" ]; then printf '%s : not readable\n' "$d/tensorlake" >> "$out/ioc-scan-errors-wsl.txt"
            elif [ -f "$d/tensorlake/package.json" ] && [ ! -L "$d/tensorlake/package.json" ]; then printf '%s\n' "$d/tensorlake/package.json"; fi
          fi ;;
        *) for n in cook.pth cook.py litellm-1.107.0.dist-info; do [ -e "$d/$n" ] && [ ! -L "$d/$n" ] && printf '%s\n' "$d/$n"; done ;;
      esac
    done
  find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -name .git -o -name node_modules -o -name site-packages \) -prune -o \
    -type f \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' -o -path '*/.vscode/tasks.json' \
       -o -path '*/.claude/settings.json' -o -path '*/.claude/settings.local.json' \
       -o -name package-lock.json -o -name npm-shrinkwrap.json -o -name pnpm-lock.yaml -o -name yarn.lock -o -name bun.lock \) -print 2>>"$out/ioc-scan-errors-wsl.txt"
} | sort -u > "$out/ioc-candidates-wsl.txt"
while IFS= read -r f; do
  # 一覧に出ても読めないもの（権限など）は未確認として記録する（grep の失敗を「痕跡なし」と取り違えないため）
  if [ -f "$f" ] && [ ! -r "$f" ]; then printf '%s : not readable\n' "$f" >> "$out/ioc-scan-errors-wsl.txt"; continue; fi
  if [ -f "$f" ] && [ "$(stat -c %s "$f" 2>/dev/null || echo 0)" -gt 52428800 ]; then printf '%s : larger than 50 MB, not read\n' "$f" >> "$out/ioc-scan-errors-wsl.txt"; continue; fi
  case "$f" in
    */site-packages/cook.pth|*/site-packages/cook.py|*/litellm-1.107.0.dist-info) echo "HIGH LiteLLM 1.107.0 indicator in site-packages: $f" ;;
    */.github/workflows/*)
      if grep -qE "$ioc" "$f"; then echo "HIGH attacker string in a workflow: $f"
      elif grep -qE 'toJSON\([[:space:]]*secrets[[:space:]]*\)' "$f"; then echo "CHECK workflow passes all secrets at once (toJSON(secrets)): $f"
      else case "${f##*/}" in security-audit.yml|github_actions_security.yml|security-check.yml) echo "CHECK workflow file name used by GhostAction-style attacks: $f" ;; esac; fi ;;
    */node_modules/tensorlake/package.json)
      v=$(grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$f" | head -1 | sed -E 's/.*"([^"]+)"$/\1/')
      [ "$v" = 0.5.144 ] && echo "HIGH tensorlake 0.5.144 installed: $f" || echo "CHECK tensorlake installed (version=$v): $f" ;;
    */.vscode/tasks.json)
      if grep -qE "$ioc" "$f"; then echo "HIGH attacker string in .vscode/tasks.json: $f"
      elif grep -qE '"runOn"[[:space:]]*:[[:space:]]*"folderOpen"' "$f"; then echo "CHECK VS Code task runs when the folder opens: $f"; fi ;;
    */.claude/settings*.json)
      if grep -qE "$ioc" "$f"; then echo "HIGH attacker string in .claude settings: $f"
      elif grep -qi tensorlake "$f"; then echo "CHECK tensorlake mentioned in .claude settings: $f"; fi ;;
    *)  # ロックファイル。版が後の行にあることがある（整形した package-lock.json、yarn.lock）
      if grep -qi tensorlake "$f"; then
        # その項目の版だけを見る: 名前と同じ行（, ; } の手前まで）、または4行以内の "version" の項目（空行・}・[ で項目の終わり。別のパッケージの版は拾わない）
        if awk '{ l = tolower($0) }
             n > 0 { if ($0 ~ /^[[:space:]]*$/ || $0 ~ /[{}]/ || $0 ~ /^[[:space:]]*\[/) n = 0   # 項目の終わり、または入れ子の始まり
                     else if ($0 ~ /^[[:space:]]*"?version"?[[:space:]]*[:=]?[[:space:]]*"?[^"[:space:],]+"?[[:space:]]*,?[[:space:]]*$/) {   # 最初の version がその項目の版
                       if ($0 ~ /^[[:space:]]*"?version"?[[:space:]]*[:=]?[[:space:]]*"?0\.5\.144"?[[:space:]]*,?[[:space:]]*$/) { f = 1; exit }; n = 0 }
                     else n-- }
             match(l, /(^|[^a-z0-9_-])tensorlake([^a-z0-9_-]|$)/) { seg = substr(l, RSTART + RLENGTH - 1); if (match(seg, /[,;}]/)) seg = substr(seg, 1, RSTART - 1)
                                                                  if (match(seg, /(^|[^0-9.])0\.5\.144([^0-9A-Za-z.+-]|$)/) && substr(seg, 1, RSTART) !~ /[<>^~!*]|\|\|/) { f = 1; exit }; n = 4 }   # 範囲の指定（>= ^ ~ など）は固定ではない
             END { exit !f }' "$f"; then echo "HIGH lockfile pins tensorlake 0.5.144: $f"
        else echo "CHECK lockfile mentions tensorlake: $f"; fi
      fi ;;
  esac
done < "$out/ioc-candidates-wsl.txt" > "$out/supply-chain-ioc-wsl.txt"
echo "サプライチェーン攻撃の痕跡: 候補 $(wc -l < "$out/ioc-candidates-wsl.txt") 件 / HIGH $(grep -c '^HIGH' "$out/supply-chain-ioc-wsl.txt") / CHECK $(grep -c '^CHECK' "$out/supply-chain-ioc-wsl.txt") / 読めなかった場所 $(sort -u "$out/ioc-scan-errors-wsl.txt" | wc -l) 件（未確認。重複は除く。ioc-scan-errors-wsl.txt）（supply-chain-ioc-wsl.txt）"
cat "$out/supply-chain-ioc-wsl.txt"

# conda（孤立 prefix 含む）
find / -xdev \( -path /proc -o -path /sys -o -path /mnt -o -path '*/pkgs' \) -prune -o -name conda-meta -type d -print0 2>/dev/null | xargs -0 -r -n1 dirname | sort -u > "$out/conda-prefixes.txt"   # NUL 区切りで空白パス対応
cat "$out/conda-prefixes.txt"
```


### 3.3b WSL: Windows 側一覧の取り込みと venv 詳細（3.2 完了後に実行）

3.1 / 3.2 / 3.3 は並列でよいが、これは 3.2 の完了（`venv-scan.done`）に依存する。マーカーが無いまま進める場合は「未取込」を残件にする。

```bash
out=~/emudhra-audit
# Windows ドライブ上の Linux 用 venv（3.2 の kind=linux）を取り込む。3.2 の完了マーカーが無ければ取り込まず「未取込」と記録する
cat > "$out/decode_winlist.py" <<'PYEOF'
import re, sys
raw = open(sys.argv[1], 'rb').read()
text = raw.decode('utf-16') if raw[:2] in (b'\xff\xfe', b'\xfe\xff') else raw.decode('utf-8-sig')   # UTF-8(BOM 有無) / UTF-16 両対応
for line in text.splitlines():
    m = re.match(r'^([A-Za-z]):\\(.*)$', line.strip())
    if m: print('/mnt/' + m.group(1).lower() + '/' + m.group(2).replace('\\', '/'))   # D:\proj\.venv -> /mnt/d/proj/.venv
PYEOF
found=no
for d in /mnt/c/Users/*/emudhra-audit; do     # Windows 側ユーザー名は WSL ユーザー名と違いうる
  [ -f "$d/venv-scan.done" ] || continue; found=yes
  python3 "$out/decode_winlist.py" "$d/venv-linux-on-windows.txt" | while IFS= read -r root; do
    if [ -f "$root/pyvenv.cfg" ]; then echo "$root/pyvenv.cfg"; else echo "MISSING $root" >> "$out/venv-import-missing.txt"; fi
  done >> "$out/venv-inventory.txt"
done
[ "$found" = yes ] || echo "未取込: Windows 側 3.2 が未完了（venv-scan.done なし）。Windows ドライブ上の Linux 用 venv は未探索として報告" | tee "$out/venv-import-pending.txt"
sort -u -o "$out/venv-inventory.txt" "$out/venv-inventory.txt"

printf 'venv\tpython_exec\tpip\tcertifi\trequests\tneed_certifi\tneed_pip\n' > "$out/venv-inventory.tsv"
while IFS= read -r -u 3 cfg; do   # 空白パス対応。FD 3 で読み、ループ内の python が stdin を吸わないようにする
  root=$(dirname "$cfg"); py="$root/bin/python"
  if [ -x "$py" ] && "$py" --version </dev/null >/dev/null 2>&1; then pe=yes; else pe=no; fi
  pip=none; cert=none; req=no; nc=no; np=no
  if [ "$pe" = yes ]; then
    pip=$("$py" -m pip --version </dev/null 2>/dev/null | awk '{print $2}'); pip=${pip:-none}
    # ImportError のみ none。それ以外の失敗は UNKNOWN（certifi は入っているが壊れている等）
    cert=$("$py" -c "
try:
    import certifi; print(certifi.__version__)
except ImportError: print('none')
except Exception as e: print('UNKNOWN:'+type(e).__name__)" </dev/null 2>/dev/null); cert=${cert:-UNKNOWN:exec}
    "$py" -c "import requests" </dev/null 2>/dev/null && req=yes
    case "$cert" in none|UNKNOWN*) ;; *) dpkg --compare-versions "$cert" lt 2026.10.19 && nc=yes ;; esac
    [ "$pip" != none ] && { dpkg --compare-versions "$pip" lt 26.2.2 && np=yes; }
  fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' "$root" "$pe" "$pip" "$cert" "$req" "$nc" "$np"
done 3< "$out/venv-inventory.txt" >> "$out/venv-inventory.tsv"
{ command -v column >/dev/null && column -t -s $'\t' "$out/venv-inventory.tsv"; } || cat "$out/venv-inventory.tsv"
echo "走査エラー: $(wc -l < "$out/venv-scan-errors.txt") 件"

```

### 3.4 GitHub の CI（サーバー側、読み取りのみ。アカウントごとに1回、どれか1台で）

同じ時期に、CI のシークレットを盗む攻撃（GhostAction 型。LiteLLM 1.107.0 も CI 経由で侵害された）と、npm の tensorlake 0.5.144 のワーム
（ChainDrop。手元のリポジトリに `.claude/settings.json` と `.vscode/tasks.json` を埋め込み、開くたびに動く）があった。手元の痕跡は 3.2 / 3.3 で見る。
ここでは GitHub 上の**アカウントと所属組織の全リポジトリ**を `gh` の GET だけで調べる（手元に clone していないリポジトリも対象）。
シークレットの値は読まない（名前と更新日だけ）。結果は `$HOME\emudhra-audit\ci-audit\` に置き、リポジトリにも外部にも出さない。

```powershell
# gh は PATH に無いことがある（C:\Program Files\GitHub CLI\gh.exe）。ログインしていなければ先に: gh auth login
& "$HOME\emudhra-audit\kit\Invoke-CiAudit.ps1"                        # ログイン中のアカウントと、その所属組織すべて
# & "$HOME\emudhra-audit\kit\Invoke-CiAudit.ps1" -Owners me,some-org   # 対象を絞るとき。複数アカウントなら gh auth switch して1つずつ
# & "$HOME\emudhra-audit\kit\Invoke-CiAudit.ps1" -KnownActors claude   # 自分が使う AI エージェントや CI 用アカウントのコミット・実行を想定内にする
```

結果の書き方: ファイルの中身は書き出さない（パス・行番号・パッケージの版・Webhook のホスト名だけ）。シークレットの値は読まない。
一覧・中身・履歴の取得に失敗した部分は **ERROR**（＝未確認。権限・レート制限・ネットワーク）として必ず残り、「検出なし」とは区別する。
組織・コミット・シークレット・Webhook・デプロイキーは全ページを取る。実行履歴は各リポジトリの直近 100 件まで（超えたら INFO で出る）。
自分の名前のコミット（GitHub アカウントに結びついていない、手元の git の名前）は INFO、それ以外の作者は CHECK（リポジトリ・作者・場所ごとに1行にまとめる）。

調べるもの: 既定ブランチのワークフローの中身（攻撃者の文字列・サーバー、`toJSON(secrets)`、シークレットを外へ送る処理、`pull_request_target`、
SHA で固定していない actions の数）、依存の litellm / tensorlake、ワームが埋め込む種類のファイル（誰がいつ追加したか、自動で動く設定があるか）、
2026-08-31 以降の実行履歴（起動したアカウント）とワークフロー・`.claude`・`.vscode` を変えたコミットの作者、シークレットの名前と更新日、Webhook、デプロイキー。

- **HIGH**（侵害された版 litellm 1.107.0 / tensorlake 0.5.144、または攻撃者の文字列・サーバーと一致）: すぐ相談する。そのリポジトリのシークレットを消し、鍵・トークンを発行元で無効化し、実行履歴を確かめる
- **CHECK**: 正当なことも多い（自分で追加した `.claude/settings.json`、パッケージ公開用の Webhook、`toJSON(secrets)` でシークレットを渡すだけのワークフロー、
  litellm / tensorlake の別の版など）。誰が追加したか・いつか・版を確かめる
- **ERROR**: その部分は調べられていない。権限やレート制限なら時間をおいて再実行する
- 最後に「シークレットを持ち、actions を SHA で固定していないリポジトリ」を出す。更新を止めたリポジトリなら、固定するよりシークレットを消して
  Actions を無効にする（`gh secret delete <名前> -R <repo>`、`gh api -X PUT repos/<repo>/actions/permissions -F enabled=false`。**承認のうえ1件ずつ**）。
  GitHub から消しても鍵そのものは有効なままなので、もう使わない鍵は発行元で無効化してもらう
- 調べないもの: 既定ブランチ以外、各リポジトリの直近 100 件より古い実行、アカウントの個人用トークン・OAuth アプリ・SSH 鍵（このトークンでは読めない）、組織の監査ログ

## 4. 判定基準

分類は4値: **対策済み / 要更新 / 判定不能 / 対象外**。「判定不能」は推測で埋めず報告する。

| ソフト | 修正版（2026-10-22 確認、2026-10-24 追記） | 一次資料 | 備考 |
|---|---|---|---|
| Windows 本体 | 信頼リスト自動更新を受信していれば対策済み。GPO 1 / オフライン / 実測で ACCEPT は要対応（Disallowed ストアの列挙 0件だけでは判定しない） | [MS: 自動信頼リスト更新](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-trust#automatic-certificate-trust-list-updates) | 受信の証拠はセクション6の実測で取る |
| Chrome / Edge / Firefox | 対策済み（CRLSets/OneCRL）。Firefox の最低版は一次資料未確認 | トラッカー | — |
| curl.exe (Schannel) | Windows ストア使用 → 本体の判定に従う | curl docs | `curl-ca-bundle.crt` は無視される |
| curl (OpenSSL ビルド) | CA バンドル 2026-10-20 以降 | [curl caextract](https://curl.se/docs/caextract.html) | Git for Windows 同梱等 |
| Git for Windows (OpenSSL) | 有効設定で `http.sslBackend=schannel`（主対策）。GitHub に 2.56.0.windows.3（2026-10-22、eMudhra 対応のセキュリティ修正として公開）。winget は 2026-10-24 時点で 2.55.0.5 のまま（同梱バンドルは事件前） | [Git for Windows releases](https://github.com/git-for-windows/git/releases) | `--show-origin` で設定元確認。`sslVerify=false` は要是正 |
| pip | 26.2.2 | [pip 26.2.2](https://github.com/pypa/pip/releases/tag/26.2.2) | pip は内蔵の certifi コピーを持つ。外部 certifi と別判定。**判定は 6.1 の pip 実測で**: pip 24.2 以降は既定で truststore（Windows の判定）を使うので、Windows 本体が対策済みなら 26.2.2 未満でも REJECT になる（24.2 より古い pip は同梱の古い certifi で検証するので、受け入れることがある） |
| certifi | 2026.10.19 | [certifi](https://github.com/certifi/python-certifi/releases/tag/2026.10.19) | venv / conda env ごと |
| uv | 0.13.5（トラッカーは 2026-10-25 に 0.13.4 から 0.13.5 へ。v2.12.1） | [uv](https://github.com/astral-sh/uv/releases/tag/0.13.5) | **アプリ同梱の uv も対象**（3.2 で uv.exe を拾い 6.1 で実測）。アプリに同梱された古い uv は、既定（自前の証明書一覧）では基本経路を受け入れることがある。環境変数 `UV_NATIVE_TLS=1`（Windows の検証を使う。新しい版では `UV_SYSTEM_CERTS=1` / `--system-certs`）にすると、Windows の不信頼・失効で拒否される。アプリが uv を起動するときに親の環境を引き継ぐなら、ユーザー環境変数に設定してアプリを再起動すれば効く（引き継ぐかは、アプリのソースや実際のプロセスの環境で確かめる） |
| pixi / mise | 0.82.1 / 2026.10.17 | トラッカー | 使っていれば |
| sigstore（Python） | 4.5.1 | 二次資料（[解説記事](https://rocket-boys.co.jp/security-measures-lab/python_emsign_emudhra_emergency_releases_cve_2026_115557_20261025/)、2026-10-25。一次資料は未確認） | 使っていれば（署名の検証に使う信頼の一覧を持つ）。一次資料で修正内容を確かめてから更新する |
| Node.js | 22.23.4 / 24.22.1 / 26.12.1 | [nodejs releases](https://github.com/nodejs/node/releases) | **同一メジャー内で更新**。20 以前は EOL → 要判断。`NODE_OPTIONS=--use-system-ca` / `NODE_USE_SYSTEM_CA=1` があると Windows ストアも読むので、3.1 で記録し 6.1 の実測で判定 |
| npm | Node 更新で解決。`cafile` 指定時はそのファイル更新 | — | — |
| Bun | トラッカーは 1.4.4 で修正済みとするが、根拠の記載が食い違う（2026-10-24） | [bun PR](https://github.com/oven-sh/bun/pull/46159) | 更新後に実測で判定。それまで判定不能 |
| Deno | 2.9.8 | トラッカー | — |
| Go | 1.27.3 / 1.26.10 | [golang-announce](https://groups.google.com/g/golang-announce/c/66pojueaQek) | 1.25 以前は EOL。自社バイナリ再ビルド+再配置+再起動まで。6.1 の Go は手元の go の判定で、配布済みのバイナリは作ったときの Go で決まる（`go version -m <exe>`） |
| Rustup 本体 | 1.29.2 | [Rust blog](https://blog.rust-lang.org/2026/10/20/Rustup-1.29.2/) | ツールチェーン更新とは別 |
| Rust crates | rustls-webpki 0.103.16 / webpki-roots 1.0.10 | トラッカー | プロジェクトごとに `cargo update` + 再ビルド |
| Java | 27.0.1.0.2 / 25.0.5.0.2 / 21.0.13.0.2 / 17.0.21.0.2 / 11.0.33.0.2 / 8u511 | [OpenJDK advisory 2026-10-21](https://openjdk.org/groups/vulnerability/advisories/2026-10-21) | 複数 JDK は各々 |
| Maven / Gradle / Kotlin / sbt | JDK の cacerts を使う → JDK 更新で解決 | — | **Gradle デーモン・IDE 内蔵ビルドは再起動**（`gradle --stop`）。独自 truststore 指定（`javax.net.ssl.trustStore`）があれば別途 |
| 独自 JRE 同梱アプリ（JetBrains IDE / Android Studio / Eclipse / DBeaver / Jenkins / Adobe 等） | JDK 更新では直らない → 各アプリの更新で | 各ベンダー | JetBrains は JBR 同梱。Toolbox または IDE 内更新。3.2 の java-found.csv で全部拾い、11 以上は 6.1 で実測（IDE の HTTP クライアントは IDE 設定の truststore を使う場合あり）。**10 以下はキットでは実測できない**（UNKNOWN）。Java 8 は修正版（8u511）があるのでアプリの更新を確認、Java 6 / 7 などサポートの終わった版は修正が出ないので、使用中止か、通信させない運用（残件）。古い Java の cacerts には comodoaaaca（Sectigo の相互署名の経路の上位）が入っていることが多い |
| pnpm / yarn / npx | Node の TLS を使う → Node 更新で解決 | — | yarn 1 の `cafile` / pnpm の `ca-file` 設定があればそのファイル更新 |
| Ruby (RubyInstaller) | 判定不能 → 実測 | — | 使う証明書は RubyInstaller の版・`SSL_CERT_FILE`・gem の組み合わせで変わる（`DEFAULT_CERT_FILE` はビルド時の既定値で、判定の根拠にならない）。実測（Windows PowerShell 5.1 は外部コマンドへの引数の中の二重引用符を落とすので、コードに二重引用符を使わない）: `ruby -rnet/http -e 'begin; r = Net::HTTP.get_response(URI(ARGV[0])); puts %q(ACCEPT ) + r.code; rescue OpenSSL::SSL::SSLError => e; puts %q(SSL ) + e.message; end' <URL>`（get_response はリダイレクトをたどらない）（certificate verify failed で、理由が unable to get local issuer / revoked のときだけ REJECT。期限切れ・名前不一致は UNKNOWN。Net::HTTP は環境変数のプロキシを使うので、`http_proxy` / `https_proxy` / `HTTP_PROXY` / `HTTPS_PROXY` を外して実行し、プロキシが必須の環境では UNKNOWN）。RubyGems の rubygems.org 用の固定証明書は gem push 等の一部だけ |
| Ruby (apt / WSL) | 標準構成ではシステムストア → ca-certificates の判定に従う。独自ビルド・`SSL_CERT_FILE` 指定は要確認 | — | — |
| Perl Mozilla::CA | 20261020 | [MetaCPAN](https://metacpan.org/release/LWP/Mozilla-CA-20261020) | Strawberry Perl は同梱。`cpan Mozilla::CA` で更新。入っていても使われるとは限らない（`SSL_CERT_FILE`、IO::Socket::SSL の設定次第）。実測（二重引用符を使わない。リダイレクトはたどらせない）: `perl -MHTTP::Tiny -e '$r=HTTP::Tiny->new(verify_SSL=>1,max_redirect=>0)->get(shift); print join(q( ),$r->{status},$r->{content}),qq(\n)' <URL>`（3xx も対象からの応答として ACCEPT。HTTP::Tiny は環境変数のプロキシを使うので、`http_proxy` / `https_proxy` / `all_proxy`（大文字も）を外して実行する。status 599 で証明書の検証失敗なら理由を見る。407 などプロキシの応答は UNKNOWN。プロキシ無しで対象から HTTP 応答が返ったときだけ ACCEPT。プロキシが必須の環境では UNKNOWN） |
| Dart / Flutter | Dart 3.13.7 以降 / Flutter 3.47.8 以降（Dart 3.13.7 以降を含む） | [Firebase の案内](https://firebase.google.com/support/guides/compromised-emudhra-intermediate-ca)（2026-10-25 更新） | **`dart:io` は Android と Windows で組み込みの BoringSSL で検証し、OS の拒否リストを読まない**。Linux はシステムの ca-certificates を使い、それを更新していない環境だけ影響。Web・iOS・macOS は影響なし（v2.12.3 で訂正、v2.12.6 で [Dart の勧告](https://github.com/dart-lang/sdk/security/advisories/GHSA-frr6-h895-5pxp) に合わせて Linux を訂正。beta は Dart 3.14.0-315.3.beta / Flutter 3.50.0-0.2.pre）。SDK を上げて Android・Windows・Linux 向けのアプリを作り直し、配布し直す（5.5）。配布済みのアプリは利用者の更新が要る |
| Cloud Firestore の SDK（アプリに証明書一覧を組み込む） | FlutterFire `cloud_firestore` 7.1.0 以降（または iOS / macOS 6.10.1、Windows 6.10.2）、Apple の `FirebaseFirestore` 13.1.1 以降（または 12.19.3）、Unity `firebase-unity-sdk` 14.1.0 以降（または 13.17.1）、C++ `firebase_cpp_sdk` 14.1.0 以降（または 13.13.1）、Android の App Distribution Gradle プラグイン 5.3.1 以降 | 同上 | 自分のプロジェクトで使っていれば、SDK を上げて作り直し・配布し直す（Gradle プラグインはプラグインの更新だけ）。React Native の Apple 向けで Firestore を使うものも対象。lockfile・pubspec.lock・Podfile.lock・build.gradle で版を確認 |
| Haskell (cabal / stack) | 判定不能 → 実測。標準構成では x509-system（Windows ではシステムストア読込 = Python 同様 Disallowed が効かない可能性） | — | — |
| Elixir castore | 1.0.22 | トラッカー | プロジェクトごとに `mix deps.update castore` |
| Erlang certifi | **pending** | トラッカー | 監視 |
| Go 製 CLI (gh / kubectl / terraform / git-lfs / docker CLI) | 判定不能 → 実測。標準構成では Windows: システムストア（Go は CryptoAPI の chain 検証を使うので Disallowed が効く）/ Linux: ca-certificates | — | 自前バンドル（`x509roots/fallback`）を埋め込むビルドや `SSL_CERT_FILE` 指定は要確認 |
| Rust 製 CLI (fnm / volta / mise / uv 等 rustls+webpki-roots 内蔵) | 各ツールの修正版へ（uv 0.13.5 / mise 2026.10.17。fnm / volta は未確認） | — | 判定不能なら実測 |
| Composer ca-bundle | 1.4.16 / 1.6.0 | トラッカー | トラッカーの表示は Pending のままだが、両版とも公開済み（2026-10-24）。`composer self-update` は本体だけ。各プロジェクトの `composer/ca-bundle` は `composer update composer/ca-bundle` で |
| **Brotli: Node.js**（CVE-2026-111497） | 22.23.4 / 24.22.1 / 26.12.1（eMudhra と同じリリース、2026-10-21）。20 以前・23・25 は修正なし | [Node.js](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases) | 6.4 で Node の版で判定（修正版も `process.versions.brotli` は 1.2.0 のまま） |
| **Brotli: Bun** | 1.4.4（2026-10-22、Brotli 1.2.1） | [bun#46392](https://github.com/oven-sh/bun/pull/46392) | 内蔵 Bun（Claude Code ネイティブ版 2.1.30x は 1.4.4、`bun build --compile` の CLI）は 3.1 の electron-apps.csv の Bun 列。古い Claude Code のネイティブ版は古い Bun を内蔵する（更新で解決） |
| **Brotli: libbrotli**（上流） | 1.0.10 / 1.1.1 / 1.2.1（2026-10-21） | [google/brotli](https://github.com/google/brotli/releases) | curl / Git の libcurl は `curl -V` の `brotli/x.y.z` で判定。**Git for Windows（2.56.0(3) まで）と PortableGit は 1.2.0 で、修正版の告知なし**（git の HTTPS は Brotli の応答を展開する）→ 5.11 の差し替え（Replace-GitBrotli.ps1）。2.56 から mingw64 が ucrt64 に変わり、DLL は `bin` と `libexec\git-core`（git-remote-https.exe が読む）の2か所。2.56 の curl は `-V` のたびに「Debug-enabled」の警告を出す（配布物側の問題、動作に支障なし）。Windows 標準の curl は Brotli 無し。curl.se の Windows 版は 8.23.0_4 以降で 1.2.1 |
| **Brotli: Python** | brotli 1.2.1 / brotlicffi 1.2.1.0 | [GHSA-9v8h-qqgm-4m35](https://github.com/advisories/GHSA-9v8h-qqgm-4m35) | 入っていると requests（urllib3）/ aiohttp が `br` を要求・展開する |
| **Brotli: Electron / .NET / Chromium / Ubuntu** | Electron: 修正版なし（最新も Node 24.22.0）。.NET: 修正なし（内蔵 1.1.0）。Chromium: 告知なし（2026-03 に上流の最新へ更新済み）。Ubuntu 24.04 libbrotli1 / nodejs: 評価待ち。Debian は修正済み | [Electron](https://github.com/electron/electron/releases) / [Ubuntu](https://ubuntu.com/security/CVE-2026-111497) | ベンダー待ちの残件。危険は「そのアプリが、攻撃者の細工した Brotli を受け取るとき」（乗っ取られたサーバーか、通信への割り込み） |
| **Brotli: アプリが抱えるライブラリ**（ImageMagick `CORE_RL_brotli_.dll` / Inkscape・gnuplot の `libbrotlidec.dll` / Python の wheel の `*.libs\libbrotlidec-<ハッシュ>.dll` / curl.exe を持たない Git（MinGit 型）の `mingw64\bin\libbrotlidec.dll`） | 各アプリの更新待ち。Git は 5.11 の差し替え（Replace-GitBrotli.ps1 は MinGit 型にも使える）。MSYS2 1.2.1-1 と同じハッシュなら修正済み | [google/brotli](https://github.com/google/brotli/releases) | 3.3 の curl -V には出ない。3.2 の brotli-lib-found.csv を 6.4 手順8b で SHA256 により判定し、既知でない DLL は UNKNOWN（版を推測しない）。持ち主の Git は Replace-GitBrotli.ps1 -GitRoot <ルート> -Check で確かめる。名前走査では、AI CLI や IDE が同梱する Git（mingw64 と mingw32）や、Edge WebView などの `brotlidec.dll` も見つかることがある |
| **Brotli: CEF / Qt WebEngine を抱えるアプリ**（`libcef.dll`: Steam・OBS Studio・Zoom など。`Qt5/Qt6WebEngineCore.dll`） | Chromium は告知なし（2026-03 に上流の最新へ更新済み）→ 判定不能。アプリの更新を確かめる | — | 3.2 が名前で拾い、6.4 手順8b が版を記録して UNKNOWN。CEF の ProductVersion には Chromium の版が入ることが多い。古い Chromium は Brotli 以外の脆弱性も抱えるので、アプリを更新する（更新が無いアプリは信頼できる回線でだけ使う） |
| **Brotli: 単体配布の .NET アプリ**（PowerToys・Paint.NET・WSL の設定・VS Code の cpptools など。`System.IO.Compression.Native.dll` を自分のフォルダに持つ） | .NET 本体と同じく 2026-10-24 時点で修正なし → 発行元が Microsoft で版を読めた DLL だけ VULNERABLE（それ以外は UNKNOWN）。.NET が修正版を出したら版で見直す | [dotnet/runtime](https://github.com/dotnet/runtime/releases) | 共有ランタイム（`dotnet\shared\Microsoft.NETCore.App\<版>`）の外にある DLL を 3.2 が拾い、6.4 手順8b が判定（発行元が Microsoft なら VULNERABLE）。アプリが同梱する .NET の更新待ち（ベンダー待ち）。ネイティブの Brotli はこの DLL（Brotli の管理側は System.IO.Compression.Brotli.dll） |
| **Pillow** | 13.0.0（2026-10-16、約 40 件の修正。**Python 3.11 以上**。3.10 向けの修正版なし） | [Pillow 13.0.0](https://pillow.readthedocs.io/en/stable/releasenotes/13.0.0.html) | 画像を開く・縮小表示するだけで起きるものを含む。EPS の件（CVE-2026-112900）は Ghostscript とファイル名の操作が前提。Python 3.10 のアプリ管理環境は 13 にできない（5.11） |
| **固めた Python のアプリ**（PyInstaller 等） | 作者のビルド待ち（中の部品だけは更新できない） | — | 3.2 の frozen-python-found.csv（フォルダ型）と frozen-onefile-found.csv（単一 exe 型。**自分の開発環境（*.spec）で作ったものだけ**。中身は起動時に展開されるまで見えないので UNKNOWN。他人の単一 exe 型は方針で対象外。**キットでは見逃す**ので未探索として報告し、中の部品の脆弱性は開発した側の申告に頼る）、6.4。更新の止まったアプリは、古い certifi（両ホストを受け入れる）や古い Pillow を抱えたままのことがある → 5.11 の起動用バッチ |
| Electron | 44.9.1 / 43.8.1 / 42.11.16 | [electron](https://github.com/electron/electron/releases/tag/v44.9.1) | **各アプリが採用したかは個別確認**（3.1 の electron-apps.csv）。修正版の Electron の採用はアプリごとに遅れることが多いので、版で確かめる |
| Claude Code | 2.1.303 | [CHANGELOG](https://github.com/anthropics/claude-code/blob/main/CHANGELOG.md#21303) | 対策に使うツール自身。最初に更新 |
| Codex CLI | 判定不能（一次資料未確認） | — | 異モデルレビューに使う場合は版を記録。修正の告知を監視 |
| ポータブル版のアプリ（ZIP を展開して使うものなど） | インストール一覧（installed-apps.csv）に出ない。3.2 の全ドライブ走査（python.exe / git.exe / uv.exe / java.exe 等）とアプリのフォルダで拾う | — | 同梱の部品ごとに判定する。同梱の PortableGit はユーザーの git 設定（`http.sslBackend=schannel`）が効けば REJECT になる。同梱の uv は上記。同梱の Python は標準 ssl が受け入れることがある（5.3 の truststore で対処） |
| アプリ同梱のランタイム（デザインツールや AI ツールが同梱する node・Python など） | 各アプリの更新待ち。同梱の node が修正版未満のまま、同梱の Python に pip / certifi が無く標準 `ssl` で受け入れる、ということがある | 各ベンダー | 手で差し替えない。残件として記録 |
| Docker Desktop | 4.96.1（10-21）/ 4.96.2（10-22）で eMudhra 中間の信頼を除去（コンポーネント別に段階配布。最新パッチへ） | [Docker Desktop release notes](https://docs.docker.com/desktop/release-notes/) | 本体版はレジストリの DisplayVersion で確認（`docker info` は Engine 版）。コンテナ内はベースイメージ側で判定 |
| Python 標準 `ssl`（Windows） | **判定不能 → セクション6 の stdlib-ssl 実測で判定**。OpenSSL 検証のため Windows の Disallowed が効かない。トラッカーは 3.15.1 / 3.14.9 / 3.13.17 を「Patched」とするが、これは同梱の pip / certifi の更新で、**Windows の標準 `ssl` には効かない**（10-21 の版には `_ssl` の修正が入っていないので、基本経路・Sectigo クロス署名経路とも受け入れうる）。`_ssl` の修正（CVE-2026-115557、[gh-160040](https://github.com/python/cpython/issues/160040)）は 10-24 に 3.11〜3.15 に取り込まれたが、2026-10-25 時点で含むリリースは無い（8章） | [Python ssl docs](https://docs.python.org/3/library/ssl.html) | ACCEPT なら残件（5.3 末尾の対処。truststore を使えば Windows の判定で拒否できる） |
| Ubuntu ca-certificates | 20260816ubuntu0.{22.04,24.04,26.04,26.10}.1 | [LP#2171507](https://bugs.launchpad.net/ubuntu/+source/ca-certificates/+bug/2171507) | `dpkg --compare-versions` で判定（日付は当てにならない） |
| Debian ca-certificates | 20250419~deb12u2 / 20250419+deb13u1 | [#1151413](https://bugs.debian.org/1151413) | 同上。トラッカーに 20260816+nmu1 の行が追加（2026-10-24。対象スイートは未確認） |
| Alpine ca-certificates | 20261020-r0 | トラッカー | Docker ベース |
| .NET (Windows) | Windows ストア使用 → 対象外 | — | Linux 上は ca-certificates 依存 |
| PowerShell / winget / choco / scoop 本体 | 対象外（Windows ストア） | — | 導入物は別 |
| conda | env ごとに certifi / ca-certificates | — | conda 本体更新は本件に不要。トラッカーに conda 26.9.4 の行が追加（2026-10-24、内容は未確認。二次資料の解説記事も更新の目安に挙げるが理由は書いていない）。`ssl_verify` が False やファイル指定なら、その設定が判定を左右する（3.1 で記録） |
| Mercurial / Subversion | 判定不能 → 最新版 + 実測（svn は 6.1 で実測） | — | **serf を使う svn（TortoiseSVN を含む）は、2026-10-24 時点の最新版でも基本経路を受け入れることがある**（Windows 本体が不信頼・失効にしていても通す。svn の `ssl-trust-default-ca=no` でも変わらない）。修正版が出るまでベンダー待ち＋運用制限（信頼できる回線でだけ使う） |
| クラウド CLI（AWS CLI v2 / Azure CLI / gcloud） | 判定不能 → 各配布元の告知と版。同梱 Python と certifi を使うものがある | 各ベンダー | 3.1 で版と CA 設定（`ca_bundle` / `REQUESTS_CA_BUNDLE` / `custom_ca_certs_file`）を記録 |
| SSH / WinMerge / 平文FTP / SFTP | 対象外 | — | — |

優先順位（一律「今週中」ではなく利用実態で）:
1. 対策作業に使うもの: Claude Code、Git、curl、Node（Claude Code が npm 導入の場合）
2. 外部からパッケージを取得するもの: pip/certifi（よく使う venv）、npm、Go、cargo、Composer
3. 常駐・外部通信するもの: Electron 系、Docker 稼働コンテナ
4. その他（休眠 venv、使っていない JDK 等）

## 5. 対応（承認済み対象のみ）

各手順の前に `winget list --id <ID>` 等で**変更前の版を記録**し、実行ログを `$HOME\emudhra-audit\changes.log` に追記する。

winget の登録内容は配布元とずれることがある。例えば 2026-10-24 時点で、Git は GitHub に 2.56.0.windows.3 があるのに winget は 2.55.0.5 のままだった。登録された版と、実際に入る版が違うこともある。**更新後は winget の表示ではなく実体の版（exe の ProductVersion、`--version`）で確認する。**

### 5.1 Claude Code 自身（最初に）

```powershell
claude --version
npm config get min-release-age   # 設定済み（例: 7 など）なら、公開直後の修正版が選ばれない/失敗する
# npm 導入: この1回だけ解除して入れる（永続設定は変えない）。入れたい版を明示し、@latest に頼らない
#   npm install -g @anthropic-ai/claude-code@2.1.303 --min-release-age=0
# native/winget 導入: claude update  または  winget upgrade --id Anthropic.ClaudeCode --exact
claude --version   # 2.1.303 以降を確認。実行中の Claude Code セッションは再起動
# changes.log に「min-release-age を一時解除して導入した版」を記録
```

### 5.2 Git

**主対策は schannel への切り替え。** 2026-10-23 時点の winget 最新版 2.55.0.5（2026-08-20 リリース）も同梱 `ca-bundle.crt` は事件前（2026-08-20 付）で、更新だけでは直らない。

```powershell
# 変更前を記録（版・backend とその設定元・バンドル日付）
git --version
git config --show-origin --show-scope --get-regexp '^http\.(sslbackend|sslcainfo)$'
(Get-Item 'C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt').LastWriteTime
# 1) Windows ストアを使わせる（社内 CA とも相性良）。system の http.sslCAInfo は schannel 時は無視される
#    （http.schannelUseSSLCAInfo=true が設定されていれば別。あれば先に確認）
git config --global http.sslBackend schannel
git config --show-origin --show-scope --get-all http.sslBackend   # 有効値が schannel か（system の openssl が残っていても global が優先）
git ls-remote https://github.com/git/git.git HEAD                 # 疎通確認
# 復元: git config --global --unset http.sslBackend
# 2) 本体更新（任意。バンドル修正版が出たら）
winget upgrade --id Git.Git --exact
git --version
```

注意:
- **Git の更新は Git Bash 以外のシェル（別ウィンドウの PowerShell 等）から実行する。** Claude Code の `!` やシェル実行ツールは Git Bash 経由のため、bash.exe がファイルを掴みインストーラーが「Replacing in-use files」で止まる。
- インストーラー（`--interactive`）で HTTPS バックエンドを選び直す場合、「Only show new options」のチェックを外さないと画面が出ない。また 2 回目以降は前回の選択（OpenSSL）が初期値になり、そのまま進むと OpenSSL に戻る。上記 1) の global 設定と `--show-origin` での確認が確実。
- TortoiseGit は Git を同梱しない（インストール済みの Git for Windows を使う）。TortoiseGit 経由で入れた Git も winget の `Git.Git` として認識される。

### 5.3 Python / pip / certifi / uv

グローバル配布（3.1 で列挙した各 python 実体で、個別に）:

```powershell
& "<python.exe の絶対パス>" -m pip install -U "pip>=26.2.2" "certifi>=2026.10.19" 2>&1 | Tee-Object -Append "$HOME\emudhra-audit\changes.log"
uv self update
# アプリ同梱の uv は self update できない・すべきでない。代わりに Windows の検証を使わせる（承認のうえ。ユーザー環境変数の永続設定）:
#   [Environment]::SetEnvironmentVariable('UV_SYSTEM_CERTS','1','User')   # uv 0.11.0 以降の名前（--system-certs と同じ）
#   [Environment]::SetEnvironmentVariable('UV_NATIVE_TLS','1','User')     # 0.11.0 より古い uv の名前。0.11.9 から非推奨（0.13.5 は警告を出すが、まだ効く）
#   → 両方を設定する（アプリや venv に同梱された uv の版がまちまちなため）。アプリを完全に終了して起動し直す。戻す: 値に $null
#   警告（UV_NATIVE_TLS is deprecated）は動作に影響しない。将来の uv で UV_NATIVE_TLS が消えても UV_SYSTEM_CERTS が効く
#   効いたかは 6.1 の uv 実測（その時点の環境変数で測る。新しい PowerShell で実行する）
# pipx: pipx upgrade-all は使わない。pipx 自身の venv と各アプリ venv の certifi のみ
pipx runpip <app> install -U certifi   # 必要なアプリごと
```

venv 巡回（3.2 の CSV から。対象を先に提示して承認を得る）:

```powershell
$out = "$HOME\emudhra-audit"
$inv = Import-Csv "$out\venv-inventory.csv"
$targets = $inv | Where-Object { $_.kind -eq 'windows' -and $_.python_exec -eq 'True' -and ($_.need_certifi -eq 'True' -or $_.need_pip -eq 'True') }
"更新対象: $(@($targets).Count) 件（うち app_managed: $(@($targets | ? app_managed -eq 'True').Count) 件）"   # @(): 5.1 で1件だと .Count が空
$targets | Select-Object venv, app_managed, pip, certifi, need_pip, need_certifi | Format-Table -AutoSize
# ---- ここで承認を待つ ----
$haveUv = [bool](Get-Command uv -ErrorAction SilentlyContinue)
$result = foreach ($t in $targets) {
  $pkgs = @()
  if ($t.need_certifi -eq 'True') { $pkgs += 'certifi>=2026.10.19' }
  # app_managed（ComfyUI 等）は certifi のみ。pip 本体はランチャー互換性のため触らない
  if ($t.need_pip -eq 'True' -and $t.pip -ne 'none' -and $t.app_managed -ne 'True') { $pkgs += 'pip>=26.2.2' }
  if ($pkgs.Count -eq 0) {
    # app_managed で pip だけ古いケース。方針により更新しないが「対策完了」ではなく残件
    $how = 'SKIP_POLICY'; $log = 'SKIP_POLICY(app_managed: old pip left in place, see residual list)'; $ok = $null
  } elseif ($t.pip -ne 'none') {
    $how = 'pip'; $log = & $t.python -m pip install -U @pkgs 2>&1 | Out-String; $ok = ($LASTEXITCODE -eq 0)
  } elseif ($haveUv) {
    # uv venv 等、pip 無しの venv は uv で certifi のみ
    $how = 'uv'; $log = uv pip install --python $t.python -U 'certifi>=2026.10.19' 2>&1 | Out-String; $ok = ($LASTEXITCODE -eq 0)
  } else { $how = 'none'; $log = 'SKIP(no pip/uv)'; $ok = $false }
  Add-Content "$out\changes.log" "[$(Get-Date -Format o)] venv=$($t.venv) via=$how pkgs=$($pkgs -join ',') ok=$ok`n$log"
  $after = (& $t.python -c "
try:
    import certifi; c=certifi.__version__
except Exception as e: c='none'
try:
    import pip; p=pip.__version__
except Exception: p='none'
print(c+'/'+p)" 2>&1 | Out-String).Trim()
  [PSCustomObject]@{ venv = $t.venv; via = $how; ok = $ok; before = "$($t.certifi)/$($t.pip)"; after_certifi_pip = $after; err = $(if ($ok -ne $true) { ($log -split "`n" | Select-String -Pattern 'ERROR|SKIP' | Select-Object -First 1) }) }
}
$result | Format-Table -AutoSize
$result | Export-Csv "$out\venv-update-result.csv" -NoTypeInformation -Encoding UTF8
# 残件一覧（完了扱いにしない）: app_managed で pip が古いもの
# Tee-Object / Format-Table は画面幅で右端が切れる（長いパスが消える）ので、一覧は CSV で残す
$residual = @($inv | Where-Object { $_.app_managed -eq 'True' -and $_.need_pip -eq 'True' } | Select-Object venv, pip)
$residual | Export-Csv "$out\residual-app-managed-pip.csv" -NoTypeInformation -Encoding UTF8
$residual | Format-Table -AutoSize | Out-String -Width 400
# → 配布元（ComfyUI 等）の更新手順で pip を上げる、または承認のうえ個別に pip 更新 + アプリ起動確認。いずれかを選んで残件を閉じる
# app_managed=True のものは更新後にアプリ（ComfyUI 等）を起動し、代表機能（ワークフロー1本）が動くことを確認
```

**pip 自身が ACCEPT だった場合（6.1 の pip 実測。古い pip が同梱の古い certifi を使う）**: 外の certifi を更新しても pip には効かない。選択肢を提示して承認を得る。
- (a) pip を 26.2.2 以降に上げる（上の venv 巡回）。app_managed では、新しい pip が古い依存の不正な版表記などを拒んで、アプリの依存の入れ直しが失敗することがある。戻すときは元の版を指定して入れ直す
- (b) pip の版はそのままで、その venv の pip だけ更新済みの certifi を見せる: `<venv>\pip.ini` に `[global]` と `cert = <venv>\Lib\site-packages\certifi\cacert.pem`。ファイルを消せば元に戻る。アプリが certifi を入れ替えると、その一覧に左右される
- (c) 使っていない環境は退役させる（出力・設定・モデルを退避してから削除）
- いずれも取らない場合は残件とし、その環境で pip が動く操作（起動時に依存を入れるランチャーを含む）を信頼できる回線に限る
- 対処後は 6.1 の pip 実測で REJECT を確認する

**Python 標準 `ssl` 経路が ACCEPT だった場合（セクション6 の stdlib-ssl）**: certifi 更新では直らない。選択肢を提示して承認を得る。
- (a) **標準の対処**: そのコードで CA ファイルを明示する（`ssl.create_default_context(cafile=certifi.where())` を作り、実際に通信するクライアントへ渡す。または requests 等 certifi を使うクライアントへ移行）。`cafile` を渡したときだけ Windows の CA/ROOT ストアの読み込みが止まる。社内 CA が必要なら、管理された CA ファイルを明示する計画を別途立てる
- (b) `SSL_CERT_FILE` の差し替えは **対処にならないので使わない**。Windows の `create_default_context()`（cafile 未指定）は Windows の CA/ROOT ストアを読み込んだうえで `SSL_CERT_FILE` も読むため、emSign / Comodo AAA ルートは Windows 側から読まれ続ける（[Python ssl: load_default_certs](https://docs.python.org/3.12/library/ssl.html#ssl.SSLContext.load_default_certs)）
- 対処後は、**変更した実際のアプリの経路**で両テストホストの REJECT を確認する。検証ツールの certifi 経路が FIXED でも、アプリがその context を使っている証拠にはならない
- (c) **CPython の修正版に上げる**（v2.12.6）: `_ssl` の修正（CVE-2026-115557）は 2026-10-24 に 3.11〜3.15 に取り込まれたが、2026-10-25 時点で含むリリースは無い（8章）。
  - 10-21 の 3.15.1 / 3.14.9 / 3.13.17 は pip と certifi の更新だけで、**上げても標準 `ssl` は直らない**。ただし同じマイナーの中の最新に上げる価値はある（それまでのセキュリティ修正と、同梱の OpenSSL の更新）。
    python.org のインストーラーは、同じマイナーが入っていれば「Upgrade Now」で同じ場所・同じ設定のまま上書きし、入っているパッケージは残る（管理者の権限が要る場合がある。署名は Python Software Foundation）
  - 修正を含むパッチ版が出たら、Python ごとに上げて 6.1 の stdlib-ssl を測り直す。python.org 版はインストーラー（3.14 以降は Python install manager も可）、uv が管理する Python は `uv python upgrade`、アプリ同梱の Python は配布元の更新を待つ。
    3.11 / 3.12（と 3.13）はセキュリティ修正だけの段階で、python.org は通常 Windows のインストーラーを出さないので、修正を含む別の配布を確かめる
  - **3.10 には修正が来ない**（10-25 時点で移植なし）。(d) の truststore で守るか、3.11 以上で作り直す
  - 修正が届くまでは (a) か (d) で対処する
- (d) **truststore で Windows の判定を使わせる**（手順は下の「truststore を venv に入れる」）: アプリの起動時に `truststore.inject_into_ssl()` を呼ぶ（Python 3.10 以上。`truststore` パッケージ、または pip 同梱の `pip._vendor.truststore`）。Windows の不信頼・失効が効く。標準 `ssl` が両ホストを受け入れる Python でも、Windows 本体が対策済みなら truststore で拒否できる見込みがある（拒否の成否と理由は Windows 側の状態による。6.1 で測り直す）。venv の中に仕込む方法（sitecustomize 等）はアプリの更新で消えることがあり、ライブラリとの相性もあるので、試験してから入れる。社内 CA は Windows ストアに入っていれば引き続き使える
- 上記いずれも取らない場合は「未対策」として残件に記載する。

**truststore を venv に入れる（(d) の具体的な手順。承認のうえ venv ごと）**: アプリのコードは変えず、その venv の起動時に
`ssl.SSLContext` を truststore 版に差し替える。効くのは**その venv の python.exe で動くもの**だけ（新しく作った venv や別の Python には効かない）。
標準 `ssl` の上に作られたライブラリ（urllib / requests / httpx / aiohttp 等）は後から入ったものも対象。独自の TLS を持つ部品（grpcio、pycurl、
Rust 製のダウンローダー等）と、外から呼ぶコマンド（git、uv、curl）は対象外なので、それぞれ別に判定する。venv を作り直すと消える。

**Python 本体（Store 版など、本体のフォルダに書けないもの）に入れる場合の注意**（v2.12.1）: `.pth` はユーザーの site-packages に置けるが、
pip.ini（`use-deprecated = legacy-certs`）は**ユーザー全体の `%APPDATA%\pip\pip.ini` にしか置けず、その PC のすべての pip に効く**。`.pth` だけだと pip が RecursionError で止まる。
ユーザー全体に legacy-certs を置いたときの pip の動き（pip の版による）:
- pip 23.0.1: `invalid choice: 'legacy-certs'` で全コマンドが止まる（安全側の故障）。直すときは `python -m pip --isolated install -U pip`
- **pip 24.2 / 25.3: truststore を使わず、同梱の古い certifi で検証して基本経路を ACCEPT**（pip.ini が無ければ truststore で拒否できていたもの。手順どおりにやって、気づかずに悪くなる）
- pip 26.2.2: 同梱の certifi が 2026.10.19 なので、legacy-certs でも両ホスト REJECT
- **pip 26.2.2 は Python 3.10 以上が必要**（PyPI の requires_python、2026-10-25 確認）。3.9 以下の Python がある PC（例: 開発ツールが同梱する 3.9）では、その pip は 26.2.2 にできず、上の 24.2 / 25.3 と同じく受け入れる側に戻る

→ Python 本体には入れず、venv に入れる（下の手順）のを基本にする。本体に入れてユーザー全体の pip.ini を置くなら、**その PC のすべての pip を 26.2.2 以上にしてから**にし、3.9 以下の Python があれば先に退役させる。
pip.ini が無い環境でも、venv を作ったらまず pip を 26.2.2 以上に上げる（同梱の古い pip は古い certifi で受け入れることがある）。

```powershell
$v = '<venv のフォルダ>'; $py = "$v\Scripts\python.exe"
& $py -m pip show truststore   # ほかのパッケージの依存として既に入っていることがある。無ければ: & $py -m pip install truststore
$pth = "$v\Lib\site-packages\emudhra-truststore.pth"   # site-packages の .pth の import 行は起動時に実行される
[IO.File]::WriteAllText($pth, "import truststore; truststore.inject_into_ssl()`n", [Text.UTF8Encoding]::new($false))
& $py -c "import ssl,truststore;print(ssl.SSLContext is truststore.SSLContext)"   # True
# pip も必ず一緒に直す: pip 24.2 以上は内蔵の truststore（pip._vendor.truststore）でもう一度差し替えようとし、.pth の truststore と
# 互いを呼び合って RecursionError になり、pip がどこにも接続できなくなる（pip 24.2 以上の内蔵の truststore と、.pth で入れた truststore が重なると起きることがある）。
# venv の中の pip.ini で pip 内蔵の truststore を止めると、pip は .pth で差し替わった ssl（＝Windows の判定）で検証する
$ini = "$v\pip.ini"   # venv の pip.ini は site の設定。その venv の pip だけに効く
if (Test-Path -LiteralPath $ini) { Get-Content -LiteralPath $ini }   # 既にあれば上書きしない。写しを取ってから [global] に1行足すかを相談する（changes.log に「既存に追記」と記録）
else { [IO.File]::WriteAllText($ini, "[global]`r`nuse-deprecated = legacy-certs`r`n", [Text.UTF8Encoding]::new($false)) }   # changes.log に「新規作成」と記録
& $py -m pip config debug   # site: <venv>\pip.ini, exists: True の下に global.use-deprecated: legacy-certs
& $py -m pip install --dry-run --no-deps six   # 通信できること（RecursionError が出ないこと）。6.1 の pip 実測で両ホスト REJECT（失効）を確かめる
# 戻す: Remove-Item $pth。pip.ini は新規作成したなら Remove-Item $ini、既存に追記したなら追記した1行だけを消す（写しから戻してもよい。
# pip.ini には他のインデックス・プロキシ・証明書の設定が入っていることがある）。.pth だけ残すと pip が壊れるので、.pth を残すなら pip.ini も残す。
# changes.log に venv・.pth・pip.ini（新規か追記か）を記録。アプリを起動して普段の操作を1つ確かめ、6.1 で再測定
# truststore をこの venv から外す（pip uninstall truststore、依存の整理で消える）と、.pth の import が起動のたびに失敗して警告が出る。その前に .pth を消す
# 正しく入れば、Windows 本体が対策済みのとき、stdlib-ssl / certifi / requests と pip は両ホストを拒否する見込み（理由は失効 0x80092010 や明示的な不信頼など、Windows の状態による）。6.1 で測り直す。
# pip.ini を置かないと、その venv の pip は RecursionError で通信できない
# 将来の pip で legacy-certs が無くなると pip が設定エラーで止まる（安全側）。そのときは .pth と pip.ini の扱いを見直す
# venv が git の管理外（.gitignore）なら git pull では消えない。venv のフォルダを消して作り直すと（アプリのランチャーでのパッケージの再インストール、
# Python の版の変更など）.pth と pip.ini が一緒に消える。venv の中で pip install し直すだけでは、手で置いたこの2つは消えない
```

Windows の ROOT ストアから emSign / Comodo AAA ルートを削除する案は他ソフトへの影響が大きいので推奨しない。

埋め込み Python（ComfyUI portable 等、pip 無しの場合）: certifi の `cacert.pem` を直接差し替えるのではなく、`python.exe -m pip` が使えるかを先に確認。使えなければ配布元の更新手順に従う（独自判断で site-packages を書き換えない）。

暫定策（任意・対象プロセス限定）:
`SSL_CERT_FILE` / `REQUESTS_CA_BUNDLE` の永続設定（setx）は行わない。Windows の標準 `ssl` 経路には効かず（上記）、起動中プロセスにも反映されず、**社内 CA を追加している環境では通信が壊れる**ことがあり、指定先の certifi が古くなれば逆効果になる。

conda（prefix 指定、ログを捨てない）:

```powershell
foreach ($p in (Get-Content "$HOME\emudhra-audit\conda-prefixes.txt")) {
  conda update -p $p --dry-run certifi ca-certificates 2>&1 | Tee-Object -Append "$HOME\emudhra-audit\changes.log"
}
# dry-run の変更計画を確認（channel 変更や無関係な依存の更新が含まれていないか）→ 承認後:
# conda update -p <prefix> -y certifi ca-certificates 2>&1 | Tee-Object -Append changes.log
```

### 5.4 Node / Bun / Deno

```powershell
node --version   # 現メジャーを確認し、同一メジャー内の修正版へ
# 直接インストール（LTS 24 系の例。22 系なら OpenJS.NodeJS.LTS の版指定または nvm で 22.23.4）
winget upgrade --id OpenJS.NodeJS.LTS --exact
# nvm: nvm install 24.22.1 ; nvm use 24.22.1   （22 系なら 22.23.4。default 切替は承認後）
# fnm / volta も同様に同一メジャー内で
# npm の min-release-age が設定済みの環境で、本件の修正版 npm パッケージ（公開直後）を入れる場合は
# その install に限り --min-release-age=0 を付け、版を明示する。設定自体は解除しない（Shai-Hulud 対策として維持）
npm config get min-release-age
npm config get cafile   # 指定があれば、そのファイルを上書きしない。中身（社内 CA のみ? 公開 CA 込み?）・他ツールとの共有・管理者を確認してから対応を提示
#   例: 社内 CA のみ → 本件無関係（公開 CA は Node 内蔵が使われる）。公開 CA 込みバンドル → バックアップのうえ、社内 CA を残して公開部分だけ更新
deno upgrade
bun upgrade             # 修正版未リリース。トラッカーで確認後に再実行
# Node を使う常駐プロセス（dev server, Claude Code 等）は再起動
```

### 5.5 Go / Rust / Java / Composer

**Dart / Flutter と Cloud Firestore の SDK**（v2.12.6。修正版は 4章。[Dart の勧告 GHSA-frr6-h895-5pxp](https://github.com/dart-lang/sdk/security/advisories/GHSA-frr6-h895-5pxp)、[Firebase の案内](https://firebase.google.com/support/guides/compromised-emudhra-intermediate-ca)）
- **Dart / Flutter**: `dart:io` で外へ TLS で通信するアプリは、Android と Windows では組み込みの BoringSSL で検証し、OS の拒否リストを読まない。Linux ではシステムの ca-certificates を使うので、それを更新していない環境（静的なコンテナ・更新していない機械）だけが影響を受ける。Web・iOS・macOS は影響なし。
  対処: SDK を修正版以上（Dart 3.13.7 / Flutter 3.47.8、beta は 4章）に上げ、**Android・Windows・Linux 向けのアプリや、コンパイルしたバイナリを作り直して配布し直す**（Firestore を使わないアプリも含む。開発機の SDK を上げただけでは、作り終えたアプリは直らない）。fvm などで複数の SDK を使い分けていればそれぞれ。Linux 向けは、動かす環境の ca-certificates の更新でも緩和できる
- **Cloud Firestore の SDK**（FlutterFire `cloud_firestore`、Apple の `FirebaseFirestore`、Unity、C++。React Native の Apple 向けも）: アプリに証明書一覧を組み込むので、OS や証明書の更新では直らない。`pubspec.lock`・`Podfile.lock`・`Package.resolved`・`package.json` などで版を確かめ、修正版に上げて**作り直し、配布し直す**。配布済みのアプリは利用者が更新するまで直らないので、更新を案内する
- **App Distribution の Gradle プラグイン**（Android のネイティブ）: 問題はビルドとアップロードの環境の側なので、プラグインを 5.3.1 以上に上げ、CI / CD のビルド環境を確かめる。アプリの配布し直しは要らない
- **見つからなくても、すぐ対象外にしない**: 3.1 の `dart --version` / `flutter --version` が空でも「未検出」と書く。PATH の外の SDK（fvm・IDE 同梱）、自分のプロジェクト（`pubspec.yaml` / Firebase の設定ファイル）、配布済みのアプリ、CI のビルド環境を確かめてから対象外と判断する

```powershell
go version; winget upgrade --id GoLang.Go --exact; go version
# Go 製の自社ツール: go build → 配置先の実行ファイルを置換 → 常駐なら再起動。置換したパスを changes.log に記録

rustup --version; rustup self update; rustup update   # Rustup 本体 1.29.2 とツールチェーンを別々に確認
# Rust プロジェクトごと: cargo update -p rustls-webpki -p webpki-roots ; cargo build --release → 成果物の置換・再起動

# 版の確認は 3.1 と同じく、出力を捕まえて伏せ字にし、版を示す行だけを出す（JAVA_TOOL_OPTIONS の通知はパスワードを含みうる）
. "$HOME\emudhra-audit\kit\Test-Emudhra.Helpers.ps1"
function Show-AuditJavaVersion { foreach ($j in @(where.exe java 2>$null)) {
  try { $r = Invoke-AuditNativeProcess -FilePath $j -ArgumentList @('-version') -TimeoutMs 30000 } catch { "== $j : $($_.Exception.Message)"; continue }
  "== $j"; @((Hide-AuditSecret ($r.StdErr + $r.StdOut)) -split "`r?`n" | Where-Object { $_ -match '^(openjdk|java) version ' })[0] } }
Show-AuditJavaVersion
winget upgrade --id EclipseAdoptium.Temurin.21.JDK --exact   # 使用ベンダー・系列ごと
# 複数 JDK は 3.1 の一覧に沿って個別に
Show-AuditJavaVersion   # 更新後の版

composer --version; composer self-update; composer --version

# JDK 更新後: Gradle デーモン停止（IDE 内蔵ビルドも IDE 再起動）
gradle --stop 2>$null
# 独自 JRE 同梱アプリ: JetBrains Toolbox / 各 IDE の「更新を確認」。Eclipse / DBeaver / Jenkins は各ベンダー手順
# Ruby (RubyInstaller): winget upgrade --id RubyInstallerTeam.Ruby.3.3 --exact  等（系列ごと）→ 同梱 cert.pem が更新される
# Perl (Strawberry): cpan Mozilla::CA   → 20261020 以降を確認
# Elixir: プロジェクトごとに mix deps.update castore
# fnm / volta: 各公式手順で最新版へ（判定不能なら実測）
```

### 5.6 Windows 信頼リスト自動更新が停止 / オフラインの場合のみ

```powershell
# 企業管理端末では IT 部門に確認。スクリプトは内容を目視確認してから、管理者 PowerShell で
# https://emudhra.we-have-a-problem.com/Block-EmudhraCompromisedCA.ps1
$out = "$HOME\emudhra-audit"
# 実行前のストア状態を保存（復元の基準）
Get-ChildItem Cert:\LocalMachine\Disallowed | Select-Object Thumbprint, Subject | Export-Csv "$out\disallowed-before.csv" -NoTypeInformation
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Block-EmudhraCompromisedCA.ps1
Get-ChildItem Cert:\LocalMachine\Disallowed | Select-Object Thumbprint, Subject | Export-Csv "$out\disallowed-after.csv" -NoTypeInformation
# 今回追加された Thumbprint だけを記録（実行前が 0 件でも動くよう配列差分で）
$before = @(Import-Csv "$out\disallowed-before.csv" -ErrorAction SilentlyContinue | ForEach-Object Thumbprint)
$after  = @(Import-Csv "$out\disallowed-after.csv"  -ErrorAction SilentlyContinue | ForEach-Object Thumbprint)
$after | Where-Object { $before -notcontains $_ } | Out-File "$out\disallowed-added.txt"
"追加: $((Get-Content "$out\disallowed-added.txt" | Measure-Object).Count) 件（期待 16）"
# 効果: LocalMachine\Disallowed に16件追加。Schannel/Authenticode 利用クライアントのみ。独自バンドル持ちは別途
# 復元（今回追加分のみ。名前一致で消すと以前からのブロックまで消える）:
# foreach ($tp in (Get-Content "$out\disallowed-added.txt")) { Remove-Item "Cert:\LocalMachine\Disallowed\$tp" }
```

### 5.7 WSL（ディストリごと）

```bash
out=~/emudhra-audit
# OS 管理分は apt で（対象パッケージのみ、全体 upgrade はしない）
sudo apt update
sudo apt install --only-upgrade ca-certificates curl wget openssl git python3-certifi python3-pip 2>&1 | tee -a "$out/changes.log"
sudo update-ca-certificates
dpkg-query -W ca-certificates python3-certifi python3-pip

# システム Python に pip で certifi を入れない（--break-system-packages は使わない）。
# apt の修正版が未配布なら、トラッカーの Debian/Ubuntu 向け root 証明書 distrust 手順（上級者向け）を承認のうえ適用
# ユーザー導入 Python（pyenv, uv python, /usr/local）は各々で:
#   <python> -m pip install -U "pip>=26.2.2" "certifi>=2026.10.19"
uv self update 2>&1 | tee -a "$out/changes.log"
# pipx: pipx runpip <app> install -U certifi（必要なアプリごと）

# venv 巡回（3.3 の TSV から。対象提示→承認→実行）
# 対象行: path / need_certifi / need_pip を一緒に読む（必要なパッケージだけ更新。certifi 未導入の venv に新規インストールしない）
awk -F'\t' 'NR>1 && $2=="yes" && ($6=="yes" || $7=="yes") {printf "%s\t%s\t%s\n", $1, $6, $7}' "$out/venv-inventory.tsv" > "$out/venv-targets.tsv"
echo "更新対象: $(wc -l < "$out/venv-targets.tsv") 件"; column -t -s $'\t' "$out/venv-targets.tsv"
# ---- 承認待ち ----
while IFS=$'\t' read -r -u 3 root nc np; do   # FD 3 で読む（ループ内の pip/uv が stdin を吸って1件目で止まるのを防ぐ）
  py="$root/bin/python"
  [ -w "$root" ] || { echo "SKIP(no write permission; sudo が必要か確認) $root" | tee -a "$out/changes.log"; continue; }
  case "$root" in *ComfyUI*|*webui*|*forge*|*automatic1111*) app=yes ;; *) app=no ;; esac
  pkgs=""
  [ "$nc" = yes ] && pkgs="certifi>=2026.10.19"
  if [ "$np" = yes ]; then
    if [ "$app" = yes ]; then echo "RESIDUAL(app_managed: pip not updated) $root" >> "$out/residual-app-managed-pip.txt"; else pkgs="$pkgs pip>=26.2.2"; fi
  fi
  [ -z "$pkgs" ] && { echo "SKIP_POLICY(app_managed: only old pip) $root" | tee -a "$out/changes.log"; continue; }
  if "$py" -m pip --version >/dev/null 2>&1; then
    if "$py" -m pip install -U $pkgs </dev/null >>"$out/changes.log" 2>&1; then echo "OK(pip) $root [$pkgs]"; else echo "FAIL $root (changes.log 参照)"; fi
  elif command -v uv >/dev/null && [ "$nc" = yes ]; then
    if uv pip install --python "$py" -U "certifi>=2026.10.19" </dev/null >>"$out/changes.log" 2>&1; then echo "OK(uv)  $root"; else echo "FAIL $root (changes.log 参照)"; fi
  else
    echo "SKIP(no pip/uv) $root" | tee -a "$out/changes.log"
  fi
done 3< "$out/venv-targets.tsv"

# conda（prefix 指定、dry-run → 承認 → 実行）
while IFS= read -r -u 3 p; do conda update -p "$p" --dry-run certifi ca-certificates </dev/null 2>&1 | tee -a "$out/changes.log"; done 3< "$out/conda-prefixes.txt"

# Node（同一メジャー内。nvm 例）
node --version; nvm install 24.22.1 2>&1 | tee -a "$out/changes.log"   # 22 系なら 22.23.4。alias default 変更は承認後
deno upgrade 2>&1 | tee -a "$out/changes.log"; bun upgrade 2>&1 | tee -a "$out/changes.log"
go version   # 公式 tarball の場合は 1.27.3/1.26.10 を https://go.dev/dl/ から入れ直し
rustup self update; rustup update
# Java: apt の openjdk-* を上の apt install --only-upgrade に追加、または SDKMAN で同系列の修正版
composer self-update 2>&1 | tee -a "$out/changes.log"
claude --version   # WSL 側の Claude Code も 2.1.303 以降へ（npm 導入なら npm install -g @anthropic-ai/claude-code@2.1.303 --min-release-age=0 2>&1 | tee -a "$out/changes.log"）
```

### 5.8 Docker

```bash
# 1. Dockerfile / compose の各ステージの FROM を確認（digest 固定なら修正版 digest へ更新、独自 CA バンドル COPY の有無も）
grep -rn --include=Dockerfile* --include=*.yml --include=*.yaml -E '^FROM|cacert|ca-bundle|ca-certificates' <プロジェクト群> 2>/dev/null
# 2. ベース更新を強制して再ビルド（--no-cache だけでは FROM の再取得は保証されない）
docker build --pull --no-cache -t <image> .
# 3. 稼働コンテナは承認したタイミングで再作成（docker compose up -d --force-recreate 等）
# 4. コンテナ内で検証（セクション6 の curl / python を docker exec で実行）
# Docker Desktop 本体: 4.96.1 / 4.96.2 で信頼除去（公式リリースノート。コンポーネント別に段階配布）→ 最新パッチへ。版は 3.1 のレジストリ DisplayVersion で確認
```

### 5.9 Electron 系 / Mercurial / Subversion

- Electron 修正版は 44.9.1 / 43.8.1 / 42.11.16。**各アプリが採用したかは個別確認**（アプリの更新履歴 or 内蔵 Electron 版）。自動更新を有効にし、「更新を確認」を手動実行。更新後はアプリを完全終了して再起動（トレイ常駐含む）。
- `http.systemCertificates`（VS Code）は追加のみで不許可リストには効かない。
- TortoiseHg / Mercurial / TortoiseSVN / SlikSVN: 最新版へ。対策の可否はセクション6の実測で判定。
  serf を使う svn（TortoiseSVN を含む）は基本経路を受け入れることがある（4章）。最新版にしても直らないので、修正版が出るまで残件（未対策）とし、
  信頼できる回線でだけ使う運用で危険を下げる（経路の途中まで保証するものではないので、対策済みには数えない）。信頼できない回線で使ったら SVN のパスワードを変える。
  Windows の「信頼されていない証明書」ストアに足しても効かない見込み（自動更新で既に不信頼になっている Windows でも通す）。
  Eclipse の SVN プラグイン（Subclipse / Subversive）は SVNKit を使う構成だと Eclipse の Java で通信する。古い Java 同梱の Eclipse からは SVN を使わない。
  TortoiseSVN で代わりに扱う場合も、上のとおり TortoiseSVN 自体も未対策のことがあるので、同じ運用制限の下で使う
- アプリ同梱の古い Java: Java 8 はアプリ側の更新で修正版（8u511 以降）が入るかを確認。Java 6 / 7 などサポートの終わった版は修正が出ないので、
  使用中止、または通信させない（自動更新の確認・Marketplace・更新サイトを使わない）運用にして残件に記録

### 5.10 更新後の再起動

3.1 の `running-processes.txt` を基に、更新したランタイムを使う常駐プロセス（dev server、Electron アプリ、Claude Code、Docker コンテナ、常駐 Python スクリプト）を再起動する。再起動しないと旧バンドルがメモリ上に残る。

### 5.11 Brotli・Pillow・固めたアプリ（6.4 の結果から。承認のうえ個別に）

- **Node / Bun / Python の brotli・Pillow**: 修正版へ更新（Node は同じメジャー内、Bun は `bun upgrade`、内蔵 Bun は本体の更新、Pillow は `pip install -U "Pillow>=13.0.0"`）。
- **Git for Windows / ポータブル版の PortableGit の libbrotli**（修正版が出るまでの技術的な緩和）: MSYS2 の brotli 1.2.1 の DLL に差し替える。キットの `Replace-GitBrotli.ps1` で行う。
  - 置き場所は2種類ある: Git 2.55 以前と PortableGit は `mingw64`（MSYS2 の `mingw-w64-x86_64-brotli`）、**Git 2.56 以降は `ucrt64`**（`mingw-w64-ucrt-x86_64-brotli`）。
    どちらも `<prefix>\bin` と **`<prefix>\libexec\git-core`** の2か所に同じ DLL がある。git の HTTPS（git-remote-https.exe）は libexec\git-core の方を読むので、bin だけ替えても git は直らない
  - スクリプトが行うこと: 差し替えが必要で、DLL が `$HOME\emudhra-audit\brotli-1.2.1-msys2[-ucrt64]` に無ければ、`repo.msys2.org` からパッケージを Windows の curl.exe で取得し、
    スクリプトに書いた SHA256（MSYS2 のパッケージ一覧 `%SHA256SUM%` と照合した値）と比べ、Windows の tar.exe で DLL 3つだけを取り出して、DLL ごとの SHA256 も照合する（パッケージの中身は実行しない）。
    差し替え先ごとに、すでに 1.2.1 なら何もしない／Git が 1.2.1 以上を同梱していれば何もしない／それ以外の見知らぬ DLL なら止まる。
    書き込めなければ何も変えずに止まる（フォルダに新しいファイルを作れるかと、各 DLL を書き込みで開けるか（読み取り専用・使用中・権限）を先に確かめる）。
    元の DLL を `<Git>\_emudhra_backup_brotli-<版>-<日時>-<乱数>\<場所>` に退避し、照合済みのバイト列を書き込み、`curl -V` が `brotli/1.2.1` を示さなければ元に戻す（curl.exe の無い MinGit 型は、差し替えた DLL の SHA256 が MSYS2 のパッケージと一致するかで確かめ、そう出力する）。最後に `git ls-remote` を試し、changes.log に記録する

```powershell
# まず判定だけ（権限不要。何も変更せず、ダウンロードもしない）。
# PortableGit などは -GitRoot で場所を渡す（3.2 の tool-exe-found.csv の git.exe の場所から。cmd\git.exe の2つ上）
& "$HOME\emudhra-audit\kit\Replace-GitBrotli.ps1" -Check
& "$HOME\emudhra-audit\kit\Replace-GitBrotli.ps1" -GitRoot 'D:\Tools\SomeApp\PortableGit' -Check
# 承認後、Git Bash や Git を使うアプリを閉じ、-Check を外して実行する。C:\Program Files\Git は管理者の PowerShell で（それ以外は通常の PowerShell でよい）
# 戻す: 退避フォルダの <場所> ごとの DLL を元の場所へコピーし直す（changes.log に退避先がある）
```

  - **Git や PortableGit を更新すると元に戻る**。更新のたびに `-Check` を実行し、必要なら差し替え直す（6.4 でも分かる）
  - 例: Git for Windows を 2.55 から 2.56 に上げると差し替えが消え、置き場所も ucrt64 に変わるので、やり直す
- **固めた Python のアプリの古い cacert.pem**（6.4 で VULNERABLE）: アプリ本体は変えず、起動用のバッチで `REQUESTS_CA_BUNDLE` と `SSL_CERT_FILE` を修正済みの certifi（2026.10.19 以降）の cacert.pem に向ける（requests / httpx に効く。Python 標準 ssl の直接利用には効かない）。
  必要なら `HF_HUB_OFFLINE=1`（モデルを先に取得しておく）や `GRADIO_ANALYTICS_ENABLED=False` で外部通信を減らす。作者へ依存の更新を依頼する（メンテナンス終了ならフォークして依存を更新し、ソースから構築）
- **Pillow を 13 にできない環境（Python 3.10 など）**: 修正版なし。出所の分からない画像・ワークフローを開かない運用制限とし、Python 3.11 以上での作り直しを計画する。
  Ghostscript が不要なら削除（EPS の件の前提を外す）。自作のコードでは、利用者が決めたファイル名を `Image.open()` に直接渡さない
- **自分のプロジェクトのサーバー**（6.4 の server-deps）: Node を修正版にする。修正できない場合は `Content-Encoding: br` のリクエストを前段で拒否する（クライアント側は `Accept-Encoding` から br を外す）
- **Electron / .NET / Chromium / Ubuntu の libbrotli**: ベンダー待ちの残件。4章で修正版を再確認し、出たら更新して 6.4 をやり直す
- **curl.exe を持たない Git（MinGit 型。AI CLI や IDE が同梱する Git など）**（6.4 手順8b の note に Git のルートが出る）: `Replace-GitBrotli.ps1 -GitRoot <ルート> -Check` で確かめ、承認後に同じ手順で差し替える。
  curl.exe が無いので、配布された libbrotlidec.dll の SHA256 が Git for Windows の 1.2.0（スクリプトに書いた2つ）に一致したときだけ版を 1.2.0 と決める。一致しない DLL（1.2.1 以降を同梱する新しい Git を含む）は版を決められないので止まり、手で確かめる。
  mingw32（32 ビット版）だけの Git は 32 ビット用のパッケージを用意していないので差し替えず、止まる（Git の更新を待つ）。
  git.exe（`cmd\`・`bin\`・`<prefix>\bin\` のどれか）が無いフォルダは Git と見なさず、差し替えない（-Check は警告だけ出す。同じ形の MSYS2 系のアプリを誤って書き換えないため）。
  Git のルートから DLL・git.exe までのフォルダにリンク（ジャンクション・シンボリックリンク）があるか、DLL・git.exe がシンボリックリンクなら止まる（管理者で実行したとき、ルートの外のファイルを書き換えたり別のプログラムを実行したりしないため。v2.12）。
  **管理者の PowerShell で実行できるのは、Program Files の中の Git で、ルートから書き込む場所・git.exe までのフォルダを管理者しか変えられない（所有者が管理者で、管理者以外に書き込み・削除・権限変更の許可が無い）ときだけ**。ユーザーのフォルダにある Git（PortableGit・MinGit）は、管理者でない普通の PowerShell で実行する（確かめてから書き込むまでのあいだにフォルダをジャンクションにすり替えられると、管理者の書き込みがルートの外へ向かうため。普通の権限なら、すり替えても本人の権限以上のことは起きない。v2.12）。調べるのは Program Files のフォルダ自身から、書き込む場所までのすべてのフォルダ（管理者での実行の経路は自動の試験に含まれていない。Program Files の Git に管理者として使う前に確かめる）。管理者で実行するときに Git のフォルダの curl.exe・git.exe を動かすこと、ユーザーのフォルダの changes.log に書くことも、理屈の上ではすり替えの経路になりうるが、同じ PC の上の管理者でないプロセスが実行中の数秒にすり替える前提で、その時点で PC は乗っ取られているので、このキットでは扱っていない
  ハードリンクは、別名がすべて Git のルートの中にあるときだけ認める（`fsutil hardlink list` で確かめる）。**インストールした Git for Windows は `bin` と `libexec\git-core` の DLL（と `cmd\git.exe`）をハードリンクで共有している**。
  v2.12 から、新しい DLL は新しいファイルとして書いてから置き換えるので、片方を書いたときにもう片方が変わることはない。
  **v2.11 で差し替えたインストール版の Git では、`libexec\git-core` の退避は差し替え後の中身（1.2.1）になっている**（`bin` に書き込んだ時点で、ハードリンクの `libexec` 側も変わったため）。元の 1.2.0 は `bin` の退避に残っているので、戻すときは `bin` の退避を両方の場所へコピーする。アプリに同梱された Git（MinGit など）は、そのアプリの更新で元に戻るので、更新のたびに `-Check`。同梱元が自動更新するアプリでは、差し替えがアプリの検証を壊さないかを先に確かめる（未確認）
- **アプリが抱える libbrotlidec / CEF / Qt WebEngine / 単体配布の .NET**（6.4 手順8b）: まずアプリの更新を確かめる。更新に修正が無いときは、次の順に考える
  - **MSYS2 の部品そのもの**（3つの DLL の SHA256 が、Git for Windows と同じ MSYS2 の brotli 1.2.0 の組に一致）なら、承認を取って同じ MSYS2 の 1.2.1-1 の組に差し替えてよい。元の DLL を退避し、差し替えた後の SHA256 を確かめ、アプリを起動して普段の操作を1つ確かめる。アプリの更新で元に戻る。キットに専用のツールは無いので、その台で小さなスクリプトを作る（Replace-GitBrotli.ps1 は Git 専用で使えない）
  - **アプリが自分でビルドした Brotli**（名前や形が違う。例: ImageMagick の `CORE_RL_brotli_.dll` は Visual Studio でビルドした1つの DLL で、使うのは JPEG XL と HEIF の部品だけ。HEIF の部品は HEIC・AVIF・AVCI も読む）は差し替えない。その部品を使う機能を止められるなら止める（ImageMagick は `policy.xml` に `<policy domain="coder" rights="none" pattern="{JXL,HEIC,HEIF,AVIF,AVCI}" />`。戻すときはその行を消す）。止められない・使う機能なら、修正版を待ち、そのあいだは出どころの分からないファイルを扱わない
  - CEF / Qt WebEngine / 単体配布の .NET は差し替えない。アプリの更新を待ち、下の「Brotli への露出を減らす」の運用にする
  - **内蔵の Chromium がとても古いアプリ**（CEF の ProductVersion の `chromium-<版>` で分かる。Qt5WebEngine は Chromium 87 系まで）は、Brotli 以外にも直っていない脆弱性を多く抱えている。次の順に判断する（v2.12.6）:
    ① 使っていなければアンインストール。② メーカーの新しいアプリに置き換えられるか確かめる（同じハードの新しい世代の管理アプリなど）。
    ③ ハードの設定などで必要なら残し、運用で制限する: 使うのはハードの設定などローカルの機能だけにし、アプリの中の Web の機能・ストア・ニュース・サインインの画面は使わない（信頼できるネットワークでも、外から取り込む内容や配信元が侵害されれば攻撃されうる）。できれば Windows Defender ファイアウォールでそのアプリの外への通信を止める（設定の同期やファームウェアの更新が止まるので、使うときだけ許可する）。メーカーの更新が出たら入れる。制限できない機能が残るなら、未対策の残件として報告書に書く
- **Python の wheel が抱える libbrotlidec**（`site-packages\<パッケージ>.libs\`、WSL では `*.libs/libbrotlidec*.so*`）: 持ち主のパッケージを更新する。Brotli を使わない環境なら、持ち主のパッケージごと不要か確かめて削除

**Brotli への露出を減らす（修正版が出ていない・更新できないもの）**

Brotli を展開されるのは、そのソフトが `br` の応答（や細工した Brotli のデータ）を受け取るときだけ。修正版が無いものは、受け取らない・信頼できない相手とは通信しない形に寄せる。**直せるものと、直せないものを分けて書く。**
- **Python（brotli / brotlicffi が要らない環境）**: `pip uninstall brotli brotlicffi` で、urllib3 / requests が `Accept-Encoding` に `br` を載せなくなる（urllib3 は Brotli のモジュールを読み込めたときだけ `br` を要求する）。
  先に `pip show brotli`（`Required-by` の欄）で、ほかのパッケージが必要としていないか確かめる。戻すときは `pip install brotli`（または brotlicffi）で戻せる。アプリ管理の環境（ComfyUI など）は承認を取ってから
- **curl**: `--compressed` を付けなければ、curl は `Accept-Encoding` を送らない（`br` の応答を要求しない）。スクリプトや `.curlrc` の `--compressed` を外す。**Git の libcurl は圧縮を自分で要求する**ので、この方法は効かない（Git 側の設定で外す方法は確認していない = 未確認）
- **Git・Node・Electron・Bun・.NET・Chromium / CEF**: オフにする設定は見つかっていない（未確認）。更新する、Git は DLL を差し替える（上）、更新が無いものは信頼できる回線でだけ使う（最後の手段）
- **WSL（Ubuntu）**: `apt` で libbrotli1 / nodejs に修正が入るのを待つ。Ubuntu の状況は 2026-10-23 時点で「Needs evaluation」（評価待ち）。入ったら `sudo apt update && sudo apt upgrade` し、USN で修正版を確かめてから 6.4 をやり直す。Ubuntu は版の番号を変えずに修正を取り込むことがあるので、版の数字だけで判断しない

## 6. 検証（3値判定 + 対照試験）

判定は **REJECT（対象チェーンを拒否＝対策済み）/ ACCEPT（受容＝未対策）/ UNKNOWN（判定不能）**。
通信失敗を一律 OK にしない。必ず対照試験（正常な HTTPS サイト）が成功することを確認し、失敗理由を記録する。

前提確認:
- 端末時刻が正しい（3.1 で記録）
- TLS 検査プロキシが無い（あれば、プロキシが eMudhra チェーンを差し替えるため ACCEPT/REJECT の判定が無効 → UNKNOWN。プロキシ無し経路で再試験）
- テストホストの証明書期限（`openssl s_client` 等で `notAfter` を確認。期限切れなら REJECT の理由が「期限」になり判定無効）
- テストホストがルートの直前まで証明書を送っていること（`openssl s_client -connect <ホスト>:443 -servername <ホスト> -showcerts`）。
  テストホストの経路は、基本経路が leaf → `EM DV TLS CA - G3B` → `emSign Root TLS CA - G3`（発行者 `emSign ECC Root CA - G3`）、
  クロス署名経路は leaf → `EM DV TLS CA - G3B`（発行者 `AAA Certificate Services`）。末尾の発行者がこのルートでなければ、
  中間証明書が欠けている可能性があり、どのツールでも「発行者が見つからない」で失敗して本件と区別できないので、判定を止めて報告する。
  Java の TlsProbe.java は、汎用の「経路が見つからない」を REJECT にする前に、この2つのルートだけを信頼する診断用の接続で
  Java 自身の検証（ホスト名・用途・期限・経路の完全性）が通ることを確かめる（通らなければ UNKNOWN。診断用の接続は ACCEPT には使わない）

完了条件: 基本経路 `dv-g3b-emudhra` と Sectigo クロス署名経路 `dv-g3b-aaa-emudhra` の**両方**が REJECT。1ホストの結果を全CA・全用途に一般化しない（テストは TLS 用 DV 中間1件。コード署名用2件は Authenticode 側＝Windows 本体の判定に従う）。

検証コードはキット同梱のスクリプトで実行する（手順書本文に長いコードを埋め込まない。Windows 用は GPT 提供の差し替え案 `Test-Emudhra.Helpers.ps1` 等、WSL 用は `verify_wsl.sh` / `audit_summary.py`）。

**集計ルール（Windows / WSL 共通。`Get-AuditSummary` と `audit_summary.py` は同一ロジック）**
- ツール・経路ごと（Python は「実体の絶対パス × stdlib-ssl / certifi / requests」ごと）に、**対照 ACCEPT がちょうど1件** かつ **対象2ホストそれぞれに REJECT がちょうど1件** のときだけ FIXED
- 対象のどちらかが ACCEPT → VULNERABLE。欠測・重複・UNKNOWN・NONE → UNKNOWN（モジュール未導入のみの経路は N/A）
- 対照がちょうど1件で UNKNOWN のときも、対象2ホストの行がそろっていてどちらかが ACCEPT なら VULNERABLE（v2.11.5。理由欄に「control UNKNOWN」。古い uv は対照の問い合わせを証明できない）。対照 UNKNOWN で FIXED にはならない
- 判定語は ACCEPT / REJECT / UNKNOWN / NONE の4語に正規化し、理由は detail 列に分ける

**TLS 検査プロキシの検出（必須の前提）**: 対照サイト（www.google.com）の証明書発行者が `Google Trust Services` でなければ、経路上で証明書が差し替えられている。プロキシの CA を信頼している端末では「対照は通る・テストホストだけ失敗」になり、**偽の FIXED** が出る。この場合は全件 UNKNOWN とし、検査されない経路で再試験する（ウイルス対策ソフトの通信の検査で、実際にこの誤判定が起きうる）。

### 6.1 Windows（PowerShell、通常ユーザー権限、キットのフォルダで実行）

```powershell
$kit = Join-Path $HOME 'emudhra-audit\kit'; Set-Location $kit   # 1.1 の Install-Kit.ps1 で配置済みのキット
$out = Join-Path $HOME 'emudhra-audit'

. .\Test-Emudhra.Helpers.ps1

# 0) キット自体のテスト（外部通信なし）。Windows PowerShell 5.1 で通ることを各台で必ず確認
powershell.exe -NoProfile -File .\Test-Helpers.ps1;                      if ($LASTEXITCODE -ne 0) { throw 'helper tests failed' }
# テスト用の Python は「起動できる1つ」を選ぶ。Get-Command python.exe は複数返すことがあり、配列のまま & に渡すと
# 実行されずに前の $LASTEXITCODE（0）が残って、失敗に気づかない
# 候補は py ランチャー・PATH・Store 版・uv に登録済みのものだけ（3.2 で見つけただけの python.exe は使わない）
$testPython = $null
foreach ($cand in @(Get-AuditWindowsPythonCandidates)) {
  try { if ((Invoke-AuditNativeProcess -FilePath $cand -ArgumentList @('--version') -TimeoutMs 15000).ExitCode -eq 0) { $testPython = $cand; break } } catch { }
}
if (-not $testPython) { throw '起動できる Python が無いのでキットのテストができない' }
"テスト用 Python: $testPython"
powershell.exe -NoProfile -File .\Test-Helpers.ps1 -PythonPath $testPython; if ($LASTEXITCODE -ne 0) { throw 'process tests failed' }
# -B: キットのフォルダに __pycache__ を作らない（作られても Install-Kit.ps1 は .pyc だけなら受け入れる）
& $testPython -B -m unittest -v test_probe_python;                       if ($LASTEXITCODE -ne 0) { throw 'python tests failed' }

# 1) TLS 検査の検出（検証は有効のまま、発行者を読むだけ）
$req = [Net.WebRequest]::Create('https://www.google.com/'); $req.Timeout = 15000
try { $req.GetResponse().Close(); $issuer = $req.ServicePoint.Certificate.Issuer } catch { $issuer = "ERROR: $($_.Exception.Message)" }
"対照サイトの証明書発行者: $issuer"
if (-not $issuer) { throw '発行者を読めない。PowerShell 7 では空になるので、Windows PowerShell 5.1（powershell.exe）で実行し直す' }
$inspect = $issuer -notmatch 'O=Google Trust Services'
if ($inspect) { Write-Warning '証明書が差し替えられている可能性。全件 UNKNOWN 扱い（-KnownTlsInspection）' }

# 2) Python 一覧（棚卸し済みの全実体）。PATH 上だけでなく、配布・埋め込み・conda・pipx・uv を統合する
# py ランチャー + PATH + Store 版（パッケージごとのエイリアス。素の WindowsApps\python.exe はストア誘導のことがあるので使わない）+ uv
$dist = @(Get-AuditWindowsPythonCandidates)
# 3.2 の全ドライブ走査で見つかった python.exe（アプリ同梱・ベース Python）。venv のベースは venv-inventory.csv からも足される
$embedded = @(Get-Content "$out\python-exe-found.txt" -Encoding UTF8 -ErrorAction SilentlyContinue | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
$conda    = @(Get-Content "$out\conda-prefixes.txt" -ErrorAction SilentlyContinue | Where-Object { $_ })
$pipxDir  = if (Get-Command pipx -ErrorAction SilentlyContinue) { pipx environment --value PIPX_LOCAL_VENVS 2>$null }   # pipx が無ければ何も出さない
$pipx     = @(if ($pipxDir) { Get-ChildItem -LiteralPath $pipxDir -Directory -ErrorAction SilentlyContinue | ForEach-Object { Join-Path $_.FullName 'Scripts\python.exe' } | Where-Object { Test-Path -LiteralPath $_ } })
$paths = @(Get-AuditPythonPaths -InventoryCsv "$out\venv-inventory.csv" -DistributionPython $dist -EmbeddedPython $embedded -CondaPrefixes $conda -PipxPython $pipx)
if ($paths.Count -eq 0) { throw '棚卸し結果から Python 実体を1件も得られない（3.2 未完了?）' }
Write-AuditUtf8 -Path "$out\python-all.txt" -Text (($paths -join "`n") + "`n")
"Python 検証対象: $($paths.Count) 件"; $paths
# 手順4と 6.4 で実行するツールの一覧。3.2 で見つけたもの（PATH 外を含む）と、PATH 上のもの（where.exe の絶対パス）を合わせる。
# 手順4・6.4 はこの一覧にあるものだけを実行する（一覧から消せば PATH 上にあっても実行しない）
$toolPaths = @(@(Import-Csv "$out\tool-exe-found.csv" -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object FullName) +
  @('curl','git','svn','uv','bun','node','java','dotnet' | ForEach-Object { where.exe $_ 2>$null }) |
  Where-Object { $_ -and [IO.Path]::IsPathRooted($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) } | Sort-Object -Unique)
Write-AuditUtf8 -Path "$out\tools-to-run.txt" -Text $(if ($toolPaths.Count) { ($toolPaths -join "`n") + "`n" } else { '' })
"ツール検証対象: $($toolPaths.Count) 件"; $toolPaths
# ---- ここで止めて一覧を確認する ----
# 3.2 の全ドライブ走査で見つけただけの python.exe（python-exe-found.csv。発行元・版を確認できる）も含まれ、次の手順3で実行される。
# 出所の分からないもの（展開しただけのアーカイブ、他人が書き込める場所など）は python-all.txt から行を消してから手順3に進む。
# tools-to-run.txt（tool-exe-found.csv で発行元・版を確認できる）も同じく確認し、出所の分からない行を消してから手順4に進む。
# 消した行は「未検証」として報告に残す

# 3) Python 経路別 + Windows ストア直接（SslStream、badssl 自己検証付き）
.\Invoke-Verification.ps1 -PythonListPath "$out\python-all.txt" -OutputDirectory $out -IncludeWindowsTrustProbe -KnownTlsInspection:$inspect

# 4) curl / Node / Go / Git（判定語を4語に正規化し、対照は 'CONTROL' ラベルで記録）
$CTRL = 'CONTROL'; $CTRL_URL = 'https://www.google.com/'
$T = @('https://dv-g3b-emudhra.we-have-a-problem.com/','https://dv-g3b-aaa-emudhra.we-have-a-problem.com/')
# (ラベル, URL) の組。@(@(a,b)) は平坦化されるので、単項カンマで「配列の配列」を明示する
$pairs = @(,@($CTRL,$CTRL_URL)) + @($T | ForEach-Object { ,@($_,$_) })
$rows = [Collections.Generic.List[object]]::new()
function Rec($tool, $target, $verdict, $detail) {
  if ($inspect) { $verdict = 'UNKNOWN' }
  # 保存する詳細（エラー出力を含む）は伏せ字にしてから 1 行にする（Java の起動時診断に JAVA_TOOL_OPTIONS のパスワードが出うる）
  $d = ((Hide-AuditSecret ($detail | Out-String)) -replace "`r?`n",' '); $rows.Add([pscustomobject]@{ Tool=$tool; Target=$target; Verdict=$verdict; Detail=$d.Substring(0,[Math]::Min(200,$d.Length)) }) }

# curl: 判定は Get-AuditCurlVerdict（期限切れ・名前不一致・失効確認不能を先に除外 → 失効・信頼されないルート・発行者不明のみ REJECT）。
# Schannel は失効を終了コード 35、信頼されないルートを 60 で返す。
# 出力は Invoke-AuditNativeProcess で受ける。"2>&1 | Out-String" だと PowerShell 5.1 がエラー出力を画面幅で折り返し
# （"CRYPT_E_ REVOKED"）、判定が崩れる
# 対象は tools-to-run.txt の curl.exe（PATH 上のものと、Git 同梱の mingw64\bin・ucrt64\bin の curl.exe など）
$toolsToRun = @(Get-Content "$out\tools-to-run.txt" -Encoding UTF8 -ErrorAction SilentlyContinue | Where-Object { $_ -and (Test-Path -LiteralPath $_) })
function Select-AuditTool([string]$Name) { @($toolsToRun | Where-Object { [IO.Path]::GetFileName($_) -ieq $Name }) }
$curls = @(Select-AuditTool 'curl.exe')
# MSYS2 版の curl（git-sdk-64 の usr\bin など）は -o NUL を普通のファイルとして作る。子プロセスは PowerShell の
# Set-Location ではなく起動したときのフォルダで動くので、使い捨てのフォルダで実行して最後に消す（v2.11.4。起動したフォルダがリポジトリなら、そこに NUL ができる）。
# NUL という名前のファイルは Remove-Item で消せないので、\\?\ 付きのパスで .NET から消す
$curlCwd = Join-Path $out ('curl-probe-' + [guid]::NewGuid().ToString('N')); [void](New-Item -ItemType Directory $curlCwd)
try {
foreach ($c in $curls) {
  foreach ($pair in $pairs) {
    try { $r = Invoke-AuditNativeProcess -FilePath $c -ArgumentList @('-sS','--max-time','15','--max-redirs','0','-o','NUL',$pair[1]) -WorkingDirectory $curlCwd; $e = $r.StdErr + $r.StdOut; $rc = $r.ExitCode }
    catch { $e = $_.Exception.Message; $rc = -1 }
    Rec "curl:$c" $pair[0] (Get-AuditCurlVerdict $rc $e $pair[1]) "rc=$rc $e"
  }
}
} finally { [IO.Directory]::Delete('\\?\' + $curlCwd, $true) }

# Node（エラーコードの許可リスト）
if (Get-Command node -ErrorAction SilentlyContinue) {
  $js = @'
const url = process.argv[2];
const REJECT = new Set(['UNABLE_TO_GET_ISSUER_CERT_LOCALLY','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','CERT_REVOKED','UNABLE_TO_GET_ISSUER_CERT']);
fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(15000) })
  .then(r => console.log('ACCEPT\thttp ' + r.status))
  .catch(e => { const c = e.cause || e; const code = c.code || c.name; console.log((REJECT.has(code) ? 'REJECT' : 'UNKNOWN') + '\t' + code); });
'@
  [IO.File]::WriteAllText("$out\nodetest.js", $js, [Text.UTF8Encoding]::new($false))
  foreach ($pair in $pairs) {
    $r = (node "$out\nodetest.js" $pair[1] 2>&1 | Select-Object -First 1) -split "`t", 2
    $v = if ($r[0] -in 'ACCEPT','REJECT','UNKNOWN') { $r[0] } else { 'UNKNOWN' }; Rec 'node' $pair[0] $v ($r -join ' ')
  }
}

# Go（UnknownAuthorityError のみ REJECT。期限切れ等の CertificateInvalidError は UNKNOWN）
if (Get-Command go -ErrorAction SilentlyContinue) {
  $go = @'
package main
import ("crypto/x509";"errors";"fmt";"net/http";"os";"time")
func main(){
  c := &http.Client{Timeout: 15*time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
  r, err := c.Get(os.Args[1])
  if err == nil { fmt.Printf("ACCEPT\thttp %d\n", r.StatusCode); return }
  var ua x509.UnknownAuthorityError
  if errors.As(err, &ua) { fmt.Printf("REJECT\t%v\n", err); return }
  fmt.Printf("UNKNOWN\t%v\n", err)
}
'@
  New-Item -ItemType Directory -Force "$out\gotest" | Out-Null
  [IO.File]::WriteAllText("$out\gotest\main.go", $go, [Text.UTF8Encoding]::new($false))
  Push-Location "$out\gotest"; if (-not (Test-Path go.mod)) { go mod init gotest 2>&1 | Out-Null }
  foreach ($pair in $pairs) {
    $r = (go run . $pair[1] 2>&1 | Select-Object -Last 1) -split "`t", 2
    $v = if ($r[0] -in 'ACCEPT','REJECT','UNKNOWN') { $r[0] } else { 'UNKNOWN' }; Rec 'go' $pair[0] $v ($r -join ' ')
  }
  Pop-Location
}

# Git（実体ごと。テスト先は Git リポジトリではないので、TLS が通れば HTTP レベルの失敗 = ACCEPT。判定は Get-AuditGitVerdict）
$gitEnv = @{ GIT_TERMINAL_PROMPT = '0' }   # 認証を求められても待たない
# 対象は tools-to-run.txt の git.exe（PATH 上のものと、ポータブル版のアプリが同梱する PortableGit など）。
# ユーザー設定（~/.gitconfig）の http.sslBackend=schannel は同梱の Git にも効く（アプリが同梱する PortableGit でも、schannel が効けば REJECT になる）
$gits = @(Select-AuditTool 'git.exe')
foreach ($g in $gits) {
  foreach ($pair in @(,@($CTRL,'https://github.com/git/git.git')) + @($T | ForEach-Object { ,@($_,$_) })) {
    $gitArgs = @('-c','http.followRedirects=false','ls-remote',$pair[1]); if ($pair[0] -eq $CTRL) { $gitArgs += 'HEAD' }
    try { $r = Invoke-AuditNativeProcess -FilePath $g -ArgumentList $gitArgs -Environment $gitEnv; $e = $r.StdErr; $rc = $r.ExitCode }
    catch { $e = $_.Exception.Message; $rc = -1 }
    $v = Get-AuditGitVerdict $rc $e $pair[1]
    if ($pair[0] -eq $CTRL -and $rc -ne 0) { $v = 'UNKNOWN' }   # 対照は ls-remote の成功だけを ACCEPT とする
    Rec "git:$g" $pair[0] $v "rc=$rc $e"
  }
}

# svn（tools-to-run.txt の svn.exe）。テスト先はリポジトリではないので、TLS が通れば DAV/HTTP レベルの失敗 = ACCEPT。
# 普段の設定を写した使い捨ての設定フォルダと --non-interactive で実行し、証明書を信頼する判断を保存しない（%APPDATA%\Subversion には書かない）。
# 保存済みの「この証明書を常に信頼」は写さないので、それがある場合は普段の動作と違いうる（%APPDATA%\Subversion\auth\svn.ssl.server を目で確認）
# serf を使う svn（TortoiseSVN を含む）は、基本経路を受け入れてクロス署名経路だけを拒否することがある（svn の設定 ssl-trust-default-ca=no でも同じ）
$svns = @(Select-AuditTool 'svn.exe')
if ($svns.Count) {
  # 実行ごとに新しいフォルダ。普段の設定（servers の ssl-authority-files・プロキシ、config）は写し、
  # 保存済みの信頼の判断（auth フォルダ）は写さない。この実行で作ったものだけを消す
  $svnCfg = Join-Path $out ('svn-config-probe-' + [guid]::NewGuid().ToString('N')); [void](New-Item -ItemType Directory $svnCfg)
  foreach ($f in 'servers','config') {
    $src = Join-Path $env:APPDATA "Subversion\$f"
    if (Test-Path -LiteralPath $src -PathType Leaf) { Copy-Item -LiteralPath $src -Destination (Join-Path $svnCfg $f) }
  }
  try {
    foreach ($s in $svns) {
      foreach ($pair in $pairs) {
        try { $r = Invoke-AuditNativeProcess -FilePath $s -ArgumentList @('info','--non-interactive','--config-dir',$svnCfg,$pair[1]); $e = $r.StdErr + $r.StdOut; $rc = $r.ExitCode }
        catch { $e = $_.Exception.Message; $rc = -1 }
        Rec "svn:$s" $pair[0] (Get-AuditSvnVerdict $rc $e $pair[1]) "rc=$rc $e"
      }
    }
  } finally { Remove-Item -LiteralPath $svnCfg -Recurse -Force }
}
# svn.exe が無い TortoiseSVN は画面で確認する: リポジトリブラウザーで2ホストを開く。
# - 証明書の警告が出たら、表示された理由を記録する。理由が「信頼された機関が発行していない」だけなら REJECT 相当、
#   期限切れ・ホスト名の不一致などが並んでいれば UNKNOWN。警告では必ず「拒否」を選ぶ（受け入れると以後も信頼が保存される）
# - 警告が出ずに「HTTP/DAV に対応していない」等のエラーになれば ACCEPT。認証を求められた・別の URL へ移動した等は UNKNOWN

# Java（tools-to-run.txt の java.exe）。11 以上はキットの TlsProbe.java をコンパイルせずに実行して、その Java の既定の信頼で判定する。
# 10 以下はこの方法では測れない（単一ファイル実行が無い）ので UNKNOWN とし、cacerts に関係するルートがあるかを記録する
# （例: comodoaaaca があれば Sectigo クロス署名経路を信頼しうる）。keytool.exe は、同じ JRE の
# keytool.exe が tools-to-run.txt に残っているときだけ実行する（一覧で確認していない実行ファイルは動かさない）。
# jdk.compiler を含まない JRE（アプリ同梱の縮小版など）は 11 以上でも TlsProbe.java を実行できず UNKNOWN になる
foreach ($j in (Select-AuditTool 'java.exe')) {
  $ji = Get-AuditJavaInfo -JavaExe $j
  if ($ji.Major -ge 11) {
    foreach ($pair in $pairs) {
      $line = $null
      try {
        $r = Invoke-AuditNativeProcess -FilePath $j -ArgumentList @((Join-Path $kit 'TlsProbe.java'), $pair[1]) -TimeoutMs 120000
        $line = @($r.StdOut -split "`r?`n" | Where-Object { $_ -match '^(ACCEPT|REJECT|UNKNOWN)\t' })[0]
        if (-not $line) { $line = "UNKNOWN`trc=$($r.ExitCode) $($r.StdErr)" }
      } catch { $line = "UNKNOWN`t$($_.Exception.Message)" }
      $parts = $line -split "`t", 2; Rec "java:$j" $pair[0] $parts[0] "Java $($ji.Version): $($parts[1])"
    }
  } else {
    $roots = 'cacerts not read'
    $kt = Join-Path $ji.Home 'bin\keytool.exe'
    if (-not (@(Select-AuditTool 'keytool.exe') -contains $kt)) { $roots = 'cacerts not read (keytool.exe not in tools-to-run.txt)' }
    elseif ($ji.Cacerts) {
      try {
        $k = Invoke-AuditNativeProcess -FilePath $kt -ArgumentList @('-list','-keystore',$ji.Cacerts,'-storepass','changeit')
        $hits = @($k.StdOut -split "`r?`n" | Where-Object { $_ -match '^[^,]*(emsign|mudhra|comodoaaa|aaacertificate)[^,]*,' } | ForEach-Object { ($_ -split ',')[0] })
        $roots = if ($k.ExitCode -ne 0) { "keytool rc=$($k.ExitCode)" } elseif ($hits.Count) { "roots: $($hits -join ' ')" } else { 'roots: none found' }
      } catch { $roots = "keytool failed: $($_.Exception.Message)" }
    }
    foreach ($pair in $pairs) { Rec "java:$j" $pair[0] 'UNKNOWN' "Java $($ji.Version) (major $($ji.Major)): not measurable (TLS probe needs 11+); $roots" }
  }
}

# pip（python-all.txt の各実体のうち pip があるもの）。インデックスの URL をテストホストに向け、実在しないパッケージ名（毎回ランダム）を
# 取りに行かせる。--only-binary=:all: でソースからのビルド（コードの実行）を禁止する。pip の設定にある extra-index-url / find-links は
# 打ち消せない（空の環境変数は無視される）ので、そこへの通常どおりの問い合わせは起きる。判定はテストホストの行だけで行う。
# pip 24.2 以降は既定で truststore（Windows の判定）を使うので、Python の他の経路と結果が違う。24.2 より古い pip は
# 古い同梱 certifi を使うので、受け入れることがある。truststore の拒否理由は Windows のメッセージ（日本語）なので、
# 同じ Python に Windows のエラー番号ごとの文面を出させて照合する（失効・信頼されないルート・経路を作れない・明示的な不信頼 = REJECT、
# 期限・名前・用途・失効確認不能 = UNKNOWN）
$pipReasonPy = "import ctypes,json;f=lambda c:ctypes.FormatError(ctypes.c_long(c).value).strip();" +
  "print(json.dumps({'reject':[f(c) for c in (0x80092010,0x800B0109,0x800B010A,0x800B0111)],'unrelated':[f(c) for c in (0x800B0101,0x800B010F,0x800B0110,0x80092012,0x80092013)]}))"
$pipDest = Join-Path $out ('pip-probe-' + [guid]::NewGuid().ToString('N')); [void](New-Item -ItemType Directory $pipDest)   # 実行ごとに新規。この実行で作ったものだけを消す
try {
foreach ($py in @(Get-Content "$out\python-all.txt" -Encoding UTF8 | Where-Object { $_ })) {
  try { $pv = Invoke-AuditNativeProcess -FilePath $py -ArgumentList @('-c','import pip;print(pip.__version__)') -TimeoutMs 30000 } catch { continue }
  if ($pv.ExitCode -ne 0) { continue }   # pip が無い（N/A）
  $reasons = $null
  try { $reasons = (Invoke-AuditNativeProcess -FilePath $py -ArgumentList @('-c',$pipReasonPy) -TimeoutMs 30000).StdOut | ConvertFrom-Json } catch { }
  foreach ($pair in $pairs) {
    $name = 'emudhra-probe-' + [guid]::NewGuid().ToString('N')
    try {
      $r = Invoke-AuditNativeProcess -FilePath $py -ArgumentList @('-m','pip','download','-vvv','--no-deps','--only-binary=:all:','--no-cache-dir',
        '--disable-pip-version-check','--retries','0','--timeout','15','--index-url',$pair[1],'--dest',$pipDest,$name) -TimeoutMs 120000 `
        -Encoding ([Text.UTF8Encoding]::new($false)) -Environment @{ PYTHONIOENCODING = 'utf-8'; PIP_NO_INPUT = '1' }
      $text = $r.StdOut + $r.StdErr
      $key = @((Remove-AuditUrlText $text $pair[1]) -split "`r?`n" | Where-Object { $_ -match '<url>|<host>' -and $_ -match '"GET |problem confirming|connection error' })[0]
      $v = Get-AuditPipVerdict $text $pair[1] -RejectReasons @($reasons.reject) -UnrelatedReasons @($reasons.unrelated)
      Rec "pip:$py" $pair[0] $v "pip $($pv.StdOut.Trim()): $key"
    } catch { Rec "pip:$py" $pair[0] 'UNKNOWN' "pip $($pv.StdOut.Trim()): $($_.Exception.Message)" }
  }
}
} finally { Remove-Item -LiteralPath $pipDest -Recurse -Force }

# uv（tools-to-run.txt の uv.exe）。pip と同じく、インデックスの URL をテストホストに向けてランダムな名前を
# 「入れたふり」（--dry-run）させる。--only-binary :all: でビルドを禁止し、キャッシュは使わない。何もインストールされない。
# UV_NATIVE_TLS / UV_SYSTEM_CERTS は2つの値がありうる。このシェルが持っている値と、保存された値（ユーザー、無ければコンピューターの環境変数）。
# 保存された値は、サインインし直した後や、設定後に起動したエクスプローラー等から起動したアプリに渡る。設定より前に起動したシェルやランチャー
# から起動したものは古い値のまま（例: シェルを起動した後に UV_NATIVE_TLS=1 を設定すると、このシェルには無いので、uv は既定の経路で測られる）。
# 2つが違うときは両方で測り、Tool 名に [saved] / [shell] を付けて別々に記録する。どちらかが ACCEPT なら、その起動のしかたでは未対策（残件）。
# 古い uv は既定（自前の証明書一覧）で基本経路を受け入れ、UV_NATIVE_TLS=1 なら Windows の検証で両方を拒否する（Revoked）ことがある。
# uv 0.13.5 は既定（UV_NATIVE_TLS なし）でも両方を自前の一覧で拒否する（Other(OtherError(CertDistrusted)) = REJECT、v2.11.6）。
# さらに古い uv は UV_NATIVE_TLS=1 でも受け入れることがある（uv を上げる。venv の中の uv は pip で上げる）
$uvs = @(Select-AuditTool 'uv.exe')
$uvPyList = @(Get-Content "$out\python-all.txt" -Encoding UTF8 | Where-Object { $_ })   # 手順2で確認した一覧の中から選ぶ
$uvPython = if ($testPython -and ($uvPyList -contains $testPython)) { $testPython } else { $uvPyList[0] }
# v2.12.2: UV_SYSTEM_CERTS（uv 0.11.0 以降の名前）も同じように扱う。どちらか一方でもシェルと保存された値が違えば両方の状態で測る
$uvVars = 'UV_NATIVE_TLS','UV_SYSTEM_CERTS'
$uvShellEnv = @{}; $uvSavedEnv = @{}
foreach ($vn in $uvVars) {
  $uvShellEnv[$vn] = [Environment]::GetEnvironmentVariable($vn)
  $sv = [Environment]::GetEnvironmentVariable($vn,'User'); if ($null -eq $sv) { $sv = [Environment]::GetEnvironmentVariable($vn,'Machine') }
  $uvSavedEnv[$vn] = $sv
}
function Get-UvNote($e) { ($uvVars | ForEach-Object { "$_=$($e[$_])" }) -join ' ' }
# Env の値が $null なら子プロセスから外す
$uvStates = @(@{ Label = ''; Env = $uvShellEnv; Note = "$(Get-UvNote $uvShellEnv) (shell = saved)" })
if (@($uvVars | Where-Object { "$($uvShellEnv[$_])" -ne "$($uvSavedEnv[$_])" }).Count) {
  Write-Warning "uv の環境変数: このシェル='$(Get-UvNote $uvShellEnv)'、保存された値='$(Get-UvNote $uvSavedEnv)'。両方で測る（uv:<パス> [saved] / [shell]）"
  $uvStates = @(@{ Label = ' [saved]'; Env = $uvSavedEnv; Note = "$(Get-UvNote $uvSavedEnv) (saved)" },
                @{ Label = ' [shell]'; Env = $uvShellEnv; Note = "$(Get-UvNote $uvShellEnv) (this shell)" })
}
foreach ($u in $uvs) {
 foreach ($st in $uvStates) {
  foreach ($pair in $pairs) {
    $name = 'emudhra-probe-' + [guid]::NewGuid().ToString('N')
    try {
      # -v: 対象 URL へ GET を送った記録（Sending fresh GET request for:）を ACCEPT の根拠にする（no-index 等で問い合わせなければ UNKNOWN）
      $r = Invoke-AuditNativeProcess -FilePath $u -ArgumentList @('-v','pip','install','--dry-run','--no-deps','--only-binary',':all:','--no-cache',
        '--python',$uvPython,'--index-url',$pair[1],$name) -TimeoutMs 120000 -Encoding ([Text.UTF8Encoding]::new($false)) -Environment $st.Env
      $text = $r.StdErr + $r.StdOut
      $key = @((Remove-AuditUrlText $text $pair[1]) -split "`r?`n" | Where-Object { $_ -notmatch '^\s*DEBUG ' -and $_ -match 'invalid peer certificate|Content-Type|not found in the package registry|Failed to fetch' })[-1]
      Rec "uv:$u$($st.Label)" $pair[0] (Get-AuditUvVerdict $r.ExitCode $text $pair[1]) "$($st.Note); $key"
    } catch { Rec "uv:$u$($st.Label)" $pair[0] 'UNKNOWN' "$($st.Note); $($_.Exception.Message)" }
  }
 }
}

Write-AuditUtf8 -Path "$out\verify-windows-tools.json" -Text (ConvertTo-Json -InputObject @($rows.ToArray()) -Depth 4)
$toolSummary = @(Get-AuditSummary -Rows $rows.ToArray() -Control $CTRL -Targets $T)
$toolSummary | Format-Table -AutoSize
Write-AuditUtf8 -Path "$out\verify-windows-tools-summary.json" -Text (ConvertTo-Json -InputObject $toolSummary -Depth 4)
```

結果ファイル: `verify-python.json`（Python 経路別）、`verify-windows-trust.json`（Windows ストア直接）、`verify-windows-tools*.json`（curl / Node / Go / Git）。

注意点:
- `winstore:direct-sslstream` の自己検証（badssl の信頼されないルート）は、UntrustedRoot に RevocationStatusUnknown / OfflineRevocation が付くのを合格とする（信頼されないルートは失効確認できないため Windows が必ず付ける。v2.7 で修正。それ以外のビットが混ざれば不合格）。対象ホストの判定は厳格なまま
- 対策済みの Windows では、対象2ホストとも flags が 0x04010004（ExplicitDistrust | PartialChain | Revoked）のような値になり REJECT
- `winstore:direct-sslstream` は失効確認を有効にして接続する。CRL/OCSP に届かず `RevocationStatusUnknown` / `OfflineRevocation` が `ExplicitDistrust` と同時に出ると、安全側に倒して UNKNOWN になる。その場合は Disallowed ストアの Thumbprint 照合（3.1、`impacted-intermediates.json` と突合）を Windows 本体の証拠として併用する。ただし自動更新分は列挙に出ないことがあるため、照合で見つからないことは未対策の証拠にならない（その場合は UNKNOWN のまま残件）
- badssl の自己検証が REJECT にならない場合（badssl に届かない等）は、Windows ストア直接判定は全件 UNKNOWN になる。判定器を信用できないので、FIXED を出さないのが正しい挙動
- Python の stdlib-ssl が VULNERABLE でも certifi 更新では直らない（5.3 末尾）
- truststore を入れた venv では、拒否の理由が Windows のエラー番号（例: 2148081680 = 0x80092010 = CRYPT_E_REVOKED）で返る。probe_python.py は失効・信頼されないルート・経路を作れない・明示的な不信頼の4つを REJECT として数える（期限切れ・名前不一致は UNKNOWN）

### 6.2 WSL（bash、ディストリごと、通常ユーザー）

```bash
# Windows 側の配置済みキットから WSL へ配置（コピー後に SHA256 照合。.sh/.py に CR が含まれていれば中止。配置先の条件は 1.1 の 4 と同じ。配置先は WSL 側のファイルシステムに限り、/mnt/ 配下は不可）。Windows ユーザー名は WSL と違いうる
bash /mnt/c/Users/<Windowsユーザー>/emudhra-audit/kit/install_kit_wsl.sh   # → ~/emudhra-audit/kit
cd ~/emudhra-audit/kit
# 0) キットの試験（外部通信なし。集計 audit_summary.py の試験を含む）が通ったときだけ verify_wsl.sh に進む。
#    && でつなぐので、試験が失敗すると verify_wsl.sh は動かない（exit を使わないのは、対話のシェルごと閉じないため）
bash test_verify_wsl.sh && python3 -B -m unittest test_probe_python && \
bash verify_wsl.sh            # TLS 検査を自動検出。既知なら --known-tls-inspection を付ける
```

`verify_wsl.sh` が行うこと: TLS 検査の自動検出 → curl / wget / Git / Node / uv / Java（PATH の先が /mnt/ 配下なら Windows 側の実体として測らない。Java は 11 以上のみ実測）→ Python（`/usr/bin/python3`、`/usr/local/bin/python3`、venv-inventory.tsv の全 venv（起動不可含む）、conda prefix、pipx、uv、pyenv）を経路別に `probe_python.py` で検査 → `audit_summary.py` で集計。結果は `~/emudhra-audit/verify-wsl.tsv` と `verify-wsl-summary.tsv`。

### 6.3 突き合わせ（未検証を完了扱いにしない）

- 棚卸しで見つけた Python 実体（`python-all.txt` / `verify-pylist.txt`）と、検証結果のツール列を突き合わせ、**一覧にあって結果が UNKNOWN のもの、一覧に無いもの**を残件にする
- `venv-scan-errors.txt`（走査エラー）、`venv-scan-skipped-links.txt`（降りなかったリンク先）、`venv-linux-on-windows.txt` 未取込（3.3b 未実施）は「未探索領域」として報告する

### 6.4 版の照合（Brotli・Pillow・固めたアプリ・証明書ファイル）

eMudhra と同じ時期に公表された、次の2件を版で照合する（細工したデータを送る実測はしない。危険なため）。修正版は 4章。
- **Brotli 展開処理の範囲外書き込み（CVE-2026-111497、通称 Node2Shell。X では HTTP2Shell とも呼ばれる）**: 細工した Brotli のデータを展開させるとメモリ破壊（RCE の可能性）。
  Node.js / Bun / libbrotli（curl・Git の libcurl）/ Python の brotli・brotlicffi / Electron / .NET / Chromium などが Brotli を同梱する。
  curl.exe を持たない Git（MinGit 型）、Inkscape・gnuplot・ImageMagick などのアプリ、Python の wheel が抱える libbrotlidec、単体配布の .NET アプリ（System.IO.Compression.Native.dll）、
  Chromium を内蔵するアプリ（CEF = libcef.dll、Qt WebEngine）も同じ範囲に入る（v2.12 から 3.2 が名前で拾い、手順8bで判定する）。
  HTTP の応答（`Content-Encoding: br`）は自動で展開されることが多い（Node の fetch、git / curl の libcurl、requests は brotli が入っていれば）。
  eMudhra の偽証明書で通信に割り込めれば、細工した応答を送り込める。
- **Pillow 13.0.0 の約 40 件の修正（2026-10-16）**: 画像を開く・縮小表示するだけで起きるものを含む（例 CVE-2026-112403）。
  EPS の件（CVE-2026-112900）は Ghostscript があり、`Image.open()` に渡すファイル名を攻撃者が操れるときだけ。**Pillow 13 は Python 3.11 以上が必要で、3.10 向けの修正版は無い。**

判定の規則:
- 版の表示だけで判定できないものがある。修正済みの Node 24.22.1 は修正部分だけを取り込んだため `brotli 1.2.0` と表示する。
  そのため Node は Node の版で、Bun は Bun の版で判定し、libbrotli の版で判定するのは curl / Git の libcurl（MSYS2 の libbrotli そのもの）と Python の brotli だけにする。
- 版は正式版の形（数字 1〜4 個）だけを比べる。`rc`・`dev`・`-canary`・`-beta` などの付いた版、読めない版は UNKNOWN（修正版のプレリリースを修正版と数えない）。
- 実行するのは 6.1 の手順2で確認した `tools-to-run.txt` と `python-all.txt` にあるものだけ。それ以外は実行せず、ファイルの版や dist-info の名前を読む。
- 手順8b の DLL（3.2 の `brotli-lib-found.csv`）は**読み込まず実行もしない**。libbrotlidec は SHA256 を既知の表（`Get-AuditBrotliKnownHashes`: MSYS2 1.2.1-1 の mingw64 / ucrt64 が FIXED、Git for Windows / PortableGit 同梱の 1.2.0 の mingw64 / ucrt64 が VULNERABLE）と照らし、
- Replace-GitBrotli.ps1 以外の方法（台ごとの1回限りのスクリプトなど）で退避した DLL は、決まった配置ではないので INFO にならず、中身の版どおり（1.2.0 なら VULNERABLE）に数える。どのプログラムも読み込まない退避だと確かめたら、報告書に「退避（読み込まれない）」と注記する（例: アプリのフォルダに置いた `_emudhra_backup_brotli-1.2.0-*`。v2.12.7）
  表にないものは版を推測せず UNKNOWN（持ち主の手がかりを Note に残す）。CEF / Qt WebEngine は UNKNOWN（版を記録。更新を確かめる）、単体配布の .NET は発行元が Microsoft で版を読めたものだけ VULNERABLE、それ以外は UNKNOWN（共有ランタイムの中の DLL は手順8の `dotnet.exe` で判定するのでここには出ない）。

```powershell
# 6.1 の後に、同じ PowerShell で実行する。実測に使う Python は python-all.txt の中から選ぶ（$testPython が一覧に残っていればそれ、無ければ先頭）
$kit = Join-Path $HOME 'emudhra-audit\kit'; $out = Join-Path $HOME 'emudhra-audit'
. "$kit\Test-Emudhra.Helpers.ps1"
$vs = [Collections.Generic.List[object]]::new()
function Add-VS($Topic, $Item, $Path, $Version, $Verdict, $Note) {
  $vs.Add([pscustomobject]@{ Topic=$Topic; Item=$Item; Path=$Path; Version=$Version; Verdict=$Verdict; Note=(Hide-AuditSecret ([string]$Note)) }) }
# 実行の一覧（6.1 手順2で確認したもの）。一覧が無い・読めない、一覧にある実体が消えている場合は UNKNOWN を残す
function Read-AuditRunList([string]$Name) {
  $f = Join-Path $out $Name
  try { $all = @(Get-Content -LiteralPath $f -Encoding UTF8 -ErrorAction Stop | Where-Object { $_ }) }
  catch { Add-VS 'scan' $Name '' '' 'UNKNOWN' "一覧が無い・読めない（6.1 を先に実施）: $($_.Exception.Message)"; return @() }
  foreach ($x in $all) { if (-not (Test-Path -LiteralPath $x -PathType Leaf)) { Add-VS 'scan' $Name $x '' 'UNKNOWN' '一覧にあるが実体が無い（6.1 の後に消えた）' } }
  @($all | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf }) }
$toolsToRun = @(Read-AuditRunList 'tools-to-run.txt')   # 1 件でも配列にする
function Select-AuditTool([string]$Name) { @($toolsToRun | Where-Object { [IO.Path]::GetFileName($_) -ieq $Name }) }
$pyList = @(Read-AuditRunList 'python-all.txt')
# 3.1 / 3.2 の結果を読む。無ければ（v2.10 の 3.1 / 3.2 を実施していない）その範囲は未探索として UNKNOWN を残す
# 3.1 / 3.2 が v2.10 で書いた目印（<名前>.ok）が無ければ、古い版の結果か未実施なので、その範囲は未探索として UNKNOWN を残す（0 件の結果でも目印は残る）。
# 目印があっても必要な列が無ければ同じく UNKNOWN
function Import-AuditScan([string]$Name, [string[]]$Required = @()) {
  $f = Join-Path $out $Name
  if (-not (Test-Path -LiteralPath "$f.ok" -PathType Leaf)) { Add-VS 'scan' $Name '' '' 'UNKNOWN' 'v2.10 の 3.1 / 3.2 で作った結果ではない（目印 .ok が無い）。やり直すまで、この範囲は未探索'; return @() }
  if (-not (Test-Path -LiteralPath $f -PathType Leaf)) { return @() }   # 0 件のとき Export-Csv はファイルを作らないことがある
  # 見出しの行を直接確かめる（データの行が 0 件でも列の不足を見逃さない）。空のファイルは 0 件の正常な結果
  try { $head = @(Get-Content -LiteralPath $f -Encoding UTF8 -TotalCount 1 -ErrorAction Stop) } catch { Add-VS 'scan' $Name '' '' 'UNKNOWN' "読めない: $($_.Exception.Message)"; return @() }
  if ($head.Count -eq 0 -or -not $head[0]) { return @() }
  $cols = @($head[0] -split ',' | ForEach-Object { $_.Trim().Trim('"') })
  $missing = @($Required | Where-Object { $cols -notcontains $_ })
  if ($missing.Count) { Add-VS 'scan' $Name '' '' 'UNKNOWN' "古い形式（列 $($missing -join ', ') が無い）。3.1 / 3.2 を v2.10 でやり直すまで、この列の範囲は未探索" }
  try { @(Import-Csv -LiteralPath $f -Encoding UTF8 -ErrorAction Stop) } catch { Add-VS 'scan' $Name '' '' 'UNKNOWN' "読めない: $($_.Exception.Message)"; @() } }
$probePy = if ($testPython -and ($pyList -contains $testPython)) { $testPython } else { $pyList[0] }
$nodeFix = @('22.23.4','24.22.1','26.12.1'); $bunFix = @('1.4.4'); $libFix = @('1.0.10','1.1.1','1.2.1')

# 1) Node（実行しない。ファイルの版）
foreach ($n in (Select-AuditTool 'node.exe')) {
  $v = (Get-Item -LiteralPath $n).VersionInfo.ProductVersion
  Add-VS 'brotli' 'node' $n $v (Compare-AuditFixedVersion $v $nodeFix) 'Node の版で判定（同じリリースで eMudhra も修正）。20 以前・23・25 は修正なし' }

# 2) Electron と内蔵 Bun（3.1 の electron-apps.csv。読み取りに失敗した exe は UNKNOWN）
foreach ($e in (Import-AuditScan 'electron-apps.csv' @('Electron','Bun','ReadError'))) {
  if ($e.ReadError) { Add-VS 'brotli' 'embedded' $e.Path '' 'UNKNOWN' "読み取れない: $($e.ReadError)"; continue }
  foreach ($x in @($e.Electron -split ',' | Where-Object { $_ })) {
    $ev = if ($x -match '^\d+\.\d+\.\d+$') { 'VULNERABLE' } else { 'UNKNOWN' }
    Add-VS 'brotli' 'electron' $e.Path $x $ev 'Electron 内蔵の Node: 2026-10-24 時点で修正を取り込んだ Electron は無い（4章で再確認。ベンダー待ち）' }
  foreach ($b in @($e.Bun -split ',' | Where-Object { $_ })) { Add-VS 'brotli' 'bun(embedded)' $e.Path $b (Compare-AuditFixedVersion $b $bunFix -LineParts 0) '内蔵 Bun（Claude Code ネイティブ版、bun build --compile の CLI など）。本体の更新で直る' } }
foreach ($b in (Select-AuditTool 'bun.exe')) {
  try { $br = Invoke-AuditNativeProcess -FilePath $b -ArgumentList @('--version') -TimeoutMs 30000 } catch { $br = $null }
  if (-not $br -or $br.ExitCode -ne 0) { Add-VS 'brotli' 'bun' $b '' 'UNKNOWN' "版を取得できない: exit=$($br.ExitCode)"; continue }
  $v = $br.StdOut.Trim()
  Add-VS 'brotli' 'bun' $b $v (Compare-AuditFixedVersion $v $bunFix -LineParts 0) 'bun upgrade で直る（版の形でなければ UNKNOWN）' }

# 3) libcurl の Brotli（tools-to-run.txt の curl.exe。Git 同梱の curl は git と同じ libcurl-4.dll / libbrotlidec.dll を使う）
foreach ($c in (Select-AuditTool 'curl.exe')) {
  try { $cr = Invoke-AuditNativeProcess -FilePath $c -ArgumentList @('-V') -TimeoutMs 30000 } catch { $cr = $null }
  $first = if ($cr) { @($cr.StdOut -split "`r?`n")[0] } else { '' }
  # 正常終了し、先頭行が「curl x.y.z (...) libcurl/x.y.z ...」の形のときだけ Brotli の有無を判断する
  if (-not $cr -or $cr.ExitCode -ne 0 -or $first -notmatch '^curl \d+\.\d+\.\d+\S* \(.*\) libcurl/\d+\.\d+\.\d+') { Add-VS 'brotli' 'libcurl' $c '' 'UNKNOWN' "curl -V を読めない: exit=$($cr.ExitCode) $first"; continue }
  $m = [regex]::Match($first, ' brotli/(\S+)')
  if ($m.Success) { Add-VS 'brotli' 'libcurl' $c $m.Groups[1].Value (Compare-AuditFixedVersion $m.Groups[1].Value $libFix -LineParts 2) 'Git 同梱なら git の HTTPS も同じ Brotli を使う（5.11）' }
  else { Add-VS 'brotli' 'libcurl' $c '' 'INFO' 'Brotli 無しでビルド（対象外）' } }

# 4) Python の Pillow / brotli / brotlicffi（python-all.txt）。未導入と、読めないメタデータを分ける
$pkgPy = Join-Path $out 'pkg_versions.py'
Write-AuditUtf8 -Path $pkgPy -Text @'
import importlib.metadata as m, json, sys
r = {'python': sys.version.split()[0], 'errors': {}}
for n in ('pillow', 'brotli', 'brotlicffi'):
    try:
        v = m.version(n)
        if v: r[n] = v
        else: r['errors'][n] = 'empty version'
    except m.PackageNotFoundError:
        pass
    except Exception as e:
        r['errors'][n] = type(e).__name__
r['done'] = True
print(json.dumps(r))
'@
foreach ($p in $pyList) {
  try {
    # -E: PYTHON* の環境変数だけ無視する。-I と違い、普段の起動と同じくユーザー領域（pip install --user）も見る
    $pr = Invoke-AuditNativeProcess -FilePath $p -ArgumentList @('-E', $pkgPy) -TimeoutMs 60000
    $j = if ($pr.ExitCode -eq 0 -and $pr.StdOut.Trim()) { $pr.StdOut.Trim() | ConvertFrom-Json } else { $null }
  } catch { $j = $null; $pr = $null }
  if (-not $j -or -not $j.done -or -not $j.python) { Add-VS 'python' 'packages' $p '' 'UNKNOWN' "取得できない: exit=$($pr.ExitCode) $($pr.StdErr)"; continue }
  foreach ($k in @($j.errors.PSObject.Properties | ForEach-Object Name)) { Add-VS 'python' $k $p '' 'UNKNOWN' "メタデータを読めない: $($j.errors.$k)" }
  if ($j.pillow) {
    $pv = Compare-AuditFixedVersion $j.pillow @('13.0.0') -LineParts 0
    $old = try { ([version]($j.python -replace '^(\d+\.\d+).*','$1')) -lt [version]'3.11' } catch { $false }
    $note = if ($pv -eq 'VULNERABLE' -and $old) { "Python $($j.python): Pillow 13 を入れられない（修正版なし）。5.11 の運用制限" } else { 'pip install -U "Pillow>=13.0.0"（app_managed は承認のうえ）' }
    Add-VS 'pillow' 'pillow' $p $j.pillow $pv $note }
  if ($j.brotli) { Add-VS 'brotli' 'pypi-brotli' $p $j.brotli (Compare-AuditFixedVersion $j.brotli @('1.2.1') -LineParts 0) 'PyPI の brotli は 1.2.1 未満がすべて影響（GHSA-9v8h-qqgm-4m35）' }
  if ($j.brotlicffi) { Add-VS 'brotli' 'pypi-brotlicffi' $p $j.brotlicffi (Compare-AuditFixedVersion $j.brotlicffi @('1.2.1.0') -LineParts 0) 'brotlicffi は 1.2.1.0 で修正' } }

# 5) 固めた Python のアプリ（3.2 の frozen-python-found.csv。実行しない。dist-info の名前から版を読む。同じパッケージが複数の版あれば UNKNOWN）
# dist-info を含めずに固めることがあるので、版が読めなくても「入っている」ことを別に確かめる:
#   Pillow / brotli / brotlicffi は C の拡張（.pyd）を持ち、これは圧縮した書庫からは読み込めないので必ずファイルとして置かれる → Native で探す。
#   certifi は純粋な Python で書庫に入りうるが、cacert.pem はファイルとして置く必要があり、6) の実測で拾う（Native なし）
$frozenPkgs = @(
  @{ Name='pillow'; Native='_imaging*.pyd'; Topic='pillow'; Fixed=@('13.0.0') }, @{ Name='certifi'; Native=''; Topic='emudhra'; Fixed=@('2026.10.19') },
  @{ Name='brotli'; Native='_brotli*.pyd'; Topic='brotli'; Fixed=@('1.2.1') }, @{ Name='brotlicffi'; Native='_brotlicffi*.pyd'; Topic='brotli'; Fixed=@('1.2.1.0') })
foreach ($f in (Import-AuditScan 'frozen-python-found.csv' @('Dir','PythonDll','Exes'))) {
  $what = "app: $($f.Exes); $($f.PythonDll)"; $any = $false
  try { $names = @(Get-ChildItem -LiteralPath $f.Dir -Directory -Filter '*.dist-info' -ErrorAction Stop | ForEach-Object Name) }
  catch { Add-VS 'frozen' 'frozen-python' $f.Dir '' 'UNKNOWN' "$what。フォルダを読めない: $($_.Exception.Message)"; continue }
  foreach ($pk in $frozenPkgs) {
    $mine = @($names | Where-Object { $_ -like "$($pk.Name)-*.dist-info" })
    $vers = @($mine | ForEach-Object { $mm = [regex]::Match($_, "^(?i)$($pk.Name)-(\d[^-]*)\.dist-info$"); if ($mm.Success) { $mm.Groups[1].Value } } | Sort-Object -Unique)
    if ($mine.Count -gt 0 -and $vers.Count -lt $mine.Count) { $any = $true; Add-VS $pk.Topic "$($pk.Name)(frozen)" $f.Dir ($mine -join ',') 'UNKNOWN' "$what。dist-info の名前から版を読めない"; continue }
    if ($vers.Count -eq 0) {
      if ($pk.Native) {
        # リンクとクラウドのプレースホルダーには降りない（v2.11.3）。降りなかった・読めなかった場所があれば、拡張が無いとは言えないので UNKNOWN
        $natSkipped = [System.Collections.Generic.List[string]]::new()
        $nat = @(Get-AuditFilesNoLinks -Root $f.Dir -Filter $pk.Native -Errors $natSkipped | Select-Object -First 3 | ForEach-Object Name)
        if ($nat.Count) { $any = $true; Add-VS $pk.Topic "$($pk.Name)(frozen)" $f.Dir ($nat -join ',') 'UNKNOWN' "$what。$($pk.Name) の拡張はあるが dist-info が無い（版を目で確かめる）" }
        elseif ($natSkipped.Count) { $any = $true; Add-VS $pk.Topic "$($pk.Name)(frozen)" $f.Dir '' 'UNKNOWN' "$what。$($pk.Name) の拡張を探す途中で降りなかった・読めなかった場所がある: $(@($natSkipped)[0])" }
      }
      continue }
    $any = $true
    $verdict = if ($vers.Count -gt 1) { 'UNKNOWN' } else { Compare-AuditFixedVersion $vers[0] $pk.Fixed -LineParts 0 }
    $extra = if ($vers.Count -gt 1) { '。複数の版があり、使われる版を確定できない' } elseif ($pk.Name -eq 'certifi') { '。下の 6) で同梱の cacert.pem を実測' } else { '' }
    Add-VS $pk.Topic "$($pk.Name)(frozen)" $f.Dir ($vers -join ',') $verdict "$what$extra。固めたアプリは中だけ更新できない（作者のビルド待ち、または 5.11）" }
  if (-not $any) { Add-VS 'frozen' 'frozen-python' $f.Dir '' 'INFO' "$what。Pillow / brotli / brotlicffi の拡張も dist-info も無い（対象外）。certifi は 6) の cacert.pem で判定" } }

# 5b) PyInstaller の単一 exe 型（3.2 の frozen-onefile-found.csv。自分の開発環境（*.spec のある dist）で作ったものだけ）: 中身は展開しないと見えないので、
#     版も cacert.pem も判定できない（UNKNOWN）。開発環境があるので、spec の依存を更新して作り直せる。
#     それ以外の単一 exe 型（もらったもの、ダウンロードしたツール）は方針で調べていない。**このキットでは見逃す**（報告書の未探索に書く）。
#     そうしたアプリの中の部品（Python、Pillow、certifi、ほかのライブラリ）の脆弱性は、開発した側が申告するもの（依存の一覧や告知）で、利用者が中を精査する前提にしない
foreach ($o in (Import-AuditScan 'frozen-onefile-found.csv' @('FullName','Kind'))) {
  $kindNote = if ($o.Kind -eq 'onefile') { 'PyInstaller の単一 exe 型' } else { 'PyInstaller の目印あり。隣に python3*.dll があり、フォルダ型の起動用（そのフォルダは frozen-python-found.csv で判定）か、同じ場所の別の単一 exe 型かを確定できない' }
  Add-VS 'frozen' "frozen-$($o.Kind)" $o.FullName $o.ProductVersion 'UNKNOWN' "$kindNote（$($o.CompanyName) $($o.LastWriteTime)）。中の Python・Pillow・certifi・brotli は展開しないと判定できない。目で確かめて、フォルダ型の起動用なら残件から外す" }

# 6) 証明書の一覧ファイル（3.2 の ca-file-found.csv）。今の中身を作業用フォルダに写し、写しでハッシュと実測を行う（3.2 の後に更新されても取り違えない）。
#    写しの内容ごとに1回、その一覧だけを信頼させて対照と2ホストへ接続する。-I -S で起動し（venv の truststore の .pth を読み込ませない）、
#    標準の ssl.SSLContext であることも確かめる。一覧を実際に使うのは、それを抱えるアプリ
$caPy = Join-Path $out 'ca_probe.py'
Write-AuditUtf8 -Path $caPy -Text @'
import json, socket, ssl, sys
if ssl.SSLContext.__module__ != 'ssl' or ssl.create_default_context.__module__ != 'ssl':
    print(json.dumps({'error': 'ssl replaced: ' + ssl.SSLContext.__module__})); sys.exit()
ca, hosts, res = sys.argv[1], sys.argv[2:], {}
for h in hosts:
    try:
        ctx = ssl.create_default_context(cafile=ca)
        with socket.create_connection((h, 443), timeout=15) as s, ctx.wrap_socket(s, server_hostname=h):
            res[h] = 'ACCEPT'
    except ssl.SSLCertVerificationError as e:
        res[h] = 'REJECT' if e.verify_code in (2, 19, 20, 21, 23) else 'UNKNOWN:%s' % e.verify_code
    except Exception as e:
        res[h] = 'UNKNOWN:' + type(e).__name__
print(json.dumps(res))
'@
$req = [Net.WebRequest]::Create('https://www.google.com/'); $req.Timeout = 15000   # TLS 検査の検出（6.1 と同じ）
try { $req.GetResponse().Close(); $issuer = $req.ServicePoint.Certificate.Issuer } catch { $issuer = '' }
if (-not $issuer) { Write-Warning '発行者を読めない（通信の失敗か、PowerShell 7。powershell.exe で実行する）。証明書ファイルの判定は全件 UNKNOWN になる' }
$inspect = $issuer -notmatch 'O=Google Trust Services'
$caHosts = @('www.google.com','dv-g3b-emudhra.we-have-a-problem.com','dv-g3b-aaa-emudhra.we-have-a-problem.com')
$snap = Join-Path $out ('ca-snapshot-' + [guid]::NewGuid().ToString('N')); [void](New-Item -ItemType Directory $snap)
try {
  $copies = foreach ($row in (Import-AuditScan 'ca-file-found.csv' @('FullName','Error'))) {
    if ($row.Error) { Add-VS 'emudhra' 'ca-file' $row.FullName '' 'UNKNOWN' "3.2 で読めなかった: $($row.Error)"; continue }
    try {
      $dst = Join-Path $snap ([guid]::NewGuid().ToString('N') + '.pem'); [IO.File]::WriteAllBytes($dst, [IO.File]::ReadAllBytes($row.FullName))
      $fi = Get-Item -LiteralPath $row.FullName
      [pscustomobject]@{ Path=$row.FullName; Copy=$dst; Hash=(Get-FileHash -LiteralPath $dst).Hash.ToLowerInvariant(); Written=$fi.LastWriteTime.ToString('s') }
    } catch { Add-VS 'emudhra' 'ca-file' $row.FullName '' 'UNKNOWN' "読み取れない: $($_.Exception.Message)" } }
  foreach ($g in @($copies | Group-Object Hash)) {
    $paths = ($g.Group | ForEach-Object Path) -join '; '
    try { $r = ((Invoke-AuditNativeProcess -FilePath $probePy -ArgumentList (@('-I', '-S', $caPy, $g.Group[0].Copy) + $caHosts) -TimeoutMs 120000).StdOut.Trim()) | ConvertFrom-Json }
    catch { Add-VS 'emudhra' 'ca-file' $paths '' 'UNKNOWN' $_.Exception.Message; continue }
    if ($r.error) { Add-VS 'emudhra' 'ca-file' $paths '' 'UNKNOWN' $r.error; continue }
    $c = $r.'www.google.com'; $t1 = $r.'dv-g3b-emudhra.we-have-a-problem.com'; $t2 = $r.'dv-g3b-aaa-emudhra.we-have-a-problem.com'
    $v = if ($inspect) { 'UNKNOWN' } elseif ($c -ne 'ACCEPT') { 'UNKNOWN' } elseif ($t1 -eq 'ACCEPT' -or $t2 -eq 'ACCEPT') { 'VULNERABLE' } elseif ($t1 -eq 'REJECT' -and $t2 -eq 'REJECT') { 'FIXED' } else { 'UNKNOWN' }
    Add-VS 'emudhra' 'ca-file' $paths "$($g.Group[0].Written) sha256 $($g.Name.Substring(0,12))" $v "control=$c base=$t1 aaa=$t2。VULNERABLE は、その一覧を使うアプリの通信が受け入れる側（5.11）" }
} finally { Remove-Item -LiteralPath $snap -Recurse -Force }

# 7) Ghostscript（Pillow の EPS の件の前提。Pillow は PATH の gswin32c → gswin64c → gs を使う。実行しない）
$gs = @('gswin32c','gswin64c','gs' | ForEach-Object { (Get-Command $_ -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1).Source } | Where-Object { $_ })
if ($gs.Count) { foreach ($x in $gs) { Add-VS 'pillow' 'ghostscript' $x ((Get-Item -LiteralPath $x).VersionInfo.ProductVersion) 'INFO' 'あると CVE-2026-112900（EPS のファイル名）が成立しうる。Pillow < 13 の環境では不要なら削除（5.11）' } }
else { Add-VS 'pillow' 'ghostscript' '' '' 'INFO' 'PATH に無い（EPS の件は成立しない）' }

# 8) 修正版が未提供・未確認のもの: .NET ランタイム（tools-to-run.txt の dotnet.exe。修正なし = VULNERABLE）、Chrome / Edge（告知なし = UNKNOWN）
foreach ($dn in (Select-AuditTool 'dotnet.exe')) {
  try { $dr = Invoke-AuditNativeProcess -FilePath $dn -ArgumentList @('--list-runtimes') -TimeoutMs 60000 } catch { Add-VS 'brotli' 'dotnet-runtime' $dn '' 'UNKNOWN' "取得できない: $($_.Exception.Message)"; continue }
  if ($dr.ExitCode -ne 0) { Add-VS 'brotli' 'dotnet-runtime' $dn '' 'UNKNOWN' "取得できない: exit=$($dr.ExitCode) $($dr.StdErr)"; continue }
  $lines = @($dr.StdOut -split "`r?`n" | Where-Object { $_.Trim() })
  if ($lines.Count -eq 0) { Add-VS 'brotli' 'dotnet-runtime' $dn '' 'INFO' 'ランタイムなし（対象外）'; continue }
  foreach ($l in $lines) {
    if ($l -match '^\S+ \d+\.\d+\.\d+\S* \[') { Add-VS 'brotli' 'dotnet-runtime' $dn $l 'VULNERABLE' '.NET は内蔵 Brotli 1.1.0。2026-10-24 時点で修正なし（ベンダー待ち。4章で再確認）' }
    else { Add-VS 'brotli' 'dotnet-runtime' $dn $l 'UNKNOWN' '想定外の出力' } } }
foreach ($b in @("${env:ProgramFiles}\Google\Chrome\Application\chrome.exe","${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path -LiteralPath $_ }) {
  Add-VS 'brotli' 'browser' $b ((Get-Item -LiteralPath $b).VersionInfo.ProductVersion) 'UNKNOWN' 'Chromium は 2026-03 に Brotli を上流の最新へ更新（修正コミットは 2026-02-27）。修正の告知は未確認（4章で再確認）' }

# 8b) Brotli を抱えるライブラリ（3.2 の brotli-lib-found.csv。curl -V に出ない Git 同梱・アプリ同梱・Python の wheel 同梱・CEF / Qt WebEngine・単体配布の .NET）。
#     DLL は読み込まず実行もしない。brotli-lib はファイルの SHA256 だけで判定する: 既知のもの（MSYS2 1.2.1-1 = FIXED、Git for Windows / PortableGit 同梱の 1.2.0 = VULNERABLE）以外は UNKNOWN で、
#     版を日付などから推測しない。クラウドにだけあるファイルは開かない（UNKNOWN）。所有者の手がかり: Git の木ならそのルート、それ以外は隣の exe の版
foreach ($b in (Import-AuditScan 'brotli-lib-found.csv' @('FullName','Kind','CloudOnly','FileVersion','ProductVersion','CompanyName','Note'))) {
  $sha = ''; $shaErr = ''
  if ($b.Kind -eq 'brotli-lib' -and $b.CloudOnly -ne 'True' -and -not $b.Note) {
    try { $sha = (Get-FileHash -LiteralPath $b.FullName -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant() } catch { $shaErr = $_.Exception.Message } }
  $r = Get-AuditBrotliLibVerdict -Row $b -Sha256 $sha -ReadError $shaErr
  $who = "$($b.CompanyName) FileVersion $($b.FileVersion) ProductVersion $($b.ProductVersion)"
  $gitHint = if ($r.GitRoot -and $r.GitIs32) { "Git for Windows の木 $($r.GitRoot)（32 ビット版 mingw32。Replace-GitBrotli.ps1 は未対応。Git の更新を待つ）" }
             elseif ($r.GitRoot) { "Git for Windows の木 $($r.GitRoot)。Replace-GitBrotli.ps1 -GitRoot '$($r.GitRoot)' -Check で確認（5.11）" } else { '' }
  $note = switch ($r.Reason) {
    'known-hash' { if ($r.Verdict -eq 'FIXED') { "$($r.Known)（ハッシュ一致）。$gitHint" } else { "$($r.Known)（ハッシュ一致）。$gitHint$(if (-not $gitHint) { 'このライブラリを持つアプリの更新待ち（4章）' })" } }
    'unknown-hash' {
      if ($gitHint) { "ハッシュが既知の版と一致しない。$gitHint" }
      else { $nb = Get-AuditNeighborExeText -Path $b.FullName; "ハッシュが既知の版と一致しないので版を決めない。持ち主のアプリを確かめる: フォルダ $(Split-Path -Parent $b.FullName)。同じ・親フォルダの exe: $(if ($nb) { $nb } else { '無し' })。$who。アプリの更新履歴で Brotli 1.2.1 以降かを確かめる" } }
    'backup' { "Replace-GitBrotli.ps1 が退避した元のファイル（Git の木の直下の決まった配置。Git は読み込まない。戻すとき用）。中身: $(if ($r.Known) { $r.Known } else { '既知の版と一致しない' })。数に入れない（v2.12.4）" }
    'cloud-only' { 'クラウドにだけあるファイルなので開いていない（ダウンロードしてから 3.2 をやり直す）' }
    'not-read' { "読んでいない: $($b.Note)" }
    'hash-error' { "ハッシュを読めない: $shaErr" }
    'chromium-embedded' { "Chromium を内蔵するアプリ（CEF / Qt WebEngine）。版 $($r.Version)（CEF の ProductVersion には Chromium の版が入ることが多い）。Chromium は 2026-03 に Brotli を上流の最新へ更新（修正コミットは 2026-02-27）だが、修正の告知は 2026-10-24 時点で未確認（4章で再確認）。古い Chromium は Brotli 以外の脆弱性も抱えるので、アプリの更新を確かめる。$who" }
    'dotnet-no-fix' { "単体配布の .NET アプリが抱えるネイティブの Brotli（System.IO.Compression.Native.dll、Microsoft 製）。.NET は 2026-10-24 時点で修正なし（ベンダー待ち。4章で再確認。.NET が修正版を出したら、この判定は版で見直す）。$who" }
    'dotnet-not-microsoft' { "System.IO.Compression.Native.dll という名前だが、発行元が Microsoft ではないので .NET の DLL とは決めない。持ち主のアプリを確かめる。$who" }
    default { "想定外の種類: $($b.Kind)" } }
  $item = switch ($b.Kind) { 'brotli-lib' { 'brotli-dll' } default { $b.Kind } }
  Add-VS 'brotli' $item $b.FullName $r.Version $r.Verdict $note }

# 9) 自分のプロジェクトのサーバー側の経路（package.json の直接の依存。node_modules / AppData / Program Files は除く）
$srvPat = '"(express|body-parser|fastify|@fastify/compress|koa|koa-body|koa-bodyparser|koa-compress|compression)"\s*:\s*"([^"]+)"'
# 調べるのは 3.2 が走査したドライブ（drives-scanned.txt）だけ。Get-ChildItem -Recurse は Windows PowerShell 5.1 でジャンクション等のリンクをたどり、
# OneDrive / iCloud などのクラウドのプレースホルダーにも降りて package.json を開く（ダウンロードが始まりうる）ので使わない（v2.11.3）。
# Get-AuditFilesNoLinks はリンクとプレースホルダーに降りず、降りなかった場所と読めなかった場所を記録する（version-scan-pkgjson-skipped.txt。未探索）
$scanDrives = @(Get-Content -LiteralPath "$out\drives-scanned.txt" -Encoding UTF8 -ErrorAction SilentlyContinue | Where-Object { $_ })
if ($scanDrives.Count -eq 0) { Add-VS 'scan' 'drives-scanned.txt' '' '' 'UNKNOWN' '3.2（v2.11.3 以降）が走査したドライブの一覧が無い。手順9は未実施（未探索）' }
$pkgSkipped = [Collections.Generic.List[string]]::new()
# 除くフォルダ（どの深さでも、名前が一致すれば中に降りない。除くのは方針なので未探索には数えない）
$pkgPrune = @('node_modules','Windows','Program Files','Program Files (x86)','ProgramData','$Recycle.Bin','AppData','System Volume Information')
foreach ($d in $scanDrives) {
  Get-AuditFilesNoLinks -Root $d -Filter package.json -Errors $pkgSkipped -PruneDirectoryName $pkgPrune |
    ForEach-Object {
      # 読めないファイル（使用中・権限・走査の後に消えた）は未探索に記録して続ける
      $pj = $_.FullName
      if (Test-AuditCloudOnly -Item $_) { $pkgSkipped.Add("$pj : cloud-only, not read"); return }
      try { $txt = [IO.File]::ReadAllText($pj) } catch { $pkgSkipped.Add("$pj : $($_.Exception.Message)"); return }
      $mm = [regex]::Matches($txt, $srvPat)
      if ($mm.Count) { Add-VS 'brotli' 'server-deps' $pj (($mm | ForEach-Object { $_.Groups[1].Value + '@' + $_.Groups[2].Value }) -join ', ') 'UNKNOWN' '人が確かめる: Express 5 / body-parser 2 などは Content-Encoding: br のリクエストを展開する。動かす Node を修正版にし、必要なら br を拒否（5.11）' } } }
Write-AuditUtf8 -Path "$out\version-scan-pkgjson-skipped.txt" -Text $(if ($pkgSkipped.Count) { ($pkgSkipped -join "`n") + "`n" } else { '' })
if ($pkgSkipped.Count) { Add-VS 'scan' 'server-deps' "$out\version-scan-pkgjson-skipped.txt" '' 'UNKNOWN' "手順9で降りなかった・読めなかった場所が $($pkgSkipped.Count) 件（リンク・クラウドのプレースホルダー・アクセス拒否）。未探索として報告する" }

$vs | Export-Csv "$out\version-scan.csv" -NoTypeInformation -Encoding UTF8
$vs | Group-Object Topic, Verdict | Sort-Object Name | Format-Table Count, Name -AutoSize
$vs | Where-Object Verdict -in 'VULNERABLE','UNKNOWN' | Format-Table Topic, Item, Version, Verdict, Path -AutoSize | Out-String -Width 400
```

WSL（bash、ディストリごと。6.2 の後。実行するのは verify_wsl.sh が既に実行した Python（verify-pylist.txt）だけで、Node / Bun / Claude Code は実行せずに版を読む。版の比較は awk）:

```bash
out=~/emudhra-audit; tsv="$out/version-scan-wsl.tsv"
printf 'Topic\tItem\tPath\tVersion\tVerdict\tNote\n' > "$tsv"
row(){ printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5" "$6" >> "$tsv"; }
# 判定は Compare-AuditFixedVersion と同じ規則（正式版の形だけ比べる。$3: 0 = 単一の系列、1 = メジャー、2 = メジャー.マイナー）
cmpv(){ awk -v v="$1" -v fixed="$2" -v lp="$3" '
function parse(x, a,   n, i) { sub(/^v/, "", x); if (x !~ /^[0-9]+(\.[0-9]+)?(\.[0-9]+)?(\.[0-9]+)?$/) return 0
  n = split(x, a, "."); for (i = 1; i <= n; i++) { y = a[i]; sub(/^0+/, "", y); if (length(y) > 10 || y + 0 > 2147483647) return 0 }   # Windows の [int]::TryParse と同じ上限
  for (i = n + 1; i <= 4; i++) a[i] = 0; return 1 }
function cmp(a, b,   i) { for (i = 1; i <= 4; i++) { if (a[i] + 0 < b[i] + 0) return -1; if (a[i] + 0 > b[i] + 0) return 1 } return 0 }
BEGIN { if (!parse(v, pv)) { print "UNKNOWN"; exit }
  nf = split(fixed, fl, ","); newer = 0; same = 0; low = 0
  for (k = 1; k <= nf; k++) { parse(fl[k], f)
    if (lp == 0) { if (!low || cmp(f, lo) < 0) { for (i = 1; i <= 4; i++) lo[i] = f[i]; low = 1 } continue }
    if (f[1] == pv[1] && (lp == 1 || f[2] == pv[2])) { same = 1; res = (cmp(pv, f) >= 0) ? "FIXED" : "VULNERABLE" }
    if (cmp(f, pv) > 0) newer = 1 }
  if (lp == 0) { print (cmp(pv, lo) >= 0) ? "FIXED" : "VULNERABLE"; exit }
  if (same) print res; else print (newer ? "VULNERABLE" : "UNKNOWN") }'; }
# OS のパッケージ（Ubuntu 24.04 の libbrotli1 1.1.0-2build2 は 2026-10-24 時点で「評価待ち」。Debian は修正済み。修正は USN で確認）
# 今入っているものだけを見る。削除済みで設定だけ残るもの（rc）や一度も入っていない名前は、版が空の行で返るので数えない（例: nodejs。v2.12.4）
dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\n' libbrotli1 brotli nodejs 'libnode*' ghostscript 2>/dev/null | while IFS=$'\t' read -r st p v; do
  # 状態の2文字目が今の状態: i = 入っている（hi = 保留、ri = 削除予定でも今は入っている）。U F H W t = 途中の状態なので残して状態を添える。それ以外（n = 入っていない、c = 設定だけ）は数えない
  case "$st" in ?i*) ;; ?[UFHWt]*) v="$v (dpkg status $st)" ;; *) continue ;; esac
  case "$p" in ghostscript) row pillow "$p" dpkg "$v" INFO "あると Pillow の EPS の件が成立しうる" ;; *) row brotli "$p" dpkg "$v" UNKNOWN "Ubuntu は 2026-10-24 時点で評価待ち。USN で修正版を確かめるまで残件" ;; esac; done
# Node / Bun / Claude Code（実行しない。/mnt/ 配下の Windows 側の実体は Windows で判定）
# claude-local: PATH に入っていない ~/.local/bin/claude（ネイティブ版の既定の置き場所。古い版が残っていることがある。v2.12.1）
for c in node bun claude claude-local; do
  if [ "$c" = claude-local ]; then
    p="$HOME/.local/bin/claude"; [ -e "$p" ] || continue; r=$(readlink -f "$p")
    [ "$r" = "$(readlink -f "$(command -v claude 2>/dev/null)" 2>/dev/null)" ] && continue   # PATH 上の claude と同じなら上で済み
  else p=$(command -v "$c") || continue; r=$(readlink -f "$p"); fi
  case "$r" in /mnt/*) continue ;; esac
  case "$c" in
    node) v=$(printf '%s' "$r" | sed -nE 's#.*/v([^/]+)/bin/node$#\1#p')   # nvm 等: .../vX.Y.Z/bin/node（接尾辞も残して厳密に比べる）
          if [ -n "$v" ]; then row brotli node "$r" "$v" "$(cmpv "$v" 22.23.4,24.22.1,26.12.1 1)" "Node の版"
          elif [ "$r" = /usr/bin/node ] || dpkg -S "$r" >/dev/null 2>&1; then
            row brotli node "$r" "$(dpkg-query -W -f='${Version}' nodejs 2>/dev/null)" UNKNOWN "apt の nodejs: Ubuntu は版の番号を変えずに修正を取り込むことがあるので、USN で確かめるまで残件"
          else row brotli node "$r" "" UNKNOWN "実行せずに版を読めない（nvm 等のパスでも apt でもない）"; fi ;;
    *) b=$(grep -aoE 'Bun v[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*' "$r" 2>/dev/null | sort -u | sed 's/^Bun v//')   # 接尾辞ごと（1.4.4rc1 も）
       n=$(printf '%s\n' "$b" | grep -c .)
       if [ "$n" = 1 ]; then row brotli "bun($c)" "$r" "$b" "$(cmpv "$b" 1.4.4 0)" "内蔵または本体の Bun"
       else row brotli "bun($c)" "$r" "$(printf '%s' "$b" | tr '\n' ' ')" UNKNOWN "Bun の版を1つに決められない"; fi ;;
  esac
done
# Python の Pillow / brotli / brotlicffi（verify_wsl.sh が実行した verify-pylist.txt。未導入と、読めないメタデータを分ける）
while IFS= read -r -u 3 py; do
  [ -x "$py" ] || { row scan verify-pylist.txt "$py" "" UNKNOWN "一覧にあるが実体が無い（6.2 の後に消えた）"; continue; }
  o=$(timeout 60 "$py" -E -c '
import importlib.metadata as m
for n in ("pillow", "brotli", "brotlicffi"):
    try:
        v = m.version(n)
        print(n, v if v else "ERROR:empty-version")
    except m.PackageNotFoundError: pass
    except Exception as e: print(n, "ERROR:" + type(e).__name__)
print("__done__")' </dev/null 2>&1); rc=$?
  if [ $rc -ne 0 ] || ! printf '%s\n' "$o" | grep -qx '__done__'; then row python packages "$py" "" UNKNOWN "取得できない: rc=$rc $(printf '%s' "$o" | tail -1)"; continue; fi
  printf '%s\n' "$o" | grep -vx '__done__' | while read -r n v; do
    case "$n:$v" in *:ERROR:*) row python "$n" "$py" "" UNKNOWN "メタデータを読めない: $v" ;;
      pillow:*) row pillow pillow "$py" "$v" "$(cmpv "$v" 13.0.0 0)" "Pillow 13 は Python 3.11 以上" ;;
      brotli:*) row brotli pypi-brotli "$py" "$v" "$(cmpv "$v" 1.2.1 0)" "" ;;
      brotlicffi:*) row brotli pypi-brotlicffi "$py" "$v" "$(cmpv "$v" 1.2.1.0 0)" "" ;;
      *) row python packages "$py" "$n $v" UNKNOWN "想定外の出力" ;; esac
  done
done 3< <(if [ -r "$out/verify-pylist.txt" ]; then cat "$out/verify-pylist.txt"; else row scan verify-pylist.txt "" "" UNKNOWN "一覧が無い・読めない（6.2 を先に実施）"; fi)
# Python の wheel が抱える libbrotlidec（site-packages の <パッケージ>.libs の中。読み取りだけ・root 不要。ホーム配下の venv などを探し、/mnt 配下（Windows 側）には降りない。
# ファイルは開かず版を読めないので UNKNOWN で残す。持ち主の wheel は、同じ venv の pip list / pip show で調べる）
find "$HOME" -xdev -path /mnt -prune -o -type f -path '*.libs/*' -name 'libbrotlidec*.so*' -print 2>/dev/null | sort | while IFS= read -r f; do
  row brotli wheel-libbrotlidec "$f" "" UNKNOWN "Python の wheel が抱える libbrotlidec（版は読めない）。持ち主のパッケージを pip list で確かめ、そのパッケージの更新を待つか、使っていなければ削除（5.11）"; done
column -t -s $'\t' "$tsv" 2>/dev/null || cat "$tsv"
```

結果: `version-scan.csv`（Windows）/ `version-scan-wsl.tsv`。判定は FIXED / VULNERABLE / UNKNOWN / INFO。VULNERABLE と UNKNOWN は 5.11 の対処か残件。
INFO は対象外の確認だけ（Brotli 無しでビルドされた curl、対象のパッケージを含まない固めたアプリ、.NET ランタイムなし、Ghostscript の有無）。修正なし・評価待ち・人の確認が要るものは INFO にしない。

## 7. 報告テンプレート（PCごと）

```
PC名:                           実施日時:                       実施者:
端末時刻正常: yes/no   TLS検査: 対照サイト発行者=（Google Trust Services なら なし）/ あり(→全件UNKNOWN)
キット版: KIT_VERSION.txt の commit=（dirty=yes なら明記）
キットのテスト(6.1 手順0): 合格 / 不合格（不合格なら検証結果は無効）
Windows: version / GPO DisableRootAutoUpdate: 未設定|0|1 / Disallowed に eMudhra: あり|なし(Thumbprint照合) / 実測(winstore SslStream ChainStatus): REJECT|ACCEPT|UNKNOWN
  ※ TLS用DV中間1件の実測。他のTLS中間・コード署名用2件は Disallowed の Thumbprint 照合を証拠とする（自動更新分は列挙に出ないことがある。見つからなければ「未確認」として残件。未対策とは書かない）
WSL: distro / ca-certificates: cur → fix (FIXED|NEEDS UPDATE|未確認)
Claude Code: before → after (Win / WSL)
Git: 実体ごと version / backend(設定元) / sslVerify=false: なし|あり / 実測: REJECT|ACCEPT|UNKNOWN
curl: 実体ごと backend / 実測
Python配布: 実体ごと version / pip before→after / certifi before→after / 経路別 stdlib-ssl・certifi・requests: FIXED|VULNERABLE|UNKNOWN|N/A（stdlib-ssl VULNERABLE は残件）
venv: 検出 N (windows/linux/unknown) / 起動不可 N / need_pip N / need_certifi N / ca_path_check N / app_managed N
      更新 OK N / FAIL N（理由） / SKIP_POLICY N（app_managed の古い pip = 残件） / 検証 REJECT N / ACCEPT N / UNKNOWN N（理由）
      stdlib-ssl ACCEPT の venv 数 N（残件。5.3末尾の対処を選択）
      走査エラー N 件・未探索領域: （drives-not-scanned.txt の外したドライブ、electron-scan-skipped.txt / version-scan-pkgjson-skipped.txt の降りなかった場所を含める。必ず「開発環境の無い単一 exe 型（もらったもの等）は対象外＝見逃す。中の部品の脆弱性は開発した側の申告に頼る」を書く）
conda: prefix N / 更新 OK N / FAIL N
Node: version(s) before→after / npm cafile / bun(pending) / deno / 実測
Go / Rust(rustup, crates) / Java / Composer / .NET: before→after / 再ビルド・置換した成果物:
Electron系: electron-apps.csv のアプリごと version / 内蔵Electron（修正版以上か）/ 自動更新ON / 再起動済
Docker: Desktop version (4.96.2以降か) / 再ビルドしたイメージ / 再作成したコンテナ / コンテナ内実測
Hg / SVN: 実体ごと version / 実測（svn.exe が無い TortoiseSVN は画面確認の結果）
pip: 実体ごと version / 実測 REJECT|ACCEPT|UNKNOWN（ACCEPT は 5.3 の pip の対処を選択）
uv: 実体ごと（アプリ同梱を含む）version / UV_NATIVE_TLS・UV_SYSTEM_CERTS（シェルと保存された値）/ 実測
サプライチェーン攻撃の痕跡（3.2 の supply-chain-ioc.csv、3.3 の supply-chain-ioc-wsl.txt）: HIGH N / CHECK N（CHECK は確かめた結果）
GitHub の CI（3.4、アカウントごと）: 実施した台・日付 / HIGH N / CHECK N / シークレットを持つ未固定のワークフロー / 対処（固定・削除・Actions 無効化・鍵の無効化）
ポータブル版のアプリ: 名前・場所 / 同梱の git・uv・Python・Java と各実測
truststore を入れた venv: パス / .pth / pip.ini / 実測（Python 経路と pip）/ アプリの動作確認
Java: java-found.csv の実体ごと version / 11以上は実測、10以下は cacerts の該当ルートと、修正版の有無（8 は 8u511）または運用（使用中止 / 通信させない）
Ruby / Perl / Dart / Haskell / Elixir: version / 実測
JRE同梱アプリ(JetBrains等): 更新済
その他（installed-apps.csv から拾った通信するアプリ、クラウド CLI、証明書関係の環境変数）:
版の照合（6.4、version-scan.csv）: Brotli（Node / 内蔵 Bun / libcurl / Python / Electron）・Pillow・固めたアプリ・cacert.pem ごとの判定と、5.11 の対処（差し替え・起動用バッチ・運用制限）
再起動した常駐プロセス:
対象範囲の外で、この PC と同じ環境にあるもの（0.1 の表から。macOS、WSL 以外の Linux、VM のゲスト、Docker のイメージ、他のユーザー、Android、ネットワーク機器、GitHub 以外の CI など）: 名前・場所 / 扱い（別に実施・運用で対応・対象外のまま）
分類まとめ: 対策済み [ ] / 要更新(残) [ ] / 判定不能 [ ] / 対象外 [ ]
変更記録: changes.log（対象パス・前後版・結果）
復元が必要になった場合の手順: 5.2(git: 変更前に値があれば changes.log の元値を戻す) / 5.6(Disallowed: disallowed-added.txt の Thumbprint のみ) / venv は venv-update-result.csv の before 版へ pip install
残課題:
```

## 8. 残課題・再確認事項

- Bun: 修正版リリース後に `bun upgrade` と検証を再実行
- Python 標準 ssl（Windows）: CPython に修正の issue と PR がある（[gh-160040](https://github.com/python/cpython/issues/160040) / [PR #160042](https://github.com/python/cpython/pull/160042)、CVE-2026-115557。漏えいした中間 CA の公開鍵を `_ssl` で拒否する。相互署名で同じ鍵を使う証明書も拒否する）。**2026-10-24 に main と 3.15 / 3.14 / 3.13 / 3.12 / 3.11 に取り込まれた**（#160568 / #160569 / #160570 / #160571 / #160572）。**2026-10-25 時点で 3.10 への移植は無い**。2026-10-25 時点で、この修正を含むリリースはまだ無い（10-21 の 3.15.1 / 3.14.9 / 3.13.17 は同梱の pip 26.2.2 と certifi の更新だけで、ssl の修正は入っていない）。次のパッチ版が出たら更新し、6.1 の stdlib-ssl を測り直す。セキュリティ修正だけの段階のブランチ（3.11 / 3.12、3.13 も）は、原則としてソースだけのリリースで、python.org は通常 Windows のインストーラーを出さない（10-21 の 3.13.17 のインストーラーは例外）。修正を含む他の配布（uv の Python = python-build-standalone、ディストリ、アプリの配布元）の対応を確かめる。アプリ同梱の Python は配布元の更新待ち。3.10 の環境は truststore（5.3）か運用制限のまま。修正が届くまでは 5.3 末尾の (a)（cafile 明示）か (d)（truststore）で対処し、実アプリの経路で再検証。`SSL_CERT_FILE` は対処にならない
- Windows ストア直接判定が失効確認不能の併発で UNKNOWN の場合: Disallowed の Thumbprint 照合を証拠として併用
- 3.3b 未取込・走査エラー・未走査リンク: 未探索領域として残件
- Electron 系: 各アプリの修正 Electron 採用を確認後に再検証（3.1 の electron-apps.csv を取り直して版を比べる）
- アプリ同梱のランタイム（アプリが抱える node・Python など）: ベンダーの更新待ち。手で差し替えない
- TortoiseSVN / svn: 修正版の告知を監視し、出たら 6.1 の svn 実測をやり直す。それまで運用制限
- アプリ同梱の古い Java（6 / 7 などサポート終了の版）: 修正なし。使用中止か、通信させない運用を続ける。Java 8 は修正版の採用を確認
- 6.1 の Java 実測（TlsProbe.java）の通信の部分は、キットの自動のテストに含まれていない。初めて使う PC では、対照が ACCEPT になることを最初に確かめる
- Docker Desktop: 4.96.x は段階配布。全コンポーネント更新後に再検証
- Node 20 以前 / Go 1.25 以前 / 修正の提供が無い JDK（4章の Java の修正版一覧に系列が無いもの。Java 6 / 7 など）: 修正なし。メジャー移行は別途判断
- app_managed 環境の古い pip（Windows: residual-app-managed-pip.csv / WSL: residual-app-managed-pip.txt）: 配布元更新 or 承認のうえ個別更新で閉じる
- Parse-Ver で接尾辞を落としたプレリリース版（例 26.3.0b1 → 26.3.0）は正式修正版と同一ではない。該当があれば正式版への更新を残件に
- アプリ同梱の uv: 0.13.5 以降の同梱を確認したら UV_NATIVE_TLS / UV_SYSTEM_CERTS の要否を見直す（残しても害は無い）。将来の uv で UV_NATIVE_TLS が消えたら、UV_SYSTEM_CERTS が設定されていることを確かめる
- GitHub の CI（3.4）: アカウントや組織が増えたら、そのアカウントでもう一度。HIGH が出たら、そのリポジトリのシークレットと、関係する鍵・トークンを発行元で無効化する
- truststore の .pth と pip.ini: アプリやパッケージの更新で venv が作り直されると消える。更新後に両方の有無と 6.1 の Python・pip 実測を確認。pip が legacy-certs をやめたら（pip が設定エラーで止まる）、.pth と pip.ini の扱いを見直す
- Brotli: Electron・.NET・Chromium・Ubuntu の修正版、Git for Windows の libbrotli 更新を監視。Git / PortableGit の DLL 差し替えは更新で元に戻るので、更新のたびに `Replace-GitBrotli.ps1 -Check`（6.4 でも分かる）
- Pillow: Python 3.10 の環境は修正版なし。3.11 以上での作り直しを別の作業として計画
- 固めた Python のアプリ: 作者のビルド更新を待つか、フォークしてソースから構築
- もらった・ダウンロードした単一 exe 型（PyInstaller 等）は調べていない（見逃す）。中の部品の脆弱性は開発した側の申告が必要。気になるものは作者に依存の版を問い合わせる
- 修正版番号・一次資料は実行前に再確認: https://emudhra.we-have-a-problem.com/ （コミュニティ運営）
- 再発防止: `pyproject.toml` / `requirements.txt` に `certifi>=2026.10.19`、`package.json` の engines に Node 修正版以降、Dockerfile の FROM を修正版 digest に
- 脆弱版に戻す必要が生じた場合（互換性問題等）は、その環境の外部通信を制限する暫定運用を別途判断

## 参考

- 対応情報サイト（コミュニティ）: https://emudhra.we-have-a-problem.com/ ／ ソース: https://github.com/galadran/we-have-a-problem.com
- Mozilla 初期インシデント報告: https://bugzilla.mozilla.org/show_bug.cgi?id=2083449
- pip の証明書利用経路: https://pip.pypa.io/en/stable/topics/https-certificates/
- 外部管理環境（PEP 668）: https://packaging.python.org/en/latest/specifications/externally-managed-environments/
- git-config: https://git-scm.com/docs/git-config
- gihyo.jp: https://gihyo.jp/article/2026/10/emudhra-ca-key-compromise-dev-tools-fixes
- lilting.ch: https://lilting.ch/articles/emudhra-weak-intermediate-ca-keys
- SafeDep: https://safedep.io/emudhra-ca-key-compromise/
- ITmedia: https://www.itmedia.co.jp/news/article/2610/21/2000002444/
