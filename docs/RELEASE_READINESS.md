# GitHub 构建与 Resk AGC 邀请测试就绪性

核查日期：2026-10-26。范围：当前 `rd-engine` 工作树、已存在的 GitHub 仓库、HAR 产物，以及当前可读取的消费接口文档。本轮只做核查和文档整理；没有提交、推送、触发 Actions、上传 AGC 或发布邀请测试。

## 结论

**可以沿现有架构建设这条自动化链，但当前不能认定“推送当前提交后，即可自动构建 Resk 并发布 AGC 邀请测试”。**

- GitHub 仓库已经存在且为公开仓库，不需要重新建仓：[`FrankHan052176/rd-engine`](https://github.com/FrankHan052176/rd-engine)。
- 引擎已有 HAR 打包入口和版本/哈希溯源；现有 HAR 的内容与 sidecar 一致，但它来自 dirty 工作树，不是干净源码发布候选。
- 当前源码尚未完整纳入 Git。现有 Windows Actions 配置也不能代替 HarmonyOS HAR → Resk → AGC 的流水线。
- Resk 当前工作流、签名、上传和邀请测试实现没有完成源码核查：实际工具读取范围仍限于 `rd-engine`。**未读取不等于未实现，更不等于已经跑通。**

用户已报告在鸿蒙完成 Resk/Flutter 客户端连接原版和 rd-engine 版本客户端的试验。本报告保留这一用户陈述，不重复设备试验，也不把互连结果当成云端构建或发布成功。

## 产品与资料边界

| 产物/工程 | 当前归属 | 对本次发布链的意义 |
| --- | --- | --- |
| `native/ohos_napi` → `rustdesk-ohrs` HAR | HarmonyOS 内核；Resk (`R_RustDesk-ArkTS`) 消费 | 本次要自动构建和交付的引擎出口 |
| `native/frb` → 原生库和 Dart 绑定 | 非鸿蒙；钉定官方 RustDesk Flutter 消费者 | Windows 工作流与 2026-10-27 新增的全平台客户端工作流的出口（见下文“后续记录”），不能代替 Resk 的 HAR |
| `R_RustDesk-Flutter` / RustDesk Unofficial | 独立鸿蒙 Flutter 移植，自有上游衍生内核和 AGC 链 | 不能据此推断 Resk 的发布链已具备 |

当前所有权以 [`AGENTS.md`](../AGENTS.md) 和 [`README.md`](../README.md) 为准；HAR 接口见 [`docs/OHRS_SURFACE.md`](OHRS_SURFACE.md)。`HANDOVER.md`、`PARITY.md`、`PROTOCOL_EXTENSIONS.md` 保留历史记录，其中的测试数、产物路径和旧构建结果不代表本次核查已重新验证。

Resk 账号登录/云地址簿不支持，以及远程摄像头、文字聊天、语音通话的产品排除，不属于本轮发布链缺口，不应为“发布就绪”而重新加入。

## 就绪矩阵

| 环节 | 当前状态 | 证据或缺口 |
| --- | --- | --- |
| GitHub 仓库 | 已具备 | GitHub 只读 API 确认仓库存在、公开、默认分支 `main`；当前登录身份有管理/推送权限，但本轮没有使用写权限 |
| 当前工作树可由 Git 完整还原 | 明确未就绪 | 核查快照有 893 个未跟踪文件，其中 879 个属于 1166 文件的原生溯源锁；另有大量已跟踪文件修改 |
| 原生锁内文件哈希 | 已核对一致 | 独立逐文件计算 1166 个锁条目的 SHA-256，缺失/不匹配为 0；这不是完整 provenance verifier、许可证审计或编译通过 |
| Windows Actions 配置 | 已有配置，未证实当前版本成功 | 本地和云端均只发现 `Windows` 工作流；查询到总计 11 次运行，返回的最近 5 次均为 `failure`，修订不同于本地 HEAD |
| HarmonyOS HAR Actions | 当前引擎仓库缺失 | 核查时本地 `.github/` 与 GitHub 工作流列表均仅有 `.github/workflows/windows.yml`；2026-10-27 新增的 `flutter-client.yml` 只构建非鸿蒙官方客户端，不产出 HAR |
| HAR 打包与溯源 | 已有脚本和可校验开发产物 | `build-har.sh` 使用 locked 构建；现有 HAR、内嵌溯源及两个动态库哈希匹配，但 `source_dirty=true` |
| 干净 runner 的鸿蒙构建 | 未验证 | SDK/NDK、Rust、原生依赖来源及恢复过程尚需固定并用干净构建证明 |
| Resk 消费固定 HAR | 文档有接口，当前实现未读 | README 指向 `refresh-native-har.sh` 和 `NATIVE_HAR_PATH`，不能据此证明跨仓自动消费 |
| Resk release 构建与签名 | 未知 | Resk 当前配置、release profile、证书/权限未读取；文档中的 debug 命令不等于发布构建 |
| AGC 上传与邀请测试 | 未知 | 未读取 Resk 上传/提交逻辑，未取得 HarmonyOS 邀请测试 API 适用性和实际任务回执 |
| 审核完成、测试者可安装 | 未验证 | 上传成功、邀请测试提交成功、审核通过、实际可安装必须分别取证 |

## 本次观察

### 1. 源码快照与 Git 跟踪

以下统计发生在新增本报告之前，不能直接当成后续工作树的实时计数：

```text
branch: recovery/two-output-baseline-20260922T154257Z
HEAD: 94598979322bca03f3d5b28a42954caa170d3aa9
origin: https://github.com/FrankHan052176/rd-engine.git
untracked files: 893
native/frb/UPSTREAM.lock entries: 1166
locked entries not tracked by Git: 879
locked entries missing or with different SHA-256: 0
```

未跟踪的锁内文件包括 `vendor/rustdesk/` 134 个、`vendor/libsodium-sys/` 566 个、`vendor/default-net/` 38 个、`vendor/secret-service/` 29 个、`src/host/` 4 个、`src/lan/` 12 个和 `src/official_account/` 26 个；其余分布在桥接、补丁等位置。

另外，`src/video.rs`、`native/ohos_napi/src/app_context.rs`、`native/ohos_napi/src/server_profile.rs` 也尚未被 Git 跟踪。只推送现有 HEAD 不会包含这些工作树内容，不能代表用户已试验的源码。

现有 [Windows 工作流](../.github/workflows/windows.yml) 在构建前执行 `verify-native-provenance.sh --require-tracked`。[校验脚本](../scripts/verify-native-provenance.sh) 的 `check_tracked` 明确拒绝未跟踪的锁定路径。因此当前跟踪状态不满足该门禁；**本次不把逐项哈希检查表述为完整校验脚本已通过。**

不要直接 `git add .`：未跟踪项同时含 `.DS_Store`、`.hvigor/`、`.omp/`、`.worktrees/` 等非交付候选。应按源码所有权审查新增源码、补丁、来源/许可证和锁文件，排除构建缓存、凭证及本机资料。不要为让 CI 变绿而删除源码门禁，或无审查刷新 provenance lock。

### 2. 云端仓库与 Actions

只读 GitHub API 返回：仓库 `FrankHan052176/rd-engine` 存在、`private=false`、`archived=false`、默认分支为 `main`；工作流总数为 1，名称 `Windows`，状态 `active`。

`actions/runs?per_page=5` 返回总计 11 次运行，最近 5 次均为 `completed/failure`。最近一条为：

- 修订：`1d706c1685c428f98d304cc87e5c66079069273c`
- 运行：<https://github.com/FrankHan052176/rd-engine/actions/runs/35094142510>

上述事实不代表所有 11 次都失败，也不能将该旧修订的失败原因归咎于当前工作树。后续全量运行查询遇到网络 `EOF`，未取得失败步骤或当前 HEAD 的运行记录；本报告不声称已经诊断云端失败根因。

当前本地工作流固定 Rust `1.95.0`、vcpkg commit、FRB codegen `1.80.1` 和 Flutter `3.24.5`，包含源码溯源门禁和绑定校验。但“本地存在 YAML”“历史构建记录”和“当前提交云端成功运行”是三个不同证据层级。

### 3. HAR 产物

[`native/ohos_napi/build-har.sh`](../native/ohos_napi/build-har.sh) 的职责止于 HAR：

- 在独立 Cargo workspace 中执行 `cargo metadata --locked` 与目标 `aarch64-unknown-linux-ohos` 的 `cargo build --locked --release`。
- 在忽略的 staging 目录组装包，不向源码 `package/` 写入生成的动态库。
- 输出 `target/package.har` 和 `target/release-provenance.json`；HAR 内嵌溯源，sidecar 额外记录 HAR 自身哈希。
- `--release-claim` 要求构建前后源码干净、期间 HEAD 不变。当前工作树不满足这一前提。
- 不负责 Resk 应用 checkout、HAP/App 构建、签名、安装或 AGC 发布。

本次对现有文件重新计算哈希，并直接读取归档成员核对，不执行解包安装或重新构建：

```text
package: rustdesk-ohrs 0.1.0
engine_sha: 94598979322bca03f3d5b28a42954caa170d3aa9
source_dirty: true
HAR sha256: 5cd4a449beadab0d9b0d6d711c1755f37679126c5eab09ed4845ef090657024a
HAR digest matches sidecar: true
embedded provenance matches sidecar (excluding har_sha256): true
librd_engine_native_har.so digest matches: true
libc++_shared.so digest matches: true
```

这些匹配证明现有开发产物的内部一致性，不证明 dirty 源码可从该 SHA 单独恢复、当前工作树与产物源码逐字一致，或当前依赖环境可在云端重建。脚本中的 `engine_repository` 是固定元数据，不能单凭该字段证明 GitHub 仓库存在；本次仓库存在性另有 API 证据。

### 4. 构建与访问限制

- 本次 `bash -n` 检查 HAR 构建、OHOS 环境和原生溯源三个脚本，退出码为 0；未执行 Cargo 编译或测试。
- 命令环境提示 `RustDesk NAS cache unavailable: /Volumes/nas is not the expected writable mounted volume. Refusing local cache fallback.`。没有绕过该缓存保护、改用私有 target-dir 或将历史编译结果称为本次验证。
- [`scripts/ohos-env.sh`](../scripts/ohos-env.sh) 配置 SDK 路径、编译器、sysroot、linker 等，并不安装依赖。[VNC CMake](../native/vnc/CMakeLists.txt) 要求 Zlib。干净 runner 必须证明能从固定 SDK/依赖输入解析到目标架构库，而不是依赖本机缓存或误链接宿主库。
- 读取父目录 `/Users/frankhan/HarmonyOS/P_RustDesk` 仍返回 `path_outside_project`，所以没有读取 Resk 的实际源码/配置。用户已表示调整范围，但本次工具的实际边界未改变；没有使用 shell、其他工具或旧工程绕过。
- 未取得可引用的 AGC HarmonyOS 邀请测试 API 说明或账号内能力证明，因此不从其他平台的发布经验推定该接口可用。

## 后续记录（2026-10-27）：非鸿蒙官方 Flutter 客户端全平台 CI

上文矩阵是 2026-10-26 的只读观察，保持原样。此后按用户要求新增了本地、未提交的 [`flutter-client.yml`](../.github/workflows/flutter-client.yml)，把钉定的官方 RustDesk Flutter 客户端（`native/frb/UPSTREAM.txt` 中的 `092a961b629d318fe290eeafac0cd214a1e9deeb`）连同本引擎的 FRB 库编译、打包到 Windows、Linux、macOS、Android、iOS 的 8 个目标；范围、产物和钉定版本见 [README](../README.md#official-client-ci-windows-linux-macos-android-ios)。它不属于上面的 A–E 链：不构建 HAR、不接触 Resk、不签名、不发布，也不使用 AGC。

| 项 | 状态 | 证据或缺口 |
| --- | --- | --- |
| 工作流、准备/构建脚本 | 已写入本地工作树，未提交 | `scripts/prepare-flutter-ci.py`、`build-flutter-ci.py`、`stage-official-client.py`、`test-flutter-ci.py` 与 workflow 均为未跟踪文件 |
| 固定官方输入 | 本地已用真实固定 commit 验证 | `scripts/test-flutter-ci.py` 对 5 个平台从原始 Git blob 暂存并回放补丁（Windows 205、Linux 201、macOS 210、Android 246、iOS 231 个文件），并拒绝可变 runner 漂移和覆盖已有输出；这不是编译 |
| 语法 | 本地已检查 | 4 个 Python 脚本 AST、workflow YAML（5 平台/8 目标）、10 个 bash 步骤 `bash -n`；未执行 PowerShell 步骤 |
| 原生溯源 | 本地 `--verify` 通过，`--require-tracked` 不能通过 | 1166 个文件/16 个树与 `UPSTREAM.lock` 一致；工作流中的 `--require-tracked` 在锁定路径仍未跟踪前会失败，不能为 CI 删除该门禁 |
| 8 个目标的实际编译 | **未运行** | 未提交、未推送、未触发 Actions；本机 Cargo 因 NAS 缓存保护不可用，也没有 Xcode/Android/Visual Studio 全套环境 |
| 运行与功能 | 未执行 | 产物不会被安装或启动；GPU/硬件解码、高帧率和各平台功能由用户后续自行测试 |

因此目前只能说“CI 已实现并通过本地静态/暂存检查”。某一平台只有在对应矩阵作业于 GitHub Actions 中成功后，才能报告为已构建。Windows/Linux ARM64、Android x86、安装包和商店发布不在范围内。

## 最小实施顺序（方案，尚未执行）

### A. 将已试验的源码变成完整、可重建提交

选择性纳入直接构建依赖、所有者源码、补丁和溯源信息，保留许可证；检查不应公开的配置/密钥和缓存。对齐根、FRB、OHOS 三个工作区的依赖补丁与锁文件。先解决 Git 跟踪缺口，再从干净 checkout 通过现有 `--require-tracked` 门禁。公开仓库已存在，若要改变可见性应单独决定，不在本轮自动修改。

验收产物：包含试验源码的确定 engine commit，以及不依赖当前 dirty 工作树的源码门禁结果。当前源码尚未被完整提交前，不应宣布现有 HEAD 是可发布基线。

### B. 建立并跑通引擎 HAR CI

在现有 Windows 工作流之外，增加 HarmonyOS HAR 工作流，固定 runner、Rust、SDK/NDK 与目标原生依赖来源。使用现有 `build-har.sh --release-claim`，不另写绕过构建/溯源门禁的产物路径。

成功后保存同一运行生成的 HAR 和 sidecar，记录 engine SHA、运行链接和 HAR SHA-256；失败时不通知下游更新。首次需要干净 runner 的实际成功记录，而不是仅提交工作流文件。

### C. 让 Resk 消费确定的产物，而不是“最新文件”

先读取 Resk 权威规则、`refresh-native-har.sh`、包依赖和现有 Actions，再复用其已有机制。仅在引擎 HAR 成功交付后，向 Resk 发送固定 engine SHA、产物定位和哈希，并校验下载内容及内嵌溯源。

跨仓触发可按现有工程选择 GitHub dispatch；不能假定引擎仓库的默认 `GITHUB_TOKEN` 自动拥有 Resk 仓库权限。配置限于目标仓库和所需动作的 GitHub App/其他已授权凭据，不在 YAML、日志或报告中保存密钥。触发分支/tag 规则与更新是否自动推进到测试渠道，需作为产品策略明确。

### D. 构建、签名 Resk 发布包

在 Resk 工程设置实际 release 构建、递增应用版本和对应的 AGC 应用身份；复用真实签名配置，凭据进入受保护 secrets/environment。README 中的 `buildMode=debug` 命令只描述本地集成入口，不应照搬成发布命令。

验收记录需将 Resk commit、engine SHA、HAR hash、应用版本与签名应用包 hash 关联。版本重用、签名不匹配或构建失败不能继续上传。

### E. 接入 AGC 上传与邀请测试，并记录各阶段状态

先确认当前 HarmonyOS 应用、账号权限和邀请测试能力，再确认已有上传/提交工具或适用 API；不要先承诺“完全无人值守审核”。以实际返回的版本/任务 ID 查询进度；超时或状态未知时先查询旧任务，不能盲目重传或重发邀请。

必须分别记录：

1. **上传完成**：AGC 已接收具体签名包及版本。
2. **邀请测试提交成功**：对应版本已进入预期测试流程。
3. **审核/处理通过并开放**：以 AGC 实际状态为准，不能用提交 HTTP 成功代替。
4. **测试者可安装**：目标受邀账号能够取得并安装这一版本。

若存在不可自动化的审核、确认或账号权限环节，应如实保留人工步骤，不绕过。失败时保持上一已验证测试版本；修复/回退应在真实包版本和 AGC 规则下进行，不能假定已上传版本可随意覆盖或降级。

## 剩余核查输入与验收边界

当前需要的是可读的 Resk 权威规则、HAR 刷新脚本、Actions、签名配置模板和 AGC 上传/邀请测试实现或脱敏回执，不是证书、私钥、密码或 token 正文。只需确认凭据所在受保护环境和是否具备所需授权。

本轮已完成引擎侧源码/构建入口与可见云端状态核查、开发 HAR 一致性检查和实施顺序整理；**Resk 源码核查仍未完成，整条发布链未验收**。后续只有在实际授权范围内补齐 Resk 证据，并取得干净 HAR CI、Resk release 包、AGC 分阶段回执及测试者安装结果后，才能将“有方案”升级为“自动发布链已跑通”。
