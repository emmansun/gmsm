# 差分测试框架（Differential Testing Framework）

本项目的大量算法实现包含 generic 纯 Go 路径、多种 AMD64/ARM64/PPC64/RISCV64/Loong64 指令集组合以及公开的运行时分发路径。差分测试框架位于 `internal/cryptotest/diff`，用于保证：**在明确定义的合法输入域内，直接 kernel 路径与公开 dispatch 路径在所有支持的架构、CPU feature、VLEN、长度、对齐及允许的内存重叠条件下，与可信参考实现保持逐位一致的语义**，并在失败时输出可复现、可定位的最小诊断信息。

## 核心概念

| 概念 | 说明 |
|------|------|
| `Run[O]` | 一个实现的执行闭包 `func(t testing.TB, c Case, b *Buffers) O`；允许 panic，panic 会作为执行结果的一部分参与比较 |
| `Case` | 一个具体测试用例：`SrcLen/DstLen`、`SrcAlign/DstAlign`、`Overlap`、`Pattern`、`Seed` 与自由语义参数 `Tag` |
| `Domain` | 声明式输入域：长度列表、tag 列表、对齐、重叠、模式与种子；`Tags` 默认按下标与 `Lengths` 配对（`tags[i % len(tags)]`），`CartesianTags: true` 则遍历每个长度的全部 tag |
| `Buffers` | 每次执行独立物化的受保护缓冲区：前后至少各 32 字节哨兵守卫，包含对齐 padding 和 disjoint gap，可检测越界写；`OverlapExact` 时 dst 与 src 共享同一区域 |
| `Implementation[O]` | 一个被测实现：`Name`、`Run`、`Available`（CPU feature 诚实性声明）与 `Required`/`Primary` 标记 |
| `Suite[O]` | 一个 API 形状对应的测试套件：参考实现 + 若干被测实现 + 比较函数；**局部构造，不做全局注册** |

`Suite.Run` 逐用例执行：先跑参考实现，再逐个跑每个可用实现，比较字节输出与 panic 结果（panic 值也必须一致）。任何不一致都以单个 `t.Errorf` 块报告：

```
differential mismatch: impl=aes-block ref=spec-xts
      case: DT-DD82A5E5 len=17 dst=17 srcAlign=0 dstAlign=0 overlap=exact pattern=zero seed=0x0 tag=1
      env: GOOS=linux GOARCH=amd64 VLEN=n/a
      rerun: go test -run '^TestDiffXTSMode$' -args -diff.seed=0x0
      error: output differs from reference at offset 0
      first difference at offset 0: ...
```

其中 `DT-*` 为稳定的用例 ID（与实现无关），`rerun` 给出精确复现命令。

固定长度但包含多个操作的 kernel 套件应使用 `CartesianTags: true`，避免只有第一个 tag 被枚举；smoke 对长度抽样时保留原始下标，从而保持 length、dst length 和 tag 的配对关系及 case ID 不变。

`Suite` 在每次参考或被测实现执行结束时运行该次调用注册的 `Cleanup`，因此 `WithValue` 修改的 dispatch 状态在检查下一实现的 `Available` 前已恢复，guard 也在同一执行边界检查。

ML-KEM/ML-DSA 的直接多项式 kernel 使用受保护的 typed backing storage；偏移按系数类型的自然对齐要求取整。内部自行分配输出、按值返回的 sampler 仍属于端到端语义比较，不声明其内部存储具有外部 guard 覆盖。

SM4 GCM 和 GCMSIV 的 Open case 同时比较 Seal 产生的密文/tag，并使用 generic 参考端生成的同一份密文执行 Open，避免仅验证各实现自身的 roundtrip。

## Profile 与命令行参数

| 参数/环境变量 | 含义 |
|------|------|
| `-diff.profile=smoke\|pr\|extended`（或 `DIFF_PROFILE`） | 用例规模：`smoke`（`-short` 默认，边界长度 + 少量对齐 + none/exact 重叠 + 2 种模式）、`pr`（默认，全部长度/重叠/模式）、`extended`（全量声明域，CI 周期任务用） |
| `-diff.seed=N` | 确定性随机输入的主种子，失败报告的 `rerun` 命令会带上它 |
| `-diff.dump` | 失败时输出完整 got/want 缓冲区（默认只输出首偏差附近的 hex dump） |
| `DIFF_REQUIRE` | 逗号分隔的 kernel 类别名列表；`TestDiffRequiredKernels` 在保证 feature 的 runner（原生硬件、SDE、QEMU）上强制要求这些 kernel 必须可用，防止 asm 路径静默回退。列表可以跨包共享，各包只校验自己拥有的名称（未知名称忽略） |

## 试点包接线总览

| 包 | 套件 | 参考 oracle | `DIFF_REQUIRE` 名称 |
|------|------|------|------|
| `internal/sm4` | block、XTS、GCM | generic kernel、`cipher/xts` 公共参考、标准库 GCM | `sm4ni`、`zvksed`、`aes`、`gfni` |
| `internal/sm3` | block、digest | generic block/digest（GB/T 32905 标准向量锚定） | （按 arch 的 `checkDispatch` 一致性检查） |
| `internal/zuc` | EEA stream/seek、EIA-128 message/bits、EIA-256 | 强制 `supportsAES`/`supportsGFMUL` 为 false 的纯 Go 路径（KAT 锚定） | `zuc-eea`、`zuc-eia` |
| `internal/cipher/xts` | mul2、doubleTweaks、XTS 模式（含 CTS 与并发批量） | 规范推导的 GF 倍乘与 XTS/CTS 参考实现 | （无运行时 dispatch，按构建标签选择） |
| `internal/cipher/gcmsiv` | POLYVAL、GCMSIV AEAD（含并发批量 deriveMessageKeys） | 强制 `supportPolyvalAsm` 为 false 的纯 Go POLYVAL（RFC 8452 向量锚定） | `gcmsiv-polyval` |
| `internal/sm2ec` | 基域 kernel（Mul/Sqr/Add/FromMont/NegCond）、标量域 kernel（OrdMul/OrdSqr/OrdReduce）、点运算（Add/Double/Select）、标量乘（ScalarMult/ScalarBaseMult） | fiat 包（purego 生产后端）与独立的 big.Int 仿射坐标参考（`TestDiffStandardVector` 以标准生成元与 `[n]G=∞` 锚定） | （无运行时 dispatch，单一 asm 路径；构建标签选择 asm/fiat 后端） |
| `internal/sm9/bn256` | 基域 kernel（Mul/Sqr/Add/Sub/Double/Triple/Neg/FromMont/Marshal/Unmarshal）、select/copy 原语（MovCond×3、Copy×5、别名写）、G1 点运算与标量乘 | big.Int 域算术、测试内 generic MovCond/Copy 参考、big.Int 仿射 G1 参考（`TestDiffStandardVector` 锚定生成元、`[Order]G=∞`、GB/T 配对向量与双线性） | `bn256-adx`、`bn256-rvv` |
| `mlkem` | NTT/逆 NTT、NTT 域乘法/累乘（含 keygen 变体）、poly 加减、ring 压缩编解码（d∈{1,4,5,10,11}）、向量 u10/u11 解码、CBD 采样、拒绝采样、sampleNTT/sampleNTTx4 | generic kernel（Montgomery 约定架构另选 `field_mont.go` 标量 kernel，keygen 恒选 plain 约定）；NTT 卷积锚定（schoolbook negacyclic，purego 也运行） | `mlkem-avx2`、`mlkem-neon`、`mlkem-lasx`、`mlkem-rvv`、`mlkem-ppc64le` |
| `mldsa` | NTT/逆 NTT、NTT 域乘法/累乘、矩阵行向量乘、poly 加减、无穷范数（有符号/无符号）、decompose r0、useHint/makeHint、六个 bit-pack 编码器与 gamma1 解码器 | generic kernel（全架构同约定）+ `field_barrett.go` 独立 Barrett oracle（purego 也可用）；NTT 卷积锚定（schoolbook negacyclic） | `mldsa-avx2`、`mldsa-neon`、`mldsa-lasx`、`mldsa-rvv` |

每包由三个（组）文件构成：

- `diff_test.go`（无标签）：公共套件、域定义、标准向量锚定（`TestDiffStandardVector`）、`FuzzDiff*` 目标与 `TestDispatchSelectedImplementation`；
- `diff_kernels_*_test.go`（互斥构建标签）：按架构提供 `*RefFor`（参考实现包装，通常用 `diff.WithValue` 强制纯 Go 回退）、`*Impls`（加速 kernel 列表）、`checkDispatch`（dispatch 变量与硬件/env 的一致性断言）与 `TestDiffRequiredKernels`；
- 互补标签文件（如 `diff_kernels_purego_test.go`）：纯 Go 构建下 hook 退化为直通/空操作，保证所有架构组合都能编译运行。

### 强制回退作为参考实现

参考实现通过 `diff.WithValue`（基于 `t.Cleanup` 自动恢复）临时覆盖包内 dispatch 变量，例如 ZUC：

```go
func diffEEARefFor(run diff.Run[[]byte]) diff.Run[[]byte] {
    return func(t testing.TB, c diff.Case, b *diff.Buffers) []byte {
        diff.WithValue(t, &supportsAES, false)
        return run(t, c, b)
    }
}
```

强制**纯 Go 回退**在任何宿主上都是安全的（不会执行 CPU 不支持的指令），因此该模式也用于 fuzz 主体；反之，在 fuzz 主体中强制加速 kernel 是被禁止的。

### Tag 归一化约定

fuzz 解码时 `SrcLen/DstLen` 会被钳制到声明域内，但 **`Tag` 是自由语义参数，不会被钳制**。如果某个 `Run` 用 `Tag` 推导分配大小、循环边界或缓冲区下标，套件**必须**注册 `WithNormalize` 把 fuzz 得到的 tag 映射回声明值列表，否则一个 fuzz 输入就可能产生 GB 级分配或不可终止的循环（参见 `internal/cipher/gcmsiv/diff_test.go` 的 `FuzzDiffPolyval`）。

## 模糊测试

每个套件通过 `Suite.Fuzz` 注册 Go 原生 fuzz 目标（`FuzzDiff*`）：

- 种子语料来自 `Enumerate(domain, ProfileSmoke)`，即结构化边界用例在普通 `go test` 下总是作为单元测试运行；
- 失败输入会被 fuzz 引擎最小化并写入 `testdata/fuzz/<Target>/`；该目录下的条目会随普通 `go test` 自动作为回归用例执行，**值得提交回仓库**，但应有所取舍：只提交刻画了持久合同边界（如输入域的隐含约束、被测实现的真实缺陷）的条目（例如 gcmsiv POLYVAL 的溢出用例），而仅暴露测试接线自身 bug、且已在同一次变更中修复的条目可以不留存；
- 周期任务 `.github/workflows/fuzz-diff.yml` 每周对全部 29 个试点 fuzz 目标各跑 10 分钟，失败输入以 artifact 上传。

本地运行示例：

```
go test -fuzz FuzzDiffXTSMode -fuzztime 60s -run ^$ ./internal/cipher/xts/
```

## CI 集成

| Workflow | 内容 |
|------|------|
| `ci.yml` | amd64 常规测试已包含差分套件；显式步骤以 `DIFF_REQUIRE=aes,zuc-eea,zuc-eia,gcmsiv-polyval,mlkem-avx2,mldsa-avx2` 强制原生 kernel 参与（GitHub amd64 runner 保证 AES-NI、PCLMULQDQ 与 AVX2）；另以 `DISABLE_SM4NI=1`、`DISABLE_GFNI=1`、`FORCE_SM4BLOCK_AESNI=1` 在独立进程中重跑非默认 dispatch 状态 |
| `smni_amd64_sde.yml` | 用 Intel SDE `-arl`（模拟 Arrow Lake：SM3-NI/SM4-NI/GFNI）运行 SM4 差分套件，`DIFF_REQUIRE=sm4ni,aes,gfni` 保证模拟路径真实参与 |
| `test_riscv64.yaml` / `test_riscv64_zvbc.yaml` | QEMU user-mode（binfmt）运行 riscv64：前者以 `QEMU_CPU=max` 覆盖 Zvkg 路径；后者固定 go 1.27 并以 `vlen=128/256/512` 矩阵覆盖 VLEN 相关路径，含 `TestRVVConfiguredVLEN` 校验与 `DISABLE_GHASH=1`（Zvbc POLYVAL 路径）重跑；riscv64 asm 由 go1.27 语言版本门控 |
| `test_arm64.yml` / `test_smni_arm64.yml` / `test_loong64.yml` | QEMU 下的 arm64/loong64 路径（含 `DISABLE_SM3NI`/`DISABLE_SM4NI` 开关） |

`internal/sm2ec` 展示了另一种接线形态：asm 构建下被测对象是包私有 kernel（`p256Mul` 等），参考 oracle 是 fiat 包与测试内独立的 big.Int 参考，因此不需要 `WithValue` 强制回退，也没有 CPU dispatch 可供 `checkDispatch` 校验；套件文件直接带 asm 构建标签（`diff_test.go`），purego 构建下 production 代码就是参考来源本身，无需差分。另外注意 kernel 合同的边界要在域中显式建模：如 `p256NegCond` 在所有架构上都采用投机减法（输入为 0 时结果为 p 而非 0），套件用共享的 `diffFieldNonZero` 把两个 Run 的输入映射到合法域内。

`internal/sm9/bn256` 展示了第三种接线形态：generic 纯 Go 后端与 asm 后端**构建标签互补**（asm 构建上 generic 域算术根本未编译），因此参考 oracle 必须完全独立——big.Int 域算术、测试内复刻的 generic MovCond/Copy 与 big.Int 仿射 G1 参考。但与 sm2ec 不同，它存在真实的运行时 dispatch 状态：amd64 的 `supportADX`（基域 kernel）与 `supportAVX2`（select/copy）、loong64 的 `supportLSX/supportLASX`、riscv64 的 `supportRVV` 都可以通过 `diff.WithValue` 强制，同一架构内的加速路径与标量路径作为多个被测实现参与差分（强制开启前必须先用 `Available` 校验真实硬件特性，否则会在不支持指令的机器上 SIGILL）。另外注意文件命名：Go 工具链会把文件名中的 `_arm64` 等后缀当作隐式构建约束，与 `//go:build` 行叠加，跨架构共享的 hook 文件名不能带架构后缀。

`mlkem`/`mldsa` 展示了第四种形态：公开 dispatch 包装 generic 实现，generic kernel 直接充当参考 oracle，无需强制回退；每个架构一个 hook 文件（`diffDispatchAvailable`/`diffForceDispatch`/`checkDispatch`/`diffCheckRequiredKernel`），asm 架构文件带 `&& !purego` 与互补的 noasm 文件避免纯 Go 构建下符号重复。mlkem 额外注意 NTT 域乘法/逆 NTT 的**按架构约定差异**：amd64/arm64/loong64/riscv64 的 asm 遵循 `field_mont.go` 的标量 Montgomery 约定（乘积与逆 NTT 输出携带 r 因子，在流水线内抵消），ppc64le 遵循 generic plain 约定（由 `diffMontMulConvention` hook 选择参考），而 keygen 累乘变体在所有架构上都产出 plain 域结果（结果直接编码），因此始终参考 `nttMulAccGeneric`。mldsa 全架构与 generic 逐位一致，另以独立的 Barrett NTT（`field_barrett.go`）作为第二个 oracle 为 purego 构建提供真实差分（Barrett 逆 NTT 输出按 r 缩放后与 generic 对齐）；两包的 NTT 卷积锚定（dispatch NTT → nttMul → dispatch INTT 对比 schoolbook negacyclic）在包括 purego 的所有构建上运行。注意：mldsa 的 schoolbook 参考必须用 64 位乘法（q≈2²³，`uint32` 乘法会回绕；mlkem 的 q≈2¹² 则无此问题）。

## 为新包接线的步骤

1. **确定 API 形状**：每种输出语义（block、stream、AEAD、MAC、seek…）一个 `Suite`；
2. **选择参考 oracle**：优先级为标准向量锚定的库内 generic 实现 > 规范推导的独立实现 > 标准库。参考必须可独立解释正确性；
3. **声明 `Domain`**：长度覆盖批量/块边界/CTS 等结构窗口，tag 按“下标配对”规划语义位；
4. **按架构写 hook 文件**：`*RefFor`（强制回退）、`*Impls`（`Available` 查询真实 CPU feature）、`checkDispatch`（变量 vs 硬件/env）与互补标签文件；
5. **fuzz 主体安全审查**：只强制纯 Go 回退；`Tag` 派生大小必须 `WithNormalize`；实现不得依赖执行顺序；
6. **接入 CI**：把包加入 `ci.yml` 的差分步骤；如需 feature 保证（SDE/QEMU），补 `TestDiffRequiredKernels` 的 kernel 名称并在对应 workflow 中设置 `DIFF_REQUIRE`。
