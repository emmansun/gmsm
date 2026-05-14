# 确定性随机数发生器（DRBG）与软件随机数发生器应用指南

## 目录
- [参考标准](#参考标准)
- [概述](#概述)
- [架构设计](#架构设计)
- [DRBG 基础包（drbg/）](#drbg-基础包drbg)
- [软件随机数发生器（rand/）](#软件随机数发生器rand)
- [熵源（internal/entropy/）](#熵源internalentropy)
- [安全等级](#安全等级)
- [使用建议](#使用建议)
- [性能](#性能)

---

## 参考标准

### 国家标准 (GB/T)
- **GM/T 0105-2021** - 软件随机数发生器设计指南

### 国际标准
- **NIST SP 800-90A** - Recommendation for Random Number Generation Using Deterministic Random Bit Generators
- **NIST SP 800-90B** - Recommendation for the Entropy Sources Used for Random Bit Generation

您可以从[国家标准全文公开系统](https://openstd.samr.gov.cn/)在线阅读国家标准。

## 概述

本软件库提供了两个层级的随机数生成能力：

1. **`drbg/` 包**：底层 DRBG（确定性随机比特发生器）原语实现，支持三种机制：SM3 Hash DRBG、SM4 CTR DRBG 和 HMAC DRBG。适用于需要直接控制 DRBG 参数的场景。
2. **`rand/` 包**：面向应用的软件随机数发生器，完全符合 GM/T 0105-2021 规范。内部使用 SM3 Hash DRBG 作为生成机制，结合三重熵源和 SP 800-90B 健康测试，提供与 `crypto/rand` 兼容的 API。

对于大多数应用场景，**推荐直接使用 `rand/` 包**。

## 架构设计

```
┌─────────────────────────────────────────────────┐
│                  应用程序                         │
│     sm2.GenerateKey(rand.Reader)                │
└─────────────┬───────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────┐
│              rand/                               │
│  Reader (io.Reader)    Read(b []byte)           │
│  ┌─────────────────────────────────────────┐    │
│  │ SM3 Hash DRBG (GM 模式)                  │    │
│  │ atomic.Pointer + sync.Pool 并发管理       │    │
│  │ 自动重播种（按计数/时间间隔）               │    │
│  │ 每次 Read 混入 OS 附加输入                 │    │
│  │ 首次使用前执行 KAT 自检                    │    │
│  └─────────────────────────────────────────┘    │
└─────────────┬───────────────────────────────────┘
              │ Seed() 获取种子
              ▼
┌─────────────────────────────────────────────────┐
│           internal/entropy/                      │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐    │
│  │ OS 熵源   │ │ 抖动熵源  │ │ 哈希循环熵源  │    │
│  │crypto/rand│ │CPU jitter│ │runtime noise │    │
│  └─────┬────┘ └─────┬────┘ └──────┬───────┘    │
│        │  SP 800-90B │ 健康测试     │            │
│        ▼             ▼             ▼            │
│  ┌─────────────────────────────────────────┐    │
│  │        熵池（Twisted GFSR，附录 A.3）      │    │
│  │   128×32-bit 循环移位寄存器混合           │    │
│  │   SM3_df (Hash_df) 压缩提取              │    │
│  │   前向安全性反馈                          │    │
│  └─────────────────────────────────────────┘    │
└─────────────────────────────────────────────────┘
```

## DRBG 基础包（drbg/）

`drbg/` 包实现了三种 DRBG 机制，同时支持 NIST SP 800-90A 模式和 GM/T 0105-2021 国密模式。

### 支持的 DRBG 机制

| 机制 | GM 模式 | NIST 模式 | 说明 |
|------|---------|-----------|------|
| SM3 Hash DRBG | ✓ | ✓ | 基于 SM3 杂凑算法，推荐用于国密场景 |
| SM4 CTR DRBG | ✓ | ✓ | 基于 SM4 分组密码算法 |
| HMAC DRBG | ✗ | ✓ | 基于 HMAC，仅支持 NIST 模式 |

### GM 模式与 NIST 模式的差异

GM/T 0105-2021 对 DRBG 提出了更严格的要求：

- **SM3 Hash DRBG GM 模式**：每次生成请求最大输出为 32 字节（SM3 输出长度），种子长度为 440 位（55 字节）
- **NIST 模式**：每次生成请求最大输出为 2048 字节

### 使用示例

#### SM3 Hash DRBG（GM 模式）

```go
import "github.com/emmansun/gmsm/drbg"

// 创建基于 SM3 Hash DRBG 的伪随机数发生器（GM/T 0105-2021 模式）
prng, err := drbg.NewGmHashDrbgPrng(nil, 32, drbg.SECURITY_LEVEL_TWO, nil)
if err != nil {
    panic(err)
}

buf := make([]byte, 32)
_, err = prng.Read(buf)
if err != nil {
    panic(err)
}
```

#### SM4 CTR DRBG（GM 模式）

```go
import "github.com/emmansun/gmsm/drbg"

// 创建基于 SM4 CTR DRBG 的伪随机数发生器（GM/T 0105-2021 模式）
prng, err := drbg.NewGmCtrDrbgPrng(nil, 32, drbg.SECURITY_LEVEL_TWO, nil)
if err != nil {
    panic(err)
}

buf := make([]byte, 32)
_, err = prng.Read(buf)
if err != nil {
    panic(err)
}
```

#### 底层 DRBG 直接使用

如果需要更精细的控制（如自定义熵源、手动重播种），可以直接使用底层 DRBG 接口：

```go
import "github.com/emmansun/gmsm/drbg"

// 直接创建 SM3 Hash DRBG 实例
entropyInput := make([]byte, 32) // 从安全熵源获取
nonce := make([]byte, 16)        // 从安全熵源获取
// ... 填充 entropyInput 和 nonce ...

hd, err := drbg.NewGMHashDrbg(drbg.SECURITY_LEVEL_TWO, entropyInput, nonce, nil)
if err != nil {
    panic(err)
}
defer hd.Destroy() // 使用完毕后销毁内部状态

output := make([]byte, 32)
err = hd.Generate(output, nil) // 生成随机字节
if err == drbg.ErrReseedRequired {
    // 需要重播种
    newEntropy := make([]byte, 32)
    // ... 获取新的熵输入 ...
    hd.Reseed(newEntropy, nil)
}
```

## 软件随机数发生器（rand/）

`rand/` 包是面向应用的高层接口，完全符合 GM/T 0105-2021 规范，提供与 Go 标准库 `crypto/rand` 一致的 API。

### 核心接口

```go
import "github.com/emmansun/gmsm/rand"

// 全局 Reader，可直接传递给需要 io.Reader 的密码学 API
var Reader io.Reader

// Read 将随机字节填入 b，始终返回 len(b), nil
func Read(b []byte) (n int, err error)

// SetSecurityLevel 设置 DRBG 安全等级（影响后续创建的 DRBG 实例）
func SetSecurityLevel(level drbg.SecurityLevel)
```

### 使用示例

#### 基本使用

```go
import "github.com/emmansun/gmsm/rand"

// 生成 16 字节随机数
buf := make([]byte, 16)
n, err := rand.Read(buf)
if err != nil {
    panic(err)
}
// n == 16, buf 已填充随机字节
```

#### 通过 io.Reader 接口使用

```go
import (
    "io"
    "github.com/emmansun/gmsm/rand"
)

buf := make([]byte, 32)
n, err := io.ReadFull(rand.Reader, buf)
if err != nil {
    panic(err)
}
```

#### 与 SM2 密钥生成集成

```go
import (
    "github.com/emmansun/gmsm/rand"
    "github.com/emmansun/gmsm/sm2"
)

// 使用符合 GM/T 0105-2021 的随机数发生器生成 SM2 密钥对
key, err := sm2.GenerateKey(rand.Reader)
if err != nil {
    panic(err)
}

// 使用 SM2 签名
msg := []byte("待签名消息")
sig, err := key.SignWithSM2(rand.Reader, nil, msg)
if err != nil {
    panic(err)
}

// 验证签名
ok := sm2.VerifyASN1WithSM2(&key.PublicKey, nil, msg, sig)
```

#### 设置安全等级

```go
import (
    "github.com/emmansun/gmsm/drbg"
    "github.com/emmansun/gmsm/rand"
)

// 设置安全等级为一级（更长的重播种间隔）
rand.SetSecurityLevel(drbg.SECURITY_LEVEL_ONE)

// 后续创建的 DRBG 实例将使用新的安全等级
buf := make([]byte, 32)
rand.Read(buf)
```

### GM/T 0105-2021 合规特性

`rand/` 包实现了 GM/T 0105-2021 规范要求的以下安全机制：

#### 1. DRNG 自检（第 5.6.6 条）

首次产生随机数输出之前，自动执行已知答案测试（KAT）。测试流程为：实例化 → 重播种 → 生成（丢弃）→ 生成（验证输出），若输出与预期不符则 panic，确保 DRBG 实现正确。

#### 2. 三重独立熵源（第 5.2 条）

每次播种从三个独立熵源收集熵：

| 熵源 | 实现方式 | 健康测试 | 熵估计 |
|------|---------|---------|--------|
| OS 系统随机数 | `crypto/rand.Reader` | 无（OS 保证质量） | 8 bits/byte = 256 位/32 字节 |
| CPU 抖动 | 高精度计时 + 内存访问噪声 | 重复计数 + 自适应比例 + LAG 预测器 | 1 bit/sample = 1024 位/1024 样本 |
| 哈希循环 | 16 次连续 SM3 计算 + `runtime.Gosched()` | 重复计数 + 自适应比例 + LAG 预测器 | 1 bit/sample = 1024 位/1024 样本 |

> **熵估计依据**：
> - **OS 熵源**：8 bits/byte 是标准做法。`crypto/rand.Reader` 读取操作系统内核 CSPRNG 的输出（如 Linux 的 `getrandom(2)`、Windows 的 `CryptGenRandom`），这些系统已经过完整的熵收集和调节处理。
> - **CPU 抖动和哈希循环**：1 bit/sample 是基于 SP 800-90B 最小熵估计的保守下限。在裸金属服务器、高精度计时器环境下，实际每样本熵通常为 2-4 bits。但在高度虚拟化环境（如容器中 CPU 被严格限制、虚拟机中计时器虚拟化粒度粗糙）或低负载单核系统中，熵质量可能降至该下限附近。
> - **总熵预算**：每次 `Seed()` 收集的总估计熵为 256 + 1024 + 1024 = 2304 位，远超池提取阈值（256 位）和种子长度（440 位），即使某个源的实际熵低于估计值，也有充足的安全余量。

#### 3. SP 800-90B 健康测试（第 5.5 条，附录 D）

对非 OS 熵源执行三项连续健康测试：
- **重复计数测试**（附录 D.2）：检测连续相同样本，阈值 C=41（$\alpha = 2^{-20}$，$h = 0.5$ bit/sample）
- **自适应比例测试**（附录 D.3）：检测偏倚分布，窗口 W=512，阈值 C=410
- **LAG 预测器测试**：检测序列自相关（交替源、短周期源），窗口 W=512，阈值 C=411

> **关于 LAG 测试**：RCT 和 APT 均无法捕获交替源（如 160→161→160→161→...）——该源无连续重复（RCT 通过），且每个值出现 256 次（≤ 410，APT 通过）。LAG 预测器检测到第三对开始每次预测均正确（509/511 ≥ 411），因此失败。参考 jitterentropy-library v3 的 LAG 测试设计。

这些测试既作为**上电健康测试**（首次收集 ≥1024 样本），也作为**连续健康测试**（后续每批样本）。

#### 4. 熵池混合（第 5.3 条，附录 A.3）

使用扭曲 GFSR（广义反馈移位寄存器）进行熵混合：
- 池容量：128 × 32 位字（512 字节）
- 本原多项式：$x^{128}+x^{103}+x^{76}+x^{51}+x^{25}+x+1$
- 扭曲表基于 CRC-32 多项式
- 提取时使用 SM3_df（附录 B）压缩为 440 位（55 字节）种子
- **前向安全性**：提取结果反馈回池中，防止从当前种子推导未来种子

#### 5. SM3_df 调节函数（附录 B）

原始熵通过 SM3 Hash_df 函数进行调节压缩：

$$\text{seed} = \text{Hash\_df}(\text{pool\_data}, 440)$$

其中 Hash_df 迭代计算 SM3 哈希，直到产生所需长度的输出。

#### 6. 自适应过采样率（OSR）

区别于旧版本的固定重试沟遐，当非 OS 熵源健康测试失败时，采用自适应过采样率机制（参考 jitterentropy-library）：

| OSR 级别 | 每次采集样本数 | 精展计数（保守） | 尝试次数 |
|---------|------------|-----------|--------|
| 1（默认） | 1024 | 1024 位 | 3 |
| 2 | 2048 | 1024 位 | 3 |
| 3 | 3072 | 1024 位 | 3 |
| 4（最大） | 4096 | 1024 位 | 3 |

- **熵积分始终按基确样本数（numSamples=1024）计算**，额外样本仅用于让健康测试通过
- 超过最大 OSR 后允许 panic，表明该熵源不适用于当前系统

#### 7. 自动重播种（第 5.6.4 条）

DRBG 根据安全等级自动重播种，无需应用程序干预。

#### 8. 附加输入混入

每次 `Read()` 调用从 `crypto/rand.Reader` 获取 16 字节作为附加输入传入 `Generate()`，提供纵深防御。即使 DRBG 状态被泄露，输出仍然与新鲜的 OS 随机性混合。

#### 9. 敏感参数清零（第 7.2 条）

所有中间熵缓冲区、种子和 nonce 在使用后立即清零，符合第 7.2 条表 1 对关键安全参数的管理要求。

## 熵源（internal/entropy/）

`internal/entropy/` 包是内部包，不对外暴露 API。以下信息供理解内部机制参考。

### OS 熵源

通过 `crypto/rand.Reader` 获取操作系统提供的随机字节。这是最可靠的熵源基线，在所有平台上可用。每次 `Seed()` 调用收集 32 字节（256 位熵）。

### CPU 抖动熵源

通过高精度计时器测量 CPU 指令执行时间的微小差异。使用 32MB 的共享内存缓冲区（BSS 段分配，不使用时不消耗物理内存），通过 LCG 索引的随机内存访问产生缓存未命中，从而引入不可预测的时序抖动。

- **Windows**：直接通过 `QueryPerformanceCounter` 系统调用获取纳秒级精度
- **其他平台**：使用 `runtime.nanotime` 获取高精度时间戳

每次 `Seed()` 调用收集 1024 个样本。

### 哈希循环噪声源

将 SM3 哈希计算时序与协程调度抖动结合：
- 每次采样执行 16 次连续 SM3 计算，状态链式更新（展示 CPU 微架构缓存、流水线和分支预测效应）
- 每次采样包含一次 `runtime.Gosched()` 产生调度抖动
- 与内存访问抖动源（`source_jitter.go`）独立

初始状态从当前计时器初始化，确保并发运行的协程起始于不同状态。
第三方参考：jitterentropy-library（Stephan Müller）hash loop 噪声源，以 SM3 替代 SHA3/SHAKE-256。

纯 Go 实现，无平台依赖。每次 `Seed()` 调用收集 1024 个样本（自适应 OSR 下最多 4096 个）。

## 安全等级

GM/T 0105-2021 定义了两个安全等级，控制 DRBG 的重播种策略：

| 安全等级 | 计数间隔 | 时间间隔 | 适用场景 |
|---------|---------|---------|---------|
| 一级 (`SECURITY_LEVEL_ONE`) | $2^{20}$ 次生成 | 600 秒 | 低安全要求场景 |
| **二级** (`SECURITY_LEVEL_TWO`，默认) | $2^{10}$ 次生成 | 60 秒 | 通用安全场景 |
| 测试 (`SECURITY_LEVEL_TEST`) | 8 次生成 | 6 秒 | 仅供测试 |

默认使用二级安全等级。安全等级越高（数值越小），重播种越频繁，安全性越强，但相应的性能开销也越大。

## 使用建议

### 推荐用法

1. **一般场景**：直接使用 `rand.Read()` 或 `rand.Reader`，无需关心底层 DRBG 细节
2. **SM2 密钥生成/签名**：将 `rand.Reader` 传入 `sm2.GenerateKey()` 和签名函数
3. **需要 GM/T 0105-2021 合规**：使用 `rand/` 包，默认配置即满足要求

### 不推荐用法

1. **不要**将 `drbg.DrbgPrng` 用于并发场景——它不是并发安全的，请使用 `rand.Reader`
2. **不要**手动管理 DRBG 的重播种——`rand/` 包已自动处理
3. **不要**在 `SECURITY_LEVEL_TEST` 模式下运行生产代码

### `drbg/` 与 `rand/` 的选择

| 场景 | 推荐 | 原因 |
|------|------|------|
| 应用层随机数需求 | `rand/` | 自动管理熵源、播种、重播种、并发安全 |
| 需要自定义熵源 | `drbg/` | 可传入自定义 `io.Reader` 作为熵源 |
| 需要 HMAC DRBG | `drbg/` | `rand/` 仅使用 SM3 Hash DRBG |
| 需要 CTR DRBG | `drbg/` | `rand/` 仅使用 SM3 Hash DRBG |
| 测试或研究目的 | `drbg/` | 可精确控制所有参数 |

## 性能

`rand.Read()` 的性能主要取决于：
- **首次调用**：需要收集熵和初始化 DRBG（约 1-2ms），包含 KAT 自检
- **后续调用**：直接从 DRBG 生成，每次额外获取 16 字节 OS 附加输入
- **重播种时**：需要重新收集三重熵（约 1ms）

SM3 Hash DRBG GM 模式下每次 `Generate` 最大输出 32 字节，大量数据生成时会多次迭代。对于性能敏感且不要求 GM/T 0105-2021 合规的场景，可考虑直接使用 `crypto/rand`。
