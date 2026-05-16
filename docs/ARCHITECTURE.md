# shadowfuzz Architecture

`shadowfuzz` 的长期目标是成为 AFL++ 的一个 DBI execution backend，定位接近 AFL++ 的 QEMU mode / FRIDA mode，而不是重新实现一个完整 fuzzer。

换句话说：

```text
AFL++ owns fuzzing.
shadowfuzz owns binary execution feedback.
```

## Non-Goals

这些不是 shadowfuzz 的长期职责：

- 不重新实现 AFL++ 的变异器
- 不重新实现 corpus 调度
- 不重新实现 crash / hang 管理
- 不重新实现多实例同步
- 不重新实现 AFL++ UI 和统计系统
- 不长期维护独立 fuzzer runtime

当前的 `mini_fuzzer.py` 只用于验证 DBI coverage 是否能驱动反馈闭环。它是测试工具，不是项目主线。

## Goals

shadowfuzz 的职责边界是：

- 启动闭源目标二进制
- 通过 DBI 对目标代码插桩
- 收集 AFL++ 可消费的 coverage feedback
- 写入 AFL++ shared memory bitmap
- 实现 AFL++ 兼容的执行控制协议
- 支持 forkserver / persistent mode
- 后续扩展 cmp feedback、context-sensitive coverage、n-gram coverage 等增强反馈

## Component Boundary

### AFL++

AFL++ 负责：

- seed corpus 管理
- mutation strategy
- power schedule
- queue culling
- crash / hang 分类
- testcase minimization
- sync / parallel fuzzing
- UI 和统计
- shared memory bitmap 分配
- forkserver 协议的上游控制

shadowfuzz 不应该复制这些逻辑。

### shadowfuzz DBI Backend

shadowfuzz 负责：

- 接收 AFL++ 提供的执行环境
- 解析 `__AFL_SHM_ID`
- 将 coverage 写入 AFL++ bitmap
- 控制 DBI client 的插桩范围
- 保证 coverage ID 在 ASLR 下稳定
- 将目标退出状态正确反馈给 AFL++
- 在未来实现 forkserver / persistent executor

## Current Prototype

当前仓库已有组件：

```text
src/shadowcov.c
  DynamoRIO client。负责 basic block 插桩、edge coverage、bitmap 写入和模块过滤。

run.sh
  Standalone runner。用于手工验证 DBI coverage engine。

shadowfuzz-dbi
  最小 AFL++ forkserver-compatible executor。负责协议握手、每轮拉起 `drrun`，并把 target 状态回传给 AFL++。

afl-shadow-trace
  旧 AFL++ wrapper runner。保留用于对比和调试，不是当前主线入口。

run_afl.sh
  AFL++ 启动辅助脚本。默认调用 `shadowfuzz-dbi`。

mini_fuzzer.py
  独立验证工具。用于证明 coverage feedback 能驱动输入保留，不是长期主线。

poc/
  演示目标程序。
```

当前执行链路：

```text
afl-fuzz
  -> shadowfuzz-dbi
    -> drrun
      -> shadowcov DynamoRIO client
        -> target binary
        -> AFL++ shared memory bitmap
```

当前模式是最小 forkserver-compatible executor。它能验证 AFL++ 可以消费 shadowfuzz 的 coverage，并且已经把协议入口从 wrapper mode 收敛到 executor mode，但每个 testcase 仍然会重新启动 DynamoRIO，性能不是最终形态。

## Target Architecture

目标形态应该演进为：

```text
afl-fuzz
  -> shadowfuzz forkserver-compatible executor
    -> DynamoRIO / DBI runtime
      -> target binary
      -> shadowcov inline instrumentation
      -> AFL++ shared memory bitmap
```

更理想的 persistent 模式：

```text
afl-fuzz
  -> shadowfuzz forkserver
    -> one DBI-managed target process
      -> persistent testcase loop
      -> reset bitmap
      -> execute one testcase
      -> report status to AFL++
```

## Execution Modes

### Mode 0: Standalone Coverage

Purpose:

- 验证 DBI client 可以插桩目标
- 验证 bitmap 生成
- 方便调试 coverage 逻辑

Entry:

```bash
./run.sh ./target
```

Status:

- 已实现
- 仅用于开发和调试

### Mode 1: Legacy AFL++ Wrapper Mode

Purpose:

- 最小接入 AFL++
- 验证 AFL++ shared memory bitmap 兼容性
- 不实现 forkserver

Entry:

```bash
AFL_NO_FORKSRV=1 afl-fuzz -i seeds -o out -- ./afl-shadow-trace ./target
```

Status:

- 已实现原型
- 性能较差
- 每个 testcase 重新启动 DBI runtime

### Mode 2: AFL++ Forkserver Mode

Purpose:

- 成为真正 AFL++ execution backend
- 避免 AFL++ 每轮完整 exec wrapper
- 对齐 QEMU mode 的执行模型

Expected responsibilities:

- forkserver handshake
- testcase execution loop
- child status reporting
- bitmap lifecycle control
- target argv / stdin / file input handling

Status:

- 已实现最小 forkserver-compatible executor
- 当前每轮仍重新启动 `drrun`，还不是最终高吞吐形态
- 下一阶段主线是继续收敛协议细节和推进 persistent mode

### Mode 3: Persistent DBI Mode

Purpose:

- 降低 DBI attach 和进程启动成本
- 提升吞吐

Expected responsibilities:

- 识别或注入 persistent loop
- 每轮重置必要状态
- 每轮读取 AFL++ testcase
- 每轮返回目标状态

Status:

- 未实现
- forkserver mode 之后推进

## Coverage Design

当前 coverage 逻辑是 AFL 经典 edge coverage：

```c
edge = cur_loc ^ prev_loc;
bitmap[edge]++;
prev_loc = cur_loc >> 1;
```

当前已有设计点：

- `prev_loc` 是线程局部状态
- bitmap 默认为 64 KiB
- 支持 `__AFL_SHM_ID`
- 默认只插桩主模块，过滤 libc / loader 噪声
- `cur_loc` 基于模块路径和模块内偏移计算，避免 ASLR 导致 coverage 不稳定

后续需要演进：

- inline instrumentation 替代 clean call
- neverzero counter
- hitcount bucket compatibility
- context-sensitive coverage
- n-gram coverage
- cmp feedback

## Process Control Design

### Current Executor Behavior

当前 `shadowfuzz-dbi` 做的事情：

```text
read AFL++ env
set shadowcov env
perform minimal forkserver handshake when AFL pipes are present
spawn drrun -c libshadowcov.so -- target argv
return target exit status through forkserver protocol
```

这个模式简单，但性能瓶颈明显：

- 每轮启动 executor
- 每轮启动 `drrun`
- 每轮加载 DynamoRIO
- 每轮初始化 DBI client
- 每轮启动目标

### Desired Forkserver Behavior

下一阶段应把 executor 的子进程管理和 testcase 生命周期处理做得更完整。

初步模块建议：

```text
src/
  shadowcov.c        DBI client instrumentation
  forkserver.c       AFL++ forkserver protocol
  executor.c         target process execution control
  shm.c              AFL++ bitmap/shared-memory handling
  options.c          env / argv parsing
```

注意：是否能把 forkserver 放进 DynamoRIO client 内部，需要单独验证。更保守的路线是先做外部 executor，executor 负责 AFL++ 协议和启动 DBI-managed target。

## Repository Policy

不应提交：

- `third_party/`
- DynamoRIO SDK 压缩包
- `build/`
- `afl-out*/`
- `coverage.map`
- 本地编译出的目标二进制
- fuzzing findings

应提交：

- DBI backend 源码
- AFL++ wrapper / runner 脚本
- POC 源码
- 文档
- seed 示例
- 构建脚本

## Roadmap

### Phase 1: Architecture Alignment

Goal:

- 明确项目是 AFL++ DBI backend
- 降级 mini fuzzer 为测试工具
- 固定组件边界

Status:

- 当前文档完成此阶段

### Phase 2: Forkserver-Compatible Executor

Goal:

- 实现 AFL++ forkserver handshake
- 正确处理每轮 testcase 执行
- 正确回传 target status
- 继续使用 shadowcov 写 AFL++ bitmap

Deliverable:

```bash
afl-fuzz -i seeds -o out -- ./shadowfuzz-dbi ./target
```

不再依赖 `AFL_NO_FORKSRV=1`。

### Phase 3: Inline Instrumentation

Goal:

- 移除 clean call 热路径
- 降低每个 basic block 的插桩开销

Deliverable:

- coverage 行为不变
- exec/s 明显提升

### Phase 4: Persistent Mode

Goal:

- 降低进程启动和 DBI 初始化成本
- 支持多 testcase 单进程执行

Deliverable:

- persistent loop prototype
- target reset strategy

### Phase 5: Enhanced Feedback

Goal:

- cmp feedback
- context-sensitive coverage
- n-gram coverage
- optional module/function filters

## Immediate Next Task

下一步应该开始 Phase 2：设计并实现最小 forkserver-compatible executor。

建议先做最小闭环：

```text
afl-fuzz starts executor
executor performs forkserver handshake
executor receives run command
executor launches drrun + target once per testcase
shadowcov writes AFL++ bitmap
executor reports child status
```

这一步即使仍然每轮启动 `drrun`，也比 wrapper mode 更接近 AFL++ backend 的真实接口。随后再把 executor 内部替换成更高性能的 DBI/persistent 执行模型。
