# shadowfuzz

基于动态二进制插桩的二进制模糊测试后端，通过增强 AFL++ 的运行时反馈能力，实现对闭源程序的高效漏洞挖掘。

当前仓库先落一个最小化 `Standalone DBI Coverage Engine`，目标不是直接做成 AFL++ 插件，而是先验证下面这条最小路径：

1. 用 DBI 对闭源二进制做运行时插桩。
2. 采集 AFL 风格的 edge coverage bitmap。
3. 支持两种输出模式：
   - 独立模式：把位图落盘到 `coverage.map`
   - AFL 兼容模式：若存在 `AFL_SHM_ID`，直接附着到 AFL 共享内存

## 选型

当前最小实现基于 `DynamoRIO client`。

原因很简单：

- 能独立运行，不需要先改 AFL++。
- 插桩 API 足够直接，适合先验证 edge coverage 逻辑。
- 后续要演进到 forkserver、persistent mode、cmp coverage 时，不需要推翻现有设计。

## 当前实现范围

已实现：

- 基于 basic block 入口的 AFL 风格边覆盖率记录
- 每线程 `prev_loc`，全局共享 bitmap
- `AFL_SHM_ID` 共享内存接入
- 本地 bitmap 文件输出
- 默认只插桩主程序模块，过滤 libc、loader 等系统库噪声

暂未实现：

- AFL++ forkserver 协议
- persistent mode
- cmpcov / laf-intel 类增强反馈
- 符号级过滤
- 命中计数压缩、neverzero、n-gram、context-sensitive coverage

## 构建

优先使用仓库内的 DynamoRIO SDK：

- 默认查找 `third_party/DynamoRIO-Linux-11.3.0-1/cmake`
- 如果 SDK 放在别处，可以通过 `-DSHADOWFUZZ_DYNAMORIO_DIR=/path/to/dynamorio/cmake` 指定

```bash
cmake -S . -B build
cmake --build build
```

生成的 client 为动态库 `shadowcov`。

## 运行

用 `drrun` 启动目标程序：

```bash
drrun -c build/libshadowcov.so -- /path/to/target arg1 arg2
```

如果没有设置 `AFL_SHM_ID`，程序退出后会在当前目录输出 `coverage.map`。

## 环境变量

- `AFL_SHM_ID`
  - 如果存在，则直接将 coverage bitmap 写入 AFL 共享内存
- `SHADOWCOV_BITMAP_OUT`
  - 独立模式输出文件路径，默认 `coverage.map`
- `SHADOWCOV_MAP_SIZE`
  - 位图大小，默认 `65536`，必须是 2 的幂
- `SHADOWCOV_INSTRUMENT_MODULES`
  - 默认只插桩主程序模块，设置为 `all` 时插桩所有模块
- `SHADOWCOV_TARGET_MODULE`
  - 指定只插桩某个模块 basename，例如 `SHADOWCOV_TARGET_MODULE=target`

## 实现说明

核心逻辑与 AFL 经典 edge coverage 一致：

```c
edge = cur_loc ^ prev_loc;
bitmap[edge]++;
prev_loc = cur_loc >> 1;
```

其中 `cur_loc` 由 basic block 起始地址哈希得到。这个版本为了先把链路跑通，采用 `clean call` 方式插桩，性能不是最终形态，但实现清晰，便于后续替换成更低开销的 inline instrumentation。

## 下一步建议

建议按下面顺序继续推进：

1. 把 `clean call` 改成寄存器安全的 inline instrumentation
2. 接入 AFL++ forkserver / shared-memory 运行协议
3. 再做 persistent mode
4. 最后补比较反馈增强

## Mini Fuzzer Prototype

仓库现在还包含一个最小化 coverage-guided fuzzer 原型：

```bash
python3 mini_fuzzer.py \
  --cmd "./run.sh ./your_target @@" \
  --seeds seeds \
  --out findings \
  --iterations 1000
```

说明：

- `--cmd` 是实际执行模板，`@@` 会被变异后的临时输入文件替换
- 如果目标从标准输入读数据，可以改成：

```bash
python3 mini_fuzzer.py \
  --stdin \
  --cmd "./run.sh ./your_target" \
  --seeds seeds \
  --out findings
```

输出目录：

- `findings/queue/`
  - 保存带来新覆盖的输入
- `findings/crashes/`
  - 保存触发崩溃信号的输入
- `findings/hangs/`
  - 保存超时输入（需开启 `--keep-timeouts`）
- `findings/stats.txt`
  - 记录执行次数、唯一边数、崩溃数等摘要

## AFL++ Minimal Wrapper

当前仓库还提供了一个最小 AFL++ wrapper：

```bash
./afl-shadow-trace /path/to/target [args...]
```

它的作用不是实现 forkserver，而是让 AFL++ 先通过共享内存 bitmap 使用 `shadowcov`：

```bash
AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
afl-fuzz -i seeds -o afl-out -- ./afl-shadow-trace ./target @@
```

如果目标从标准输入读数据：

```bash
AFL_NO_FORKSRV=1 AFL_SKIP_BIN_CHECK=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
afl-fuzz -i seeds -o afl-out -- ./afl-shadow-trace ./target
```

说明：

- AFL++ 通常会通过 `__AFL_SHM_ID` 提供共享内存 ID
- `shadowcov` 现在同时兼容 `__AFL_SHM_ID` 和 `AFL_SHM_ID`
- 这个模式每个 testcase 都会重新启动 `drrun`，因此会比较慢
- 如果需要高性能，下一步仍然要做 forkserver / persistent mode
- 在 WSL 或 core dump 被系统服务接管的环境里，测试时通常需要设置 `AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1`

为了减少手工输入环境变量，也可以直接使用：

```bash
./run_afl.sh ./target
```

常用参数：

```bash
./run_afl.sh -V 30 ./target
./run_afl.sh -E 1000 ./target
./run_afl.sh --file ./target
./run_afl.sh -i seeds -o afl-out-custom ./target
```

默认按 `stdin` 目标处理；如果目标需要文件路径输入，使用 `--file`，脚本会自动追加 `@@`。
