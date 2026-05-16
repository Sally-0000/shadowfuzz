# shadowfuzz

基于动态二进制插桩的二进制模糊测试后端，通过增强 AFL++ 的运行时反馈能力，实现对闭源程序的高效漏洞挖掘。

长期目标是做一个 AFL++ 的 DBI execution backend，定位接近 AFL++ 的 QEMU mode / FRIDA mode，而不是重新实现一个完整 fuzzer。

当前仓库先落一个最小化 `Standalone DBI Coverage Engine`，用于验证下面这条最小路径：

1. 用 DBI 对闭源二进制做运行时插桩。
2. 采集 AFL 风格的 edge coverage bitmap。
3. 支持两种输出模式：
   - 独立模式：把位图落盘到 `coverage.map`
   - AFL 兼容模式：若存在 `AFL_SHM_ID`，直接附着到 AFL 共享内存

完整架构边界见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)，AFL++ mode
说明见 [docs/AFLPP_MODE.md](docs/AFLPP_MODE.md)。

真实目标 harness 模板见 [docs/HARNESS_TEMPLATES.md](docs/HARNESS_TEMPLATES.md)，
已验证 recipe 见 [docs/TARGET_RECIPES.md](docs/TARGET_RECIPES.md)。当前 release
边界见 [docs/RELEASE_NOTES_v0.1.0-alpha.1.md](docs/RELEASE_NOTES_v0.1.0-alpha.1.md)，
性能记录见 [docs/BENCHMARK.md](docs/BENCHMARK.md)，已知限制见
[docs/LIMITATIONS.md](docs/LIMITATIONS.md)。

## 选型

当前最小实现基于 `DynamoRIO client`。

原因很简单：

- 能独立运行，不需要先改 AFL++。
- 插桩 API 足够直接，适合先验证 edge coverage 逻辑。
- 后续要演进到 forkserver、persistent mode、cmp coverage 时，不需要推翻现有设计。

## 当前状态

已实现：

- 基于 basic block 入口的 AFL 风格边覆盖率记录
- 每线程 `prev_loc`，全局共享 bitmap
- `AFL_SHM_ID` 共享内存接入
- 本地 bitmap 文件输出
- 默认只插桩主程序模块，过滤 libc、loader 等系统库噪声
- neverzero 8-bit coverage counter，避免命中计数溢出回到 0
- 可选 n-gram coverage context
- 可选 comparison tracing：`strcmp` / `strncmp` / `memcmp`
- 可选危险 API oracle：`system` / `popen`
- `shadowfuzz-dbi` 最小 executor，支持 direct-run、`--check` 和 forkserver-compatible 路径
- `shadowfuzz-dbi --persistent` 实验模式，支持配套 harness 的长生命周期 testcase loop
- `shadowfuzz-dbi` CLI 选项可直接控制常用 `shadowcov` 配置
- target policy file，支持 section、校验、重复 `--policy-file` 叠加和
  `include=...`
- `smoke_test.sh` 覆盖 standalone、direct-run、forkserver、check 成功/失败路径

暂未实现：

- 通用闭源二进制 persistent mode
- 符号级过滤
- upstream AFL++ mode packaging

## 构建

优先使用仓库内的 DynamoRIO SDK：

- 默认查找 `third_party/DynamoRIO-Linux-11.3.0-1/cmake`
- 如果 SDK 放在别处，可以通过 `-DSHADOWFUZZ_DYNAMORIO_DIR=/path/to/dynamorio/cmake` 指定

```bash
cmake -S . -B build
cmake --build build
```

生成的 client 为动态库 `shadowcov`。

仓库还会同时构建两个本地验证目标：

- `build/poc-a`
- `build/poc-b`
- `build/poc-stack-overflow`
- `build/poc-file-magic`
- `build/poc-format-string`
- `build/poc-command-injection`
- `build/poc-command-system`
- `build/poc-strcmp-magic`
- `build/poc-compare-more`
- `build/poc-int-compare`
- `build/poc-counter-loop`
- `build/poc-path-open`
- `build/poc-exec-path`
- `build/poc-env-access`
- `build/poc-credential-file`
- `build/poc-network-connect`
- `build/poc-network-send`
- `build/poc-file-mutation`
- `build/poc-branch-churn`
- `build/poc-persistent-harness`
- `build/harness-shared-object-entry`
- `build/harness-plugin-host`
- `build/libpoc-shared-entry.so`
- `build/libpoc-plugin-target.so`

## 运行

用 `drrun` 启动目标程序：

```bash
drrun -c build/libshadowcov.so -- /path/to/target arg1 arg2
```

如果没有设置 `AFL_SHM_ID`，程序退出后会在当前目录输出 `coverage.map`。

快速验证：

```bash
./smoke_test.sh
```

这个脚本会验证当前初版原型的关键路径：

- `run.sh` standalone 路径
- `shadowfuzz-dbi` executor 路径
- `shadowfuzz-dbi --check` 预检成功和失败路径
- `shadowfuzz-dbi` 最小 forkserver 协议路径
- `shadowfuzz-dbi` direct-run 路径下的正常退出和崩溃状态回传
- forkserver 路径下的正常退出和崩溃状态回传

## 环境变量

- `AFL_SHM_ID`
  - 如果存在，则直接将 coverage bitmap 写入 AFL 共享内存
- `SHADOWFUZZ_DRRUN_PATH`
  - 覆盖 `shadowfuzz-dbi` 默认使用的 `drrun` 路径
- `SHADOWFUZZ_CLIENT_PATH`
  - 覆盖 `shadowfuzz-dbi` 默认使用的 `libshadowcov.so` 路径
- `SHADOWFUZZ_VERBOSE`
  - 如果设置，则让 `shadowfuzz-dbi` 打印 executor 路径、最终生效的 `SHADOWCOV_*` 配置和子进程调试日志
- `SHADOWFUZZ_PERSISTENT_IN_FD` / `SHADOWFUZZ_PERSISTENT_OUT_FD`
  - `--persistent` 实验模式传给配套 harness 的内部协议 fd；普通用户不需要手工设置
- `--policy-file PATH`
  - 让 `shadowfuzz-dbi` 或 `run_afl.sh` 读取目标级 policy 文件，把常用 oracle 开关和 allowlist 固化为可复用配置；示例见 `policies/oracles.example.policy`
- `SHADOWCOV_PERSISTENT_RESET_HOOK`
  - `--persistent` 实验模式内部启用；配套 harness 每轮用 `SIGUSR1` 请求 shadowcov 重置 bitmap、线程 coverage state 并启用 coverage，用 `SIGUSR2` 关闭 coverage
- `SHADOWCOV_BITMAP_OUT`
  - 独立模式输出文件路径，默认 `coverage.map`
- `SHADOWCOV_MAP_SIZE`
  - 位图大小，默认 `65536`，必须是 2 的幂
- `SHADOWCOV_ABORT_ON_DANGEROUS_API`
  - 启用 DBI 层危险 API oracle；当前会 wrap `system` / `popen`，命令字符串包含 shell 元字符时触发 `SIGABRT`
- `SHADOWCOV_ABORT_ON_CREDENTIAL_FILE`
  - 启用 DBI 层凭据文件访问 oracle；目标访问 `.aws/credentials`、`.kube/config`、`.netrc`、SSH 私钥等常见凭据路径时触发 `SIGABRT`
- `SHADOWCOV_ABORT_ON_EXEC`
  - 启用 DBI 层 `exec*` oracle；可疑 exec path 不在 allowlist 内时触发 `SIGABRT`
- `SHADOWCOV_ABORT_ON_ENV_ACCESS`
  - 启用 DBI 层敏感环境变量读取 oracle；目标调用 `getenv` / `secure_getenv` 读取 `SECRET`、`TOKEN`、`PASSWORD` 等敏感变量名时触发 `SIGABRT`
- `SHADOWCOV_ENV_ALLOWLIST`
  - 环境变量 oracle 白名单，支持逗号或冒号分隔的精确变量名，例如 `PATH,AWS_REGION`
- `SHADOWCOV_ABORT_ON_FILE_MUTATION`
  - 启用 DBI 层文件破坏性操作 oracle；当前会拦截 `unlink` / `remove` / `rename` / `creat` 和带创建、截断、写入语义的 `open` / `openat` / `fopen`
- `SHADOWCOV_ABORT_ON_NETWORK`
  - 启用 DBI 层网络 oracle；当前会检查 `connect` 非 loopback 地址和 `send` / `sendto` 可疑出站 payload，命中时触发 `SIGABRT`
- `SHADOWCOV_EXEC_ALLOWLIST`
  - `exec*` oracle 的 basename 白名单，支持逗号或冒号分隔，例如 `true,echo`
- `SHADOWCOV_NETWORK_ALLOWLIST`
  - 网络 oracle 白名单，支持逗号或冒号分隔；`connect()` 按 IP 前缀匹配，`send` / `sendto` 按 payload 子串匹配
- `SHADOWCOV_PATH_ALLOWLIST`
  - 路径 oracle 白名单，支持逗号或冒号分隔的路径前缀，例如 `./work,/tmp/target-fixtures`
- `SHADOWCOV_ABORT_ON_PATH_TRAVERSAL`
  - 启用 DBI 层路径穿越 oracle；当前会 wrap `open` / `openat` / `fopen`，路径包含 `../`、`..\` 或绝对路径时触发 `SIGABRT`
- `SHADOWCOV_TRACE_CMP`
  - 启用 DBI 层 comparison tracing；当前会 wrap `strcmp` / `strncmp` / `memcmp` / `strcasecmp` / `strncasecmp` / `strstr` / `memmem`，并跟踪 x86 `cmp reg, imm` / `cmp imm, reg` 的整数匹配进度
- `SHADOWCOV_NGRAM_SIZE`
  - 启用 n-gram coverage context，支持 `1`、`2`、`4`、`8`，默认 `1` 表示经典 AFL edge coverage
- `SHADOWCOV_HITCOUNT_BUCKETS`
  - 启用 AFL 风格 hitcount bucket counter，减少原始命中次数细微变化造成的 bitmap 噪声
- `SHADOWCOV_INLINE_COVERAGE`
  - 启用 inline edge counter 更新。当前支持 raw counter、hitcount bucket 和 n-gram 组合
- `SHADOWCOV_DISABLE_NEVERZERO`
  - 调试开关；设置后允许 8-bit coverage counter 自然溢出到 0。默认不设置，启用 neverzero
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

其中 `cur_loc` 由 basic block 起始地址哈希得到。当前版本为了先保证链路稳定，仍然采用 `clean call` 方式插桩。性能还不是最终形态，但实现清晰，便于后续继续替换成更低开销的 inline instrumentation。

## 当前边界

当前这一版已经可以视为 `v0` 原型：

- 目标是证明 DBI coverage backend 和最小 executor 接口都成立
- 不是高性能版本
- 不是完整 AFL++ backend
- 重点是“链路跑通、状态清楚、便于继续迭代”

## 下一步建议

建议按下面顺序继续推进：

1. 继续打磨 AFL++ forkserver / shared-memory 运行协议
2. 再做 persistent mode
3. 把 `clean call` 热路径替换成稳定的 inline instrumentation
4. 最后补 neverzero、hitcount bucket、n-gram、context-sensitive coverage 和比较反馈增强

## Benchmark

可以用仓库内 benchmark 工具对 coverage 模式做本地吞吐对比：

```bash
tools/bench_shadowcov.py --iterations 5 --target build/poc-branch-churn
```

默认会比较 clean-call、inline、hitcount bucket、n-gram 及其组合，并输出 Markdown 表格。快速自检可以缩短为：

```bash
tools/bench_shadowcov.py --iterations 1 --warmups 0 \
  --configs clean,inline --target build/poc-branch-churn
```

## Real Target Harness Templates

仓库提供了四类可复制的真实目标 harness 起点：

- `templates/cli_stdin_harness.sh`
- `templates/file_input_harness.sh`
- `templates/shared_object_entry_harness.c`
- `templates/plugin_host_harness.c`

详见 [docs/HARNESS_TEMPLATES.md](docs/HARNESS_TEMPLATES.md)。

当前仓库内已提供 `.so` entrypoint 和 plugin host 的本地验证 recipe，见
[docs/TARGET_RECIPES.md](docs/TARGET_RECIPES.md)。

## Mini Fuzzer Prototype

仓库现在还包含一个最小化 coverage-guided fuzzer 原型：

注意：`mini_fuzzer.py` 只是验证 DBI coverage feedback 的测试工具，不是项目长期主线。长期主线是让 AFL++ 负责 fuzzing，让 shadowfuzz 只负责 DBI execution backend。

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

## AFL++ 接入

当前仓库的主线入口是 `shadowfuzz-dbi`，它是一个最小 AFL++ forkserver-compatible executor：

```bash
./build/shadowfuzz-dbi /path/to/target [args...]
```

在真正运行前，也可以先做一次执行器路径自检：

```bash
./build/shadowfuzz-dbi --check ./build/poc-a
```

`shadowfuzz-dbi` 也可以直接透传常用的 `shadowcov` 运行配置：

```bash
./build/shadowfuzz-dbi --map-size 65536 --target-module poc-a ./build/poc-a
./build/shadowfuzz-dbi --instrument-all ./build/poc-a
./build/shadowfuzz-dbi --bitmap-out /tmp/coverage.map ./build/poc-a
./build/shadowfuzz-dbi --ngram 4 ./build/poc-a
```

实验性 persistent harness 模式：

```bash
./build/shadowfuzz-dbi --persistent ./build/poc-persistent-harness
```

这个模式只支持识别 `SHADOWFUZZ_PERSISTENT_IN_FD` /
`SHADOWFUZZ_PERSISTENT_OUT_FD` 协议的目标。executor 每轮从 AFL 当前
testcase stdin 读取 bytes，写入长期运行的 harness，再把 harness 返回的
wait-status 回传给 AFL++。它用于验证 persistent execution contract，还不是
任意闭源程序的自动 persistent 化。

当前 persistent demo 已能显著降低单轮启动开销，并且用 `SIGUSR1` /
`SIGUSR2` 把 harness transport 代码从目标 coverage 中隔离。这个 gating
当前走 clean-call `record_edge` 路径；`--persistent` 下暂不启用 inline coverage
fast path。

`templates/shared_object_entry_harness.c` 和 `templates/plugin_host_harness.c`
已经接入同一 persistent helper。也就是说，`.so` entrypoint 和 plugin host
这两类真实 harness 形态可以直接用：

```bash
AFL_NO_UI=1 ./run_afl.sh --persistent -V 60 \
  ./build/harness-shared-object-entry /path/to/library.so entry_symbol

AFL_NO_UI=1 ./run_afl.sh --persistent -V 60 \
  ./build/harness-plugin-host /path/to/plugin.so
```

直接接入 AFL++ 的推荐方式是：

```bash
AFL_SKIP_BIN_CHECK=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
afl-fuzz -i seeds -o afl-out -- ./build/shadowfuzz-dbi ./target @@
```

如果目标从标准输入读数据：

```bash
AFL_SKIP_BIN_CHECK=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 \
afl-fuzz -i seeds -o afl-out -- ./build/shadowfuzz-dbi ./target
```

仓库内有几个可以直接跑的 fuzz demo：

```bash
# stdin 输入，触发一个带 stack protector 的栈溢出
AFL_NO_UI=1 ./run_afl.sh -V 5 -o afl-out-stack ./build/poc-stack-overflow

# 文件输入，使用 AFL++ 的 @@ 文件占位符，匹配 magic bytes 后 abort
AFL_NO_UI=1 ./run_afl.sh --file -V 10 -o afl-out-file ./build/poc-file-magic

# stdin 输入，格式化字符串 bug-class oracle
AFL_NO_UI=1 ./run_afl.sh -V 10 -x dicts/format.dict \
  -o afl-out-format ./build/poc-format-string

# stdin 输入，命令注入 bug-class oracle；不会实际执行 shell
AFL_NO_UI=1 ./run_afl.sh -V 10 -x dicts/cmdi.dict \
  -o afl-out-cmdi ./build/poc-command-injection

# stdin 输入，真实调用 system()；由 shadowcov 在 DBI 层 hook system/popen 做 oracle
AFL_NO_UI=1 ./run_afl.sh --abort-on-dangerous-api -V 10 -x dicts/cmdi.dict \
  -o afl-out-cmdi-hook ./build/poc-command-system

# stdin 输入，真实调用 open()；由 shadowcov 在 DBI 层 hook open/openat/fopen 做路径穿越 oracle
AFL_NO_UI=1 ./run_afl.sh --abort-on-path-traversal -V 10 -x dicts/path.dict \
  -o afl-out-path-hook ./build/poc-path-open

# 同上，但允许目标合法访问指定路径前缀
AFL_NO_UI=1 ./run_afl.sh --abort-on-path-traversal \
  --path-allowlist ./fixtures,/tmp/target-work -V 10 -x dicts/path.dict \
  -o afl-out-path-hook ./build/poc-path-open

# stdin 输入，真实调用 execv()；由 shadowcov 在 DBI 层 hook exec* 做白名单 oracle
AFL_NO_UI=1 ./run_afl.sh --abort-on-exec --exec-allowlist true \
  -V 10 -x dicts/exec.dict -o afl-out-exec-hook ./build/poc-exec-path

# stdin 输入，真实调用 getenv()；由 shadowcov 在 DBI 层 hook 敏感环境变量读取
AFL_NO_UI=1 ./run_afl.sh --abort-on-env-access --env-allowlist PATH,AWS_REGION \
  -V 10 -o afl-out-env-hook ./build/poc-env-access

# stdin 输入，真实调用 open()；由 shadowcov 在 DBI 层 hook 常见凭据文件路径
AFL_NO_UI=1 ./run_afl.sh --abort-on-credential-file \
  --path-allowlist ./fixtures -V 10 -x dicts/credential_file.dict \
  -o afl-out-credential-hook ./build/poc-credential-file

# 使用目标级 policy 文件集中启用 oracle 和 allowlist
AFL_NO_UI=1 ./run_afl.sh --policy-file policies/oracles.example.policy \
  -V 10 -o afl-out-policy ./build/poc-env-access

# stdin 输入，真实调用 connect()；由 shadowcov 在 DBI 层 hook 非 loopback 地址
AFL_NO_UI=1 ./run_afl.sh --abort-on-network -V 10 -x dicts/network.dict \
  -o afl-out-network-hook ./build/poc-network-connect

# 同上，但允许目标连接测试服务 IP
AFL_NO_UI=1 ./run_afl.sh --abort-on-network \
  --network-allowlist 203.0.113.1 -V 10 -x dicts/network.dict \
  -o afl-out-network-hook ./build/poc-network-connect

# stdin 输入，真实调用 send()；由 shadowcov 在 DBI 层 hook 可疑出站 payload
AFL_NO_UI=1 ./run_afl.sh --abort-on-network -V 10 -x dicts/network_send.dict \
  -o afl-out-network-send-hook ./build/poc-network-send

# stdin 输入，真实调用 unlink()/open(O_TRUNC)；由 shadowcov 在 DBI 层 hook 文件删除/覆盖
AFL_NO_UI=1 ./run_afl.sh --abort-on-file-mutation -V 10 -x dicts/file_mutation.dict \
  -o afl-out-file-mutation-hook ./build/poc-file-mutation

# stdin 输入，strcmp magic 分支；启用 comparison tracing 反馈匹配前缀
AFL_NO_UI=1 ./run_afl.sh --trace-cmp -V 10 \
  -o afl-out-cmp ./build/poc-strcmp-magic

# stdin 输入，扩展 comparison tracing：strcasecmp/strncasecmp/strstr/memmem
AFL_NO_UI=1 ./run_afl.sh --trace-cmp -V 10 -x dicts/compare_more.dict \
  -o afl-out-cmp-more ./build/poc-compare-more

# stdin 输入，整数 compare tracing：immediate、memory/immediate、register/register
AFL_NO_UI=1 ./run_afl.sh --trace-cmp -V 10 -x dicts/int_compare.dict \
  -o afl-out-int-cmp ./build/poc-int-compare

# stdin 输入，启用 4-gram coverage context
AFL_NO_UI=1 ./run_afl.sh --ngram 4 -V 10 \
  -o afl-out-ngram ./build/poc-b

# stdin 输入，启用 AFL 风格 hitcount bucket counter
AFL_NO_UI=1 ./run_afl.sh --hitcount-buckets -V 10 \
  -o afl-out-hitcount ./build/poc-counter-loop

# stdin 输入，启用 inline edge counter 更新
AFL_NO_UI=1 ./run_afl.sh --inline-coverage -V 5 \
  -o afl-out-inline ./build/poc-a

# stdin 输入，同时启用 inline edge counter 和 hitcount bucket
AFL_NO_UI=1 ./run_afl.sh --inline-coverage --hitcount-buckets -V 5 \
  -o afl-out-inline-hitcount ./build/poc-counter-loop

# stdin 输入，同时启用 inline edge counter 和 4-gram coverage context
AFL_NO_UI=1 ./run_afl.sh --inline-coverage --ngram 4 -V 5 \
  -o afl-out-inline-ngram ./build/poc-b

# stdin 输入，实验性 persistent harness 协议
AFL_NO_UI=1 ./run_afl.sh --persistent -V 5 -x dicts/persistent.dict \
  -o afl-out-persistent ./build/poc-persistent-harness
```

这些 demo 分别验证：

- stdin testcase 路径
- file testcase / `@@` 路径
- forkserver 下 crash status 回传
- `__AFL_SHM_ID` shared-memory coverage 写入
- DBI 层 `system` / `popen` hook oracle
- DBI 层 `exec*` whitelist oracle
- DBI 层 `getenv` / `secure_getenv` sensitive environment access oracle
- DBI 层 common credential file access oracle
- DBI 层 `open` / `openat` / `fopen` path traversal oracle
- DBI 层 `connect` non-loopback network oracle
- DBI 层 `send` / `sendto` suspicious outbound payload oracle
- target-specific path and network oracle allowlists
- DBI 层 destructive file mutation oracle
- DBI 层 `strcmp` / `strncmp` / `memcmp` / `strcasecmp` / `strncasecmp` / `strstr` / `memmem` comparison tracing
- x86 integer compare tracing for immediate, memory/immediate, and register/register forms
- n-gram coverage context
- neverzero counter 更新
- AFL-style hitcount bucket counter
- inline edge counter fast path
- experimental persistent harness protocol
- shadowcov coverage-mode benchmark tool

说明：

- 栈溢出、格式化字符串这类漏洞通常可以通过 crash 被 AFL++ 直接保存。
- 命令注入、路径穿越、SSRF 这类语义漏洞通常需要 oracle，把危险输入转成 `abort()`、非零退出、marker 文件或 sanitizer 报告，AFL++ 才能稳定分类。
- `poc-command-system` 展示的是 backend 层 oracle：目标程序实际调用 `system()`，但 `shadowcov` 在调用前拦截危险命令字符串并 abort，避免真的执行注入 payload。
- `poc-path-open` 展示的是 backend 层路径 oracle：目标程序实际调用 `open()`，但 `shadowcov` 在调用前拦截可疑路径并 abort，避免依赖目标源码手写路径穿越判断。
- `poc-exec-path` 展示的是 backend 层 exec 白名单 oracle：目标程序实际调用 `execv()`，但 `shadowcov` 在调用前拦截不在 allowlist 里的可疑执行路径。
- `poc-env-access` 展示的是 backend 层环境变量 oracle：目标程序实际调用 `getenv()`，但 `shadowcov` 在调用前拦截敏感变量名读取。
- `poc-credential-file` 展示的是 backend 层凭据文件 oracle：目标程序实际调用 `open()`，但 `shadowcov` 在调用前拦截 `.aws/credentials`、`.kube/config`、`.netrc`、SSH 私钥等常见凭据路径。
- `poc-network-connect` 展示的是 backend 层网络 oracle：目标程序实际调用 `connect()`，但 `shadowcov` 在调用前拦截非 loopback 地址，避免 fuzz 过程真的向外连。
- `poc-network-send` 展示的是 backend 层出站 payload oracle：目标程序实际调用 `send()`，但 `shadowcov` 在发送前拦截云元数据地址、非 loopback HTTP host 等可疑内容。
- `poc-file-mutation` 展示的是 backend 层文件 mutation oracle：目标程序实际调用 `unlink()` 或 `open(O_TRUNC)`，但 `shadowcov` 在文件被删除或覆盖前 abort。
- `--env-allowlist`、`--path-allowlist` 和 `--network-allowlist` 用于真实目标的合法例外；它们只放行显式匹配的变量名、路径前缀、连接 IP 或 payload token，不会关闭 oracle 本身。
- `--policy-file` 支持根级 `key=value`，也支持 `[oracles]`、`[allowlists]`、`[coverage]`、`[target]` 分组；当前支持 `abort_on_*`、`exec_allowlist`、`env_allowlist`、`network_allowlist`、`path_allowlist`、`ngram`、`target_module`、`trace_cmp`、`hitcount_buckets`、`inline_coverage`。parser 会拒绝未知 section、未知 key、空字符串值和非法 `ngram`。同一次命令中，policy 后面的 CLI 参数会覆盖 policy 默认值。
- `--trace-cmp` 不是直接制造 crash，而是给 AFL++ 增加“比较进度”反馈，帮助它逐步靠近 magic string、magic bytes、大小写不敏感比较、substring/memmem 搜索和 x86 整数比较。
- `--ngram N` 会把前 N 个 basic block 的历史混进 coverage id。它能区分同一条边在不同上下文中出现的情况，但也会增加 bitmap 压力；当前支持 `1`、`2`、`4`、`8`。
- neverzero counter 是默认行为：coverage byte 从 `255` 再增加时保持非零，避免 AFL 把“被命中”误看成“未命中”。
- `--hitcount-buckets` 会把 coverage counter 更新到 AFL 风格等级：`1`、`2`、`4`、`8`、`16`、`32`、`128`，避免把细微循环次数差异全都暴露成不同 byte 值。
- `--inline-coverage` 会把 edge counter 更新直接插入 code cache，减少 clean-call 热路径开销；当前覆盖 raw counter、hitcount bucket 和 n-gram history 更新。

说明：

- AFL++ 通常会通过 `__AFL_SHM_ID` 提供共享内存 ID
- `shadowcov` 兼容 `__AFL_SHM_ID` 和 `AFL_SHM_ID`
- `shadowfuzz-dbi` 当前采用最小 forkserver loop，每轮仍然会重新启动 `drrun`
- 如果需要更高吞吐，下一步仍然是把执行模型推进到 persistent mode
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

`afl-shadow-trace` 仍然保留为旧 wrapper 入口，便于对比和回归调试，但不再是主线。

用仓库自带 POC 做一个最小 AFL 验证：

```bash
./run_afl.sh ./build/poc-a
```
