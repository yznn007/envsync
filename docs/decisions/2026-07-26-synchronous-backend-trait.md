# ADR-0004：Backend 与适配器 trait 采用同步 I/O

**日期：** 2026-07-26

**状态：** 已接受

**相关计划：** M0 任务 4、任务 10；M3 任务 3

## 背景

M0 计划写「定义 async `Backend` trait」，技术栈中列有 Tokio；M3 的 `PackageAdapter`
契约同样使用 `async fn`。同时，多处设计要求 `dyn Backend`（应用服务在运行期按配置选择
Local / Git / Gist 后端）。

## 决策

`Backend`、`PackageAdapter` 及其余端口 trait 全部使用**同步**方法签名，工作区不引入
Tokio 运行时。需要网络 I/O 的实现（M4 的 Gist 后端）使用 `reqwest::blocking`。

## 理由

1. **dyn 兼容性。** `async fn` in trait 目前不是 dyn-compatible。要同时拥有 `async` 和
   `dyn Backend`，只能引入 `async-trait` 的装箱宏，代价是每次调用一次堆分配和一层
   `Pin<Box<dyn Future>>`，并让错误信息与生命周期显著复杂化。
2. **没有并发收益。** EnvSync 的同步事务本质是**串行**的：preflight → CAS publish →
   逐动作 apply → verify → journal。设计文档明确要求动作按固定顺序逐个应用并逐项落
   receipt，禁止并行写入用户文件。唯一可并行的是对象上传，而这在本地后端上是纯文件
   复制，在 Git 后端上由单次 push 完成。
3. **依赖链的现实约束。** `rusqlite` 是同步的，`git2` 是同步的，文件系统能力层
   （`cap-std`）也是同步的。强行 async 化只会在每个边界上出现 `spawn_blocking`，把
   「异步」变成纯粹的仪式。
4. **进程模型。** CLI 是一次性进程；桌面端在 Tauri 的 `async_runtime::spawn_blocking`
   中调用同一套应用服务，UI 线程不会被阻塞。

## 后果

- 工作区不含 Tokio，构建更快、依赖树更小、供应链面更窄；
- 桌面端必须显式把长操作放进 `spawn_blocking`，这一约束写入
  `docs/api/application-service-v1.md`；
- 若未来出现真正需要并发的后端（例如按对象并行上传到对象存储），可在该后端**内部**
  使用线程池，而不必让整个 trait 变成 async。

## 影响范围

`envsync-backend::Backend`；`envsync-core` 的全部服务；M3 `PackageAdapter`；M4 Gist 后端
与 Tauri 命令层。
