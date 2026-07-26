//! 通用文件适配器引擎。
//!
//! 所有内建适配器都是同一个类型 [`FileAdapter`] 的不同**数据**实例：一个静态描述符
//! 加上一张资源表（[`FileSpec`]）。这样做的好处是行为只有一份实现——Managed Block 的
//! marker 处理、换行策略、幂等判定、`verify` 与 `render` 的一致性，全都无法在某个具体
//! 适配器里被悄悄改写。
//!
//! # 三种模式
//!
//! | 模式 | capture | render |
//! |---|---|---|
//! | [`FileMode::FullFile`] | 整份文件即受管内容 | 期望内容即完整文件 |
//! | [`FileMode::ManagedBlock`] | 抽出 marker 之间的块内内容 | 只替换块内，块外逐字保留 |
//! | [`FileMode::StructuredMerge`] | 整份文件，并做一次结构化解析校验 | 期望内容即完整文件 |
//!
//! ## Structured Merge 的职责边界
//!
//! [`FileMode::StructuredMerge`] 描述的是**跨设备协调时用哪种语义去合并**，而不是
//! 「写盘时怎么写」。三方合并需要 base（上一次同步点的内容），而 [`Adapter::render`]
//! 的签名里只有 `existing` 与 `desired`——适配器**没有** base，也不应该有：它拿不到
//! Journal。因此：
//!
//! * 跨设备合并由 `envsync-core` 的 [`mod@envsync_core::merge`] 按
//!   [`envsync_domain::resource::StructuredFormat`] 完成，那里有完整的三方输入；
//! * 适配器只负责把合并后的权威字节落盘，并在 capture 阶段用同一个解析器**校验**
//!   内容确实是合法的结构化配置，避免把语法损坏的文件同步给其他设备。
//!
//! 复用 [`mod@envsync_core::merge`] 的解析器（而不是在本 crate 里再写一个）保证了「能被
//! capture 的内容一定能被合并」，两侧不会出现解析口径漂移。
//!
//! [`Adapter::render`]: crate::Adapter::render

use envsync_core::merge::{self, MergeInput};
use envsync_core::render::{self, RenderInput, RenderedChange};
use envsync_domain::id::ResourceId;
use envsync_domain::profile::Selector;
use envsync_domain::resource::{DesiredDisposition, FileMode, ResourcePolicy, StructuredFormat};
use envsync_platform::RelativeTarget;

use crate::{
    sealed, Adapter, AdapterContext, AdapterDescriptor, AdapterError, DiscoveredResource,
    RenderedFile,
};

/// 一条静态资源定义。
///
/// 字段刻意都是简单数据：整张表可以被打印、比较、写进快照诊断，也可以在没有文件
/// 系统的环境里被审阅。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileSpec {
    /// 资源标识。
    pub id: ResourceId,
    /// 授权根别名，例如 [`crate::ROOT_HOME`]。
    pub root: &'static str,
    /// 相对「授权根前缀」的路径分段。
    pub segments: &'static [&'static str],
    /// 文件管理模式。
    pub mode: FileMode,
    /// 期望处置。
    pub disposition: DesiredDisposition,
    /// 写入策略。
    pub policy: ResourcePolicy,
    /// Managed Block 使用的注释前缀。
    pub comment_prefix: &'static str,
    /// 资源级选择器。
    pub selector: Option<Selector>,
}

impl FileSpec {
    /// 构造一条资源定义。
    ///
    /// `id` 必须是合法的 [`ResourceId`]；内建适配器传入的都是字面量，非法字面量属于
    /// 编程错误，会在构造时立刻 panic 而不是等到运行期悄悄产出错误资源。
    pub fn new(
        id: &str,
        root: &'static str,
        segments: &'static [&'static str],
        mode: FileMode,
    ) -> Self {
        FileSpec {
            id: ResourceId::parse(id).expect("内建资源标识必须合法"),
            root,
            segments,
            mode,
            disposition: DesiredDisposition::Managed,
            policy: ResourcePolicy::default(),
            comment_prefix: render::DEFAULT_COMMENT_PREFIX,
            selector: None,
        }
    }

    /// 设置注释前缀。
    pub fn with_comment_prefix(mut self, prefix: &'static str) -> Self {
        self.comment_prefix = prefix;
        self
    }

    /// 设置资源级选择器。
    pub fn with_selector(mut self, selector: Selector) -> Self {
        self.selector = Some(selector);
        self
    }

    /// 设置期望处置。
    pub fn with_disposition(mut self, disposition: DesiredDisposition) -> Self {
        self.disposition = disposition;
        self
    }

    /// 设置结构化合并格式。
    pub fn with_structured_format(mut self, format: StructuredFormat) -> Self {
        self.policy.structured_format = Some(format);
        self
    }

    /// 设置 POSIX 权限位。
    pub fn with_unix_mode(mut self, mode: u32) -> Self {
        self.policy.unix_mode = Some(mode);
        self
    }
}

/// 由静态资源表驱动的文件适配器。
///
/// 它同时实现了 Full File、Managed Block 与 Structured Merge 三种模式；具体适配器
/// （[`crate::shell`]、[`crate::wezterm`]、[`crate::git_config`]）只提供描述符和资源表。
#[derive(Debug, Clone)]
pub struct FileAdapter {
    descriptor: &'static AdapterDescriptor,
    specs: Vec<FileSpec>,
}

impl FileAdapter {
    /// 由描述符与资源表构造。
    ///
    /// 资源表中的标识必须互不相同；重复标识属于编程错误，会立刻 panic。
    pub fn new(descriptor: &'static AdapterDescriptor, specs: Vec<FileSpec>) -> Self {
        for (index, spec) in specs.iter().enumerate() {
            assert!(
                !specs[..index].iter().any(|other| other.id == spec.id),
                "适配器 {} 的资源表存在重复标识 {}",
                descriptor.id,
                spec.id
            );
        }
        FileAdapter { descriptor, specs }
    }

    /// 资源表视图。
    pub fn specs(&self) -> &[FileSpec] {
        &self.specs
    }

    /// 按标识查找资源定义。
    pub fn spec(&self, resource: &ResourceId) -> Option<&FileSpec> {
        self.specs.iter().find(|spec| spec.id == *resource)
    }

    /// 查找资源定义，找不到时返回 [`AdapterError::UnknownResource`]。
    fn require_spec(&self, resource: &ResourceId) -> Result<&FileSpec, AdapterError> {
        self.spec(resource)
            .ok_or_else(|| AdapterError::UnknownResource(resource.clone()))
    }
}

impl sealed::Sealed for FileAdapter {}

impl Adapter for FileAdapter {
    fn descriptor(&self) -> &'static AdapterDescriptor {
        self.descriptor
    }

    /// 逐条把资源表映射成 [`DiscoveredResource`]。
    ///
    /// 授权根缺失时**跳过**对应资源而不是报错：宿主可能只授权了主目录，这属于正常
    /// 配置而不是故障。资源级选择器在这里**不**求值，由
    /// [`crate::AdapterRegistry::discover_all`] 统一处理，这样单独调用 `discover`
    /// 可以看到该适配器的全部候选资源。
    fn discover(&self, ctx: &AdapterContext<'_>) -> Result<Vec<DiscoveredResource>, AdapterError> {
        let mut out = Vec::with_capacity(self.specs.len());
        for spec in &self.specs {
            let Some(prefix) = ctx.prefix(spec.root) else {
                continue;
            };
            let target = join_target(spec.root, prefix, spec.segments)?;
            out.push(DiscoveredResource {
                id: spec.id.clone(),
                root: spec.root.to_owned(),
                target,
                mode: spec.mode,
                disposition: spec.disposition,
                policy: spec.policy.clone(),
                comment_prefix: spec.comment_prefix.to_owned(),
                selector: spec.selector.clone(),
            });
        }
        Ok(out)
    }

    /// 抽取受管内容。
    ///
    /// 处置为 [`DesiredDisposition::Unmanaged`] 的资源一律返回 `Ok(None)`：观察态资源
    /// 只记录存在性，内容不进入快照。这条规则在这里统一强制，具体适配器无法绕过。
    fn capture(&self, resource: &ResourceId, raw: &[u8]) -> Result<Option<Vec<u8>>, AdapterError> {
        let spec = self.require_spec(resource)?;
        if spec.disposition == DesiredDisposition::Unmanaged {
            return Ok(None);
        }
        match spec.mode {
            FileMode::FullFile => Ok(Some(raw.to_vec())),
            FileMode::ManagedBlock => Ok(render::extract_managed_block(raw, resource)?),
            FileMode::StructuredMerge => {
                validate_structured(resource, raw, spec.policy.structured_format)?;
                Ok(Some(raw.to_vec()))
            }
            mode => Err(unsupported_mode(mode)),
        }
    }

    /// 渲染完整文件内容。
    ///
    /// 处置为 [`DesiredDisposition::Unmanaged`] 的资源直接返回
    /// [`AdapterError::ObserveOnly`]：观察态资源永远不会产生待写入字节。
    fn render(
        &self,
        resource: &ResourceId,
        existing: Option<&[u8]>,
        desired: &[u8],
    ) -> Result<RenderedFile, AdapterError> {
        let spec = self.require_spec(resource)?;
        if spec.disposition == DesiredDisposition::Unmanaged {
            return Err(AdapterError::ObserveOnly(resource.clone()));
        }
        // Structured Merge 在写盘层面等价于 Full File：权威字节已经由 core 的合并器
        // 算好（那里才有 base）。这里额外校验一次，防止把语法损坏的内容写到用户盘上。
        let render_mode = match spec.mode {
            FileMode::StructuredMerge => {
                validate_structured(resource, desired, spec.policy.structured_format)?;
                FileMode::FullFile
            }
            FileMode::FullFile => FileMode::FullFile,
            FileMode::ManagedBlock => FileMode::ManagedBlock,
            mode => return Err(unsupported_mode(mode)),
        };

        let input = RenderInput {
            resource,
            existing,
            desired,
            mode: render_mode,
            policy: &spec.policy,
            comment_prefix: spec.comment_prefix,
        };
        Ok(match render::render(&input)? {
            RenderedChange::Write(bytes) => RenderedFile::Write(bytes),
            RenderedChange::Unchanged => RenderedFile::Unchanged,
        })
    }

    fn verify(
        &self,
        resource: &ResourceId,
        actual: &[u8],
        desired: &[u8],
    ) -> Result<(), AdapterError> {
        match self.render(resource, Some(actual), desired)? {
            RenderedFile::Unchanged => Ok(()),
            RenderedFile::Write(_) => Err(AdapterError::VerifyFailed {
                resource: resource.clone(),
                detail: "目标内容与期望不一致".to_owned(),
            }),
        }
    }
}

/// 把「授权根前缀 + 静态分段」拼成受校验的相对目标。
///
/// 前缀可以为空（主目录就是授权根本身），也可以包含多段（例如 `Users/用户`）。
/// 拼接结果一律交给 [`RelativeTarget`] 校验：`..`、绝对路径、盘符、保留设备名、
/// 控制字符等一切逃逸形式都会在这里被拒绝。
pub fn join_target(
    root: &'static str,
    prefix: &str,
    segments: &[&str],
) -> Result<String, AdapterError> {
    let mut parts: Vec<&str> = prefix.split('/').filter(|part| !part.is_empty()).collect();
    parts.extend(segments.iter().copied());
    let joined = parts.join("/");
    let target = RelativeTarget::parse(&joined)
        .map_err(|source| AdapterError::InvalidTarget { root, source })?;
    Ok(target.display_path())
}

/// 用 [`envsync_core::merge`] 的解析器校验结构化内容。
///
/// 实现手法：对「本侧 = 待校验内容、对侧 = 空文件、无 base」做一次退化的三方合并。
/// 合并器会解析两侧、执行合并、再把结果渲染回文本并重新解析比对，因此任何语法错误
/// 都会以 [`envsync_core::merge::MergeError`] 的形式暴露出来。之所以绕这一道，是因为
/// core 目前只对外暴露合并入口而没有独立的解析入口；复用同一个解析器可以保证
/// capture 与合并对「什么是合法配置」的判断完全一致。
///
/// 未声明格式时不做任何校验（内容按不透明字节处理）。
fn validate_structured(
    resource: &ResourceId,
    bytes: &[u8],
    format: Option<StructuredFormat>,
) -> Result<(), AdapterError> {
    let Some(format) = format else {
        return Ok(());
    };
    let input = MergeInput {
        resource,
        base: None,
        ours: Some(bytes),
        theirs: Some(b""),
    };
    merge::merge_structured(&input, format).map_err(|error| AdapterError::Structured {
        resource: resource.clone(),
        detail: error.to_string(),
    })?;
    Ok(())
}

/// 构造「模式不受支持」错误。
///
/// [`FileMode::GeneratedInclude`] 不会走到这里：它被拆成两个资源实现，见
/// [`crate::wezterm`]。
fn unsupported_mode(mode: FileMode) -> AdapterError {
    AdapterError::Render(render::RenderError::UnsupportedMode { mode })
}
