/**
 * 首次使用流程的受限 native 边界。
 *
 * 目录选择由 Rust 发起；WebView 只拿到不透明 capability token 与安全显示标签，绝不接收
 * 或保存绝对路径。
 */

export type OnboardingBackend = 'local' | 'git' | 'gist'
export type SupportedOnboardingBackend = Exclude<OnboardingBackend, 'gist'>
export type GitOnboardingAuth = 'ssh-agent' | 'credential-helper'

export interface RootCapabilityView {
  /** Rust 注册的根能力标识，不能从 token 推导路径。 */
  token: string
  /** Rust 给出的安全显示标签，不是文件系统路径。 */
  label: string
}

export interface WorkspaceView {
  workspaceId: string
  backendKind: SupportedOnboardingBackend
  deviceId: string
  root: RootCapabilityView
}

export interface CreateWorkspaceIntent {
  backendKind: SupportedOnboardingBackend
  deviceProfile: string
  rootCapabilityToken: string
  /** Git 远端地址只在提交 intent 时交给 Rust，不写入 UI store。 */
  remoteUrl?: string
  /** Git 只允许系统 SSH agent 或 credential helper，不接受 token 明文。 */
  gitAuth?: GitOnboardingAuth
}

export type OnboardingResult<T> = ({ kind: 'success' } & T) | { kind: 'error'; code: string }

export interface OnboardingPort {
  selectRoot(): Promise<OnboardingResult<{ root: RootCapabilityView }>>
  createWorkspace(intent: CreateWorkspaceIntent): Promise<OnboardingResult<{ workspace: WorkspaceView }>>
  openWorkspace(): Promise<OnboardingResult<{ workspace: WorkspaceView }>>
}

const unavailable = async (): Promise<OnboardingResult<never>> => ({
  kind: 'error',
  code: 'desktop.onboarding_unavailable',
})

/** 默认端口明确拒绝操作，绝不把演示状态伪装成创建成功。 */
export const unavailableOnboardingPort: OnboardingPort = {
  selectRoot: unavailable,
  createWorkspace: unavailable,
  openWorkspace: unavailable,
}
