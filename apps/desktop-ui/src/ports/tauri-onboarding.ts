/**
 * 首次使用的受限 Tauri command 端口。
 *
 * 目录选择仍在 Rust 原生层进行；此处只携带 capability token 和经审核的工作区摘要。
 */

import type {
  CreateWorkspaceIntent,
  OnboardingPort,
  RootCapabilityView,
  WorkspaceView,
} from './onboarding'
import { invokeDesktop, opaqueIdentifier } from './tauri-api'

const SAFE_ROOT_LABEL = '已授权目录'

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function rootCapability(value: unknown): RootCapabilityView | null {
  if (!isRecord(value) || !opaqueIdentifier(value.token)) {
    return null
  }
  // Rust 固定提供通用标签；前端也投影为固定文本，杜绝异常宿主把路径塞进 label。
  return { token: value.token, label: SAFE_ROOT_LABEL }
}

function workspaceView(value: unknown): WorkspaceView | null {
  if (!isRecord(value) || !isRecord(value.workspace)) {
    return null
  }
  const root = rootCapability(value.root)
  const { workspace } = value
  if (
    !root
    || !opaqueIdentifier(workspace.id)
    || !opaqueIdentifier(workspace.device_id)
    || (workspace.backend_kind !== 'local' && workspace.backend_kind !== 'git')
  ) {
    return null
  }
  return {
    workspaceId: workspace.id,
    backendKind: workspace.backend_kind,
    deviceId: workspace.device_id,
    root,
  }
}

function rootResult(value: unknown) {
  const root = rootCapability(value)
  return root ? { root } : null
}

function workspaceResult(value: unknown) {
  const workspace = workspaceView(value)
  return workspace ? { workspace } : null
}

/** 生产环境的原生首次使用端口。 */
export const tauriOnboardingPort: OnboardingPort = {
  selectRoot: () => invokeDesktop('onboarding_select_root', {}, rootResult),
  createWorkspace: (intent: CreateWorkspaceIntent) =>
    invokeDesktop(
      'onboarding_create_workspace',
      {
        backend_kind: intent.backendKind,
        device_profile: intent.deviceProfile,
        root_capability_token: intent.rootCapabilityToken,
        ...(intent.backendKind === 'git'
          ? {
              remote_url: intent.remoteUrl,
              git_auth: intent.gitAuth,
            }
          : {}),
      },
      workspaceResult,
    ),
  openWorkspace: () => invokeDesktop('onboarding_open_workspace', {}, workspaceResult),
}
