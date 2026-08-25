import { defineStore } from 'pinia'

import type { RootCapabilityView, WorkspaceView } from '../ports/onboarding'

export type WorkspaceStateName =
  | 'clean'
  | 'drifted'
  | 'conflicted'
  | 'published_not_converged'
  | 'backend_unreachable'

/** 与 application-service `StatusView` 对齐的脱敏前端形状。 */
export interface SafeStatusView {
  workspace: {
    id: string
    device_id: string
    backend_kind: string
  }
  state: WorkspaceStateName
  backend_reachable: boolean
  last_known_revision_at_unix_ms: number | null
  revision: number
  head: string | null
  draft_head: string | null
  resources: Array<{
    resource: string
    observed: string
    disposition: string | null
    needs_action: boolean
  }>
  unfinished_operations: Array<{
    operation: string
    state: string
  }>
  pending_actions: number
  open_conflicts: number
  diagnostics: Array<{
    severity: 'info' | 'warning' | 'blocking'
    code: string
    resource: string | null
  }>
}

export type WorkspacePhase = 'onboarding' | 'loading' | 'ready' | 'error'

/**
 * 工作区 store 只保存 application-service 已审核的摘要、根 capability token 与稳定错误码。
 * 它故意不包含路径、远端 URL、文件正文、秘密或原始错误文本。
 */
export const useWorkspaceStore = defineStore('workspace', {
  state: () => ({
    phase: 'onboarding' as WorkspacePhase,
    workspace: null as WorkspaceView | null,
    status: null as SafeStatusView | null,
    lastErrorCode: null as string | null,
  }),
  actions: {
    setWorkspace(workspace: WorkspaceView) {
      this.workspace = workspace
      this.phase = 'loading'
      this.lastErrorCode = null
    },
    setStatus(status: SafeStatusView) {
      this.status = status
      this.phase = 'ready'
      this.lastErrorCode = null
    },
    setFailure(code: string) {
      this.phase = 'error'
      this.lastErrorCode = code
    },
    resumeOnboarding() {
      this.phase = 'onboarding'
      this.lastErrorCode = null
    },
  },
})

export type { RootCapabilityView, WorkspaceView }
