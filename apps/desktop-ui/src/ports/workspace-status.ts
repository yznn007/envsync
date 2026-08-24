/** 读取已注册工作区的脱敏状态。 */

import type { SafeStatusView } from '../stores/workspace'
import {
  invokeDesktop,
  opaqueIdentifier,
  safeResourceIdentifier,
  type SafeDiagnostic,
} from './tauri-api'

const stateNames = new Set<SafeStatusView['state']>([
  'clean',
  'drifted',
  'conflicted',
  'published_not_converged',
  'backend_unreachable',
])

type JsonRecord = Record<string, unknown>

export type WorkspaceStatusResult =
  | { kind: 'success'; status: SafeStatusView }
  | { kind: 'error'; code: string }

/** 安全状态 API 的可替换端口，便于页面测试。 */
export interface WorkspaceStatusPort {
  loadStatus(workspaceId: string): Promise<WorkspaceStatusResult>
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function naturalNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}

function optionalOpaqueIdentifier(value: unknown): value is string | null {
  return value === null || opaqueIdentifier(value)
}

function workspaceState(value: unknown): value is SafeStatusView['state'] {
  return typeof value === 'string' && stateNames.has(value as SafeStatusView['state'])
}

function resources(value: unknown): SafeStatusView['resources'] | null {
  if (!Array.isArray(value)) {
    return null
  }
  const result: SafeStatusView['resources'] = []
  for (const resource of value) {
    if (
      !isRecord(resource)
      || !safeResourceIdentifier(resource.resource)
      || !opaqueIdentifier(resource.observed)
      || (resource.disposition !== null && !opaqueIdentifier(resource.disposition))
      || typeof resource.needs_action !== 'boolean'
    ) {
      return null
    }
    result.push({
      resource: resource.resource,
      observed: resource.observed,
      disposition: resource.disposition,
      needs_action: resource.needs_action,
    })
  }
  return result
}

function unfinishedOperations(value: unknown): SafeStatusView['unfinished_operations'] | null {
  if (!Array.isArray(value)) {
    return null
  }
  const result: SafeStatusView['unfinished_operations'] = []
  for (const operation of value) {
    if (
      !isRecord(operation)
      || !opaqueIdentifier(operation.operation)
      || !opaqueIdentifier(operation.state)
    ) {
      return null
    }
    result.push({ operation: operation.operation, state: operation.state })
  }
  return result
}

function statusView(value: unknown, diagnostics: SafeDiagnostic[]): { status: SafeStatusView } | null {
  if (!isRecord(value) || !isRecord(value.workspace)) {
    return null
  }
  const { workspace } = value
  const resourceViews = resources(value.resources)
  const operations = unfinishedOperations(value.unfinished_operations)
  if (
    !opaqueIdentifier(workspace.id)
    || !opaqueIdentifier(workspace.device_id)
    || !opaqueIdentifier(workspace.backend_kind)
    || !workspaceState(value.state)
    || typeof value.backend_reachable !== 'boolean'
    || (value.last_known_revision_at_unix_ms !== null
      && !naturalNumber(value.last_known_revision_at_unix_ms))
    || !naturalNumber(value.revision)
    || !optionalOpaqueIdentifier(value.head)
    || !optionalOpaqueIdentifier(value.draft_head)
    || resourceViews === null
    || operations === null
    || !naturalNumber(value.pending_actions)
    || !naturalNumber(value.open_conflicts)
  ) {
    return null
  }
  return {
    status: {
      workspace: {
        id: workspace.id,
        device_id: workspace.device_id,
        backend_kind: workspace.backend_kind,
      },
      state: value.state,
      backend_reachable: value.backend_reachable,
      last_known_revision_at_unix_ms: value.last_known_revision_at_unix_ms,
      revision: value.revision,
      head: value.head,
      draft_head: value.draft_head,
      resources: resourceViews,
      unfinished_operations: operations,
      pending_actions: value.pending_actions,
      open_conflicts: value.open_conflicts,
      diagnostics,
    },
  }
}

/** 生产环境的 workspace status 端口。 */
export const tauriWorkspaceStatusPort: WorkspaceStatusPort = {
  loadStatus: async (workspaceId) => {
    if (!opaqueIdentifier(workspaceId)) {
      return { kind: 'error', code: 'desktop.workspace_not_registered' }
    }
    return invokeDesktop('workspace_status', { workspace_id: workspaceId }, statusView)
  },
}
