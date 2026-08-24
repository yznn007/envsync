/**
 * Tauri application-service 的最小安全客户端。
 *
 * 这里统一生成版本化请求、验证信封，并把 native 失败收敛为稳定错误码。它不使用任何
 * 高权限插件，也不会回显 transport 或诊断的自由文本。
 */

import { invoke } from '@tauri-apps/api/core'

const SCHEMA_VERSION = 1
let requestSequence = 0

type JsonRecord = Record<string, unknown>

/** 可安全显示的诊断投影。 */
export interface SafeDiagnostic {
  severity: 'info' | 'warning' | 'blocking'
  code: string
  resource: string | null
}

/** 原生调用的安全终态。 */
export type NativeCallResult<T> = ({ kind: 'success' } & T) | { kind: 'error'; code: string }

interface DesktopResponse {
  schema_version: number
  request_id: string
  status: 'ok' | 'error'
  data: unknown
  diagnostics: SafeDiagnostic[]
}

function isRecord(value: unknown): value is JsonRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/** 仅接受 API 契约里的短 opaque ID；路径、URL 与自由文本会被拒绝。 */
export function opaqueIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string'
    && value.length > 0
    && value.length <= 128
    && /^[A-Za-z0-9._-]+$/.test(value)
  )
}

/** 验证安全资源标识，而不是把可能是路径的文本展示给 UI。 */
export function safeResourceIdentifier(value: unknown): value is string {
  return (
    typeof value === 'string'
    && value.length > 0
    && value.length <= 256
    && /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/.test(value)
  )
}

function nextRequestId() {
  const random = globalThis.crypto?.randomUUID?.()
  if (random) {
    return `desktop-${random}`
  }
  requestSequence += 1
  return `desktop-${Date.now()}-${requestSequence}`
}

function parseDiagnostics(value: unknown[]): SafeDiagnostic[] {
  return value.flatMap((diagnostic) => {
    if (!isRecord(diagnostic) || !opaqueIdentifier(diagnostic.code)) {
      return []
    }
    if (
      diagnostic.severity !== 'info'
      && diagnostic.severity !== 'warning'
      && diagnostic.severity !== 'blocking'
    ) {
      return []
    }
    const resource = safeResourceIdentifier(diagnostic.resource) ? diagnostic.resource : null
    return [{ severity: diagnostic.severity, code: diagnostic.code, resource }]
  })
}

function parseDesktopResponse(value: unknown): DesktopResponse | null {
  if (!isRecord(value)) {
    return null
  }
  if (
    value.schema_version !== SCHEMA_VERSION
    || !opaqueIdentifier(value.request_id)
    || (value.status !== 'ok' && value.status !== 'error')
    || !Array.isArray(value.diagnostics)
  ) {
    return null
  }
  return {
    schema_version: value.schema_version,
    request_id: value.request_id,
    status: value.status,
    data: value.data,
    diagnostics: parseDiagnostics(value.diagnostics),
  }
}

function diagnosticCode(diagnostics: SafeDiagnostic[]) {
  return diagnostics[0]?.code ?? 'desktop.ipc_response_invalid'
}

/**
 * 调用单个审查过的 command，并只将 decoder 明确许可的 View 字段交给页面层。
 */
export async function invokeDesktop<T extends object>(
  command: string,
  data: JsonRecord,
  decode: (data: unknown, diagnostics: SafeDiagnostic[]) => T | null,
): Promise<NativeCallResult<T>> {
  try {
    const value = await invoke<unknown>(command, {
      request: {
        schema_version: SCHEMA_VERSION,
        request_id: nextRequestId(),
        data,
      },
    })
    const response = parseDesktopResponse(value)
    if (!response) {
      return { kind: 'error', code: 'desktop.ipc_response_invalid' }
    }
    if (response.status === 'error') {
      return { kind: 'error', code: diagnosticCode(response.diagnostics) }
    }
    const decoded = decode(response.data, response.diagnostics)
    return decoded
      ? { kind: 'success', ...decoded }
      : { kind: 'error', code: 'desktop.ipc_response_invalid' }
  } catch {
    return { kind: 'error', code: 'desktop.ipc_unavailable' }
  }
}
