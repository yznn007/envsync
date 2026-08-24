import { defineStore } from 'pinia'

export type ColorTheme = 'system' | 'light' | 'dark'
export type ContrastMode = 'standard' | 'high'

/** 只保存 application-service 允许交给 UI 的诊断形状。 */
export interface SafeDiagnostic {
  severity: 'info' | 'warning' | 'blocking'
  code: string
  resource: string | null
}

/**
 * UI 状态不得保存 Vault 明文、文件内容、绝对路径或未脱敏异常。request ID 和 diagnostic
 * code 足以让界面展示可定位、可本地化的反馈。
 */
export const useUiStore = defineStore('ui', {
  state: () => ({
    navigationOpen: false,
    theme: 'system' as ColorTheme,
    contrast: 'standard' as ContrastMode,
    lastRequestId: null as string | null,
    diagnostics: [] as SafeDiagnostic[],
    boundaryErrorCode: null as string | null,
  }),
  actions: {
    toggleNavigation() {
      this.navigationOpen = !this.navigationOpen
    },
    closeNavigation() {
      this.navigationOpen = false
    },
    cycleTheme() {
      this.theme =
        this.theme === 'system' ? 'light' : this.theme === 'light' ? 'dark' : 'system'
    },
    toggleContrast() {
      this.contrast = this.contrast === 'standard' ? 'high' : 'standard'
    },
    recordSafeResponse(requestId: string, diagnostics: SafeDiagnostic[]) {
      this.lastRequestId = requestId
      this.diagnostics = diagnostics.map(({ severity, code, resource }) => ({
        severity,
        code,
        resource,
      }))
    },
    recordBoundaryError() {
      this.boundaryErrorCode = 'ui.unexpected'
    },
  },
})
