import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'

import ChangesPage from './ChangesPage.vue'
import ConflictsPage from './ConflictsPage.vue'
import HistoryPage from './HistoryPage.vue'
import type { SyncReviewPort } from '../ports/sync-review'
import { useWorkspaceStore } from '../stores/workspace'

function setupWorkspace() {
  setActivePinia(createPinia())
  useWorkspaceStore().setWorkspace({
    workspaceId: 'workspace-01',
    backendKind: 'local',
    deviceId: 'device-01',
    root: { token: 'cap-root-01', label: '已授权目录' },
  })
}

function basePort(): SyncReviewPort {
  return {
    buildPlan: vi.fn(),
    loadDiff: vi.fn(),
    applyPlan: vi.fn(),
    listConflicts: vi.fn(),
    showConflict: vi.fn(),
    resolveConflict: vi.fn(),
    listOperations: vi.fn(),
    showOperation: vi.fn(),
    reviewRollback: vi.fn(),
    executeRollback: vi.fn(),
  }
}

describe('M4 Task 5 pages', () => {
  it('高风险动作必须逐项确认，且只提交当前 Plan ID', async () => {
    setupWorkspace()
    const port = basePort()
    vi.mocked(port.buildPlan).mockResolvedValue({
      kind: 'success',
      plan: {
        id: 'plan-current-01',
        workspace: 'workspace-01',
        device_id: 'device-01',
        target_snapshot: 'snapshot-01',
        base_revision: 1,
        next_revision: 2,
        diagnostics: [],
        actions: [{
          resource: 'shell/zsh/main',
          kind: 'replace_file',
          target: 'home:.zshrc',
          risk: 'high',
          backup: 'required',
          rollback: 'exact',
          sensitive: false,
        }],
      },
    })
    vi.mocked(port.loadDiff).mockResolvedValue({
      kind: 'success',
      diff: { plan: 'plan-current-01', diffs: [] },
    })
    vi.mocked(port.applyPlan).mockResolvedValue({ kind: 'success', operation: 'operation-queued-01' })

    const wrapper = mount(ChangesPage, { props: { port } })
    await flushPromises()

    const apply = wrapper.get('[data-action="apply-current-plan"]')
    expect(apply.attributes('disabled')).toBeDefined()
    await wrapper.get('[data-high-risk-confirmation]').setValue(true)
    expect(apply.attributes('disabled')).toBeUndefined()
    await apply.trigger('click')
    await flushPromises()

    expect(port.applyPlan).toHaveBeenCalledWith('workspace-01', 'plan-current-01')
    expect(wrapper.get('[data-apply-queued]').text()).toContain('不等于同步成功')
  })

  it('秘密冲突不开放手动编辑，裁决后也不把状态说成同步成功', async () => {
    setupWorkspace()
    const port = basePort()
    vi.mocked(port.listConflicts).mockResolvedValue({
      kind: 'success',
      conflicts: [{
        id: 'conflict-01',
        workspace: 'workspace-01',
        resource: 'secret/token',
        kind: 'text_overlap',
        state: 'open',
        choice: null,
        created_at_unix_ms: 1,
        resolved_at_unix_ms: null,
      }],
    })
    vi.mocked(port.showConflict).mockResolvedValue({
      kind: 'success',
      conflict: {
        conflict: {
          id: 'conflict-01',
          workspace: 'workspace-01',
          resource: 'secret/token',
          kind: 'text_overlap',
          state: 'open',
          choice: null,
          created_at_unix_ms: 1,
          resolved_at_unix_ms: null,
        },
        mode: 'full_file',
        structured_format: null,
        ours_available: true,
        theirs_available: true,
        manual_allowed: false,
        manual_max_bytes: 0,
      },
    })
    vi.mocked(port.resolveConflict).mockResolvedValue({
      kind: 'success',
      resolution: {
        conflict: 'conflict-01',
        state: 'resolved',
        choice: 'ours',
        resolved_at_unix_ms: 2,
      },
    })

    const wrapper = mount(ConflictsPage, { props: { port } })
    await flushPromises()
    await wrapper.get('.conflict-list__item').trigger('click')
    await flushPromises()

    expect(wrapper.get('[data-manual-unavailable]').text()).toContain('不能通过手动编辑器')
    expect(wrapper.find('[data-manual-resolution]').exists()).toBe(false)
    await wrapper.get('.review-actions .preference-button').trigger('click')
    await flushPromises()
    expect(port.resolveConflict).toHaveBeenCalledWith({
      workspaceId: 'workspace-01',
      conflictId: 'conflict-01',
      choice: 'ours',
    })
    expect(wrapper.get('[data-resolution-notice]').text()).toContain('同步尚未执行')
  })

  it('回滚先要求逆向计划审核和逐项确认，再传递一次性 token', async () => {
    setupWorkspace()
    const port = basePort()
    const operation = {
      operation: 'operation-01',
      plan: 'plan-01',
      snapshot: 'snapshot-01',
      workspace: 'workspace-01',
      revision: 4,
      state: 'completed',
      created_at_unix_ms: 1,
      updated_at_unix_ms: 2,
      error_code: null,
    }
    vi.mocked(port.listOperations).mockResolvedValue({ kind: 'success', operations: [operation] })
    vi.mocked(port.showOperation).mockResolvedValue({
      kind: 'success',
      operation: {
        operation,
        actions: [{
          ordinal: 7,
          resource: 'shell/zsh/main',
          kind: 'replace_file',
          target: 'home:.zshrc',
          state: 'completed',
          error_code: null,
        }],
        receipts: [{
          ordinal: 7,
          resource: 'shell/zsh/main',
          guarantee: 'exact',
          created_at_unix_ms: 2,
        }],
        rollback_available: true,
      },
    })
    vi.mocked(port.reviewRollback).mockResolvedValue({
      kind: 'success',
      review: {
        review_token: 'review-token-01',
        operation,
        actions: [{
          ordinal: 7,
          resource: 'shell/zsh/main',
          target: 'home:.zshrc',
          original_kind: 'replace_file',
          guarantee: 'exact',
        }],
        requires_individual_confirmation: true,
      },
    })
    vi.mocked(port.executeRollback).mockResolvedValue({
      kind: 'success',
      operation: { ...operation, state: 'rolled_back' },
    })

    const wrapper = mount(HistoryPage, { props: { port } })
    await flushPromises()
    await wrapper.get('.history-list__item').trigger('click')
    await flushPromises()
    await wrapper.get('[data-action="review-rollback"]').trigger('click')
    await flushPromises()

    const execute = wrapper.get('[data-action="execute-rollback"]')
    expect(execute.attributes('disabled')).toBeDefined()
    await wrapper.get('[data-rollback-confirmation]').setValue(true)
    await execute.trigger('click')
    await flushPromises()

    expect(port.executeRollback).toHaveBeenCalledWith({
      workspaceId: 'workspace-01',
      operationId: 'operation-01',
      reviewToken: 'review-token-01',
      confirmations: [7],
    })
  })
})
