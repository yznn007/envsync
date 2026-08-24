import { createPinia, setActivePinia } from 'pinia'
import { flushPromises, mount } from '@vue/test-utils'

import AgentsPage from './AgentsPage.vue'
import DevicesPage from './DevicesPage.vue'
import PackagesPage from './PackagesPage.vue'
import VaultPage from './VaultPage.vue'
import type { SecurityReviewPort } from '../ports/security-review'
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

function basePort(): SecurityReviewPort {
  return {
    loadVaultMetadata: vi.fn(),
    listDevices: vi.fn(),
    revokeDevice: vi.fn(),
  }
}

describe('M4 Task 6 security pages', () => {
  it('包操作使用不同风险标签，批量选择始终排除 policy deny', async () => {
    const wrapper = mount(PackagesPage, {
      props: {
        actions: [
          {
            id: 'install-ripgrep',
            identity: 'brew:ripgrep',
            kind: 'install',
            risk: 'low',
            elevation_required: false,
            policy: 'allow',
          },
          {
            id: 'upgrade-node',
            identity: 'npm:node',
            kind: 'upgrade',
            risk: 'medium',
            elevation_required: true,
            policy: 'require_confirmation',
          },
          {
            id: 'downgrade-tool',
            identity: 'brew:tool',
            kind: 'downgrade',
            risk: 'high',
            elevation_required: false,
            policy: 'allow',
          },
          {
            id: 'uninstall-denied',
            identity: 'apt:legacy',
            kind: 'uninstall',
            risk: 'high',
            elevation_required: true,
            policy: 'deny',
          },
        ],
      },
    })

    expect(wrapper.text()).toContain('安装')
    expect(wrapper.text()).toContain('升级')
    expect(wrapper.text()).toContain('降级')
    expect(wrapper.text()).toContain('卸载')
    expect(wrapper.text()).toContain('需提权')

    const denied = wrapper.get('[data-package-approval="uninstall-denied"]')
    expect(denied.attributes('disabled')).toBeDefined()
    await wrapper.get('[data-action="approve-all-allowed-packages"]').trigger('click')

    expect(wrapper.get('[data-package-approval="install-ripgrep"]').element).toHaveProperty('checked', true)
    expect(wrapper.get('[data-package-approval="upgrade-node"]').element).toHaveProperty('checked', true)
    expect(wrapper.get('[data-package-approval="downgrade-tool"]').element).toHaveProperty('checked', true)
    expect(denied.element).toHaveProperty('checked', false)
    expect(wrapper.text()).toContain('策略拒绝项保持不可批准')
  })

  it('Bundle 审核显示签名、摘要、文件、能力和 SecretRef，新增能力需逐项确认', async () => {
    const wrapper = mount(AgentsPage, {
      props: {
        bundles: [{
          id: 'com.example.agent',
          signer: 'publisher-fingerprint-01',
          digest: 'manifest-digest-01',
          files: [{ path: 'agents/main.md', digest: 'file-digest-01' }],
          capabilities: ['fs.read', 'mcp.observe'],
          secret_refs: ['secret://ci/npm-token'],
          previous_version: '1.1.0',
          version: '1.2.0',
          added_capabilities: ['mcp.observe'],
          state: 'inspected',
        }],
      },
    })

    expect(wrapper.text()).toContain('publisher-fingerprint-01')
    expect(wrapper.text()).toContain('manifest-digest-01')
    expect(wrapper.text()).toContain('agents/main.md')
    expect(wrapper.text()).toContain('fs.read')
    expect(wrapper.text()).toContain('secret://ci/npm-token')
    expect(wrapper.text()).toContain('1.1.0 → 1.2.0')
    expect(wrapper.find('[data-action="execute-quarantine"]').exists()).toBe(false)
    expect(wrapper.text()).toContain('不可从此界面执行')

    const confirmation = wrapper.get('[data-capability-confirmation="mcp.observe"]')
    expect((confirmation.element as HTMLInputElement).checked).toBe(false)
    await confirmation.setValue(true)
    expect((confirmation.element as HTMLInputElement).checked).toBe(true)
  })

  it('Vault 页面仅显示 metadata，秘密输入保留在有界的 CLI 通道', async () => {
    setupWorkspace()
    const port = basePort()
    vi.mocked(port.loadVaultMetadata).mockResolvedValue({
      kind: 'success',
      vault: {
        workspace: 'workspace-01',
        index_missing: false,
        entries: [{
          id: 'ci/npm-token',
          updated_at_unix_ms: 1,
          referenced_by: ['agents/npm/publish'],
        }],
      },
    })
    const wrapper = mount(VaultPage, { props: { port } })
    await flushPromises()
    expect(wrapper.text()).toContain('ci/npm-token')
    expect(wrapper.text()).toContain('envsync vault set')
    expect(wrapper.find('[data-vault-secret-value]').exists()).toBe(false)
    expect(wrapper.find('[data-action="open-vault-set-modal"]').exists()).toBe(false)
    expect(wrapper.html()).not.toContain('secret_value')
  })

  it('设备撤销明确提示密钥轮换与旧设备重新授权，并要求匹配 ID 确认', async () => {
    setupWorkspace()
    const port = basePort()
    const otherDevice = 'device-other-01'
    vi.mocked(port.listDevices).mockResolvedValue({
      kind: 'success',
      devices: {
        workspace: 'workspace-01',
        key_epoch: 5,
        membership_sequence: 9,
        devices: [
          {
            device: 'device-self-01',
            role: 'admin',
            added_at_sequence: 1,
            is_self: true,
            has_current_envelope: true,
          },
          {
            device: otherDevice,
            role: 'member',
            added_at_sequence: 8,
            is_self: false,
            has_current_envelope: true,
          },
        ],
      },
    })
    vi.mocked(port.revokeDevice).mockResolvedValue({
      kind: 'success',
      revocation: {
        revoked: otherDevice,
        from_epoch: 5,
        to_epoch: 6,
        stage: 'complete',
        envelopes: 1,
        pending_rewrap: 2,
        resumed: false,
      },
    })

    const wrapper = mount(DevicesPage, { props: { port } })
    await flushPromises()
    expect(wrapper.text()).toContain('重新授权')
    expect(wrapper.text()).toContain('不含 private material')

    await wrapper.get(`[data-action="begin-revoke-${otherDevice}"]`).trigger('click')
    const confirm = wrapper.get('[data-action="confirm-device-revoke"]')
    expect(confirm.attributes('disabled')).toBeDefined()
    await wrapper.get('[data-device-revoke-confirmation]').setValue(otherDevice)
    expect(confirm.attributes('disabled')).toBeUndefined()
    await confirm.trigger('click')
    await flushPromises()

    expect(port.revokeDevice).toHaveBeenCalledWith({
      workspaceId: 'workspace-01',
      deviceId: otherDevice,
      confirmation: otherDevice,
    })
    expect(wrapper.text()).toContain('密钥纪元 5 → 6')
  })
})
