<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import {
  tauriSecurityReviewPort,
  type SafeVaultMetadataView,
  type SecurityReviewPort,
} from '../ports/security-review'
import { useWorkspaceStore } from '../stores/workspace'

const props = defineProps<{
  port?: SecurityReviewPort
}>()

const workspace = useWorkspaceStore()
const port = computed(() => props.port ?? tauriSecurityReviewPort)
const vault = ref<SafeVaultMetadataView | null>(null)
const busy = ref(false)
const errorCode = ref<string | null>(null)
const receiptNotice = ref<string | null>(null)
const modalOpen = ref(false)
const secretId = ref('')
const secretValue = ref('')

function clearModalBuffer() {
  secretId.value = ''
  secretValue.value = ''
  modalOpen.value = false
}

function closeModal() {
  clearModalBuffer()
}

function openModal() {
  errorCode.value = null
  receiptNotice.value = null
  modalOpen.value = true
}

async function loadVault() {
  const current = workspace.workspace
  if (!current) {
    vault.value = null
    clearModalBuffer()
    return
  }
  const workspaceId = current.workspaceId
  busy.value = true
  errorCode.value = null
  const result = await port.value.loadVaultMetadata(workspaceId)
  if (workspace.workspace?.workspaceId !== workspaceId) {
    return
  }
  busy.value = false
  if (result.kind === 'error') {
    vault.value = null
    errorCode.value = result.code
    return
  }
  vault.value = result.vault
}

async function submitSecret() {
  const current = workspace.workspace
  if (!current || busy.value || !modalOpen.value) {
    return
  }
  const workspaceId = current.workspaceId
  const id = secretId.value
  const value = secretValue.value
  busy.value = true
  errorCode.value = null
  try {
    const result = await port.value.setVaultSecret({
      workspaceId,
      secretId: id,
      secretValue: value,
    })
    if (workspace.workspace?.workspaceId !== workspaceId) {
      return
    }
    if (result.kind === 'error') {
      errorCode.value = result.code
      return
    }
    receiptNotice.value = `已写入 ${result.receipt.id}。响应未包含值；请刷新元数据确认引用关系。`
    await loadVault()
  } finally {
    // 不论成功、失败、切换工作区或 IPC 异常，modal buffer 都不能残留在组件状态中。
    busy.value = false
    clearModalBuffer()
  }
}

watch(
  () => workspace.workspace?.workspaceId,
  () => {
    void loadVault()
  },
  { immediate: true },
)
</script>

<template>
  <section
    class="review-panel security-panel"
    aria-labelledby="vault-title"
  >
    <p class="route-panel__eyebrow">
      Metadata-only secrets
    </p>
    <h2 id="vault-title">
      保险库
    </h2>
    <p class="review-panel__copy">
      这里从不读取或默认显示 Vault 值。列表只含 Secret ID、更新时间和引用资源；写入值仅停留在单次 modal buffer，提交或关闭后立即清空。
    </p>

    <p
      v-if="!workspace.workspace"
      class="review-empty"
      role="status"
    >
      先连接一个工作区，才能读取 Vault 元数据。
    </p>
    <p
      v-else-if="busy && !vault"
      class="review-empty"
      role="status"
    >
      正在读取 Vault 元数据；没有结果不代表 Vault 为空。
    </p>
    <p
      v-if="errorCode"
      class="error-boundary"
      role="alert"
    >
      无法读取或写入 Vault。错误码：{{ errorCode }}
    </p>
    <p
      v-if="receiptNotice"
      class="review-success"
      role="status"
    >
      {{ receiptNotice }}
    </p>

    <template v-if="workspace.workspace">
      <p
        v-if="vault?.index_missing"
        class="review-warning"
        data-vault-index-missing
      >
        当前头快照缺失 Vault 索引；空列表表示“读不到”，不是“没有秘密”。请勿据此删除或重建值。
      </p>
      <div class="review-section-heading">
        <h3>Secret metadata · {{ vault?.entries.length ?? 0 }} 项</h3>
        <div class="review-actions">
          <button
            class="preference-button"
            :disabled="busy"
            type="button"
            @click="loadVault"
          >
            刷新
          </button>
          <button
            class="primary-action"
            data-action="open-vault-set-modal"
            :disabled="busy"
            type="button"
            @click="openModal"
          >
            设置 Secret
          </button>
        </div>
      </div>
      <p
        v-if="vault && !vault.index_missing && !vault.entries.length"
        class="review-empty"
        data-vault-empty
      >
        当前 Vault 中没有可见的 Secret metadata。
      </p>
      <ul
        v-if="vault?.entries.length"
        class="security-list security-list--cards"
      >
        <li
          v-for="entry in vault.entries"
          :key="entry.id"
          class="security-card"
        >
          <code>{{ entry.id }}</code>
          <dl class="plan-action__facts">
            <div>
              <dt>更新时间</dt>
              <dd>{{ new Date(entry.updated_at_unix_ms).toLocaleString('zh-CN') }}</dd>
            </div>
            <div>
              <dt>引用者</dt>
              <dd>{{ entry.referenced_by.length ? entry.referenced_by.join('、') : '暂无引用' }}</dd>
            </div>
          </dl>
        </li>
      </ul>
    </template>

    <form
      v-if="modalOpen"
      class="secret-modal"
      aria-labelledby="vault-set-title"
      @submit.prevent="submitSecret"
    >
      <div class="secret-modal__heading">
        <h3 id="vault-set-title">
          单次设置 Secret
        </h3>
        <button
          class="preference-button"
          data-action="close-vault-set-modal"
          type="button"
          @click="closeModal"
        >
          关闭并清空
        </button>
      </div>
      <label class="onboarding-field">
        <span>Secret ID</span>
        <input
          v-model="secretId"
          autocomplete="off"
          data-vault-secret-id
          maxlength="128"
          required
        >
      </label>
      <label class="onboarding-field">
        <span>Secret 值</span>
        <input
          v-model="secretValue"
          autocomplete="new-password"
          data-vault-secret-value
          maxlength="1048576"
          required
          type="password"
        >
      </label>
      <p class="security-muted">
        值不会写进 Pinia、日志、回执或页面列表。这里不提供复制全部 Vault，也不提供默认 reveal。
      </p>
      <div class="review-actions">
        <button
          class="preference-button"
          :disabled="busy"
          type="button"
          @click="closeModal"
        >
          取消
        </button>
        <button
          class="primary-action"
          data-action="submit-vault-secret"
          :disabled="busy || !secretId || !secretValue"
          type="submit"
        >
          写入一次性 buffer
        </button>
      </div>
    </form>
  </section>
</template>
