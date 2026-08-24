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

async function loadVault() {
  const current = workspace.workspace
  if (!current) {
    vault.value = null
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
      这里从不读取、显示或接收 Vault 值。列表只含 Secret ID、更新时间和引用资源；桌面端不会把秘密交给 WebView IPC。
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
      无法读取 Vault 元数据。错误码：{{ errorCode }}
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
        <button
          class="preference-button"
          :disabled="busy"
          type="button"
          @click="loadVault"
        >
          刷新
        </button>
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

    <section class="security-guidance">
      <h3>安全写入</h3>
      <p>
        设置或轮换值请在受信任终端使用 <code>envsync vault set &lt;SECRET-ID&gt; --prompt</code>。CLI 使用有界隐藏输入；此桌面页面不提供值输入、复制全部或默认 reveal。
      </p>
    </section>
  </section>
</template>
