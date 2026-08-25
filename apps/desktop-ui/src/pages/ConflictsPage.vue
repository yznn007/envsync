<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import {
  tauriSyncReviewPort,
  type SafeConflictDetailView,
  type SafeConflictView,
  type SyncReviewPort,
} from '../ports/sync-review'
import { useWorkspaceStore } from '../stores/workspace'

const props = defineProps<{
  port?: SyncReviewPort
}>()

const workspace = useWorkspaceStore()
const port = computed(() => props.port ?? tauriSyncReviewPort)
const conflicts = ref<SafeConflictView[]>([])
const selected = ref<SafeConflictDetailView | null>(null)
const busy = ref(false)
const errorCode = ref<string | null>(null)
const manualContent = ref('')
const resolutionNotice = ref<string | null>(null)

const choiceLabel = {
  ours: '采用本地版本',
  theirs: '采用远端版本',
  manual: '提交手动文本',
  delete: '确认删除资源',
} as const

function resetSelection() {
  selected.value = null
  manualContent.value = ''
  resolutionNotice.value = null
}

async function loadConflicts() {
  const current = workspace.workspace
  if (!current) {
    conflicts.value = []
    resetSelection()
    return
  }
  const workspaceId = current.workspaceId
  busy.value = true
  errorCode.value = null
  const result = await port.value.listConflicts(workspaceId)
  if (workspace.workspace?.workspaceId !== workspaceId) {
    return
  }
  busy.value = false
  if (result.kind === 'error') {
    conflicts.value = []
    resetSelection()
    errorCode.value = result.code
    return
  }
  conflicts.value = result.conflicts
  if (selected.value && !conflicts.value.some((conflict) => conflict.id === selected.value?.conflict.id)) {
    resetSelection()
  }
}

async function selectConflict(conflict: SafeConflictView) {
  const current = workspace.workspace
  if (!current) {
    return
  }
  const workspaceId = current.workspaceId
  busy.value = true
  errorCode.value = null
  resolutionNotice.value = null
  const result = await port.value.showConflict(workspaceId, conflict.id)
  if (workspace.workspace?.workspaceId !== workspaceId) {
    return
  }
  busy.value = false
  if (result.kind === 'error') {
    errorCode.value = result.code
    return
  }
  selected.value = result.conflict
  manualContent.value = ''
}

async function resolve(choice: keyof typeof choiceLabel) {
  const current = workspace.workspace
  const detail = selected.value
  if (!current || !detail || busy.value) {
    return
  }
  const workspaceId = current.workspaceId
  busy.value = true
  errorCode.value = null
  const result = await port.value.resolveConflict({
    workspaceId,
    conflictId: detail.conflict.id,
    choice,
    ...(choice === 'manual' ? { manualContent: manualContent.value } : {}),
  })
  if (workspace.workspace?.workspaceId !== workspaceId) {
    return
  }
  busy.value = false
  if (result.kind === 'error') {
    errorCode.value = result.code
    return
  }
  // 冲突索引已经变更，但此时没有重新 merge、更没有同步；明确避免向用户暗示成功收敛。
  resolutionNotice.value = `已保存 ${choiceLabel[result.resolution.choice]}。请重新合并并生成新计划；同步尚未执行。`
  manualContent.value = ''
  await loadConflicts()
}

watch(
  () => workspace.workspace?.workspaceId,
  () => {
    void loadConflicts()
  },
  { immediate: true },
)
</script>

<template>
  <section
    class="review-panel conflicts-panel"
    aria-labelledby="conflicts-title"
  >
    <p class="route-panel__eyebrow">
      显式冲突裁决
    </p>
    <h2 id="conflicts-title">
      冲突
    </h2>
    <p class="review-panel__copy">
      EnvSync 不会把冲突标记写入用户文件。这里不显示三侧正文或 Blob；选择会先写入本地冲突索引，之后仍需重新合并和审核。
    </p>

    <p
      v-if="!workspace.workspace"
      class="review-empty"
      role="status"
    >
      先连接一个工作区，才能读取开放冲突。
    </p>
    <p
      v-else-if="busy && !conflicts.length && !selected"
      class="review-empty"
      role="status"
    >
      正在读取开放冲突；没有数据不代表没有冲突。
    </p>
    <p
      v-if="errorCode"
      class="error-boundary"
      role="alert"
    >
      无法完成冲突操作。错误码：{{ errorCode }}
    </p>
    <p
      v-if="resolutionNotice"
      class="review-warning"
      data-resolution-notice
      role="status"
    >
      {{ resolutionNotice }}
    </p>

    <div
      v-if="workspace.workspace"
      class="conflicts-layout"
    >
      <section aria-labelledby="open-conflicts-title">
        <div class="review-section-heading">
          <h3 id="open-conflicts-title">
            开放冲突 · {{ conflicts.length }} 项
          </h3>
          <button
            class="preference-button"
            :disabled="busy"
            type="button"
            @click="loadConflicts"
          >
            刷新
          </button>
        </div>
        <p
          v-if="!conflicts.length && !busy"
          class="review-empty"
          data-conflicts-empty
        >
          当前没有开放冲突。
        </p>
        <ul
          v-else
          class="conflict-list"
        >
          <li
            v-for="conflict in conflicts"
            :key="conflict.id"
          >
            <button
              class="conflict-list__item"
              :aria-pressed="selected?.conflict.id === conflict.id"
              type="button"
              @click="selectConflict(conflict)"
            >
              <code>{{ conflict.resource }}</code>
              <span>{{ conflict.kind }}</span>
            </button>
          </li>
        </ul>
      </section>

      <section
        v-if="selected"
        class="conflict-resolution"
        :aria-labelledby="`conflict-${selected.conflict.id}`"
      >
        <h3 :id="`conflict-${selected.conflict.id}`">
          裁决 {{ selected.conflict.resource }}
        </h3>
        <dl class="review-facts">
          <div>
            <dt>冲突类别</dt>
            <dd>{{ selected.conflict.kind }}</dd>
          </div>
          <div>
            <dt>资源模式</dt>
            <dd>{{ selected.mode }}</dd>
          </div>
          <div>
            <dt>结构化格式</dt>
            <dd>{{ selected.structured_format ?? '文本' }}</dd>
          </div>
        </dl>
        <p class="review-warning">
          三侧内容保持在 core 中；“采用本地/远端”不会向 WebView 传递文件正文。
        </p>
        <div class="review-actions">
          <button
            class="preference-button"
            :disabled="busy || !selected.ours_available"
            type="button"
            @click="resolve('ours')"
          >
            {{ choiceLabel.ours }}
          </button>
          <button
            class="preference-button"
            :disabled="busy || !selected.theirs_available"
            type="button"
            @click="resolve('theirs')"
          >
            {{ choiceLabel.theirs }}
          </button>
          <button
            class="danger-action"
            :disabled="busy"
            type="button"
            @click="resolve('delete')"
          >
            {{ choiceLabel.delete }}
          </button>
        </div>

        <form
          v-if="selected.manual_allowed"
          class="manual-resolution"
          @submit.prevent="resolve('manual')"
        >
          <label :for="`manual-${selected.conflict.id}`">
            手动文本裁决（仅本次提交，最多 {{ selected.manual_max_bytes }} B）
          </label>
          <textarea
            :id="`manual-${selected.conflict.id}`"
            v-model="manualContent"
            :maxlength="selected.manual_max_bytes"
            autocomplete="off"
            data-manual-resolution
            spellcheck="false"
          />
          <p>
            提交前由 core 重新检查字节上限、非秘密策略和 JSON/YAML/TOML/INI 语法；文本不会写入全局 store。
          </p>
          <button
            class="primary-action"
            :disabled="busy"
            type="submit"
          >
            {{ choiceLabel.manual }}
          </button>
        </form>
        <p
          v-else
          class="review-warning"
          data-manual-unavailable
        >
          此资源是秘密、二进制或不支持的模式，不能通过手动编辑器提交内容。
        </p>
      </section>
    </div>
  </section>
</template>
