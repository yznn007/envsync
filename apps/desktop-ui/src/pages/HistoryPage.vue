<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import {
  tauriSyncReviewPort,
  type SafeOperationDetailView,
  type SafeOperationView,
  type SafeRollbackReviewView,
  type SyncReviewPort,
} from '../ports/sync-review'
import { useWorkspaceStore } from '../stores/workspace'

const props = defineProps<{
  port?: SyncReviewPort
}>()

const workspace = useWorkspaceStore()
const port = computed(() => props.port ?? tauriSyncReviewPort)
const operations = ref<SafeOperationView[]>([])
const selected = ref<SafeOperationDetailView | null>(null)
const rollbackReview = ref<SafeRollbackReviewView | null>(null)
const confirmedActions = ref<Set<number>>(new Set())
const busy = ref(false)
const errorCode = ref<string | null>(null)
const notice = ref<string | null>(null)

const reviewComplete = computed(() => (
  Boolean(rollbackReview.value)
  && rollbackReview.value?.actions.every((action) => confirmedActions.value.has(action.ordinal))
  && !busy.value
))

function formatTimestamp(timestamp: number) {
  return new Intl.DateTimeFormat('zh-CN', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(timestamp))
}

function resetDetail() {
  selected.value = null
  rollbackReview.value = null
  confirmedActions.value = new Set()
  notice.value = null
}

async function loadHistory() {
  const current = workspace.workspace
  if (!current) {
    operations.value = []
    resetDetail()
    return
  }
  const workspaceId = current.workspaceId
  busy.value = true
  errorCode.value = null
  const result = await port.value.listOperations(workspaceId)
  if (workspace.workspace?.workspaceId !== workspaceId) {
    return
  }
  busy.value = false
  if (result.kind === 'error') {
    operations.value = []
    resetDetail()
    errorCode.value = result.code
    return
  }
  operations.value = result.operations
  if (selected.value && !operations.value.some((item) => item.operation === selected.value?.operation.operation)) {
    resetDetail()
  }
}

async function selectOperation(operation: SafeOperationView) {
  const current = workspace.workspace
  if (!current) {
    return
  }
  const workspaceId = current.workspaceId
  busy.value = true
  errorCode.value = null
  notice.value = null
  rollbackReview.value = null
  confirmedActions.value = new Set()
  const result = await port.value.showOperation(workspaceId, operation.operation)
  if (workspace.workspace?.workspaceId !== workspaceId) {
    return
  }
  busy.value = false
  if (result.kind === 'error') {
    errorCode.value = result.code
    return
  }
  selected.value = result.operation
}

async function createRollbackReview() {
  const current = workspace.workspace
  const detail = selected.value
  if (!current || !detail || busy.value) {
    return
  }
  const workspaceId = current.workspaceId
  busy.value = true
  errorCode.value = null
  notice.value = null
  const result = await port.value.reviewRollback(workspaceId, detail.operation.operation)
  if (workspace.workspace?.workspaceId !== workspaceId || selected.value?.operation.operation !== detail.operation.operation) {
    return
  }
  busy.value = false
  if (result.kind === 'error') {
    errorCode.value = result.code
    return
  }
  rollbackReview.value = result.review
  confirmedActions.value = new Set()
}

function setConfirmation(ordinal: number, checked: boolean) {
  const next = new Set(confirmedActions.value)
  if (checked) {
    next.add(ordinal)
  } else {
    next.delete(ordinal)
  }
  confirmedActions.value = next
}

async function executeRollback() {
  const current = workspace.workspace
  const review = rollbackReview.value
  if (!current || !review || !reviewComplete.value) {
    return
  }
  const workspaceId = current.workspaceId
  busy.value = true
  errorCode.value = null
  const result = await port.value.executeRollback({
    workspaceId,
    operationId: review.operation.operation,
    reviewToken: review.review_token,
    confirmations: review.actions.map((action) => action.ordinal),
  })
  if (workspace.workspace?.workspaceId !== workspaceId) {
    return
  }
  busy.value = false
  if (result.kind === 'error') {
    errorCode.value = result.code
    rollbackReview.value = null
    confirmedActions.value = new Set()
    return
  }
  notice.value = `回滚已执行，operation 状态为 ${result.operation.state}。请刷新历史确认最终收据状态。`
  rollbackReview.value = null
  confirmedActions.value = new Set()
  await loadHistory()
  await selectOperation(result.operation)
}

watch(
  () => workspace.workspace?.workspaceId,
  () => {
    void loadHistory()
  },
  { immediate: true },
)
</script>

<template>
  <section
    class="review-panel history-panel"
    aria-labelledby="history-title"
  >
    <p class="route-panel__eyebrow">
      Journal 与可恢复操作
    </p>
    <h2 id="history-title">
      历史
    </h2>
    <p class="review-panel__copy">
      状态、失败点和收据均来自本地 journal。备份路径、内容摘要和错误正文不会显示；任何回滚都必须先生成逆向计划并逐项审核。
    </p>

    <p
      v-if="!workspace.workspace"
      class="review-empty"
      role="status"
    >
      先连接一个工作区，才可以读取操作历史。
    </p>
    <p
      v-if="errorCode"
      class="error-boundary"
      role="alert"
    >
      无法读取或恢复操作。错误码：{{ errorCode }}
    </p>
    <p
      v-if="notice"
      class="review-success"
      role="status"
    >
      {{ notice }}
    </p>

    <div
      v-if="workspace.workspace"
      class="history-layout"
    >
      <section aria-labelledby="operations-title">
        <div class="review-section-heading">
          <h3 id="operations-title">
            操作 · {{ operations.length }} 项
          </h3>
          <button
            class="preference-button"
            :disabled="busy"
            type="button"
            @click="loadHistory"
          >
            刷新
          </button>
        </div>
        <p
          v-if="!operations.length && !busy"
          class="review-empty"
          data-history-empty
        >
          当前 journal 中还没有已登记操作。
        </p>
        <ul
          v-else
          class="history-list"
        >
          <li
            v-for="operation in operations"
            :key="operation.operation"
          >
            <button
              class="history-list__item"
              :aria-pressed="selected?.operation.operation === operation.operation"
              type="button"
              @click="selectOperation(operation)"
            >
              <code>{{ operation.operation }}</code>
              <span>{{ operation.state }}</span>
              <time :datetime="new Date(operation.updated_at_unix_ms).toISOString()">
                {{ formatTimestamp(operation.updated_at_unix_ms) }}
              </time>
            </button>
          </li>
        </ul>
      </section>

      <section
        v-if="selected"
        class="operation-detail"
        :aria-labelledby="`operation-${selected.operation.operation}`"
      >
        <h3 :id="`operation-${selected.operation.operation}`">
          操作详情
        </h3>
        <dl class="review-facts">
          <div>
            <dt>状态机</dt>
            <dd>{{ selected.operation.state }}</dd>
          </div>
          <div>
            <dt>Revision</dt>
            <dd>{{ selected.operation.revision }}</dd>
          </div>
          <div>
            <dt>失败点</dt>
            <dd>{{ selected.operation.error_code ?? '无记录错误' }}</dd>
          </div>
          <div>
            <dt>恢复操作</dt>
            <dd>{{ selected.rollback_available ? '可生成逆向计划审核' : '当前不可回滚' }}</dd>
          </div>
        </dl>

        <section aria-labelledby="operation-actions-title">
          <h4 id="operation-actions-title">
            动作进度
          </h4>
          <ul class="operation-list">
            <li
              v-for="action in selected.actions"
              :key="action.ordinal"
            >
              #{{ action.ordinal }} · <code>{{ action.resource }}</code> · {{ action.kind }} · {{ action.state }}
              <span v-if="action.error_code"> · {{ action.error_code }}</span>
            </li>
          </ul>
        </section>

        <section aria-labelledby="operation-receipts-title">
          <h4 id="operation-receipts-title">
            回滚收据 · {{ selected.receipts.length }} 项
          </h4>
          <ul class="operation-list">
            <li
              v-for="receipt in selected.receipts"
              :key="receipt.ordinal"
            >
              #{{ receipt.ordinal }} · <code>{{ receipt.resource }}</code> · {{ receipt.guarantee }}
            </li>
          </ul>
        </section>

        <button
          v-if="selected.rollback_available && !rollbackReview"
          class="danger-action"
          :disabled="busy"
          data-action="review-rollback"
          type="button"
          @click="createRollbackReview"
        >
          生成逆向计划并审核
        </button>

        <section
          v-if="rollbackReview"
          class="rollback-review"
          aria-labelledby="rollback-review-title"
        >
          <h4 id="rollback-review-title">
            逆向计划审核
          </h4>
          <p class="review-warning">
            将按收据逆序恢复。每项都必须确认；执行时 core 仍会重新验证现场摘要并拒绝外部修改后的错误回滚。
          </p>
          <ul class="rollback-review__actions">
            <li
              v-for="action in rollbackReview.actions"
              :key="action.ordinal"
            >
              <label class="review-confirmation">
                <input
                  :checked="confirmedActions.has(action.ordinal)"
                  data-rollback-confirmation
                  type="checkbox"
                  @change="setConfirmation(action.ordinal, ($event.target as HTMLInputElement).checked)"
                >
                #{{ action.ordinal }} · <code>{{ action.resource }}</code> · {{ action.original_kind }} → 回滚（{{ action.guarantee }}）
              </label>
            </li>
          </ul>
          <div class="review-actions">
            <button
              class="preference-button"
              :disabled="busy"
              type="button"
              @click="rollbackReview = null"
            >
              取消审核
            </button>
            <button
              class="danger-action"
              data-action="execute-rollback"
              :disabled="!reviewComplete"
              type="button"
              @click="executeRollback"
            >
              执行已审核的回滚
            </button>
          </div>
        </section>
      </section>
    </div>
  </section>
</template>
