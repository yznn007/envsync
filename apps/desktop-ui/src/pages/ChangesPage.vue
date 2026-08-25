<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import DiffViewer from '../components/DiffViewer.vue'
import {
  tauriSyncReviewPort,
  type SafePlanAction,
  type SafePlanView,
  type SyncReviewPort,
} from '../ports/sync-review'
import { useWorkspaceStore } from '../stores/workspace'

const props = defineProps<{
  port?: SyncReviewPort
}>()

const workspace = useWorkspaceStore()
const port = computed(() => props.port ?? tauriSyncReviewPort)
const plan = ref<SafePlanView | null>(null)
const diffs = ref<ReturnType<typeof emptyDiffs>>(emptyDiffs())
const errorCode = ref<string | null>(null)
const busy = ref(false)
const queuedOperation = ref<string | null>(null)
const confirmedHighRisk = ref<Set<string>>(new Set())

function emptyDiffs() {
  return [] as import('../ports/sync-review').SafeDiffView[]
}

const riskGroups = computed(() => {
  const groups: Record<'high' | 'medium' | 'low', SafePlanAction[]> = {
    high: [],
    medium: [],
    low: [],
  }
  for (const action of plan.value?.actions ?? []) {
    groups[action.risk].push(action)
  }
  return groups
})

const highRiskActions = computed(() => riskGroups.value.high)
const readyToApply = computed(() => (
  Boolean(plan.value)
  && highRiskActions.value.every((action) => confirmedHighRisk.value.has(actionKey(action)))
  && !busy.value
))

function actionKey(action: SafePlanAction) {
  return `${action.resource}:${action.kind}:${action.target}`
}

function riskLabel(risk: SafePlanAction['risk']) {
  return { high: '高风险', medium: '中风险', low: '低风险' }[risk]
}

function setHighRiskConfirmation(action: SafePlanAction, checked: boolean) {
  const next = new Set(confirmedHighRisk.value)
  if (checked) {
    next.add(actionKey(action))
  } else {
    next.delete(actionKey(action))
  }
  confirmedHighRisk.value = next
}

function resetReview() {
  plan.value = null
  diffs.value = emptyDiffs()
  confirmedHighRisk.value = new Set()
  queuedOperation.value = null
}

async function loadPlan() {
  const current = workspace.workspace
  if (!current) {
    resetReview()
    return
  }
  const workspaceId = current.workspaceId
  busy.value = true
  errorCode.value = null
  queuedOperation.value = null
  const planResult = await port.value.buildPlan(workspaceId)
  if (workspace.workspace?.workspaceId !== workspaceId) {
    return
  }
  if (planResult.kind === 'error') {
    resetReview()
    errorCode.value = planResult.code
    busy.value = false
    return
  }
  plan.value = planResult.plan
  confirmedHighRisk.value = new Set()
  const diffResult = await port.value.loadDiff(workspaceId, planResult.plan.id)
  if (workspace.workspace?.workspaceId !== workspaceId || plan.value?.id !== planResult.plan.id) {
    return
  }
  if (diffResult.kind === 'error') {
    diffs.value = emptyDiffs()
    errorCode.value = diffResult.code
    busy.value = false
    return
  }
  diffs.value = diffResult.diff.diffs
  busy.value = false
}

async function applyCurrentPlan() {
  const current = workspace.workspace
  const reviewedPlan = plan.value
  if (!current || !reviewedPlan || !readyToApply.value) {
    return
  }
  const workspaceId = current.workspaceId
  const planId = reviewedPlan.id
  busy.value = true
  errorCode.value = null
  const result = await port.value.applyPlan(workspaceId, planId)
  if (workspace.workspace?.workspaceId !== workspaceId || plan.value?.id !== planId) {
    return
  }
  busy.value = false
  if (result.kind === 'error') {
    errorCode.value = result.code
    if (result.code === 'plan.stale') {
      resetReview()
      await loadPlan()
    }
    return
  }
  queuedOperation.value = result.operation
}

watch(
  () => workspace.workspace?.workspaceId,
  () => {
    void loadPlan()
  },
  { immediate: true },
)
</script>

<template>
  <section
    class="review-panel"
    aria-labelledby="changes-title"
  >
    <p class="route-panel__eyebrow">
      不可变计划审核
    </p>
    <h2 id="changes-title">
      变更
    </h2>
    <p class="review-panel__copy">
      生成计划后，所有写入都绑定到当前 Plan ID。文件在审核期间发生变化时，core 会拒绝旧计划并要求重新审核。
    </p>

    <p
      v-if="!workspace.workspace"
      class="review-empty"
      role="status"
    >
      先连接一个工作区，才可以生成受控同步计划。
    </p>
    <p
      v-else-if="busy && !plan"
      class="review-empty"
      role="status"
    >
      正在生成并读取当前计划；不会把缺失结果解释为无变更。
    </p>
    <p
      v-if="errorCode"
      class="error-boundary"
      role="alert"
    >
      无法完成计划审核。错误码：{{ errorCode }}
    </p>

    <template v-if="plan">
      <dl class="review-facts">
        <div>
          <dt>Plan ID</dt>
          <dd><code>{{ plan.id }}</code></dd>
        </div>
        <div>
          <dt>Revision</dt>
          <dd>{{ plan.base_revision }} → {{ plan.next_revision }}</dd>
        </div>
        <div>
          <dt>动作</dt>
          <dd>{{ plan.actions.length }}</dd>
        </div>
      </dl>

      <section
        v-for="risk in ['high', 'medium', 'low'] as const"
        :key="risk"
        class="plan-risk-group"
        :data-risk-group="risk"
        :aria-labelledby="`risk-${risk}-title`"
      >
        <h3 :id="`risk-${risk}-title`">
          {{ riskLabel(risk) }} · {{ riskGroups[risk].length }} 项
        </h3>
        <p
          v-if="!riskGroups[risk].length"
          class="review-empty"
        >
          没有此风险等级的动作。
        </p>
        <ul
          v-else
          class="plan-action-list"
        >
          <li
            v-for="action in riskGroups[risk]"
            :key="actionKey(action)"
            class="plan-action"
          >
            <div>
              <code>{{ action.resource }}</code>
              <span class="risk-tag">{{ action.kind }}</span>
            </div>
            <dl class="plan-action__facts">
              <div>
                <dt>来源</dt>
                <dd>{{ action.resource }}</dd>
              </div>
              <div>
                <dt>目标</dt>
                <dd><code>{{ action.target }}</code></dd>
              </div>
              <div>
                <dt>备份</dt>
                <dd>{{ action.backup }}</dd>
              </div>
              <div>
                <dt>回滚保证</dt>
                <dd>{{ action.rollback }}</dd>
              </div>
            </dl>
            <label
              v-if="risk === 'high'"
              class="review-confirmation"
            >
              <input
                :checked="confirmedHighRisk.has(actionKey(action))"
                data-high-risk-confirmation
                type="checkbox"
                @change="setHighRiskConfirmation(action, ($event.target as HTMLInputElement).checked)"
              >
              我已逐项审核此高风险动作
            </label>
          </li>
        </ul>
      </section>

      <section aria-labelledby="diff-title">
        <h3 id="diff-title">
          差异摘要
        </h3>
        <DiffViewer :diffs="diffs" />
      </section>

      <p
        v-if="queuedOperation"
        class="review-success"
        data-apply-queued
        role="status"
      >
        已提交当前 Plan ID，操作 {{ queuedOperation }} 正在受控执行。请在历史页查看终态；排队不等于同步成功。
      </p>
      <div class="review-actions">
        <button
          class="preference-button"
          :disabled="busy"
          type="button"
          @click="loadPlan"
        >
          重新生成计划
        </button>
        <button
          class="primary-action"
          data-action="apply-current-plan"
          :disabled="!readyToApply"
          type="button"
          @click="applyCurrentPlan"
        >
          应用当前 Plan ID
        </button>
      </div>
    </template>
  </section>
</template>
