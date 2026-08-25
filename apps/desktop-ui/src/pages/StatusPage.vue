<script setup lang="ts">
import { computed } from 'vue'

import { type WorkspaceStateName, useWorkspaceStore } from '../stores/workspace'

const workspace = useWorkspaceStore()
const status = computed(() => workspace.status)
const lastErrorCode = computed(() => workspace.lastErrorCode)
const offline = computed(
  () => status.value?.state === 'backend_unreachable' || status.value?.backend_reachable === false,
)

const guidance: Record<WorkspaceStateName, { title: string; nextAction: string }> = {
  clean: {
    title: '同步已完成',
    nextAction: '继续观察状态，新的本地变更会在下次计划中出现。',
  },
  drifted: {
    title: '发现待同步变更',
    nextAction: '查看变更并生成新的审核计划。',
  },
  conflicted: {
    title: '存在待解决冲突',
    nextAction: '先在冲突页面完成裁决，再继续同步。',
  },
  published_not_converged: {
    title: '远端已发布，本机尚未收敛',
    nextAction: '查看恢复建议，确认后继续收敛或创建回滚计划。',
  },
  backend_unreachable: {
    title: '后端不可达',
    nextAction: '检查网络与受控凭据后刷新状态；不要把本地缓存当作已同步。',
  },
}

const currentGuidance = computed(() => {
  if (!status.value) {
    return null
  }
  return offline.value ? guidance.backend_unreachable : guidance[status.value.state]
})

const driftedResources = computed(
  () => status.value?.resources.filter((resource) => resource.needs_action) ?? [],
)

const emit = defineEmits<{
  refreshStatus: []
}>()

function formatTimestamp(timestamp: number | null) {
  if (timestamp === null) {
    return '尚无已知远端状态'
  }
  return new Intl.DateTimeFormat('zh-CN', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(timestamp))
}
</script>

<template>
  <section
    class="status-panel"
    aria-labelledby="status-title"
  >
    <p class="route-panel__eyebrow">
      经审核的工作区状态
    </p>
    <h2 id="status-title">
      工作区状态
    </h2>

    <p
      v-if="!status"
      class="status-panel__empty"
      role="status"
    >
      正在等待受限宿主提供状态。不会把缺失数据解释为已同步。
    </p>
    <p
      v-if="lastErrorCode"
      class="error-boundary"
      role="alert"
    >
      无法取得工作区状态。错误码：{{ lastErrorCode }}
    </p>

    <template v-if="status">
      <div
        class="status-panel__summary"
        :data-status-state="status.state"
      >
        <div>
          <p
            class="status-panel__connection"
            data-connection-state
          >
            {{ currentGuidance?.title }}
          </p>
          <p
            class="status-panel__next-action"
            data-next-action
          >
            下一步：{{ currentGuidance?.nextAction }}
          </p>
        </div>
        <span
          class="status-ledger"
          :class="{ 'status-ledger--warning': offline }"
        >
          {{ offline ? '离线' : '已连接' }}
        </span>
      </div>

      <dl class="status-facts">
        <div>
          <dt>后端</dt>
          <dd>{{ status.workspace.backend_kind }}</dd>
        </div>
        <div>
          <dt>设备</dt>
          <dd>{{ status.workspace.device_id }}</dd>
        </div>
        <div>
          <dt>Head</dt>
          <dd>{{ status.head ?? '尚未发布快照' }}</dd>
        </div>
        <div>
          <dt>Revision</dt>
          <dd>{{ status.revision }}</dd>
        </div>
      </dl>

      <p
        v-if="offline"
        class="status-panel__last-known"
        data-last-known-state
      >
        最后已知状态：{{ formatTimestamp(status.last_known_revision_at_unix_ms) }}
      </p>

      <div class="status-panel__counts">
        <p>待应用动作：{{ status.pending_actions }}</p>
        <p>存在漂移资源：{{ driftedResources.length }}</p>
        <p>开放冲突：{{ status.open_conflicts }}</p>
        <p>未完成操作：{{ status.unfinished_operations.length }}</p>
      </div>

      <section
        v-if="driftedResources.length"
        aria-labelledby="drifted-resources-title"
      >
        <h3 id="drifted-resources-title">
          待处理资源
        </h3>
        <ul class="status-list">
          <li
            v-for="resource in driftedResources"
            :key="resource.resource"
          >
            <code>{{ resource.resource }}</code> · {{ resource.observed }}
          </li>
        </ul>
      </section>

      <section
        v-if="status.unfinished_operations.length"
        aria-labelledby="unfinished-operations-title"
      >
        <h3 id="unfinished-operations-title">
          未完成操作
        </h3>
        <ul class="status-list">
          <li
            v-for="operation in status.unfinished_operations"
            :key="operation.operation"
          >
            <code>{{ operation.operation }}</code> · {{ operation.state }}
          </li>
        </ul>
      </section>

      <section
        v-if="status.diagnostics.length"
        aria-labelledby="security-notices-title"
      >
        <h3 id="security-notices-title">
          安全通知
        </h3>
        <ul class="status-list">
          <li
            v-for="diagnostic in status.diagnostics"
            :key="`${diagnostic.code}:${diagnostic.resource ?? ''}`"
          >
            {{ diagnostic.severity }} · {{ diagnostic.code }}
          </li>
        </ul>
      </section>

      <button
        class="preference-button"
        data-action="refresh-status"
        type="button"
        @click="emit('refreshStatus')"
      >
        刷新状态
      </button>
    </template>
  </section>
</template>
