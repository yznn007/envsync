<script setup lang="ts">
import { computed, ref, watch } from 'vue'

import {
  tauriSecurityReviewPort,
  type SafeDeviceListView,
  type SecurityReviewPort,
} from '../ports/security-review'
import { useWorkspaceStore } from '../stores/workspace'

const props = defineProps<{
  port?: SecurityReviewPort
}>()

const workspace = useWorkspaceStore()
const port = computed(() => props.port ?? tauriSecurityReviewPort)
const devices = ref<SafeDeviceListView | null>(null)
const busy = ref(false)
const errorCode = ref<string | null>(null)
const revokeCandidate = ref<SafeDeviceListView['devices'][number] | null>(null)
const confirmation = ref('')
const notice = ref<string | null>(null)

const revokeReady = computed(() => (
  Boolean(revokeCandidate.value)
  && confirmation.value === revokeCandidate.value?.device
  && !busy.value
))

function resetRevoke() {
  revokeCandidate.value = null
  confirmation.value = ''
}

async function loadDevices() {
  const current = workspace.workspace
  if (!current) {
    devices.value = null
    resetRevoke()
    return
  }
  const workspaceId = current.workspaceId
  busy.value = true
  errorCode.value = null
  const result = await port.value.listDevices(workspaceId)
  if (workspace.workspace?.workspaceId !== workspaceId) {
    return
  }
  busy.value = false
  if (result.kind === 'error') {
    devices.value = null
    errorCode.value = result.code
    return
  }
  devices.value = result.devices
}

function beginRevoke(device: SafeDeviceListView['devices'][number]) {
  if (device.is_self) {
    return
  }
  notice.value = null
  errorCode.value = null
  revokeCandidate.value = device
  confirmation.value = ''
}

async function revoke() {
  const current = workspace.workspace
  const candidate = revokeCandidate.value
  if (!current || !candidate || !revokeReady.value) {
    return
  }
  const workspaceId = current.workspaceId
  busy.value = true
  errorCode.value = null
  try {
    const result = await port.value.revokeDevice({
      workspaceId,
      deviceId: candidate.device,
      confirmation: confirmation.value,
    })
    if (workspace.workspace?.workspaceId !== workspaceId) {
      return
    }
    if (result.kind === 'error') {
      errorCode.value = result.code
      return
    }
    notice.value = `已撤销 ${result.revocation.revoked}，密钥纪元 ${result.revocation.from_epoch} → ${result.revocation.to_epoch}，轮换阶段：${result.revocation.stage}。`
    await loadDevices()
  } finally {
    busy.value = false
    resetRevoke()
  }
}

watch(
  () => workspace.workspace?.workspaceId,
  () => {
    void loadDevices()
  },
  { immediate: true },
)
</script>

<template>
  <section
    class="review-panel security-panel"
    aria-labelledby="devices-title"
  >
    <p class="route-panel__eyebrow">
      Membership and recovery
    </p>
    <h2 id="devices-title">
      设备
    </h2>
    <p class="review-panel__copy">
      设备清单来自已验证成员链。撤销会触发工作区密钥轮换；旧设备即使保留本地文件，也必须经新的管理员邀请重新授权，不能用旧身份恢复访问。
    </p>

    <p
      v-if="!workspace.workspace"
      class="review-empty"
      role="status"
    >
      先连接一个工作区，才能读取成员设备。
    </p>
    <p
      v-else-if="busy && !devices"
      class="review-empty"
      role="status"
    >
      正在验证成员链和设备状态；没有数据不代表没有设备。
    </p>
    <p
      v-if="errorCode"
      class="error-boundary"
      role="alert"
    >
      无法读取或撤销设备。错误码：{{ errorCode }}
    </p>
    <p
      v-if="notice"
      class="review-success"
      role="status"
    >
      {{ notice }}
    </p>

    <template v-if="workspace.workspace">
      <div class="review-section-heading">
        <h3>成员设备 · {{ devices?.devices.length ?? 0 }} 项</h3>
        <button
          class="preference-button"
          :disabled="busy"
          type="button"
          @click="loadDevices"
        >
          刷新
        </button>
      </div>
      <dl
        v-if="devices"
        class="review-facts"
      >
        <div>
          <dt>密钥纪元</dt>
          <dd>{{ devices.key_epoch }}</dd>
        </div>
        <div>
          <dt>成员链序号</dt>
          <dd>{{ devices.membership_sequence }}</dd>
        </div>
      </dl>
      <p
        v-if="devices && !devices.devices.length"
        class="review-empty"
      >
        当前未读取到已验证成员设备。
      </p>
      <ul
        v-if="devices?.devices.length"
        class="security-list security-list--cards"
      >
        <li
          v-for="device in devices.devices"
          :key="device.device"
          class="security-card"
        >
          <div class="security-card__heading">
            <code>{{ device.device }}</code>
            <span class="risk-tag">{{ device.is_self ? '当前设备' : device.role }}</span>
          </div>
          <dl class="plan-action__facts">
            <div>
              <dt>加入序号</dt>
              <dd>{{ device.added_at_sequence }}</dd>
            </div>
            <div>
              <dt>当前信封</dt>
              <dd>{{ device.has_current_envelope ? '已持有' : '等待轮换完成' }}</dd>
            </div>
          </dl>
          <button
            class="danger-action"
            :disabled="busy || device.is_self"
            :data-action="`begin-revoke-${device.device}`"
            type="button"
            @click="beginRevoke(device)"
          >
            {{ device.is_self ? '不能撤销当前设备' : '撤销并轮换密钥' }}
          </button>
        </li>
      </ul>

      <section
        v-if="revokeCandidate"
        class="secret-modal"
        aria-labelledby="revoke-title"
      >
        <div class="secret-modal__heading">
          <h3 id="revoke-title">
            撤销设备并轮换密钥
          </h3>
          <button
            class="preference-button"
            type="button"
            @click="resetRevoke"
          >
            取消
          </button>
        </div>
        <p class="review-warning">
          这会撤销 <code>{{ revokeCandidate.device }}</code> 并启动密钥轮换。恢复旧设备需要一台管理员设备重新授权；请勿把恢复短语或私钥输入此页面。
        </p>
        <label class="onboarding-field">
          <span>输入完整设备 ID 确认</span>
          <input
            v-model="confirmation"
            autocomplete="off"
            data-device-revoke-confirmation
          >
        </label>
        <div class="review-actions">
          <button
            class="danger-action"
            data-action="confirm-device-revoke"
            :disabled="!revokeReady"
            type="button"
            @click="revoke"
          >
            确认撤销并轮换
          </button>
        </div>
      </section>

      <section class="security-guidance">
        <h3>邀请与恢复</h3>
        <p>
          受签名的设备邀请可以作为不含 private material 的 QR 负载或传输码；当前桌面端尚未接入受控跨设备传输，因此不会伪造可加入的短码。
        </p>
        <p>
          恢复短语永远不进入此 UI、日志或 IPC 回执。使用恢复机制重新取得密钥后，旧设备仍须完成新的管理员重新授权。
        </p>
      </section>
    </template>
  </section>
</template>
