<script setup lang="ts">
import { computed, ref } from 'vue'

import {
  type OnboardingPort,
  type RootCapabilityView,
  type SupportedOnboardingBackend,
} from '../ports/onboarding'
import { tauriOnboardingPort } from '../ports/tauri-onboarding'
import { useWorkspaceStore } from '../stores/workspace'

const props = defineProps<{
  port?: OnboardingPort
}>()

const workspace = useWorkspaceStore()
const port = computed(() => props.port ?? tauriOnboardingPort)
const backendKind = ref<SupportedOnboardingBackend>('local')
const deviceProfile = ref('此设备')
const gitRemoteUrl = ref('')
const gitAuth = ref<'ssh-agent' | 'credential-helper'>('ssh-agent')
const root = ref<RootCapabilityView | null>(null)
const errorCode = ref<string | null>(null)
const busy = ref(false)

function chooseBackend(backend: SupportedOnboardingBackend) {
  backendKind.value = backend
  errorCode.value = null
}

async function selectRoot() {
  busy.value = true
  errorCode.value = null
  const result = await port.value.selectRoot()
  busy.value = false
  if (result.kind === 'error') {
    errorCode.value = result.code
    return
  }
  root.value = result.root
}

async function createWorkspace() {
  if (!root.value) {
    errorCode.value = 'desktop.root_capability_required'
    return
  }

  busy.value = true
  errorCode.value = null
  const intent = {
    backendKind: backendKind.value,
    deviceProfile: deviceProfile.value.trim() || '此设备',
    rootCapabilityToken: root.value.token,
  }
  if (backendKind.value === 'git' && !gitRemoteUrl.value.trim()) {
    busy.value = false
    errorCode.value = 'desktop.git_remote_required'
    return
  }
  const result = await port.value.createWorkspace(
    backendKind.value === 'git'
      ? {
          ...intent,
          remoteUrl: gitRemoteUrl.value.trim(),
          gitAuth: gitAuth.value,
        }
      : intent,
  )
  busy.value = false
  if (result.kind === 'error') {
    errorCode.value = result.code
    workspace.setFailure(result.code)
    return
  }
  workspace.setWorkspace(result.workspace)
}

async function openWorkspace() {
  busy.value = true
  errorCode.value = null
  const result = await port.value.openWorkspace()
  busy.value = false
  if (result.kind === 'error') {
    errorCode.value = result.code
    workspace.setFailure(result.code)
    return
  }
  workspace.setWorkspace(result.workspace)
}
</script>

<template>
  <section
    class="onboarding-panel"
    aria-labelledby="onboarding-title"
  >
    <p class="route-panel__eyebrow">
      安全首次使用
    </p>
    <h1 id="onboarding-title">
      连接一个工作区
    </h1>
    <p class="onboarding-panel__copy">
      目录选择由原生层授权。此页面只保存能力令牌，不读取或显示绝对路径。
    </p>

    <fieldset class="onboarding-choice">
      <legend>后端</legend>
      <div class="onboarding-choice__options">
        <button
          class="choice-button"
          :aria-pressed="backendKind === 'local'"
          data-backend="local"
          type="button"
          @click="chooseBackend('local')"
        >
          Local
        </button>
        <button
          class="choice-button"
          :aria-pressed="backendKind === 'git'"
          data-backend="git"
          type="button"
          @click="chooseBackend('git')"
        >
          Git
        </button>
        <button
          class="choice-button"
          data-backend="gist"
          disabled
          type="button"
        >
          Gist（尚不可用）
        </button>
      </div>
    </fieldset>

    <fieldset
      v-if="backendKind === 'git'"
      class="onboarding-choice"
    >
      <legend>Git 连接</legend>
      <label class="onboarding-field">
        <span>远端 URL</span>
        <input
          v-model="gitRemoteUrl"
          autocomplete="off"
          data-git-remote-url
          inputmode="url"
          maxlength="2048"
          name="git-remote-url"
          placeholder="ssh://git@example.com/team/envsync.git"
        >
      </label>
      <div class="onboarding-choice__options">
        <button
          class="choice-button"
          :aria-pressed="gitAuth === 'ssh-agent'"
          data-git-auth="ssh-agent"
          type="button"
          @click="gitAuth = 'ssh-agent'"
        >
          SSH agent
        </button>
        <button
          class="choice-button"
          :aria-pressed="gitAuth === 'credential-helper'"
          data-git-auth="credential-helper"
          type="button"
          @click="gitAuth = 'credential-helper'"
        >
          Credential Helper
        </button>
      </div>
      <p class="onboarding-panel__copy">
        不输入或保存密码、访问令牌和私钥；认证由系统受控组件在需要时完成。
      </p>
    </fieldset>

    <label class="onboarding-field">
      <span>设备 Profile</span>
      <input
        v-model="deviceProfile"
        autocomplete="off"
        maxlength="80"
        name="device-profile"
      >
    </label>

    <div class="onboarding-root">
      <button
        class="preference-button"
        data-action="select-root"
        :disabled="busy"
        type="button"
        @click="selectRoot"
      >
        选择授权根
      </button>
      <p
        v-if="root"
        class="onboarding-root__selected"
        data-root-label
      >
        已授权：{{ root.label }}
      </p>
      <p
        v-else
        class="onboarding-root__selected"
      >
        尚未授权目录
      </p>
    </div>

    <div class="onboarding-actions">
      <button
        class="primary-action"
        data-action="create-workspace"
        :disabled="busy || !root"
        type="button"
        @click="createWorkspace"
      >
        创建 {{ backendKind === 'local' ? 'Local' : 'Git' }} 工作区
      </button>
      <button
        class="preference-button"
        data-action="open-workspace"
        :disabled="busy"
        type="button"
        @click="openWorkspace"
      >
        打开已有工作区
      </button>
    </div>

    <p
      v-if="errorCode"
      class="error-boundary"
      role="alert"
    >
      无法完成该操作。错误码：{{ errorCode }}
    </p>
  </section>
</template>
