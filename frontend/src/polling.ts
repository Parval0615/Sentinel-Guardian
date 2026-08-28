export const PROFILE_POLL_TIMEOUT_MS = 5 * 60 * 1000

export class PollingTimeoutError extends Error {
  constructor() {
    super('画像构建等待已超过 5 分钟。任务可能仍在后台运行，请重试检查状态。')
    this.name = 'PollingTimeoutError'
  }
}

function abortError() {
  return new DOMException('Polling cancelled', 'AbortError')
}

export function isPollingCancelled(reason: unknown) {
  return reason instanceof DOMException && reason.name === 'AbortError'
}

function waitFor(delayMs: number, signal: AbortSignal) {
  return new Promise<void>((resolve, reject) => {
    if (signal.aborted) {
      reject(abortError())
      return
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', cancel)
      resolve()
    }, delayMs)
    const cancel = () => {
      clearTimeout(timer)
      reject(abortError())
    }
    signal.addEventListener('abort', cancel, { once: true })
  })
}

export async function pollWithTimeout<T>({
  initial,
  poll,
  isComplete,
  onUpdate,
  intervalMs,
  timeoutMs = PROFILE_POLL_TIMEOUT_MS,
  signal,
}: {
  initial?: T
  poll: (signal: AbortSignal) => Promise<T>
  isComplete: (value: T) => boolean
  onUpdate: (value: T) => void
  intervalMs: number
  timeoutMs?: number
  signal: AbortSignal
}) {
  if (signal.aborted) throw abortError()

  const controller = new AbortController()
  let timeout: ReturnType<typeof setTimeout>
  let cancel: () => void
  const timedOut = new Promise<never>((_, reject) => {
    timeout = setTimeout(() => {
      const reason = new PollingTimeoutError()
      reject(reason)
      controller.abort(reason)
    }, timeoutMs)
  })
  const cancelled = new Promise<never>((_, reject) => {
    cancel = () => {
      const reason = abortError()
      reject(reason)
      controller.abort(reason)
    }
    signal.addEventListener('abort', cancel, { once: true })
  })
  const polling = (async () => {
    let current = initial
    while (current === undefined || !isComplete(current)) {
      if (current !== undefined) await waitFor(intervalMs, controller.signal)
      current = await poll(controller.signal)
      if (controller.signal.aborted) throw controller.signal.reason
      onUpdate(current)
    }
    return current
  })()

  try {
    return await Promise.race([polling, timedOut, cancelled])
  } finally {
    clearTimeout(timeout!)
    signal.removeEventListener('abort', cancel!)
  }
}
