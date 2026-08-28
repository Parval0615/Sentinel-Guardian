import { afterEach, describe, expect, it, vi } from 'vitest'
import { PollingTimeoutError, pollWithTimeout } from './polling'

describe('pollWithTimeout', () => {
  afterEach(() => {
    vi.useRealTimers()
  })

  it('总超时会中止并结束永不 resolve 的单次请求', async () => {
    vi.useFakeTimers()
    let pollSignal: AbortSignal | undefined
    const polling = pollWithTimeout({
      poll: (signal) => {
        pollSignal = signal
        return new Promise<number>(() => {})
      },
      isComplete: () => false,
      onUpdate: vi.fn(),
      intervalMs: 10,
      timeoutMs: 100,
      signal: new AbortController().signal,
    })
    const rejection = expect(polling).rejects.toBeInstanceOf(PollingTimeoutError)

    await vi.advanceTimersByTimeAsync(100)

    await rejection
    expect(pollSignal?.aborted).toBe(true)
  })

  it('外部 AbortSignal 取消仍以 AbortError 结束', async () => {
    const controller = new AbortController()
    const polling = pollWithTimeout({
      poll: () => new Promise<number>(() => {}),
      isComplete: () => false,
      onUpdate: vi.fn(),
      intervalMs: 10,
      timeoutMs: 100,
      signal: controller.signal,
    })

    controller.abort()

    await expect(polling).rejects.toMatchObject({ name: 'AbortError' })
  })
})
