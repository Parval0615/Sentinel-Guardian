import { describe, expect, it } from 'vitest'
import { calculateProfileSha256 } from './profileIntegrity'
import type { ImageAgentProfile } from './types'

describe('agent-profile-v0.2 integrity', () => {
  it('按后端 canonical JSON 规则计算 SHA-256 并忽略展示字段', async () => {
    const profile = {
      z: 2,
      schema_version: 'agent-profile-v0.2',
      profile_sha256: 'f'.repeat(64),
      profile_id: 'x',
      a: 1,
    } as unknown as ImageAgentProfile

    await expect(calculateProfileSha256(profile)).resolves.toBe(
      'e53ce2eb25d238f3f75fe116f4cc9728c48a1198515f7622924ebd8f7f3a7f93',
    )
  })
})
