import type { ImageAgentProfile } from './types'

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize)
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, item]) => item !== undefined)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonicalize(item)]),
    )
  }
  return value
}

export async function calculateProfileSha256(profile: ImageAgentProfile) {
  const { profile_sha256: _providedHash, ...contract } = profile
  const canonicalJson = JSON.stringify(canonicalize(contract))
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonicalJson))
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}
