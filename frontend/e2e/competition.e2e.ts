import AxeBuilder from '@axe-core/playwright'
import { expect, test } from '@playwright/test'
import { createHash } from 'node:crypto'
import { resolve } from 'node:path'

test('registration reaches a stable responsive dashboard', async ({ page }, testInfo) => {
  test.setTimeout(60_000)
  const consoleErrors: string[] = []
  page.on('console', (message) => {
    if (message.type() === 'error') consoleErrors.push(message.text())
  })

  await page.goto('/app.html#/login')
  await expect(page.getByRole('heading', { name: '欢迎回来' })).toBeVisible()
  if (testInfo.project.name === 'desktop-1440') {
    await expect(page.getByRole('status')).toContainText('本地审计服务可用')
  }
  await expectNoHorizontalOverflow(page)
  await expectAccessible(page)
  await page.screenshot({
    path: evidencePath(`ui-login-${testInfo.project.name}.png`),
    fullPage: true,
  })

  await page.getByRole('tab', { name: '注册' }).click()
  const suffix = testInfo.project.name.replace(/[^a-z0-9]/gi, '-').toLowerCase()
  await page.getByLabel('用户名').fill(`review-${suffix}`)
  await page.getByLabel('邮箱').fill(`review-${suffix}@example.test`)
  await page.getByLabel('密码').fill('competition-ready-password')
  await page.getByRole('button', { name: '创建账号' }).click()

  await expect(page.getByRole('heading', { name: '审计总览' })).toBeVisible()
  await expect(page.getByRole('link', { name: /新建审计/ })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await expectAccessible(page)
  await page.screenshot({
    path: evidencePath(`ui-dashboard-${testInfo.project.name}.png`),
    fullPage: true,
  })

  const demoStatus = await page.evaluate(async () => {
    const token = sessionStorage.getItem('sentinel.auth.token')
    const response = await fetch('/v1/demo/agents/ecommerce', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    })
    return response.status
  })
  expect(demoStatus).toBe(200)
  await page.goto('/app.html#/agents')
  await expect(page.getByRole('heading', { name: 'Agent 资产' })).toBeVisible()
  await expect(page.getByRole('link', { name: 'E-commerce Customer Guide Agent' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await expectAccessible(page)
  await page.screenshot({
    path: evidencePath(`ui-enterprise-agent-${testInfo.project.name}.png`),
    fullPage: true,
  })

  await expect(page.getByText('接入镜像')).toHaveCount(1)
  await page.getByLabel('选择 Agent 镜像文件').setInputFiles({
    name: 'competition-agent.tar',
    mimeType: 'application/x-tar',
    buffer: Buffer.from('test archive'),
  })
  const dialog = page.getByRole('dialog', { name: '导入 Agent 镜像' })
  await expect(dialog).toBeVisible()
  await expect(page.getByText('competition-agent.tar')).toBeVisible()
  const dialogBounds = await dialog.boundingBox()
  const viewport = page.viewportSize()
  expect(dialogBounds).not.toBeNull()
  expect(viewport).not.toBeNull()
  expect(dialogBounds!.x).toBeGreaterThanOrEqual(0)
  expect(dialogBounds!.y).toBeGreaterThanOrEqual(0)
  expect(dialogBounds!.x + dialogBounds!.width).toBeLessThanOrEqual(viewport!.width)
  expect(dialogBounds!.y + dialogBounds!.height).toBeLessThanOrEqual(viewport!.height)
  await expectNoHorizontalOverflow(page)
  await expectAccessible(page)
  await page.screenshot({
    path: evidencePath(`ui-agent-import-dialog-${testInfo.project.name}.png`),
  })
  await page.getByRole('button', { name: '关闭上传窗口' }).click()

  await page.goto('/app.html#/audits/new')
  await expect(page.getByRole('heading', { name: '新建安全审计' })).toBeVisible()
  await expect(page.getByRole('heading', { name: '选择审计对象' })).toBeVisible()
  await page.getByRole('combobox', { name: 'Agent', exact: true })
    .selectOption('ecommerce_customer_guide')
  await expect(page.getByLabel('不能发生什么')).toHaveValue('')
  await expect(page.getByLabel('业务任务')).toHaveValue('')
  await expect(page.getByText(/ecommerce-security-v0.1 内置基准模板/)).toBeVisible()
  await expect(page.getByRole('button', { name: '生成攻击集' })).toBeDisabled()
  await page.getByRole('button', { name: '填入示例' }).click()
  await expect(page.getByLabel('不能发生什么')).toHaveValue('拒绝直接提示词注入')
  await expect(page.getByRole('button', { name: '生成攻击集' })).toBeEnabled()
  await expectNoHorizontalOverflow(page)
  await expectAccessible(page)
  const pageScroller = page.locator(
    testInfo.project.name === 'desktop-1440' ? '#main-content' : '.workspace',
  )
  const scrollMetrics = await pageScroller.evaluate((element) => ({
    clientHeight: element.clientHeight,
    scrollHeight: element.scrollHeight,
  }))
  expect(scrollMetrics.scrollHeight).toBeGreaterThan(scrollMetrics.clientHeight)
  await page.screenshot({
    path: evidencePath(`ui-new-audit-${testInfo.project.name}.png`),
  })

  await page.getByRole('button', { name: /业务验证/ }).click()
  await expect(page.getByRole('heading', { name: '定义正常业务验证' })).toBeInViewport()
  await expectNoHorizontalOverflow(page)
  await page.screenshot({
    path: evidencePath(`ui-new-audit-scrolled-${testInfo.project.name}.png`),
  })
  await pageScroller.evaluate((element) => {
    element.scrollTop = element.scrollHeight
  })
  await expect(page.getByText('配置完整，可以生成攻击集')).toBeInViewport()
  await page.screenshot({
    path: evidencePath(`ui-new-audit-actions-${testInfo.project.name}.png`),
  })
  expect(consoleErrors).toEqual([])
})

test('uploaded Agent completes two audited defense rounds', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop-1440')
  test.setTimeout(120_000)

  await page.goto('/app.html#/login')
  await page.getByRole('tab', { name: '注册' }).click()
  await page.getByLabel('用户名').fill('closed-loop-demo')
  await page.getByLabel('邮箱').fill('closed-loop-demo@example.test')
  await page.getByLabel('密码').fill('competition-ready-password')
  await page.getByRole('button', { name: '创建账号' }).click()

  await expect(page.getByRole('heading', { name: '审计总览' })).toBeVisible()
  await page.getByRole('link', { name: 'Agent 资产' }).click()
  await expect(page.getByRole('heading', { name: 'Agent 资产' })).toBeVisible()
  await page.getByLabel('选择 Agent 镜像文件').setInputFiles({
    name: 'recorded-agent.tar',
    mimeType: 'application/x-tar',
    buffer: dockerArchive(),
  })
  await page.getByRole('button', { name: '开始导入' }).click()

  const agentLink = page.getByRole('link', { name: /recorded agent/i })
  await expect(agentLink).toBeVisible({ timeout: 30_000 })
  await agentLink.click()
  await expect(page.getByRole('heading', { name: '镜像与画像身份' })).toBeVisible()
  await page.getByRole('link', { name: '发起审计' }).first().click()

  await expect(page.getByRole('heading', { name: '新建安全审计' })).toBeVisible()
  await page.getByRole('button', { name: '填入示例' }).click()
  await page.getByRole('button', { name: '生成攻击集' }).click()

  await expect(page.getByRole('heading', { name: '确认正式审计范围' })).toBeVisible()
  await page.getByRole('checkbox').check()
  await page.getByRole('button', { name: '批准并执行正式审计' }).click()

  await expect(page.getByRole('heading', { name: 'Agent 上线审计报告' }))
    .toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('防护已挂载并用于本轮复测')).toBeVisible()
  await expect(page.getByText('第 1 轮攻击矩阵')).toBeVisible()
  await expect(page.getByRole('button', { name: '生成第 2 轮攻击集' })).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await page.screenshot({
    path: evidencePath('ui-closed-loop-round-1-desktop-1440.png'),
    fullPage: true,
  })
  await page.getByRole('heading', { name: '防护方案' }).scrollIntoViewIfNeeded()
  await page.screenshot({
    path: evidencePath('ui-closed-loop-defense-mounted-desktop-1440.png'),
  })

  await page.getByRole('button', { name: '生成第 2 轮攻击集' }).click()
  await expect(page.getByText(/根据上一轮失效反馈生成/)).toBeVisible()
  await expect(page.getByText('上一轮失效反馈', { exact: true })).toBeVisible()
  await page.getByRole('checkbox').check()
  await page.getByRole('button', { name: '批准并执行正式审计' }).click()

  await expect(page.getByText(/第 2 轮 · 审计编号/)).toBeVisible({ timeout: 30_000 })
  await expect(page.getByText('第 2 轮攻击矩阵')).toBeVisible()
  await expect(page.getByText('上一轮结果反馈生成')).toBeVisible()
  await expect(page.getByText('防护已挂载并用于本轮复测')).toBeVisible()
  await expectNoHorizontalOverflow(page)
  await expectAccessible(page)
  await page.screenshot({
    path: evidencePath('ui-closed-loop-round-2-desktop-1440.png'),
    fullPage: true,
  })
})

async function expectNoHorizontalOverflow(page: import('@playwright/test').Page) {
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - window.innerWidth,
  )
  expect(overflow).toBeLessThanOrEqual(1)
}

async function expectAccessible(page: import('@playwright/test').Page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze()
  expect(results.violations, JSON.stringify(results.violations, null, 2)).toEqual([])
}

function evidencePath(filename: string) {
  return resolve(process.cwd(), '..', 'docs', 'competition', 'evidence-pack', filename)
}

function dockerArchive() {
  const layer = tarArchive({
    'app/agent.py': Buffer.from(
      'import subprocess\n\ndef run(user_input):\n    return subprocess.run(user_input, shell=True)\n',
    ),
  })
  const layerDigest = createHash('sha256').update(layer).digest('hex')
  const config = Buffer.from(JSON.stringify({
    architecture: 'arm64',
    os: 'linux',
    config: {
      Entrypoint: ['python', '-m', 'app.agent'],
      WorkingDir: '/app',
    },
    rootfs: {
      type: 'layers',
      diff_ids: [`sha256:${layerDigest}`],
    },
  }))
  const configName = `${createHash('sha256').update(config).digest('hex')}.json`
  const manifest = Buffer.from(JSON.stringify([{
    Config: configName,
    RepoTags: ['local/recorded-agent:latest'],
    Layers: ['layer.tar'],
  }]))
  return tarArchive({
    'manifest.json': manifest,
    [configName]: config,
    'layer.tar': layer,
  })
}

function tarArchive(files: Record<string, Buffer>) {
  const chunks: Buffer[] = []
  for (const [name, content] of Object.entries(files)) {
    const header = Buffer.alloc(512)
    header.write(name, 0, 100, 'utf8')
    writeTarOctal(header, 100, 8, 0o644)
    writeTarOctal(header, 108, 8, 0)
    writeTarOctal(header, 116, 8, 0)
    writeTarOctal(header, 124, 12, content.length)
    writeTarOctal(header, 136, 12, 0)
    header.fill(0x20, 148, 156)
    header.write('0', 156, 1, 'ascii')
    header.write('ustar\u0000', 257, 6, 'ascii')
    header.write('00', 263, 2, 'ascii')
    const checksum = header.reduce((sum, value) => sum + value, 0)
    header.write(`${checksum.toString(8).padStart(6, '0')}\u0000 `, 148, 8, 'ascii')
    chunks.push(header, content)
    const padding = (512 - (content.length % 512)) % 512
    if (padding) chunks.push(Buffer.alloc(padding))
  }
  chunks.push(Buffer.alloc(1024))
  return Buffer.concat(chunks)
}

function writeTarOctal(buffer: Buffer, offset: number, length: number, value: number) {
  buffer.write(`${value.toString(8).padStart(length - 1, '0')}\u0000`, offset, length, 'ascii')
}
