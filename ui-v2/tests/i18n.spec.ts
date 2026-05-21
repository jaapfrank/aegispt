import { expect, test } from '@playwright/test';

test.beforeEach(async ({ page }) => {
  await page.route('**/api/v1/**', async (route) => {
    const url = new URL(route.request().url());
    let body: unknown = {};

    if (url.pathname === '/api/v1/engagements') {
      body = [{
        id: 'eng-1',
        name: 'Demo Engagement',
        client: 'Demo Client',
        tenant_id: 'tenant-1',
        roe_ref: null,
        authorization_confirmed_by: 'operator-ui',
        authorization_confirmed_at: '2026-05-21T00:00:00Z',
        status: 'active',
        retention_days: 30,
        starts_at: null,
        ends_at: null,
      }];
    } else if (url.pathname === '/api/v1/dashboard') {
      body = { generated_at: '2026-05-21T00:00:00Z', has_engagements: true, engagements: [], activity_feed: [] };
    } else if (url.pathname === '/api/v1/problems') {
      body = { stats: {}, items: [], recently_resolved: [] };
    } else if (url.pathname === '/api/v1/custom-vulnerabilities') {
      body = { items: [] };
    } else if (url.pathname === '/api/v1/ai/research') {
      body = { cve_records: [], research_proposals: [], lifecycle_note: null };
    } else if (url.pathname.endsWith('/runs')) {
      body = [];
    } else if (url.pathname.endsWith('/packs')) {
      body = [];
    } else if (url.pathname === '/api/v1/settings') {
      body = { tenant_id: 'default', sections: [] };
    } else if (url.pathname === '/api/v1/settings/readiness') {
      body = {
        tenant_id: 'default',
        generated_at: '2026-05-21T00:00:00Z',
        overall_status: 'ready',
        capabilities: [],
        tools: [],
        artifact: {},
      };
    } else if (url.pathname === '/api/v1/auth/keys') {
      body = [];
    } else if (url.pathname === '/api/v1/auth/identity/status') {
      body = { provider: 'local', status: 'unavailable', summary: 'Identity status unavailable', operator_next_step: 'Configure identity.' };
    } else if (url.pathname === '/api/v1/deception/traps') {
      body = { traps: [] };
    } else if (url.pathname === '/api/v1/deception/alerts') {
      body = { alerts: [] };
    } else if (url.pathname.endsWith('/schedules')) {
      body = [];
    }

    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify(body),
    });
  });
});

test('language selector switches core shell, settings, and mission control and persists across reloads', async ({ page }) => {
  await page.goto('/app-v2/');

  const selector = page.getByTestId('language-selector');
  await expect(selector).toBeVisible();
  await expect(page.getByRole('link', { name: 'New Mission', exact: true })).toBeVisible();

  await selector.selectOption('nl');
  await expect(page.getByRole('link', { name: 'Nieuwe missie', exact: true })).toBeVisible();
  await expect(page.locator('aside').getByText('Bediening', { exact: true })).toBeVisible();

  await page.goto('/app-v2/settings');
  await expect(page.getByRole('heading', { name: 'Instellingen' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Vernieuwen', exact: true })).toBeVisible();

  await page.reload();
  await expect(page.getByRole('heading', { name: 'Instellingen' })).toBeVisible();

  await selector.selectOption('de');
  await expect(page.getByRole('heading', { name: 'Einstellungen' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Aktualisieren', exact: true })).toBeVisible();

  await page.goto('/app-v2/mission-control');
  await expect(page.getByRole('heading', { name: 'Missionskontrolle' })).toBeVisible();

  await selector.selectOption('fr');
  await expect(page.getByRole('heading', { name: 'Controle de mission' })).toBeVisible();
  await expect(page.getByRole('complementary').getByRole('link', { name: 'Nouvelle mission', exact: true })).toBeVisible();
});

test('mobile language selector keeps translated navigation usable', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/app-v2/');

  await page.getByTestId('language-selector').selectOption('fr');
  await expect(page.getByRole('link', { name: 'Nouvelle mission', exact: true })).toBeVisible();
  await expect(page.locator('aside').getByText('Operations', { exact: true })).toBeVisible();

  await page.goto('/app-v2/settings');
  await expect(page.getByRole('heading', { name: 'Parametres' })).toBeVisible();
});

test('static phrase catalog localizes deeper screen chrome without external translation', async ({ page }) => {
  await page.goto('/app-v2/');
  const selector = page.getByTestId('language-selector');

  await selector.selectOption('fr');
  await expect(page.getByRole('main').getByRole('heading', { name: 'Tableau de bord' })).toBeVisible();
  await expect(page.getByText('Actions rapides')).toBeVisible();

  await page.goto('/app-v2/problems');
  await expect(page.getByRole('main').getByRole('heading', { name: 'Centre des problemes' })).toBeVisible();
  await expect(page.getByText('Filtres', { exact: true })).toBeVisible();

  await selector.selectOption('de');
  await page.goto('/app-v2/history');
  await expect(page.getByRole('main').getByRole('heading', { name: 'Verlauf' })).toBeVisible();
  await expect(page.getByText('Filter', { exact: true })).toBeVisible();

  await page.goto('/app-v2/research');
  await expect(page.getByRole('main').getByRole('heading', { name: 'KI-Recherche' })).toBeVisible();
  await expect(page.getByText('Rechercheentwurf')).toBeVisible();

  await selector.selectOption('nl');
  await page.goto('/app-v2/evidence');
  await expect(page.getByRole('main').getByRole('heading', { name: 'Bewijsreplay' })).toBeVisible();
  await expect(page.getByText('Runselectie')).toBeVisible();

  await page.goto('/app-v2/packs');
  await expect(page.getByRole('main').getByRole('heading', { name: 'Pakketten', exact: true })).toBeVisible();
  await expect(page.getByText('Pakketlijst')).toBeVisible();
});
