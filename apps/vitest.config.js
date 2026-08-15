import { defineConfig } from 'vitest/config';

// Two vitest tiers by suffix: *.test = unit (one unit, deps faked), *.int = integration (two
// or more real units wired together). Both run in Node. Browser tests are *.e2e.ts under
// apps/e2e/ and run only via Playwright (pnpm test:e2e) — never here.
export default defineConfig({
  test: {
    include: ['test/**/*.{test,int}.{js,ts}'],
  },
});
