import { spawnSync } from 'node:child_process';

function run(command, args) {
  const result = spawnSync(command, args, { stdio: 'inherit', shell: process.platform === 'win32' });
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

const args = process.argv.slice(2);
const runI18nOnly = args.includes('--run') && args.includes('i18n');

run('node', ['scripts/check-i18n.mjs']);
run('npx', ['playwright', 'test', ...(runI18nOnly ? ['tests/i18n.spec.ts'] : [])]);
