const esbuild = require('esbuild');

esbuild.build({
  entryPoints: ['./src/index.ts'],
  outfile: 'lib/index.cjs',
  bundle: true,
  sourcemap: true,
  minify: false,
  platform: 'node',
  target: ['node16', 'node14', 'node12'],
}).catch(() => process.exit(1))
