const esbuild = require('esbuild');

esbuild
  .build({
    entryPoints: ['src/index.ts'],
    outfile: 'lib/index.mjs',
    bundle: true,
    sourcemap: true,
    minify: false,
    format: 'esm',
    target: ['esnext']
  })
  .catch(() => process.exit(1));
