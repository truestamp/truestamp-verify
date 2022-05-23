const esbuild = require('esbuild');

esbuild
  .build({
    entryPoints: ['src/index.ts'],
    outfile: 'lib/index.iife.js',
    bundle: true,
    sourcemap: true,
    minify: true,
    target: ['es2020'],
    format: 'iife',
    globalName: 'truestamp',
  })
  .catch(() => process.exit(1));
