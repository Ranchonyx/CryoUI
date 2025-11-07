import * as esbuild from 'esbuild'

await esbuild.build({
    entryPoints: ["src/backend.ts"],
    bundle: true,
    outdir: "dist",
    format: "esm",
    platform: "node",
    target: "node22",
    sourcemap: true,
    minify: false,
    legalComments: "inline",
    treeShaking: true,
    logLevel: "info",
    external: ["node", "ws"],
    keepNames: true
});
console.log(`Backend built.`);