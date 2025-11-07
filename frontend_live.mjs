import * as esbuild from 'esbuild'

const frontend_ctx = await esbuild.context({
    entryPoints: ['src/frontend.ts'],
    bundle: true,
    minify: false,
    keepNames: true,
    outdir: 'public',
    format: 'esm',
    charset: 'utf8',
    sourcemap: "inline"
});

await frontend_ctx.watch();

const {hosts, port} = await frontend_ctx.serve({
    servedir: 'public',
})

console.log(`Frontend running on ${hosts.join(", ")}, under ${port}`);