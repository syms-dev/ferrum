// Builds the library with esbuild.
//
// esbuild rather than a framework toolchain: the output has to be
// reproducible under Nix with no network, and esbuild is one binary with
// no plugin ecosystem to pin. React is external -- the consumer supplies
// it -- so the bundle stays small and the design tool can load its own.
import { build } from "esbuild";
import { rm } from "node:fs/promises";

await rm("dist", { recursive: true, force: true });

await build({
  entryPoints: ["src/index.ts"],
  outfile: "dist/index.js",
  bundle: true,
  format: "esm",
  target: "es2020",
  jsx: "automatic",
  external: ["react", "react-dom", "react/jsx-runtime"],
  logLevel: "info",
});

// The stylesheet ships alongside, not inlined: ferrum's UI is themed with
// CSS custom properties that the host page owns, so a component library
// that injected its own <style> would fight the theme rather than follow it.
await build({
  entryPoints: ["src/styles.css"],
  outfile: "dist/styles.css",
  bundle: true,
  loader: { ".css": "css" },
  logLevel: "info",
});
