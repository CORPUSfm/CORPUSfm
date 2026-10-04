import { copyFile, mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createElement, StrictMode } from "react";
import { renderToString } from "react-dom/server";
import { createServer } from "vite";

const siteDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const dist = path.join(siteDir, "dist");
const source = path.join(dist, "index.html");
const generated = await readFile(path.join(siteDir, "src/generated/docs.ts"), "utf8");
const slugs = [...generated.matchAll(/"slug":\s*"([a-z0-9-]+)"/g)].map((match) => match[1]);

for (const route of ["docs", ...slugs.map((slug) => `docs/${slug}`)]) {
  const destination = path.join(dist, route);
  await mkdir(destination, { recursive: true });
  await copyFile(source, path.join(destination, "index.html"));
}

// The installation guide must be readable before CORPUSfm exists and without JavaScript, so its
// route carries the rendered page rather than an empty application shell.
const server = await createServer({ root: siteDir, appType: "custom", server: { middlewareMode: true }, logLevel: "error" });
try {
  const { default: App } = await server.ssrLoadModule("/src/app.tsx");
  const base = server.config.base;
  const markup = renderToString(createElement(StrictMode, null, createElement(App, { pathname: `${base}install/` })));
  const shell = await readFile(source, "utf8");
  const title = "Install CORPUSfm — CORPUSfm";
  const description = "How to install CORPUSfm beside FileMaker Server on Ubuntu Server or Windows Server.";
  const page = shell
    .replace(/<title>[^<]*<\/title>/, `<title>${title}</title>`)
    .replace(/(<meta name="description" content=")[^"]*(")/, `$1${description}$2`)
    .replace('<div id="root"></div>', `<div id="root">${markup}</div>`);
  if (!page.includes('id="download-and-verify"')) throw new Error("the installation guide did not render into its route");
  await mkdir(path.join(dist, "install"), { recursive: true });
  await writeFile(path.join(dist, "install", "index.html"), page);
} finally {
  await server.close();
}

process.stdout.write(`Wrote ${slugs.length + 1} documentation routes and the installation guide.\n`);
