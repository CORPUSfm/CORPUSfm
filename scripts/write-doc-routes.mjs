import { copyFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

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

process.stdout.write(`Wrote ${slugs.length + 1} documentation routes.\n`);
