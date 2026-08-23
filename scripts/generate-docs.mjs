import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import MarkdownIt from "markdown-it";

const siteDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const candidates = [
  path.resolve(siteDir, "../corpusfm/app/web/docs"),
  path.resolve(siteDir, "corpusfm/app/web/docs"),
];

async function docsRoot() {
  for (const candidate of candidates) {
    try {
      if ((await readdir(candidate)).some((name) => name.endsWith(".md"))) return candidate;
    } catch {
      // Try the other supported repository layout.
    }
  }
  throw new Error("could not find the CORPUSfm product documentation source");
}

function parseDocument(source, filename) {
  const match = source.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!match) throw new Error(`${filename}: missing front matter`);
  const metadata = Object.fromEntries(match[1].split("\n").map((line) => {
    const separator = line.indexOf(":");
    if (separator < 1) throw new Error(`${filename}: invalid front matter line`);
    return [line.slice(0, separator).trim(), line.slice(separator + 1).trim()];
  }));
  return { metadata, markdown: match[2] };
}

function plainSummary(markdown) {
  const paragraph = markdown
    .replace(/^#.*$/gm, "")
    .split(/\n\s*\n/)
    .map((value) => value.trim())
    .find((value) => value && !value.startsWith(">") && !value.startsWith("```")) ?? "";
  return paragraph
    .replace(/!\[[^\]]*\]\([^)]*\)/g, "")
    .replace(/\[([^\]]+)\]\([^)]*\)/g, "$1")
    .replace(/[*_`>#]/g, "")
    .replace(/\s+/g, " ")
    .trim();
}

const md = new MarkdownIt({ html: false, linkify: true, typographer: true });
const defaultLink = md.renderer.rules.link_open
  ?? ((tokens, index, options, _environment, renderer) => renderer.renderToken(tokens, index, options));
md.renderer.rules.link_open = (tokens, index, options, environment, renderer) => {
  const href = tokens[index].attrGet("href");
  const internal = href?.match(/^\/docs\/([a-z0-9-]+)\/?(?:#(.*))?$/);
  if (internal) {
    const fragment = internal[2] ? `#${internal[2]}` : "";
    tokens[index].attrSet("href", `__CORPUSFM_BASE__docs/${internal[1]}/${fragment}`);
  } else if (href?.startsWith("http://") || href?.startsWith("https://")) {
    tokens[index].attrSet("rel", "noreferrer");
  }
  return defaultLink(tokens, index, options, environment, renderer);
};

const root = await docsRoot();
const filenames = (await readdir(root)).filter((name) => name.endsWith(".md")).sort();
const documents = [];
for (const filename of filenames) {
  const source = await readFile(path.join(root, filename), "utf8");
  const { metadata, markdown } = parseDocument(source, filename);
  if (metadata.status !== "published" || metadata.public !== "true") continue;
  if (!metadata.title || !metadata.slug || !metadata.public_section) {
    throw new Error(`${filename}: public articles require title, slug, and public_section`);
  }
  documents.push({
    title: metadata.title,
    slug: metadata.slug,
    section: metadata.public_section,
    order: Number(metadata.order ?? 999),
    summary: plainSummary(markdown),
    html: md.render(markdown),
  });
}
documents.sort((left, right) => left.order - right.order || left.title.localeCompare(right.title));

const output = path.resolve(siteDir, "src/generated/docs.ts");
await mkdir(path.dirname(output), { recursive: true });
await writeFile(output, `// Generated from corpusfm/app/web/docs. Do not edit.\nexport default ${JSON.stringify(documents, null, 2)} as const;\n`, "utf8");
process.stdout.write(`Generated ${documents.length} public documentation articles.\n`);
