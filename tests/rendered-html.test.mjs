import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const dist = new URL("../dist/", import.meta.url);

async function built(relative) {
  return readFile(new URL(relative, dist), "utf8");
}

test("builds the CORPUSfm public home for its GitHub Pages path", async () => {
  const html = await built("index.html");
  assert.match(html, /<title>CORPUSfm — Take your FileMaker work further<\/title>/i);
  assert.match(html, /\/CORPUSfm\/assets\/index-[^"']+\.js/);
  assert.match(html, /\/CORPUSfm\/assets\/index-[^"']+\.css/);
  assert.match(html, /https:\/\/corpusfm\.github\.io\/CORPUSfm\/og\.png/);
  assert.match(html, /corpusfm-site-theme/);
});

test("ships product images, real brand assets, and social metadata", async () => {
  for (const path of [
    "screenshots/artifacts.png",
    "screenshots/explorer.png",
    "screenshots/diff.png",
    "brand/corpusfm-wordmark-light.png",
    "brand/corpusfm-wordmark-dark.png",
    "brand/corpusfm-node-icon.png",
    "og.png",
  ]) {
    const content = await readFile(new URL(path, dist));
    assert.ok(content.length > 1000, `${path} must be a real image asset`);
  }
});

test("compiled site keeps the approved product narrative", async () => {
  const files = await Promise.all([
    built("index.html"),
    readFile(new URL("../src/page.tsx", import.meta.url), "utf8"),
  ]);
  const content = files.join("\n");
  assert.match(content, /Take your FileMaker work/);
  assert.match(content, /moving with FileMaker’s expansion into AI/);
  assert.match(content, /One developer/);
  assert.match(content, /A whole team/);
  assert.match(content, /Put CORPUSfm on a development server/);
  assert.match(content, /PINAX SOFTWARE LLC/);
  assert.match(content, /Published and supported by PINAX SOFTWARE LLC/);
  assert.doesNotMatch(content, /developed and maintained by PINAX|Copyright[^\n<]*PINAX|©[^\n<]*PINAX/i);
  const privateCopyrightHolder = ["William", "Wheeler"].join(" ");
  assert.doesNotMatch(content, new RegExp(`${privateCopyrightHolder}|Alpha|Start here`, "i"));
});

test("builds direct public-documentation routes from the product manual", async () => {
  for (const path of [
    "docs/index.html",
    "docs/overview/index.html",
    "docs/explorer/index.html",
    "docs/mcp/index.html",
    "docs/mcp-client-cannot-connect/index.html",
  ]) {
    const html = await built(path);
    assert.match(html, /\/CORPUSfm\/assets\/index-[^"']+\.js/);
  }
  const generated = await readFile(new URL("../src/generated/docs.ts", import.meta.url), "utf8");
  assert.match(generated, /"slug": "overview"/);
  assert.match(generated, /"slug": "mcp"/);
  assert.match(generated, /__CORPUSFM_BASE__docs\/artifacts-catalog\//);
  assert.doesNotMatch(generated, /"slug": "(?:settings|logs|queue|monitoring|ollama|changelog)"/);
});
