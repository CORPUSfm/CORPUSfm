import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";

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
  // The download page must show the Windows code-signing subject verbatim, and that subject carries
  // the holder's name. Read the subject from the page instead of restating it here, pin its exact
  // bytes, and hold every other occurrence of the name to the original ban.
  const signingSubject = content.match(/CN=[^<>{}"'\n]+C=US/)?.[0];
  assert.ok(signingSubject, "the page must display the code-signing subject as the publisher identity");
  assert.equal(
    createHash("sha256").update(signingSubject, "utf8").digest("hex"),
    "911b55f39a0fd5e400251f1a511374123851e9901c1ada719ff2109346b66429",
  );
  const residual = content.split(signingSubject).join("");
  assert.doesNotMatch(residual, new RegExp(`${privateCopyrightHolder}|Alpha|Start here`, "i"));
});

test("carries the signed-installer trust path and claims nothing about a release yet", async () => {
  const page = await readFile(new URL("../src/page.tsx", import.meta.url), "utf8");
  const trust = await readFile(new URL("../src/release-trust.ts", import.meta.url), "utf8");

  assert.match(page, /id="windows-trust"/);
  assert.match(page, /LocalMachine\\TrustedPublisher/);
  assert.match(page, /NT AUTHORITY\\SYSTEM/);
  assert.match(page, /Import-Certificate -FilePath/);
  assert.match(page, /Get-ChildItem Cert:\\\\LocalMachine\\\\TrustedPublisher/);
  assert.match(page, /Do not uninstall a previous CORPUSfm first/);
  assert.match(page, /Do not use <code>-ExecutionPolicy Bypass<\/code>/);
  assert.doesNotMatch(page, /Unblock-File|Intune/i);

  // Every release-bound value can only be read back from the one signing run, so until the seam is
  // populated the page must carry no version, release link, asset filename or thumbprint.
  assert.match(trust, /export const releaseTrust: ReleaseTrust \| null = null;/);
  assert.doesNotMatch(page, /corpusfm-installer-windows-|\.trust\.json/);
  assert.doesNotMatch(page, /corpusfm-signing-leaf-[0-9a-f]/i);
  assert.doesNotMatch(page, /\b[0-9a-f]{40}\b|releases\/(?:tag|download)\//i);
});

test("links the release certificate and trust record only from supplied release data", async () => {
  const server = await createServer({
    root: fileURLToPath(new URL("../", import.meta.url)),
    appType: "custom",
    server: { middlewareMode: true },
    logLevel: "error",
  });
  try {
    const page = await server.ssrLoadModule("/src/page.tsx");
    // Synthetic, obviously non-release values: this proves the render path carries whatever the seam
    // supplies, and must never be mistaken for a real release.
    const populated = renderToStaticMarkup(createElement(page.ReleaseTrustBlock, {
      trust: {
        version: "0.0.0-synthetic",
        releaseUrl: "https://example.invalid/synthetic/release",
        installerAsset: "synthetic-installer.zip",
        signerThumbprint: "SYNTHETIC-THUMBPRINT",
        certificateAsset: "synthetic-leaf.cer",
        certificateUrl: "https://example.invalid/synthetic/leaf.cer",
        trustRecordAsset: "synthetic-installer.trust.json",
        trustRecordUrl: "https://example.invalid/synthetic/trust.json",
      },
    }));
    assert.match(populated, /<a href="https:\/\/example\.invalid\/synthetic\/leaf\.cer"><code>synthetic-leaf\.cer<\/code><\/a>/);
    assert.match(populated, /<a href="https:\/\/example\.invalid\/synthetic\/trust\.json"><code>synthetic-installer\.trust\.json<\/code><\/a>/);
    assert.match(populated, /Get-ChildItem<\/code> command\s+below before you install/);

    const home = renderToStaticMarkup(createElement(page.default));
    assert.match(home, /id="windows-trust"/);
    assert.doesNotMatch(home, /synthetic/i);
    assert.doesNotMatch(home, /This release —/);
    assert.doesNotMatch(home, /<a [^>]*href="[^"]*\.(?:cer|trust\.json)"/);
  } finally {
    await server.close();
  }
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
