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

async function withSsr(run) {
  const server = await createServer({
    root: fileURLToPath(new URL("../", import.meta.url)),
    appType: "custom",
    server: { middlewareMode: true },
    logLevel: "error",
  });
  try {
    return await run(server);
  } finally {
    await server.close();
  }
}

function section(html, id) {
  const start = html.indexOf(`<h2 id="${id}">`);
  assert.ok(start >= 0, `the guide must render the ${id} section`);
  const next = html.indexOf("<h2 ", start + 1);
  return html.slice(start, next === -1 ? undefined : next);
}

function text(html) {
  return html.replace(/<[^>]+>/g, "").replaceAll("&lt;", "<").replaceAll("&gt;", ">").replaceAll("&amp;", "&")
    .replaceAll("&#x27;", "'").replaceAll("&quot;", '"');
}

test("builds the installation guide as a readable static route", async () => {
  const html = await built("install/index.html");
  assert.match(html, /<title>Install CORPUSfm — CORPUSfm<\/title>/);
  assert.match(html, /\/CORPUSfm\/assets\/index-[^"']+\.js/);
  // Everything a reader needs is in the file itself, before any script runs.
  const ids = [...html.matchAll(/<h2 id="([a-z-]+)">/g)].map((match) => match[1]);
  assert.deepEqual(ids, [
    "before-you-install", "download-and-verify", "linux", "windows",
    "existing-installation", "after-installation", "if-installation-stops",
  ]);
  assert.match(html, /<a[^>]*href="https:\/\/github\.com\/CORPUSfm\/CORPUSfm\/releases\/latest"/);
  assert.match(html, /href="\/CORPUSfm\/docs\/overview\/"/);

  const linux = text(section(html, "linux"));
  const windows = text(section(html, "windows"));
  assert.match(linux, /sudo bash install\.sh/);
  assert.doesNotMatch(linux, /powershell|install\.ps1/i);
  assert.match(windows, /powershell -File install\.ps1/);
  assert.match(windows, /Windows PowerShell 5\.1/);
  assert.doesNotMatch(windows, /sudo|install\.sh\b/);
  // FileMaker Server supplies the Windows web components; the guide says CORPUSfm checks them and must
  // not turn them into a separate installation step.
  const before = text(section(html, "before-you-install"));
  assert.match(before, /FileMaker Server normally installs IIS, URL Rewrite 2\.1 and ARR 3\.0/);
  assert.match(before, /CORPUSfm checks that these components are present; if a check fails, follow the installer’s message/);
  assert.doesNotMatch(before, /\b(?:download|install|add)\s+(?:the\s+)?(?:IIS|URL Rewrite|ARR|Web-Server)\b|rewrite_amd64|requestRouter|Install-WindowsFeature|Add-WindowsFeature/i);
  assert.match(before, /On the default IIS path this avoids a FileMaker Server web-server restart/);
  const existing = text(section(html, "existing-installation"));
  assert.match(existing, /Code-only update/);
  assert.match(existing, /Installer-required upgrade/);
  assert.match(existing, /Do not uninstall/);
});

test("every Install and Get CORPUSfm entry point opens the guide", async () => {
  await withSsr(async (server) => {
    const { resolveRoute } = await server.ssrLoadModule("/src/app.tsx");
    for (const path of ["/CORPUSfm/install/", "/CORPUSfm/install"]) {
      assert.deepEqual(resolveRoute(path, "/CORPUSfm/"), { page: "install" });
    }
    assert.deepEqual(resolveRoute("/CORPUSfm/", "/CORPUSfm/"), { page: "home" });

    const page = await server.ssrLoadModule("/src/page.tsx");
    const home = renderToStaticMarkup(createElement(page.default));
    assert.match(home, /<a href="\/CORPUSfm\/install\/">Install<\/a>/);
    assert.match(home, /<a class="button secondary" href="\/CORPUSfm\/install\/">Get CORPUSfm<\/a>/);
    assert.match(home, /<a class="button primary" href="\/CORPUSfm\/install\/">Read the installation guide/);
    // The release notes link here for the signed-installer trust steps; the section stays.
    assert.match(home, /id="windows-trust"/);

    const docs = renderToStaticMarkup(createElement((await server.ssrLoadModule("/src/docs-page.tsx")).default, {}));
    assert.match(docs, /<a href="\/CORPUSfm\/install\/">Install<\/a>/);

    for (const markup of [home, docs]) {
      for (const [, label] of markup.matchAll(/<a [^>]*href="https:\/\/github\.com\/CORPUSfm\/CORPUSfm\/releases[^"]*"[^>]*>([^<]*)/g)) {
        assert.doesNotMatch(label, /Install|Get CORPUSfm/, "an install call to action must enter the guide, not the release page");
      }
    }
  });
});

// The package generator is the authority for the launch contract. The public repository carries it
// beside the site, so its site build always runs this comparison; elsewhere, point
// CORPUSFM_INSTALLER_ROOT at an installer checkout.
async function packageGenerator() {
  const candidates = [
    process.env.CORPUSFM_INSTALLER_ROOT && new URL("installer/package-installer.sh", `file://${process.env.CORPUSFM_INSTALLER_ROOT.replace(/\/?$/, "/")}`),
    new URL("../installer/package-installer.sh", import.meta.url),
  ].filter(Boolean);
  for (const candidate of candidates) {
    try {
      return await readFile(candidate, "utf8");
    } catch {
      // try the next location
    }
  }
  return null;
}

function heredoc(script, name) {
  const body = script.match(new RegExp(`${name}="\\$BUILD_DIR/[^"]+"\\ncat > "\\$${name}" <<TXT\\n([\\s\\S]*?)\\nTXT\\n`))?.[1];
  assert.ok(body, `the package generator must author ${name}`);
  return body.replaceAll("\\\\", "\\");
}

test("the guide's launch contract equals the packaged READ-ME-FIRST", async (t) => {
  const script = await packageGenerator();
  if (script === null) {
    t.skip("no installer package generator here; set CORPUSFM_INSTALLER_ROOT to compare");
    return;
  }
  const { installContract } = await withSsr((server) => server.ssrLoadModule("/src/install-contract.ts"));
  const readme = { linux: heredoc(script, "LINUX_README"), windows: heredoc(script, "WIN_README") };
  for (const platform of ["linux", "windows"]) {
    const facts = installContract[platform];
    assert.match(readme[platform], new RegExp(`^ {4}${facts.launch.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}$`, "m"),
      `${platform}: the default launch command must be the package's`);
    assert.ok(readme[platform].includes(facts.installDir), `${platform}: install location must be the package's`);
    assert.ok(readme[platform].includes(installContract.keepTogether), `${platform}: keep-together rule must be the package's`);
    const asset = facts.asset.replace("<version>", `{os.environ['VER']}`);
    assert.ok(script.includes(`"zip": f"${asset}"`), `${platform}: asset name must be the package's`);
  }
  assert.ok(script.includes('cp "$readme" "$outer/READ-ME-FIRST.txt"'), "the package must ship READ-ME-FIRST.txt");
});

test("the guide keeps the signed-installer contract and skips no verification", async () => {
  const [html, source] = await Promise.all([built("install/index.html"), readFile(new URL("../src/install-page.tsx", import.meta.url), "utf8")]);
  const guide = text(html);
  for (const sentence of guide.split(/(?<=[.:])\s+/)) {
    if (/ExecutionPolicy/i.test(sentence)) assert.match(sentence, /\b(?:do not|never)\b/i, `must only forbid a policy override: ${sentence}`);
  }
  assert.doesNotMatch(guide, /Set-ExecutionPolicy|Unblock-File|PowerShell 7|\bpwsh\b|Import-Certificate[^\n]*CurrentUser/i);
  assert.match(guide, /never imports a certificate for you and never changes execution policy/);
  assert.match(guide, /RemoteSigned/);
  assert.match(guide, /AllSigned/);
  assert.match(guide, /LocalMachine\\TrustedPublisher/);
  assert.match(guide, /NT AUTHORITY\\SYSTEM/);
  // Hash and signature checks are part of the path, not optional reading.
  assert.match(guide, /sha256sum -c corpusfm-installer-linux-<version>\.zip\.sha256/);
  assert.match(guide, /Get-FileHash \.\\corpusfm-installer-windows-<version>\.zip -Algorithm SHA256/);
  assert.match(guide, /Get-AuthenticodeSignature \.\\install\.ps1/);
  assert.match(guide, /Status must be Valid/);
  // The publisher is the one pinned subject from page.tsx, rendered, never retyped here.
  const subject = guide.match(/CN=[^<>{}"'\n]+C=US/)?.[0];
  assert.equal(createHash("sha256").update(subject ?? "", "utf8").digest("hex"),
    "911b55f39a0fd5e400251f1a511374123851e9901c1ada719ff2109346b66429");
  assert.doesNotMatch(source, /CN=|William/);
});

test("the guide exposes nothing private and pins no release", async () => {
  const [html, source, contract] = await Promise.all([
    built("install/index.html"),
    readFile(new URL("../src/install-page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../src/install-contract.ts", import.meta.url), "utf8"),
  ]);
  for (const content of [text(html), source, contract]) {
    assert.doesNotMatch(content, /PRIVATE_|\/Users\/|\/home\/|C:\\Users|github_pat_|ghp_|password\s*[:=]/i);
    assert.doesNotMatch(content, /\b0\.\d{3,}\b|\bv0\.\d+|releases\/(?:tag|download)\//);
    assert.doesNotMatch(content, /\b[0-9A-Fa-f]{40}\b/);
  }
});
