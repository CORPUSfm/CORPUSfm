import { installContract } from "./install-contract";
import { Brand, ReleaseTrustBlock, installGuideUrl, latestReleaseUrl, repositoryUrl, windowsTrustSteps } from "./page";
import { releaseTrust } from "./release-trust";
import ThemeToggle from "./theme-toggle";

const siteBase = import.meta.env.BASE_URL;
const { linux, windows } = installContract;

const contents = [
  ["before-you-install", "Before you install"],
  ["download-and-verify", "Download and verify"],
  ["linux", "Install on Ubuntu Server"],
  ["windows", "Install on Windows Server"],
  ["existing-installation", "Existing installation"],
  ["after-installation", "After installation"],
  ["if-installation-stops", "If installation stops"],
] as const;

const capabilities = [
  ["FileMaker Server 2024", "Explore, Diff, Jobs, MCP", "—", "—"],
  ["FileMaker Server 2025", "Explore, Diff, Jobs, MCP", "Apply patches", "—"],
  ["FileMaker Server 2026", "Explore, Diff, Jobs, MCP", "Apply patches", "Create files"],
];

export default function InstallPage() {
  return (
    <main className="docs-site install-guide">
      <header className="site-header docs-header shell">
        <a className="brand" href={siteBase} aria-label="CORPUSfm home"><Brand /></a>
        <nav aria-label="Main navigation">
          <a href={`${siteBase}docs/`}>Documentation</a>
          <a href={installGuideUrl} aria-current="page">Install</a>
        </nav>
        <div className="header-actions"><ThemeToggle /><a className="nav-action" href={repositoryUrl}>GitHub <span aria-hidden="true">↗</span></a></div>
      </header>

      <div className="docs-layout shell">
        <aside className="docs-sidebar" aria-label="Installation guide">
          <a className="docs-back" href={siteBase}>← CORPUSfm home</a>
          <section>
            <h2>On this page</h2>
            {contents.map(([id, title]) => <a key={id} href={`#${id}`}>{title}</a>)}
          </section>
        </aside>

        <article className="docs-article">
          <p className="docs-section-label">Installation</p>
          <h1>Install CORPUSfm</h1>
          <p>
            CORPUSfm installs on the same machine as FileMaker Server and is reached through that server’s web
            address. This guide takes you from choosing a server to your first sign-in. Read it before you download:
            the release package then supplies the options specific to that release in its <code>READ-ME-FIRST.txt</code>.
          </p>
          <p><a className="button primary install-download" href={latestReleaseUrl}>Open the latest release <span aria-hidden="true">↗</span></a></p>

          <h2 id="before-you-install">Before you install</h2>
          <h3>Choose the server</h3>
          <p>
            Install on a <strong>development or staging</strong> FileMaker Server, not your production server. From
            there, CORPUSfm can acquire and ingest schema XML from your other FileMaker Servers.
          </p>
          <ul>
            <li>
              <strong>Ubuntu Server:</strong> applying the reverse proxy restarts the FileMaker Server web server — a
              few-second interruption of WebDirect, the Data and OData APIs, and the Admin Console. FileMaker Pro
              clients are unaffected. Uninstalling restarts it too.
            </li>
            <li>
              <strong>Windows Server:</strong> installation deploys a database, registers services, and mounts an
              isolated IIS application. On the default IIS path this avoids a FileMaker Server web-server restart, but
              still plan a maintenance window on a live server.
            </li>
          </ul>
          <h3>Supported servers</h3>
          <p>
            CORPUSfm supports FileMaker Server 2024, 2025, and 2026 on Ubuntu Server or Windows Server, on an operating
            system version Claris supports for that FileMaker Server release. There is a Linux package and a Windows
            package; macOS is not a packaged installation target. The server version sets what CORPUSfm can do:
          </p>
          <table>
            <thead><tr><th scope="col">Server</th><th scope="col">Core</th><th scope="col">Patch</th><th scope="col">File</th></tr></thead>
            <tbody>{capabilities.map((row) => <tr key={row[0]}>{row.map((cell, index) => index === 0 ? <th scope="row" key={cell}>{cell}</th> : <td key={index}>{cell}</td>)}</tr>)}</tbody>
          </table>
          <h3>What you need</h3>
          <ul>
            <li>
              <strong>Administrative access on the server.</strong> On Ubuntu Server, an account that can use{" "}
              <code>sudo</code>. On Windows Server, a local administrator who can open <strong>Windows PowerShell 5.1</strong>{" "}
              with <strong>Run as Administrator</strong>. That is the PowerShell built into Windows Server.
            </li>
            <li>
              <strong>On Windows, the web components FileMaker Server provides.</strong> FileMaker Server normally
              installs IIS, URL Rewrite 2.1 and ARR 3.0. CORPUSfm checks that these components are present; if a check
              fails, follow the installer’s message to restore the missing prerequisite.
            </li>
            <li>
              <strong>The FileMaker OData API enabled</strong> in the FileMaker Server Admin Console. The installer checks
              and stops with directions when it is off.
            </li>
            <li>
              <strong>FileMaker Server administrator credentials.</strong> The installer uses them for that run.
            </li>
            <li>
              <strong>A name and password for the first CORPUSfm administrator.</strong> The installer creates this account.
            </li>
          </ul>

          <h2 id="download-and-verify">Download and verify</h2>
          <ol>
            <li>
              Open the <a href={latestReleaseUrl}>latest CORPUSfm release</a>. Each release lists one package per
              platform, and each package has a <code>.sha256</code> checksum file beside it:
              <ul>
                <li>Ubuntu Server: <code>{linux.asset}</code></li>
                <li>Windows Server: <code>{windows.asset}</code></li>
              </ul>
            </li>
            <li>Download the package for your platform and its <code>.sha256</code> file into the same folder.</li>
            <li>
              Check the package against its checksum before you extract it. The Ubuntu command prints <code>OK</code>; the
              Windows command prints <code>True</code>. Replace <code>{"<version>"}</code> with the release you downloaded.
            </li>
          </ol>
          <p><strong>Ubuntu Server</strong></p>
          <pre><code>{`sha256sum -c ${linux.asset}.sha256`}</code></pre>
          <p><strong>Windows Server — Windows PowerShell</strong></p>
          <pre><code>{`(Get-FileHash .\\${windows.asset} -Algorithm SHA256).Hash -eq (Get-Content .\\${windows.asset}.sha256).Split(' ')[0]`}</code></pre>
          <ol start={4}>
            <li>
              Extract the complete package on the FileMaker Server machine. {installContract.keepTogether} The installer
              verifies its own bundle, so a missing or separated file stops the installation.
            </li>
            <li>Open <code>READ-ME-FIRST.txt</code> in the extracted folder. It names the release and its options.</li>
          </ol>
          <p>If a checksum does not match, delete the download and fetch it again. Do not install a package that fails.</p>

          <h2 id="linux">Install on Ubuntu Server</h2>
          <p className="install-platform">Linux package · <code>{linux.entryPoint}</code></p>
          <p>From the extracted folder, on the FileMaker Server machine, run:</p>
          <pre><code>{linux.launch}</code></pre>
          <p>
            The installer checks the server, asks for what it needs, shows what it will do, and installs CORPUSfm
            to <code>{linux.installDir}</code>. Unattended installation options are listed in the package’s{" "}
            <code>READ-ME-FIRST.txt</code>.
          </p>

          <h2 id="windows">Install on Windows Server</h2>
          <p className="install-platform">Windows package · <code>{windows.entryPoint}</code> · signed</p>
          <p>
            The Windows installer’s PowerShell scripts are signed. Whether Windows asks you to confirm the publisher,
            or requires the certificate to be deployed first, depends on your server’s execution policy:
          </p>
          <ul>
            <li>
              <strong><code>RemoteSigned</code></strong> (the Windows Server default): an interactive launch runs the signed
              script and may ask you to confirm the publisher shown below.
            </li>
            <li>
              <strong><code>AllSigned</code></strong>, usually set by your organization: an unattended launch cannot answer
              a prompt, and the CORPUSfm updater runs unattended. Deploy the release’s signing certificate to{" "}
              <code>LocalMachine\TrustedPublisher</code> before installing, using your organization’s tooling, as the
              steps below describe.
            </li>
          </ul>
          <p>CORPUSfm never imports a certificate for you and never changes execution policy.</p>
          <h3>Check the signature before you run it</h3>
          <p>In Windows PowerShell 5.1, from the extracted folder:</p>
          <pre><code>{`Get-AuthenticodeSignature .\\${windows.entryPoint} | Format-List Status, SignerCertificate, TimeStamperCertificate`}</code></pre>
          <p>
            <code>Status</code> must be <code>Valid</code>, the signer certificate’s subject must be the publisher in step 1
            below, and a timestamp certificate must be present. If any of these differs, stop and do not run the script.
          </p>
          {releaseTrust ? <ReleaseTrustBlock trust={releaseTrust} /> : null}
          <ol className="install-steps">
            {windowsTrustSteps.map((step) => <li key={step.title}><h3>{step.title}</h3>{step.body}</li>)}
          </ol>
          <p>
            The full signed-installer trust procedure also appears on the home page under{" "}
            <a href={`${siteBase}#windows-trust`}>Windows Server: establish trust before you install</a>, where each
            release’s signing details are published. Unattended installation options are listed in the package’s{" "}
            <code>READ-ME-FIRST.txt</code>. CORPUSfm installs to <code>{windows.installDir}</code>.
          </p>

          <h2 id="existing-installation">Existing installation</h2>
          <p>Do not uninstall CORPUSfm to upgrade it. Choose the route by what CORPUSfm reports.</p>
          <h3>Code-only update</h3>
          <p>
            Most updates do not need the installer. Sign in with Settings access, open{" "}
            <strong>Settings → CORPUSfm → Updates</strong>, and choose <strong>Check for updates</strong>. When the result
            is <strong>Update available (code-only)</strong>, review it and choose <strong>Apply update &amp; restart</strong>.
            This restarts CORPUSfm, not FileMaker Server.
          </p>
          <h3>Installer-required upgrade</h3>
          <p>
            When Updates reports that a release needs the installer, download that release, verify it, and run its
            package on the same server with the same command as a fresh installation:
          </p>
          <ul>
            <li>Ubuntu Server: <code>{linux.launch}</code></li>
            <li>Windows Server: <code>{windows.launch}</code> from elevated Windows PowerShell 5.1</li>
          </ul>
          <p>
            The installer detects the existing installation and reuses its recorded locations. Read the plan it shows and
            continue only when the target installation is the one you intend. On Windows under <code>AllSigned</code>,
            deploy that release’s signing certificate first; the certificate can change between installer-bearing
            releases. A later code-only update does not repeat this step.
          </p>
          <p>
            If an update does not appear or cannot be applied, follow{" "}
            <a href={`${siteBase}docs/update-not-appearing-or-applying/`}>An update does not appear or cannot be applied</a>.
          </p>

          <h2 id="after-installation">After installation</h2>
          <ol>
            <li>In a browser, open <code>{"https://<your-fms-host>/corpusfm/"}</code>.</li>
            <li>Sign in with the CORPUSfm administrator account you created during installation.</li>
            <li>Open <strong>Settings → Health</strong>. Continue when storage and the application report ready.</li>
            <li>
              Follow <a href={`${siteBase}docs/overview/`}>Your first artifact</a> to import a schema and open it in
              Explorer.
            </li>
          </ol>

          <h2 id="if-installation-stops">If installation stops</h2>
          <ul>
            <li>Read the installer’s message in full. It states what stopped and what to do next.</li>
            <li>
              Keep the extracted package and the install log. When the installer stops, it prints the log’s location.
            </li>
            <li>
              Resolve the stated condition, then run the same command from the same package again. Use the{" "}
              <code>READ-ME-FIRST.txt</code> of that release; do not mix files or commands from different releases.
            </li>
            <li>
              Do not bypass execution policy, unblock or replace installer files by hand, or edit the installed files.
              None of these is a remedy the installer relies on.
            </li>
            <li>
              If the message does not resolve it, open an issue on the{" "}
              <a href={`${repositoryUrl}/issues`}>CORPUSfm repository</a> with the release version, your platform, and the
              exact message. Remove passwords and host names you do not want to share.
            </li>
          </ul>

          <footer><a href={siteBase}>← CORPUSfm home</a><span>Release-specific options are in each package’s READ-ME-FIRST.txt.</span></footer>
        </article>
      </div>

      <footer className="site-footer shell"><a className="brand" href={siteBase} aria-label="CORPUSfm home"><Brand /></a><p>Take your FileMaker work further.</p><span>Apache 2.0 · Published and supported by PINAX SOFTWARE LLC</span></footer>
    </main>
  );
}
