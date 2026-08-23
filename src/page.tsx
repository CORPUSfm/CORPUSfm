import ThemeToggle from "./theme-toggle";

const releasesUrl = "https://github.com/CORPUSfm/CORPUSfm/releases";
export const latestReleaseUrl = `${releasesUrl}/latest`;
export const repositoryUrl = "https://github.com/CORPUSfm/CORPUSfm";
const siteBase = import.meta.env.BASE_URL;

export function Brand() {
  return (
    <span className="brand-logos" aria-hidden="true">
      <img className="brand-logo brand-logo-light" src={`${siteBase}brand/corpusfm-wordmark-light.png`} alt="" />
      <img className="brand-logo brand-logo-dark" src={`${siteBase}brand/corpusfm-wordmark-dark.png`} alt="" />
    </span>
  );
}

const workflow = [
  { number: "01", title: "Bring the schema in", body: "Import or paste a FileMaker schema export, or let a Job acquire it from another FileMaker Server." },
  { number: "02", title: "Follow the system", body: "Use Explorer to move from an object to its references, related files, scripts, fields, layouts, and dependencies." },
  { number: "03", title: "See what changed", body: "Compare durable artifact versions in Diff, where additions, removals, and modifications keep their structure." },
  { number: "04", title: "Move the work forward", body: "Share the evidence with your team or an AI assistant, then plan, review, export, create, or apply the next change." },
];

const setupSteps = [
  ["Choose the server", "Install CORPUSfm on a development FileMaker Server running Ubuntu Server or Windows Server."],
  ["Download the package", "Choose the current Series 2 installer for that platform from the CORPUSfm release page."],
  ["Follow its checklist", "Keep the extracted files together, open READ-ME-FIRST, and follow the package’s installation recipe."],
  ["Bring in a schema", "Sign in, open Artifacts, and choose Import or Paste. A Job can later acquire XML from other FileMaker Servers."],
];

const requirements = [
  ["FileMaker Server 2024", "Explore, Diff, Jobs, MCP", "—", "—"],
  ["FileMaker Server 2025", "Explore, Diff, Jobs, MCP", "Apply patches", "—"],
  ["FileMaker Server 2026", "Explore, Diff, Jobs, MCP", "Apply patches", "Create files"],
];

export default function Home() {
  return (
    <main id="top">
      <header className="site-header shell">
        <a className="brand" href="#top" aria-label="CORPUSfm home">
          <Brand />
        </a>
        <nav aria-label="Main navigation">
          <a href="#workflow">Workflow</a>
          <a href="#people">For people &amp; teams</a>
          <a href="#setup">Install</a>
          <a href="#documentation">Documentation</a>
        </nav>
        <div className="header-actions">
          <ThemeToggle />
          <a className="nav-action" href={repositoryUrl}>GitHub <span aria-hidden="true">↗</span></a>
        </div>
      </header>

      <section className="hero shell">
        <div className="hero-copy">
          <p className="eyebrow"><span /> Open source · Apache 2.0</p>
          <h1>Take your FileMaker work <em>further.</em></h1>
          <p className="hero-lede">
            CORPUSfm brings schema exploration, structured comparison, automation, team knowledge,
            and AI-assisted development into one connected workflow. It elevates the work around
            FileMaker while moving with FileMaker’s expansion into AI.
          </p>
          <div className="hero-actions">
            <a className="button primary" href="#workflow">Ride along <span>↓</span></a>
            <a className="button secondary" href={latestReleaseUrl}>Get CORPUSfm</a>
          </div>
          <dl className="hero-facts" aria-label="Product facts">
            <div><dt>Start with</dt><dd>Schema XML</dd></div>
            <div><dt>Build</dt><dd>Durable artifacts</dd></div>
            <div><dt>Work with</dt><dd>People and AI</dd></div>
          </dl>
        </div>

        <figure className="product-frame hero-frame">
          <div className="frame-bar"><span /><span /><span /><small>Artifacts · CORPUSfm</small></div>
          <img src={`${siteBase}screenshots/artifacts.png`} alt="The CORPUSfm Artifacts catalog with Import and Paste controls" width={1263} height={995} fetchPriority="high" />
          <figcaption>One library for the schema evidence you keep.</figcaption>
        </figure>
      </section>

      <section className="promise-band"><div className="shell"><p>Give people and AI a shared understanding of a FileMaker solution—then use that understanding to improve what exists or create what comes next.</p></div></section>

      <section className="section shell workflow-section" id="workflow">
        <div className="section-heading-row">
          <div><p className="eyebrow"><span /> A connected workflow</p><h2>Bring the schema.<br />Follow where it leads.</h2></div>
          <p>CORPUSfm keeps the source, the structure, and the resulting evidence together so each next step begins with context instead of reconstruction.</p>
        </div>
        <ol className="workflow-grid">
          {workflow.map((step) => <li key={step.number}><span>{step.number}</span><h3>{step.title}</h3><p>{step.body}</p></li>)}
        </ol>
      </section>

      <section className="section product-section" aria-labelledby="product-heading">
        <div className="shell">
          <div className="product-intro">
            <p className="eyebrow"><span /> The evidence stays visible</p>
            <h2 id="product-heading">Explore the system.<br />Compare the decisions.</h2>
            <p>Explorer and Diff are generated views of durable artifacts. Remake them whenever the artifact changes; share them when the work needs another set of eyes.</p>
          </div>
          <div className="product-gallery">
            <figure className="product-frame explorer-frame">
              <div className="frame-label"><span>Explorer</span><small>Trace objects and references</small></div>
              <img src={`${siteBase}screenshots/explorer.png`} alt="CORPUSfm Explorer showing a FileMaker script and its related schema objects" width={1440} height={1000} loading="lazy" />
            </figure>
            <figure className="product-frame diff-frame">
              <div className="frame-label"><span>Diff</span><small>Review structured changes</small></div>
              <img src={`${siteBase}screenshots/diff.png`} alt="CORPUSfm Diff showing added, removed, and changed FileMaker objects" width={1440} height={1000} loading="lazy" />
            </figure>
          </div>
        </div>
      </section>

      <section className="section shell people-section" id="people">
        <div className="section-heading-row">
          <div><p className="eyebrow"><span /> From one person to a whole team</p><h2>Keep your own bearings.<br />Give everyone the same map.</h2></div>
          <p>The same artifact can support a focused investigation, a scheduled team practice, or an AI-assisted development conversation.</p>
        </div>
        <div className="audience-grid">
          <article>
            <span className="audience-kicker">One developer</span><h3>Understand the solution in front of you.</h3>
            <p>Import a schema, follow unfamiliar references, compare versions, and keep the evidence beside the work you are planning.</p>
            <ul><li>Explore inherited or long-lived solutions</li><li>Answer impact questions before editing</li><li>Return to a durable record of what you saw</li></ul>
          </article>
          <article>
            <span className="audience-kicker">A whole team</span><h3>Share context without passing snapshots around.</h3>
            <p>Use Jobs to refresh artifacts, make structured Diffs part of review, and give each collaborator access through their own account.</p>
            <ul><li>Build a common library of solution knowledge</li><li>Review change through shared evidence</li><li>Connect each person’s preferred AI client</li></ul>
          </article>
        </div>
      </section>

      <section className="ai-section">
        <div className="shell ai-grid">
          <div>
            <p className="eyebrow light"><span /> FileMaker and AI</p><h2>Bring an assistant into the same conversation.</h2>
            <p>CORPUSfm exposes its schema intelligence through MCP. An OAuth-capable client signs in through the browser, the connection belongs to a CORPUSfm user, and the assistant can work from the same artifacts people inspect.</p>
          <a className="text-link" href={`${siteBase}docs/mcp/`}>See the MCP setup path <span>→</span></a>
          </div>
          <div className="ai-steps" aria-label="AI-assisted workflow">
            <div><span>Ask</span><strong>How does this solution work?</strong><p>Ground the answer in schema objects and their relationships.</p></div>
            <div><span>Explore</span><strong>What would this change touch?</strong><p>Move from a question to the relevant scripts, fields, layouts, and dependencies.</p></div>
            <div><span>Create</span><strong>What should come next?</strong><p>Use shared understanding to plan improvements or shape a new solution.</p></div>
          </div>
        </div>
      </section>

      <section className="section shell setup-section" id="setup">
        <div className="setup-intro">
          <p className="eyebrow"><span /> First installation</p><h2>Put CORPUSfm on a development server.</h2>
          <p>From there, it can acquire and ingest schema XML from other FileMaker Servers. The installer package carries the exact checklist for its platform and release.</p>
          <a className="button primary" href={latestReleaseUrl}>Open the latest release <span>→</span></a>
        </div>
        <ol className="recipe-list">
          {setupSteps.map(([title, body], index) => <li key={title}><span>{String(index + 1).padStart(2, "0")}</span><div><h3>{title}</h3><p>{body}</p></div></li>)}
        </ol>
      </section>

      <section className="section requirements-section" id="requirements">
        <div className="shell">
          <div className="section-heading-row compact">
            <div><p className="eyebrow"><span /> Capability by server</p><h2>One application.<br />The server sets the reach.</h2></div>
            <p>CORPUSfm reports the installed server’s actual capability. The version changes what it can author or apply, not the value of the artifact.</p>
          </div>
          <div className="requirements-table" role="table" aria-label="FileMaker Server capabilities">
            <div className="table-row table-head" role="row"><span>Server</span><span>Core</span><span>Patch</span><span>File</span></div>
            {requirements.map((row) => <div className="table-row" role="row" key={row[0]}>{row.map((cell, index) => <span key={cell + index} data-label={["Server", "Core", "Patch", "File"][index]}>{cell}</span>)}</div>)}
          </div>
        </div>
      </section>

      <section className="section shell documentation-section" id="documentation">
        <div className="section-heading-row">
          <div><p className="eyebrow"><span /> Learn as you go</p><h2>A public guide outside.<br />A matched manual inside.</h2></div>
          <p>The public site can introduce the workflow, installation, examples, and project. Detailed usage and problem-solving guidance remains available in CORPUSfm, matched to the installed version.</p>
        </div>
        <div className="documentation-grid">
          <a href={`${siteBase}docs/`}><article><span>Get started</span><h3>Install and bring in the first schema</h3><p>Import, Paste, and the path to a first Explorer and Diff.</p><b>Open the guide →</b></article></a>
          <a href={`${siteBase}docs/explorer/`}><article><span>Workflows</span><h3>Follow real FileMaker development work</h3><p>Understand an inherited solution, compare versions, establish a team library, and work with AI.</p><b>Explore workflows →</b></article></a>
          <a href={`${siteBase}docs/mcp/`}><article><span>AI</span><h3>Connect an assistant to the same evidence</h3><p>Set up MCP, search by meaning, and follow the AI build loop from understanding through change.</p><b>Work with AI →</b></article></a>
          <a href={`${siteBase}docs/mcp-client-cannot-connect/`}><article><span>Troubleshooting</span><h3>Move from a problem to a tested solution</h3><p>Use problem-and-solution recipes for MCP access and the CORPUSfm update path.</p><b>Find a solution →</b></article></a>
        </div>
      </section>

      <section className="project-section" id="open-source">
        <div className="shell project-grid">
          <div><p className="eyebrow light"><span /> Project stewardship</p><h2>Open source,<br />with one product story.</h2></div>
          <div>
            <p>CORPUSfm is published and supported by <strong>PINAX SOFTWARE LLC</strong> and licensed under Apache 2.0.</p>
            <p>Its public repository contains the product source, installer source, public site, documentation, tests, and legal files as they are published.</p>
            <a className="text-link" href={repositoryUrl}>Visit the repository <span>↗</span></a>
            <small>FileMaker is a registered trademark of Claris International Inc. CORPUSfm is an independent tool and is not affiliated with or endorsed by Claris.</small>
          </div>
        </div>
      </section>

      <footer className="site-footer shell">
        <a className="brand" href="#top" aria-label="CORPUSfm home"><Brand /></a>
        <p>Take your FileMaker work further.</p>
        <span>Apache 2.0 · Published and supported by PINAX SOFTWARE LLC</span>
      </footer>
    </main>
  );
}
