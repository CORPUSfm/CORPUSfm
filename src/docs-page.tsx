import docs from "./generated/docs";
import { Brand, installGuideUrl, repositoryUrl } from "./page";
import ThemeToggle from "./theme-toggle";

const siteBase = import.meta.env.BASE_URL;
const sectionOrder = ["Get started", "Concepts", "Workflows", "AI", "Integrations", "Troubleshooting"];
type Article = (typeof docs)[number];

function Header() {
  return (
    <header className="site-header docs-header shell">
      <a className="brand" href={siteBase} aria-label="CORPUSfm home"><Brand /></a>
      <nav aria-label="Documentation navigation">
        <a href={`${siteBase}docs/`}>Documentation</a>
        <a href={installGuideUrl}>Install</a>
      </nav>
      <div className="header-actions"><ThemeToggle /><a className="nav-action" href={repositoryUrl}>GitHub <span aria-hidden="true">↗</span></a></div>
    </header>
  );
}

function GuideIndex() {
  return (
    <main className="docs-site">
      <Header />
      <section className="docs-hero shell">
        <p className="eyebrow"><span /> Product guide</p>
        <h1>Learn CORPUSfm<br />as you use it.</h1>
        <p>Start with a schema, follow a FileMaker workflow, connect an AI assistant, or solve a specific problem. These articles come from the same documentation authority as the installed manual.</p>
      </section>
      <section className="docs-index shell" aria-label="Documentation articles">
        {sectionOrder.map((section) => {
          const articles = docs.filter((article) => article.section === section);
          return <section key={section} className="docs-section"><h2>{section}</h2><div>{articles.map((article) => <a key={article.slug} href={`${siteBase}docs/${article.slug}/`}><strong>{article.title}</strong><p>{article.summary}</p><span>Read →</span></a>)}</div></section>;
        })}
      </section>
      <Footer />
    </main>
  );
}

function ArticlePage({ article }: { article: Article }) {
  const sections = sectionOrder.map((section) => ({ section, articles: docs.filter((item) => item.section === section) }));
  const html = article.html.replaceAll("__CORPUSFM_BASE__", siteBase);
  return (
    <main className="docs-site">
      <Header />
      <div className="docs-layout shell">
        <aside className="docs-sidebar" aria-label="Product guide">
          <a className="docs-back" href={`${siteBase}docs/`}>← All documentation</a>
          {sections.map(({ section, articles }) => <section key={section}><h2>{section}</h2>{articles.map((item) => <a className={item.slug === article.slug ? "active" : ""} aria-current={item.slug === article.slug ? "page" : undefined} key={item.slug} href={`${siteBase}docs/${item.slug}/`}>{item.title}</a>)}</section>)}
        </aside>
        <article className="docs-article">
          <p className="docs-section-label">{article.section}</p>
          <div dangerouslySetInnerHTML={{ __html: html }} />
          <footer><a href={`${siteBase}docs/`}>← Back to documentation</a><span>Also available in the version-matched in-app manual.</span></footer>
        </article>
      </div>
      <Footer />
    </main>
  );
}

function Footer() {
  return <footer className="site-footer shell"><a className="brand" href={siteBase} aria-label="CORPUSfm home"><Brand /></a><p>Product documentation from the CORPUSfm source.</p><span>Apache 2.0 · Published and supported by PINAX SOFTWARE LLC</span></footer>;
}

export default function Docs({ slug }: { slug?: string }) {
  if (!slug) return <GuideIndex />;
  const article = docs.find((item) => item.slug === slug);
  if (!article) return <GuideIndex />;
  return <ArticlePage article={article} />;
}
