import { useEffect } from "react";
import Docs from "./docs-page";
import InstallPage from "./install-page";
import Home from "./page";

export type Route = { page: "home" } | { page: "install" } | { page: "docs"; slug?: string };

export function resolveRoute(pathname: string, base: string): Route {
  const relative = pathname.startsWith(base) ? pathname.slice(base.length) : pathname.replace(/^\//, "");
  if (/^install\/?$/.test(relative)) return { page: "install" };
  const match = relative.match(/^docs(?:\/([^/]+))?\/?$/);
  if (match) return { page: "docs", slug: match[1] };
  return { page: "home" };
}

export default function App({ pathname = window.location.pathname }: { pathname?: string }) {
  const route = resolveRoute(pathname, import.meta.env.BASE_URL);
  // A client-rendered page has no target yet when the browser applies the URL fragment, so links
  // such as the release notes' #windows-trust would otherwise land at the top of the page.
  useEffect(() => {
    let id = "";
    try {
      id = decodeURIComponent(window.location.hash.slice(1));
    } catch {
      return; // a malformed escape names no element on this site
    }
    if (id) document.getElementById(id)?.scrollIntoView();
  }, []);
  if (route.page === "install") return <InstallPage />;
  if (route.page === "docs") return <Docs slug={route.slug} />;
  return <Home />;
}
