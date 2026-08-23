import Docs from "./docs-page";
import Home from "./page";

export default function App() {
  const base = import.meta.env.BASE_URL;
  const pathname = window.location.pathname;
  const relative = pathname.startsWith(base) ? pathname.slice(base.length) : pathname.replace(/^\//, "");
  const match = relative.match(/^docs(?:\/([^/]+))?\/?$/);
  if (match) return <Docs slug={match[1]} />;
  return <Home />;
}
