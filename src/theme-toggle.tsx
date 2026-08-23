"use client";

export default function ThemeToggle() {
  function toggleTheme() {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    window.localStorage.setItem("corpusfm-site-theme", next);
  }

  return <button className="theme-toggle" type="button" onClick={toggleTheme} aria-label="Toggle light or dark theme"><span className="theme-light" aria-hidden="true">☀</span><span className="theme-dark" aria-hidden="true">◐</span><small>Theme</small></button>;
}
