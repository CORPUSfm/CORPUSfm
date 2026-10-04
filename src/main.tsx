import { StrictMode } from "react";
import { createRoot, hydrateRoot } from "react-dom/client";
import App from "./app";
import "./globals.css";

const container = document.getElementById("root")!;
const app = <StrictMode><App /></StrictMode>;
// Routes that must read without JavaScript are rendered at build time; hydrate those instead of
// replacing the markup a reader may already be using.
if (container.hasChildNodes()) hydrateRoot(container, app);
else createRoot(container).render(app);
