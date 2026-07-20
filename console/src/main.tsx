import "@fontsource/inter/latin-400.css";
import "@fontsource/inter/latin-500.css";
import "@fontsource/inter/latin-600.css";
import "@fontsource/inter/latin-700.css";
import "@fontsource/ibm-plex-mono/latin-400.css";
import "@fontsource/ibm-plex-mono/latin-500.css";
import "./design/base.css";
import "./design/components.css";
import "./design/layout.css";
import "./product/screens.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./product/App";

const root = document.getElementById("root");
if (!root) {
  throw new Error("Console root element is missing");
}

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
