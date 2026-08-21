import { readFile, readdir } from "node:fs/promises";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const appRoot = fileURLToPath(new URL("..", import.meta.url));
const sourceRoot = join(appRoot, "src");
const tokenPath = join(sourceRoot, "design", "tokens.css");
const allowedRemoteText = new Set();
const failures = [];

async function filesBelow(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await filesBelow(path)));
    else files.push(path);
  }
  return files;
}

for (const path of await filesBelow(sourceRoot)) {
  const extension = extname(path);
  if (![".css", ".ts", ".tsx"].includes(extension)) continue;
  const contents = await readFile(path, "utf8");
  const name = relative(appRoot, path);

  if (path !== tokenPath && /#[0-9a-f]{3,8}\b/iu.test(contents)) {
    failures.push(`${name}: couleur littérale hors tokens.css`);
  }
  if (/dangerouslySetInnerHTML/iu.test(contents)) {
    failures.push(`${name}: rendu HTML actif interdit`);
  }
  for (const match of contents.matchAll(/https?:\/\/[^\s"')]+/giu)) {
    if (!allowedRemoteText.has(match[0])) {
      failures.push(`${name}: ressource ou URL distante interdite (${match[0]})`);
    }
  }
  for (const match of contents.matchAll(/font-family\s*:\s*([^;]+)/giu)) {
    if (!match[1]?.trimStart().startsWith("var(")) {
      failures.push(`${name}: fonte locale hors token`);
    }
  }
}

const index = await readFile(join(appRoot, "index.html"), "utf8");
if (!index.includes("default-src 'self'")) failures.push("index.html: CSP default-src manquante");
if (!index.includes("font-src 'self'")) failures.push("index.html: fontes embarquées non bornées");

if (failures.length > 0) {
  for (const failure of failures) process.stderr.write(`visual-contract: ${failure}\n`);
  process.exit(1);
}

process.stdout.write("visual-contract: PASS\n");
