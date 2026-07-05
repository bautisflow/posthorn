// Generates the docs-site Changelog page from the repo-root CHANGELOG.md.
//
// Single source of truth: edit CHANGELOG.md, never the generated page.
// Wired into dev/start/build in package.json; the output is gitignored.

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const SRC = new URL('../../CHANGELOG.md', import.meta.url);
const OUT = new URL('../src/content/docs/changelog.md', import.meta.url);
const REPO_BLOB = 'https://github.com/craigmccaskill/posthorn/blob/main/';

const frontmatter = `---
title: Changelog
description: Release notes for Posthorn, version by version — every notable change since v1.0.0.
---

<!-- Generated from CHANGELOG.md by scripts/gen-changelog.mjs. Do not edit. -->

`;

let raw;
try {
  raw = readFileSync(SRC, 'utf8');
} catch (err) {
  console.error(`gen-changelog: cannot read ${fileURLToPath(SRC)}: ${err.message}`);
  process.exit(1);
}

const body = raw
  // Drop the top-level "# Changelog" H1 — Starlight renders the frontmatter title as the page H1.
  .replace(/^#\s+Changelog[^\n]*\n/, '')
  // Rewrite relative repo links (e.g. spec/...) to absolute GitHub URLs so they resolve on the site.
  .replace(/\]\((?!https?:\/\/|#|\/|mailto:)([^)]+)\)/g, `](${REPO_BLOB}$1)`)
  .trimStart();

writeFileSync(OUT, frontmatter + body);
console.log(`gen-changelog: wrote ${fileURLToPath(OUT)}`);
