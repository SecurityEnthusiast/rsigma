import fs from "node:fs";
import path from "node:path";
import { parse as parseYaml } from "yaml";

/** @type {Record<string, unknown> | null} */
let rsigmaVars = null;
/** @type {string | null} */
let repoRoot = null;

/**
 * Walk up from a starting directory until we find the workspace `Cargo.toml`
 * (the repository root). The docmd project lives under `docs/`, so the repo
 * root is a parent of the current working directory.
 *
 * @param {string} startDir
 * @returns {string}
 */
function findRepoRoot(startDir) {
  let dir = path.resolve(startDir);
  for (;;) {
    if (fs.existsSync(path.join(dir, "Cargo.toml"))) {
      return dir;
    }
    const parent = path.dirname(dir);
    if (parent === dir) {
      return path.resolve(startDir);
    }
    dir = parent;
  }
}

/**
 * @param {string} root Repository root (directory containing Cargo.toml).
 * @returns {Record<string, unknown>}
 */
function loadRsigmaVars(root) {
  const cargoPath = path.join(root, "Cargo.toml");
  const varsPath = path.join(root, "docs", "_data", "vars.yml");
  const cargoText = fs.readFileSync(cargoPath, "utf8");
  const staticVars = parseYaml(fs.readFileSync(varsPath, "utf8"));

  const pkg = {};
  const inWorkspacePackage = cargoText.match(
    /\[workspace\.package\]([\s\S]*?)(?:\n\[|\n*$)/,
  );
  if (inWorkspacePackage) {
    for (const line of inWorkspacePackage[1].split("\n")) {
      const m = line.match(/^(\w[\w-]*) = "(.*)"\s*$/);
      if (m) {
        pkg[m[1]] = m[2];
      }
    }
  }

  const rsigma = {
    ...(staticVars.rsigma ?? {}),
    version: pkg.version,
    edition: pkg.edition,
    msrv: pkg["rust-version"],
    license: pkg.license,
  };

  return { rsigma };
}

/**
 * @param {Record<string, unknown>} vars
 * @param {string} dottedPath
 * @returns {unknown}
 */
function getVar(vars, dottedPath) {
  return dottedPath.split(".").reduce((obj, key) => {
    if (obj && typeof obj === "object" && key in obj) {
      return /** @type {Record<string, unknown>} */ (obj)[key];
    }
    return undefined;
  }, /** @type {unknown} */ (vars));
}

/**
 * @param {unknown} value
 * @param {string | undefined} search
 * @param {string | undefined} replaceWith
 * @returns {string}
 */
function applyReplaceFilter(value, search, replaceWith) {
  const text = String(value ?? "");
  if (search === undefined || replaceWith === undefined) {
    return text;
  }
  return text.split(search).join(replaceWith);
}

/**
 * @param {string} src
 * @param {Record<string, unknown>} vars
 * @returns {string}
 */
function substituteRsigmaMacros(src, vars) {
  return src.replace(
    /\{\{\s*rsigma\.([\w.]+)\s*(?:\|\s*replace\("([^"]*)",\s*"([^"]*)"\))?\s*\}\}/g,
    (_match, dottedPath, search, replaceWith) =>
      applyReplaceFilter(getVar(vars, `rsigma.${dottedPath}`), search, replaceWith),
  );
}

/**
 * @param {string} src
 * @param {string} filePath
 * @param {string} projectRoot
 * @returns {string}
 */
function inlineIncludeMarkdown(src, filePath, projectRoot) {
  const includeRe =
    /\{%\s*include-markdown\s+"([^"]+)"\s*%\}/g;
  return src.replace(includeRe, (_match, relPath) => {
    const baseDir = path.dirname(filePath);
    const target = path.resolve(baseDir, relPath);
    const relToRoot = path.relative(projectRoot, target);
    if (relToRoot.startsWith("..") || path.isAbsolute(relToRoot)) {
      throw new Error(
        `include-markdown target escapes project root: ${relPath} from ${filePath}`,
      );
    }
    return fs.readFileSync(target, "utf8").trimEnd();
  });
}

/**
 * Turn GitHub issue/PR shorthand (`#123`) into links, matching the old
 * MkDocs `pymdownx.magiclink` behaviour. Skips fenced code blocks and inline
 * code spans, and leaves already-linked references (`[#123](...)`) untouched.
 * `/issues/N` redirects to `/pull/N` for pull requests, so it resolves for both.
 *
 * @param {string} md
 * @param {string} repoUrl e.g. https://github.com/timescale/rsigma
 * @returns {string}
 */
function linkifyIssueRefs(md, repoUrl) {
  const base = `${repoUrl.replace(/\/$/, "")}/issues/`;
  // Not preceded by a word char, `[` (existing link text), `#`, `&`, or `/`
  // (URL path/entity); followed by digits ending on a word boundary.
  const issueRe = /(?<![\w[#&/])#(\d+)\b/g;
  // `#N` tokens whose immediately preceding word marks an external reference
  // (a newsletter issue or a SigmaHQ spec proposal), not an rsigma issue/PR.
  const excludeBefore = [
    /\bweekly\s*$/i, // Detection Engineering Weekly #N
    /\bdew\s*$/i, // DEW #N
    /\bsec\s*$/i, // tl;dr sec #N
    /\bnewsletter\s*$/i,
    /\bblacknoise\s*$/i,
    /\bsep\s*$/i, // Sigma Enhancement Proposal #N
    /\bdiscussion\s*$/i, // SigmaHQ spec Discussion #N
    /\bspecification\s*$/i, // (sigma-)specification #N
  ];
  // Split out inline code spans and existing markdown links so `#N` inside
  // them (e.g. `[issue #158](...)`, `[SEP #212](...)`) is never rewritten.
  const skipRe = /(`+[^`]*`+|\[[^\]]*\]\([^)]*\))/;
  const linkInline = (text) =>
    text
      .split(skipRe)
      .map((seg) => {
        if (!seg || seg.startsWith("`") || seg.startsWith("[")) return seg;
        return seg.replace(issueRe, (m, n, offset, str) =>
          excludeBefore.some((re) => re.test(str.slice(0, offset)))
            ? m
            : `[#${n}](${base}${n})`,
        );
      })
      .join("");
  let inFence = false;
  return md
    .split("\n")
    .map((line) => {
      const t = line.trimStart();
      if (t.startsWith("```") || t.startsWith("~~~")) {
        inFence = !inFence;
        return line;
      }
      return inFence ? line : linkInline(line);
    })
    .join("\n");
}

/**
 * Recursively collect every .html file under a directory.
 *
 * @param {string} dir
 * @returns {string[]}
 */
function collectHtmlFiles(dir) {
  /** @type {string[]} */
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...collectHtmlFiles(full));
    } else if (entry.isFile() && entry.name.endsWith(".html")) {
      out.push(full);
    }
  }
  return out;
}

export default {
  plugin: {
    name: "docmd-plugin-rsigma",
    version: "1.0.0",
    capabilities: ["init", "build", "post-build"],
  },

  onConfigResolved(config) {
    repoRoot = findRepoRoot(config._projectRoot ?? process.cwd());
    rsigmaVars = loadRsigmaVars(repoRoot);
  },

  onBeforeParse(src, _frontmatter, filePath) {
    if (!repoRoot) {
      repoRoot = findRepoRoot(process.cwd());
    }
    if (!rsigmaVars) {
      rsigmaVars = loadRsigmaVars(repoRoot);
    }
    let out = inlineIncludeMarkdown(src, filePath ?? repoRoot, repoRoot);
    out = substituteRsigmaMacros(out, rsigmaVars);
    // Linkify `#123` issue/PR shorthand on the release-notes page (the inlined
    // CHANGELOG), replacing the old MkDocs magiclink behaviour.
    if (typeof filePath === "string" && /release-notes\.md$/.test(filePath)) {
      const repoUrl =
        /** @type {any} */ (rsigmaVars)?.rsigma?.repo_url ||
        "https://github.com/timescale/rsigma";
      out = linkifyIssueRefs(out, repoUrl);
    }
    return out;
  },

  // docmd emits page-relative asset/link URLs (e.g. `../../assets/...`) together
  // with a `<base href="{siteRoot}">` tag. The base tag re-roots those relative
  // URLs at the site root, which breaks deep pages when combined with how the
  // client resolves paths. The client JS reads `window.DOCMD_BASE`, not the tag,
  // so removing the tag lets relative URLs resolve against the real document URL.
  onPostBuild(ctx) {
    const outputDir = ctx?.outputDir ?? path.join(process.cwd(), "site");
    const log = typeof ctx?.log === "function" ? ctx.log : () => {};
    let stripped = 0;
    for (const file of collectHtmlFiles(outputDir)) {
      const html = fs.readFileSync(file, "utf8");
      const next = html.replace(/[ \t]*<base\b[^>]*>\n?/i, "");
      if (next !== html) {
        fs.writeFileSync(file, next);
        stripped += 1;
      }
    }
    log(`docmd-plugin-rsigma: stripped <base> tag from ${stripped} pages`);
  },
};
