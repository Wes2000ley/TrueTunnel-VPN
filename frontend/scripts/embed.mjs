import fs from "node:fs";
import path from "node:path";

// Only build output is written here. Production assets become read-only EXE
// resources; the desktop host never loads JavaScript from an editable folder.
const output = path.resolve(process.argv[2] ?? "../build/desktop-assets");
const dist = path.resolve(import.meta.dirname, "../dist");
fs.mkdirSync(output, { recursive: true });
const assets = [];
function walk(directory, relative = "") {
  for (const file of fs.readdirSync(directory).sort()) {
    const name = path.posix.join(relative, file);
    const full = path.join(directory, file);
    if (fs.statSync(full).isDirectory()) walk(full, name);
    else assets.push({ name: `/${name}`, full });
  }
}
walk(dist);
const mime = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".woff2": "font/woff2",
};
const rows = assets.map((asset, index) => ({
  ...asset,
  id: 1001 + index,
  mime: mime[path.extname(asset.name)] ?? "application/octet-stream",
}));
fs.writeFileSync(
  path.join(output, "DesktopAssets.rc"),
  rows
    .map((asset) => `${asset.id} RCDATA "${asset.full.replaceAll("\\", "/")}"`)
    .join("\n") + "\n",
);
fs.writeFileSync(
  path.join(output, "DesktopAssets.h"),
  "#pragma once\nstruct EmbeddedAsset { const wchar_t* path; int id; const wchar_t* mime; };\ninline constexpr EmbeddedAsset kDesktopAssets[] = {\n" +
    rows
      .map((asset) => `  {L"${asset.name}", ${asset.id}, L"${asset.mime}"},`)
      .join("\n") +
    "\n};\n",
);
console.log(
  `Embedded ${rows.length} frontend assets (${rows.reduce((size, asset) => size + fs.statSync(asset.full).size, 0)} bytes)`,
);
