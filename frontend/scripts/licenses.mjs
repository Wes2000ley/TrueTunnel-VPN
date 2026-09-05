import fs from "node:fs";
import path from "node:path";
const root = path.resolve(import.meta.dirname, "..");
const output = path.resolve(process.argv[2]);
const packages = new Set();
const notices = [];
function visit(name) {
  if (packages.has(name)) return;
  packages.add(name);
  const folder = path.join(root, "node_modules", name);
  const metadata = JSON.parse(
    fs.readFileSync(path.join(folder, "package.json"), "utf8"),
  );
  const licenseFiles = fs
    .readdirSync(folder)
    .filter((file) => /^(licen[sc]e|copying|notice)(\.|$)/i.test(file));
  // This pinned npm tarball omits LICENSE; preserve the exact upstream notice.
  const fallback =
    name === "react-remove-scroll-bar" && metadata.version === "2.3.8"
      ? fs.readFileSync(
          path.join(root, "../licenses/react-remove-scroll-bar-MIT.txt"),
          "utf8",
        )
      : "";
  if (!licenseFiles.length && !fallback)
    throw new Error(`Missing license for shipped frontend dependency ${name}`);
  notices.push(
    `${name} ${metadata.version}\n${"=".repeat(64)}\n${fallback || licenseFiles.map((file) => fs.readFileSync(path.join(folder, file), "utf8")).join("\n")}\n`,
  );
  for (const dependency of Object.keys(metadata.dependencies ?? {}))
    visit(dependency);
}
for (const name of Object.keys(
  JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"))
    .dependencies,
))
  visit(name);
fs.mkdirSync(output, { recursive: true });
fs.writeFileSync(
  path.join(output, "Frontend-NOTICES.txt"),
  "TrueTunnel bundled frontend licenses\n\n" + notices.join("\n"),
);
console.log(
  `Collected exact license text for ${packages.size} frontend packages`,
);
