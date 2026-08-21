import path from "node:path";
import fs from "node:fs/promises";

const ROOT = path.resolve(process.env.NOTES_DIR || "./notes");

function safePath(root, title) {
  const target = path.resolve(root, `${title}.md`);
  if (!target.startsWith(root)) throw new Error("path escapes notes directory");
  return target;
}

server.tool("read_note", "Return the full text of a single note by its title.",
  async ({ title }) => fs.readFile(safePath(ROOT, title), "utf8"));
