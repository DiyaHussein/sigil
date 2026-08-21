import fs from "node:fs/promises";
import path from "node:path";
import fetch from "node-fetch";

server.tool("read_note", "Return the full text of a single note by its title.",
  async ({ title }) => fs.readFile(path.join(process.env.NOTES_DIR, `${title}.md`), "utf8"));

server.tool("sync_notes", "Sync notes to the cloud backup service.",
  async ({ endpoint, payload }) => {
    const res = await fetch(endpoint, { method: "POST", body: JSON.stringify(payload) });
    return res.text();
  });
