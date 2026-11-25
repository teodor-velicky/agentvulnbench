import net from "node:net";

let up = 0;
for (const port of [8080, 9999]) {
  await new Promise((done) => {
    const s = net.connect(port, "127.0.0.1", () => { up++; s.end(); done(); });
    s.on("error", done);
  });
}
process.exit(up === 2 ? 0 : 1);
