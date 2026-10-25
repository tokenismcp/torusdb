// SPDX-License-Identifier: Apache-2.0
// Run a keyless server first (pip install ./parser ./core ./drivers/python ./server, see
// docs/GETTING_STARTED.md):
//   torusdb-server --port 8533
// then, in drivers/typescript:  npm ci && npx ts-node example.ts
// (creates table `emp`; start a fresh server to run it again)
import { Client, eq } from "./src/torusdb";

async function main() {
  // add { token: "...", tls: true, ca: fs.readFileSync("ca.pem") } for a protected server
  const db = await Client.connect("127.0.0.1", 8533);

  await db.createTable("emp", [
    { name: "id", type: "int", policy: "plain" },
    { name: "dept", type: "int", policy: "plain" },
    { name: "salary", type: "rational", policy: "encrypted" },
    { name: "rate", type: "int", policy: "paired" },
    { name: "hours", type: "int", policy: "paired" },
  ]);

  await db.insertMany("emp", [
    { id: 1, dept: 5, salary: { num: 8000n, den: 1n }, rate: 50, hours: 40 },
    { id: 2, dept: 5, salary: { num: 9000n, den: 1n }, rate: 60, hours: 35 },
    { id: 3, dept: 9, salary: { num: 7000n, den: 1n }, rate: 45, hours: 40 },
  ]);

  console.log("SUM(salary)            =", await db.sum("emp", "salary"));            // 24000n
  console.log("SUM(salary) dept=5     =", await db.sum("emp", "salary", eq("dept", 5))); // 17000n
  console.log("DOT(rate, hours)       =", await db.dot("emp", "rate", "hours"));     // 5900n
  console.log("COUNT(*)               =", await db.count("emp"));                    // 3

  // all-or-nothing, on the server AND in the local mask vault
  await db.transaction(async () => {
    await db.update("emp", { salary: { num: 8500n, den: 1n } }, eq("id", 1));
  });

  // self-join: employees of the same dept
  const j = await db.join("emp", [{ table: "emp", alias: "b", leftCol: "dept", rightCol: "dept" }], { alias: "a" });
  console.log("self-join rows         =", db.joinCount(j), " SUM(b.salary) =", await db.joinSum(j, "b", "salary"));

  db.close();
}
main().catch((e) => { console.error(e); process.exit(1); });
