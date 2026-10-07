import { mkdirSync } from "node:fs";
import { DatabaseSync } from "node:sqlite";
export async function createStore() {
  if (process.env.DATABASE_URL) {
    const { Pool } = await import("pg");
    const pool = new Pool({ connectionString: process.env.DATABASE_URL });
    await pool.query(
      "CREATE TABLE IF NOT EXISTS blue_lock_state (id INTEGER PRIMARY KEY, value JSONB NOT NULL)",
    );
    return {
      read: async () =>
        (await pool.query("SELECT value FROM blue_lock_state WHERE id=1"))
          .rows[0]?.value,
      write: async (s) => {
        await pool.query(
          "INSERT INTO blue_lock_state(id,value) VALUES(1,$1) ON CONFLICT(id) DO UPDATE SET value=$1",
          [JSON.stringify(s)],
        );
      },
    };
  }
  mkdirSync(process.env.DATA_DIR || "data", { recursive: true });
  const db = new DatabaseSync(
    `${process.env.DATA_DIR || "data"}/blue-lock.sqlite`,
  );
  db.exec(
    "PRAGMA journal_mode=WAL; CREATE TABLE IF NOT EXISTS state(id INTEGER PRIMARY KEY,value TEXT NOT NULL)",
  );
  return {
    read: async () => {
      const r = db.prepare("SELECT value FROM state WHERE id=1").get();
      return r ? JSON.parse(r.value) : undefined;
    },
    write: async (s) => {
      db.prepare(
        "INSERT INTO state VALUES(1,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value",
      ).run(JSON.stringify(s));
    },
  };
}
