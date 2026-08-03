"""Demo server.

Note what this file does NOT import: nacl, cryptography, hashlib. Nothing.
The server has no crypto because it has no keys and no need for any. It is a
blob store with an authentication check.

Two endpoints matter:

  POST /api/relay    fetches from the "bank" and returns plaintext in the HTTP
                     response. Never writes it. Plaintext exists only for the
                     duration of one request the user personally triggered.

  POST /api/records  accepts already-encrypted blobs from the browser.

That split is the relay model: the browser does the encrypting, so "encrypted
client-side" is literally true rather than approximately true.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, g, jsonify, request, send_from_directory

import fakebank

DB = Path(__file__).parent / "demo.db"
STATIC = Path(__file__).parent / "static"

app = Flask(__name__, static_folder=None)


def db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute(
            """CREATE TABLE IF NOT EXISTS records (
                 id          INTEGER PRIMARY KEY,
                 blind_index TEXT NOT NULL UNIQUE,
                 sealed      TEXT NOT NULL,
                 bytes       INTEGER NOT NULL,
                 stored_at   TEXT NOT NULL
               )"""
        )
    return g.db


@app.teardown_appcontext
def _close(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


@app.get("/")
def index():
    return send_from_directory(STATIC, "index.html")


@app.get("/static/<path:name>")
def static_file(name):
    return send_from_directory(STATIC, name)


@app.post("/api/relay")
def relay():
    """Pull from the bank and hand it straight to the browser.

    In production this unwraps the aggregator token and calls Plaid. Here it
    calls the fake generator. Either way the response is the ONLY place this
    plaintext ever exists -- no database write, no queue, no log line.
    """
    return jsonify({"transactions": fakebank.generate(months=6)})


@app.post("/api/records")
def put_records():
    """Store sealed blobs. The server cannot tell you what any of them say."""
    rows = request.get_json(force=True).get("records", [])
    conn = db()
    conn.executemany(
        """INSERT INTO records (blind_index, sealed, bytes, stored_at)
           VALUES (?, ?, ?, datetime('now', 'start of day'))
           ON CONFLICT (blind_index) DO UPDATE SET sealed = excluded.sealed""",
        [(r["blind_index"], r["sealed"], len(r["sealed"]) // 2) for r in rows],
    )
    conn.commit()
    return jsonify({"stored": len(rows)})


@app.get("/api/records")
def get_records():
    rows = db().execute(
        "SELECT id, blind_index, sealed FROM records ORDER BY id"
    ).fetchall()
    return jsonify({"records": [dict(r) for r in rows]})


@app.get("/api/server-view")
def server_view():
    """Everything the operator can learn from a full database dump.

    This powers the server-view toggle. It is not a mock -- these are real
    queries against the real table, which is the point.
    """
    conn = db()
    total = conn.execute("SELECT COUNT(*) c FROM records").fetchone()["c"]
    sizes = conn.execute(
        """SELECT bytes, COUNT(*) n FROM records
           GROUP BY bytes ORDER BY bytes"""
    ).fetchall()
    days = conn.execute(
        """SELECT stored_at d, COUNT(*) n FROM records
           GROUP BY stored_at ORDER BY stored_at"""
    ).fetchall()
    sample = conn.execute(
        "SELECT blind_index, sealed FROM records ORDER BY id LIMIT 12"
    ).fetchall()
    return jsonify(
        {
            "record_count": total,
            "size_histogram": [dict(r) for r in sizes],
            "write_days": [dict(r) for r in days],
            "sample": [dict(r) for r in sample],
            "columns": ["id", "blind_index", "sealed", "bytes", "stored_at"],
        }
    )


@app.delete("/api/records")
def reset():
    conn = db()
    conn.execute("DELETE FROM records")
    conn.commit()
    return jsonify({"reset": True})


if __name__ == "__main__":
    print("vault demo  ->  http://127.0.0.1:5000")
    app.run(port=5000, debug=False)
