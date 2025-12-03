from flask import Flask, request, jsonify, send_file, make_response
import sqlite3
from datetime import datetime
import os
import csv
import io

app = Flask(__name__, static_folder="public", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

DB_PATH = "data.sqlite"
ADMIN_PIN = os.environ.get("ADMIN_PIN", "6162")


def db():
	conn = sqlite3.connect(DB_PATH)
	conn.row_factory = sqlite3.Row
	return conn


def ensure_column(conn, table, col_name, col_type):
	cols = [r["name"] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
	if col_name not in cols:
		conn.execute(f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}")


def init_db():
	conn = db()
	conn.execute("""
		CREATE TABLE IF NOT EXISTS submissions (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			created_at TEXT NOT NULL,

			public_ip TEXT,
			public_ipv4 TEXT,
			public_ipv6 TEXT,

			country TEXT,
			region TEXT,
			city TEXT,
			postal TEXT,

			isp TEXT,
			org TEXT,
			asn TEXT,

			ip_lat REAL,
			ip_lon REAL,

			gps_lat REAL,
			gps_lon REAL,
			gps_accuracy_m REAL,

			is_vpn INTEGER,
			is_proxy INTEGER,
			is_tor INTEGER,

			device_name TEXT,
			platform TEXT,
			language TEXT,
			timezone TEXT,
			screen TEXT,
			viewport TEXT,
			device_pixel_ratio REAL,
			touch_points INTEGER,
			user_agent TEXT,

			referrer TEXT,
			page_url TEXT
		)
	""")

	# Migrations
	ensure_column(conn, "submissions", "public_ipv4", "TEXT")
	ensure_column(conn, "submissions", "public_ipv6", "TEXT")
	ensure_column(conn, "submissions", "postal", "TEXT")
	ensure_column(conn, "submissions", "isp", "TEXT")
	ensure_column(conn, "submissions", "org", "TEXT")
	ensure_column(conn, "submissions", "asn", "TEXT")
	ensure_column(conn, "submissions", "ip_lat", "REAL")
	ensure_column(conn, "submissions", "ip_lon", "REAL")
	ensure_column(conn, "submissions", "gps_lat", "REAL")
	ensure_column(conn, "submissions", "gps_lon", "REAL")
	ensure_column(conn, "submissions", "gps_accuracy_m", "REAL")
	ensure_column(conn, "submissions", "is_vpn", "INTEGER")
	ensure_column(conn, "submissions", "is_proxy", "INTEGER")
	ensure_column(conn, "submissions", "is_tor", "INTEGER")
	ensure_column(conn, "submissions", "referrer", "TEXT")
	ensure_column(conn, "submissions", "page_url", "TEXT")

	conn.commit()
	conn.close()


init_db()


def require_admin(req):
	return req.headers.get("x-admin-pin", "") == ADMIN_PIN


def clean_text(x, max_len=1000):
	s = "" if x is None else str(x)
	return s.strip()[:max_len]


def fnum(x):
	try:
		if x is None or x == "":
			return None
		return float(x)
	except Exception:
		return None


def inum(x):
	try:
		if x is None or x == "":
			return None
		return int(x)
	except Exception:
		return None


@app.after_request
def add_security_headers(resp):
	resp.headers["X-Content-Type-Options"] = "nosniff"
	resp.headers["X-Frame-Options"] = "DENY"
	resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
	resp.headers["Permissions-Policy"] = "geolocation=(self), microphone=(), camera=()"
	resp.headers["Content-Security-Policy"] = "default-src 'self' https: data:; img-src 'self' https: data:; style-src 'self' 'unsafe-inline' https:; script-src 'self' 'unsafe-inline' https:;"
	return resp


@app.get("/")
def index():
	return send_file("index.html")


@app.get("/admin")
def admin_page():
	return send_file("admin.html")


@app.post("/api/submit")
def submit():
	try:
		data = request.get_json(force=True, silent=True) or {}

		public_ip = clean_text(data.get("publicIP"), 200)
		public_ipv4 = clean_text(data.get("publicIPv4"), 200)
		public_ipv6 = clean_text(data.get("publicIPv6"), 300)

		di = data.get("deviceInfo") or {}
		geo = data.get("geo") or {}
		gps = data.get("gps") or {}
		page = data.get("page") or {}

		ua = clean_text(di.get("userAgent") or "", 600)
		if not ua:
			return jsonify(ok=False, error="Missing deviceInfo.userAgent"), 400

		conn = db()
		conn.execute("""
			INSERT INTO submissions (
				created_at,
				public_ip, public_ipv4, public_ipv6,
				country, region, city, postal,
				isp, org, asn,
				ip_lat, ip_lon,
				gps_lat, gps_lon, gps_accuracy_m,
				is_vpn, is_proxy, is_tor,
				device_name, platform, language, timezone,
				screen, viewport, device_pixel_ratio, touch_points,
				user_agent,
				referrer, page_url
			) VALUES (
				?,
				?, ?, ?,
				?, ?, ?, ?,
				?, ?, ?,
				?, ?,
				?, ?, ?,
				?, ?, ?,
				?, ?, ?, ?,
				?, ?, ?, ?,
				?,
				?, ?
			)
		""", (
			datetime.utcnow().isoformat() + "Z",

			public_ip, public_ipv4, public_ipv6,

			clean_text(geo.get("country"), 120),
			clean_text(geo.get("region"), 120),
			clean_text(geo.get("city"), 120),
			clean_text(geo.get("postal"), 40),

			clean_text(geo.get("isp"), 200),
			clean_text(geo.get("org"), 200),
			clean_text(geo.get("asn"), 80),

			fnum(geo.get("lat")),
			fnum(geo.get("lon")),

			fnum(gps.get("lat")),
			fnum(gps.get("lon")),
			fnum(gps.get("accuracy_m")),

			inum(geo.get("is_vpn")),
			inum(geo.get("is_proxy")),
			inum(geo.get("is_tor")),

			clean_text(di.get("deviceName") or di.get("platform"), 120),
			clean_text(di.get("platform"), 120),
			clean_text(di.get("language"), 40),
			clean_text(di.get("timeZone"), 80),

			clean_text(di.get("screen"), 40),
			clean_text(di.get("viewport"), 40),
			float(di.get("devicePixelRatio", 0) or 0),
			int(di.get("touchPoints", 0) or 0),

			ua,

			clean_text(page.get("referrer"), 800),
			clean_text(page.get("url"), 800),
		))
		conn.commit()
		conn.close()

		return jsonify(ok=True)
	except Exception as e:
		import traceback
		traceback.print_exc()
		return jsonify(ok=False, error="Server exception: " + repr(e)), 500


@app.get("/api/admin/data")
def admin_data():
	if not require_admin(request):
		return jsonify(ok=False, error="Unauthorized"), 401

	try:
		limit_i = int(request.args.get("limit", "200"))
		limit_i = max(1, min(500, limit_i))
	except Exception:
		limit_i = 200

	conn = db()
	rows = conn.execute("SELECT * FROM submissions ORDER BY id DESC LIMIT ?", (limit_i,)).fetchall()
	conn.close()
	return jsonify(ok=True, rows=[dict(r) for r in rows])


@app.get("/api/admin/export.csv")
def admin_export_csv():
	if not require_admin(request):
		return jsonify(ok=False, error="Unauthorized"), 401

	conn = db()
	rows = conn.execute("SELECT * FROM submissions ORDER BY id DESC LIMIT 500").fetchall()
	conn.close()

	out = io.StringIO()
	fieldnames = list(dict(rows[0]).keys()) if rows else ["id", "created_at"]
	w = csv.DictWriter(out, fieldnames=fieldnames)
	w.writeheader()
	for r in rows:
		w.writerow(dict(r))

	resp = make_response(out.getvalue())
	resp.headers["Content-Type"] = "text/csv; charset=utf-8"
	resp.headers["Content-Disposition"] = "attachment; filename=submissions.csv"
	return resp


@app.post("/api/admin/clear")
def admin_clear():
	if not require_admin(request):
		return jsonify(ok=False, error="Unauthorized"), 401

	conn = db()
	conn.execute("DELETE FROM submissions")
	conn.commit()
	try:
		conn.execute("VACUUM")
		conn.commit()
	except Exception:
		pass
	conn.close()
	return jsonify(ok=True)

if __name__ == "__main__":
	port = int(os.environ.get("PORT", "3000"))
	app.run(host="0.0.0.0", port=port)
