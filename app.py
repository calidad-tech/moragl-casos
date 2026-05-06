import csv
import io
import os
import sqlite3

try:
    import psycopg2
    import psycopg2.extras
except Exception:
    psycopg2 = None
from datetime import datetime
from functools import wraps

from flask import Flask, Response, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(APP_DIR, "moragl_casos.db"))
DATABASE_URL = os.environ.get("DATABASE_URL", "")
USING_POSTGRES = bool(DATABASE_URL and psycopg2)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "cambiar-esta-clave")

CRM_BASE_URL = os.environ.get("CRM_BASE_URL", "https://gestion.moragl.com/admin/contenidos.php")
DEFAULT_PANEL = os.environ.get("DEFAULT_PANEL", "5")

HEADER_SYNONYMS = {
    "did": ["did", "id", "iddeuda", "id_deuda", "id deuda", "id de deuda", "deuda_id", "id_deuda_id", "id_deudaid"],
    "dni": ["dni", "documento", "doc", "nro documento", "nro_documento"],
    "operador": ["operador", "agente", "agent", "usuario", "user", "asesor", "op"],
}


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def pg_sql(sql):
    sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
    sql = sql.replace("SUM(status='pendiente')", "SUM(CASE WHEN status='pendiente' THEN 1 ELSE 0 END)")
    sql = sql.replace("SUM(status='abierto')", "SUM(CASE WHEN status='abierto' THEN 1 ELSE 0 END)")
    sql = sql.replace("SUM(status='trabajado')", "SUM(CASE WHEN status='trabajado' THEN 1 ELSE 0 END)")
    sql = sql.replace("SUM(status='sin_gestion')", "SUM(CASE WHEN status='sin_gestion' THEN 1 ELSE 0 END)")
    sql = sql.replace("SUM(status='error')", "SUM(CASE WHEN status='error' THEN 1 ELSE 0 END)")
    sql = sql.replace("?", "%s")
    return sql


class PGCursorAdapter:
    def __init__(self, connection):
        self.connection = connection
        self.cursor = connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        self.lastrowid = None

    def execute(self, sql, params=()):
        sql2 = pg_sql(sql)
        self.lastrowid = None
        if sql2.strip().lower().startswith("insert into cases") and "returning id" not in sql2.lower():
            sql2 = sql2.rstrip().rstrip(";") + " RETURNING id"
            self.cursor.execute(sql2, params)
            row = self.cursor.fetchone()
            if row:
                self.lastrowid = row["id"]
        else:
            self.cursor.execute(sql2, params)
        return self

    def fetchone(self):
        return self.cursor.fetchone()

    def fetchall(self):
        return self.cursor.fetchall()

    def commit(self):
        self.connection.commit()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type:
            self.connection.rollback()
        self.cursor.close()
        self.connection.close()


class SQLiteConnection(sqlite3.Connection):
    pass


def conn():
    if USING_POSTGRES:
        return PGCursorAdapter(psycopg2.connect(DATABASE_URL))
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    return c


def init_db():
    with conn() as db:
        db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'operator',
            display_name TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
        """)
        db.execute("""
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            did TEXT NOT NULL,
            dni TEXT NOT NULL,
            operator TEXT NOT NULL DEFAULT 'SIN ASIGNAR',
            status TEXT NOT NULL DEFAULT 'pendiente',
            notes TEXT DEFAULT '',
            extra_json TEXT DEFAULT '{}',
            created_at TEXT NOT NULL,
            opened_at TEXT DEFAULT '',
            worked_at TEXT DEFAULT '',
            UNIQUE(did, dni)
        )
        """)
        db.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            created_at TEXT NOT NULL
        )
        """)
        existing = db.execute("SELECT id FROM users WHERE username = ?", ("admin",)).fetchone()
        if not existing:
            db.execute(
                "INSERT INTO users (username, password_hash, role, display_name, active, created_at) VALUES (?,?,?,?,?,?)",
                ("admin", generate_password_hash("admin123"), "admin", "Administrador", 1, now()),
            )
        db.commit()


def normalize_header(h):
    s = "".join(ch for ch in (h or "").strip().lower() if ch.isalnum() or ch in ["_", " "])
    s = " ".join(s.split())
    for key, values in HEADER_SYNONYMS.items():
        if s in values:
            return key
    return s


def parse_csv_upload(file_storage):
    raw = file_storage.read()
    text = raw.decode("utf-8-sig", errors="replace")
    sample = text[:2048]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=";,	,")
    except Exception:
        dialect = csv.excel
        dialect.delimiter = ";"
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    if not reader.fieldnames:
        return []
    normalized = [normalize_header(h) for h in reader.fieldnames]
    rows = []
    for row in reader:
        obj = {}
        for original, norm in zip(reader.fieldnames, normalized):
            obj[norm] = (row.get(original) or "").strip()
        if obj.get("did") and obj.get("dni"):
            rows.append(obj)
    return rows


def current_user():
    if "user_id" not in session:
        return None
    with conn() as db:
        return db.execute("SELECT * FROM users WHERE id=? AND active=1", (session["user_id"],)).fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u:
            return redirect(url_for("login"))
        if u["role"] != "admin":
            flash("No tenés permisos para acceder a esa pantalla.", "error")
            return redirect(url_for("operator_cases"))
        return fn(*args, **kwargs)
    return wrapper


def add_log(case_id, action, detail=""):
    u = current_user()
    username = u["username"] if u else "sistema"
    with conn() as db:
        db.execute(
            "INSERT INTO logs (case_id, username, action, detail, created_at) VALUES (?,?,?,?,?)",
            (case_id, username, action, detail, now()),
        )
        db.commit()


def crm_link(case_row, panel=None):
    panel = panel or DEFAULT_PANEL
    return f"{CRM_BASE_URL}?did={case_row['did']}&panelsel={panel}"


@app.context_processor
def inject_globals():
    return {"current_user": current_user(), "crm_link": crm_link}


@app.route("/")
def index():
    u = current_user()
    if not u:
        return redirect(url_for("login"))
    if u["role"] == "admin":
        return redirect(url_for("dashboard"))
    return redirect(url_for("operator_cases"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with conn() as db:
            u = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
        if u and check_password_hash(u["password_hash"], password):
            session["user_id"] = u["id"]
            add_log(None, "login", f"Inició sesión {username}")
            return redirect(url_for("index"))
        flash("Usuario o clave incorrectos.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    add_log(None, "logout", "Cerró sesión")
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@admin_required
def dashboard():
    with conn() as db:
        stats = db.execute("""
            SELECT 
              COUNT(*) total,
              SUM(status='pendiente') pendiente,
              SUM(status='abierto') abierto,
              SUM(status='trabajado') trabajado,
              SUM(status='sin_gestion') sin_gestion,
              SUM(status='error') error
            FROM cases
        """).fetchone()
        by_operator = db.execute("""
            SELECT operator,
              COUNT(*) total,
              SUM(status='pendiente') pendiente,
              SUM(status='abierto') abierto,
              SUM(status='trabajado') trabajado,
              SUM(status='sin_gestion') sin_gestion,
              SUM(status='error') error
            FROM cases
            GROUP BY operator
            ORDER BY operator
        """).fetchall()
    return render_template("dashboard.html", stats=stats, by_operator=by_operator)


@app.route("/upload", methods=["GET", "POST"])
@admin_required
def upload():
    if request.method == "POST":
        f = request.files.get("file")
        default_operator = request.form.get("default_operator", "SIN ASIGNAR").strip() or "SIN ASIGNAR"
        replace = request.form.get("replace") == "1"
        if not f:
            flash("Seleccioná un archivo CSV.", "error")
            return redirect(url_for("upload"))
        rows = parse_csv_upload(f)
        added = updated = skipped = 0
        with conn() as db:
            for r in rows:
                did = r.get("did", "").strip()
                dni = r.get("dni", "").strip()
                operator = r.get("operador", "").strip() or default_operator
                extra = {k: v for k, v in r.items() if k not in ["did", "dni", "operador"]}
                existing = db.execute("SELECT id FROM cases WHERE did=? AND dni=?", (did, dni)).fetchone()
                if existing and replace:
                    db.execute(
                        "UPDATE cases SET operator=?, extra_json=? WHERE id=?",
                        (operator, str(extra), existing["id"]),
                    )
                    db.execute(
                        "INSERT INTO logs (case_id, username, action, detail, created_at) VALUES (?,?,?,?,?)",
                        (existing["id"], current_user()["username"], "actualizo_caso", "Actualizado desde carga CSV", now()),
                    )
                    updated += 1
                elif existing:
                    skipped += 1
                else:
                    cur = db.execute(
                        "INSERT INTO cases (did, dni, operator, status, notes, extra_json, created_at) VALUES (?,?,?,?,?,?,?)",
                        (did, dni, operator, "pendiente", "", str(extra), now()),
                    )
                    db.execute(
                        "INSERT INTO logs (case_id, username, action, detail, created_at) VALUES (?,?,?,?,?)",
                        (cur.lastrowid, current_user()["username"], "cargo_caso", "Cargado desde CSV", now()),
                    )
                    added += 1
            db.commit()
        flash(f"Carga lista. Agregados: {added}. Actualizados: {updated}. Omitidos: {skipped}.", "ok")
        return redirect(url_for("cases"))
    return render_template("upload.html")


@app.route("/cases")
@admin_required
def cases():
    q = request.args.get("q", "").strip()
    operator = request.args.get("operator", "").strip()
    status = request.args.get("status", "").strip()
    params = []
    where = ["1=1"]
    if q:
        where.append("(dni LIKE ? OR did LIKE ? OR operator LIKE ? OR notes LIKE ?)")
        like = f"%{q}%"
        params += [like, like, like, like]
    if operator:
        where.append("operator=?")
        params.append(operator)
    if status:
        where.append("status=?")
        params.append(status)
    with conn() as db:
        rows = db.execute(f"SELECT * FROM cases WHERE {' AND '.join(where)} ORDER BY operator, id", params).fetchall()
        operators = db.execute("SELECT DISTINCT operator FROM cases ORDER BY operator").fetchall()
    return render_template("cases.html", rows=rows, operators=operators, q=q, operator=operator, status=status)


@app.route("/operator")
@login_required
def operator_cases():
    u = current_user()
    if u["role"] == "admin" and request.args.get("as_operator"):
        operator_name = request.args.get("as_operator")
    else:
        operator_name = u["display_name"]
    status = request.args.get("status", "pendiente")
    q = request.args.get("q", "").strip()
    params = [operator_name]
    where = ["operator=?"]
    if status:
        where.append("status=?")
        params.append(status)
    if q:
        where.append("(dni LIKE ? OR did LIKE ? OR notes LIKE ?)")
        like = f"%{q}%"
        params += [like, like, like]
    with conn() as db:
        rows = db.execute(f"SELECT * FROM cases WHERE {' AND '.join(where)} ORDER BY id", params).fetchall()
    return render_template("operator.html", rows=rows, status=status, q=q, operator_name=operator_name)


@app.route("/case/<int:case_id>/open")
@login_required
def open_case(case_id):
    panel = request.args.get("panel", DEFAULT_PANEL)
    with conn() as db:
        c = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not c:
            flash("Caso no encontrado.", "error")
            return redirect(url_for("index"))
        u = current_user()
        if u["role"] != "admin" and c["operator"] != u["display_name"]:
            flash("Ese caso no está asignado a tu usuario.", "error")
            return redirect(url_for("operator_cases"))
        if c["status"] == "pendiente":
            db.execute("UPDATE cases SET status='abierto', opened_at=? WHERE id=?", (now(), case_id))
        elif not c["opened_at"]:
            db.execute("UPDATE cases SET opened_at=? WHERE id=?", (now(), case_id))
        db.execute(
            "INSERT INTO logs (case_id, username, action, detail, created_at) VALUES (?,?,?,?,?)",
            (case_id, u["username"], "abrio_caso", f"Abrio CRM panel {panel}", now()),
        )
        db.commit()
    return redirect(crm_link(c, panel))


@app.route("/case/<int:case_id>/update", methods=["POST"])
@login_required
def update_case(case_id):
    status = request.form.get("status", "").strip()
    notes = request.form.get("notes", "").strip()
    allowed = {"pendiente", "abierto", "trabajado", "sin_gestion", "error"}
    if status not in allowed:
        flash("Estado inválido.", "error")
        return redirect(url_for("index"))
    with conn() as db:
        c = db.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()
        if not c:
            flash("Caso no encontrado.", "error")
            return redirect(url_for("index"))
        u = current_user()
        if u["role"] != "admin" and c["operator"] != u["display_name"]:
            flash("Ese caso no está asignado a tu usuario.", "error")
            return redirect(url_for("operator_cases"))
        worked_at = now() if status == "trabajado" else c["worked_at"]
        db.execute("UPDATE cases SET status=?, notes=?, worked_at=? WHERE id=?", (status, notes, worked_at, case_id))
        db.execute(
            "INSERT INTO logs (case_id, username, action, detail, created_at) VALUES (?,?,?,?,?)",
            (case_id, u["username"], "actualizo_caso", f"Estado: {status}. Obs: {notes[:200]}", now()),
        )
        db.commit()
    flash("Caso actualizado.", "ok")
    ref = request.referrer or url_for("index")
    return redirect(ref)


@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        display_name = request.form.get("display_name", "").strip() or username
        password = request.form.get("password", "").strip()
        role = request.form.get("role", "operator")
        if not username or not password:
            flash("Usuario y clave son obligatorios.", "error")
        else:
            try:
                with conn() as db:
                    db.execute(
                        "INSERT INTO users (username, password_hash, role, display_name, active, created_at) VALUES (?,?,?,?,?,?)",
                        (username, generate_password_hash(password), role, display_name, 1, now()),
                    )
                    db.commit()
                flash("Usuario creado.", "ok")
            except Exception:
                flash("Ese usuario ya existe.", "error")
        return redirect(url_for("users"))
    with conn() as db:
        rows = db.execute("SELECT * FROM users ORDER BY role, display_name").fetchall()
    return render_template("users.html", rows=rows)



@app.route("/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def delete_user(user_id):
    u = current_user()
    with conn() as db:
        target = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if not target:
            flash("Usuario no encontrado.", "error")
            return redirect(url_for("users"))
        if target["username"] == "admin" or target["id"] == u["id"]:
            flash("No se puede eliminar el usuario admin ni tu propio usuario.", "error")
            return redirect(url_for("users"))
        db.execute("DELETE FROM users WHERE id=?", (user_id,))
        db.execute(
            "INSERT INTO logs (case_id, username, action, detail, created_at) VALUES (?,?,?,?,?)",
            (None, u["username"], "elimino_usuario", f"Eliminó usuario {target['username']}", now()),
        )
        db.commit()
    flash("Usuario eliminado.", "ok")
    return redirect(url_for("users"))


@app.route("/logs")
@admin_required
def logs():
    with conn() as db:
        rows = db.execute("""
            SELECT logs.*, cases.dni, cases.did, cases.operator
            FROM logs
            LEFT JOIN cases ON logs.case_id = cases.id
            ORDER BY logs.id DESC
            LIMIT 500
        """).fetchall()
    return render_template("logs.html", rows=rows)


@app.route("/export")
@admin_required
def export():
    with conn() as db:
        rows = db.execute("SELECT * FROM cases ORDER BY operator, id").fetchall()
    output = io.StringIO()
    writer = csv.writer(output, delimiter=";")
    writer.writerow(["operador", "dni", "did", "estado", "observacion", "cargado", "abierto", "trabajado", "link"])
    for r in rows:
        writer.writerow([r["operator"], r["dni"], r["did"], r["status"], r["notes"], r["created_at"], r["opened_at"], r["worked_at"], crm_link(r)])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=casos_moragl.csv"},
    )


if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
else:
    init_db()
