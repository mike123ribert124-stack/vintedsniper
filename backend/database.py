"""
Gestion de la base de donnees SQLite
"""
import sqlite3
import hashlib
import secrets
import time
import json
import os
from config import DATABASE_PATH


def get_db():
    """Cree une connexion a la base de donnees"""
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """Initialise les tables de la base de donnees"""
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            plan TEXT DEFAULT 'free',
            stripe_customer_id TEXT,
            stripe_subscription_id TEXT,
            paypal_subscription_id TEXT,
            discord_webhook TEXT,
            vinted_cookie TEXT,
            created_at REAL DEFAULT (strftime('%s','now')),
            last_login REAL,
            is_active INTEGER DEFAULT 1,
            api_key TEXT UNIQUE
        );

        CREATE TABLE IF NOT EXISTS searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            keywords TEXT DEFAULT '',
            brand_ids TEXT DEFAULT '[]',
            catalog_ids TEXT DEFAULT '[]',
            size_ids TEXT DEFAULT '[]',
            price_from REAL DEFAULT 0,
            price_to REAL DEFAULT 50,
            sort_order TEXT DEFAULT 'newest_first',
            is_active INTEGER DEFAULT 1,
            created_at REAL DEFAULT (strftime('%s','now')),
            last_scan REAL,
            items_found INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS found_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            search_id INTEGER NOT NULL,
            vinted_id INTEGER NOT NULL,
            title TEXT,
            price REAL,
            currency TEXT DEFAULT 'EUR',
            brand TEXT,
            size TEXT,
            url TEXT,
            photo_url TEXT,
            seller TEXT,
            favourite_count INTEGER DEFAULT 0,
            found_at REAL DEFAULT (strftime('%s','now')),
            notified INTEGER DEFAULT 0,
            auto_bought INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (search_id) REFERENCES searches(id),
            UNIQUE(user_id, vinted_id)
        );

        CREATE TABLE IF NOT EXISTS notifications_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            item_id INTEGER,
            channel TEXT NOT NULL,
            status TEXT DEFAULT 'sent',
            sent_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT DEFAULT 'EUR',
            status TEXT DEFAULT 'pending',
            provider_id TEXT,
            event_id TEXT,
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            event_id TEXT NOT NULL UNIQUE,
            processed_at REAL DEFAULT (strftime('%s','now'))
        );

        CREATE TABLE IF NOT EXISTS password_resets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            expires_at REAL NOT NULL,
            used INTEGER DEFAULT 0,
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token);
        CREATE INDEX IF NOT EXISTS idx_found_items_user ON found_items(user_id);
        CREATE INDEX IF NOT EXISTS idx_found_items_vinted ON found_items(vinted_id);
        CREATE INDEX IF NOT EXISTS idx_searches_user ON searches(user_id);
    """)

    conn.commit()
    conn.close()
    print("[DB] Base de donnees initialisee")


def hash_password(password, salt=None):
    """Hash un mot de passe avec un salt"""
    if salt is None:
        salt = secrets.token_hex(32)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return hashed.hex(), salt


def create_user(email, username, password):
    """Cree un nouvel utilisateur"""
    conn = get_db()
    password_hash, salt = hash_password(password)
    api_key = secrets.token_urlsafe(32)

    try:
        conn.execute(
            "INSERT INTO users (email, username, password_hash, salt, api_key) VALUES (?, ?, ?, ?, ?)",
            (email, username, password_hash, salt, api_key)
        )
        conn.commit()
        user_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.close()
        return {"id": user_id, "email": email, "username": username, "api_key": api_key}
    except sqlite3.IntegrityError as e:
        conn.close()
        if "email" in str(e):
            raise ValueError("Cet email est deja utilise")
        elif "username" in str(e):
            raise ValueError("Ce nom d'utilisateur est deja pris")
        raise


def verify_user(email, password):
    """Verifie les identifiants d'un utilisateur"""
    conn = get_db()
    # Recherche insensible a la casse
    user = conn.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email,)).fetchone()
    conn.close()

    if not user:
        return None

    password_hash, _ = hash_password(password, user["salt"])
    if password_hash == user["password_hash"]:
        return dict(user)
    return None


def get_user_by_api_key(api_key):
    """Recupere un utilisateur par sa cle API"""
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE api_key = ? AND is_active = 1", (api_key,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_id(user_id):
    """Recupere un utilisateur par ID"""
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_searches(user_id):
    """Recupere les recherches d'un utilisateur"""
    conn = get_db()
    searches = conn.execute("SELECT * FROM searches WHERE user_id = ? ORDER BY created_at DESC", (user_id,)).fetchall()
    conn.close()
    return [dict(s) for s in searches]


def create_search(user_id, name, keywords, price_from=0, price_to=50, brand_ids=None, catalog_ids=None, size_ids=None, sort_order="newest_first"):
    """Cree une nouvelle recherche"""
    conn = get_db()
    conn.execute(
        """INSERT INTO searches (user_id, name, keywords, price_from, price_to, brand_ids, catalog_ids, size_ids, sort_order)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, name, keywords, price_from, price_to,
         json.dumps(brand_ids or []), json.dumps(catalog_ids or []),
         json.dumps(size_ids or []), sort_order)
    )
    conn.commit()
    search_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
    conn.close()
    return search_id


def save_found_item(user_id, search_id, item):
    """Sauvegarde un article trouve"""
    conn = get_db()
    try:
        conn.execute(
            """INSERT OR IGNORE INTO found_items
               (user_id, search_id, vinted_id, title, price, currency, brand, size, url, photo_url, seller, favourite_count)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, search_id, item["id"], item["title"], item["price"],
             item.get("currency", "EUR"), item.get("brand", ""),
             item.get("size", ""), item["url"], item.get("photo", ""),
             item.get("user", ""), item.get("favourite_count", 0))
        )
        conn.commit()
        inserted = conn.execute("SELECT changes()").fetchone()[0]
        conn.close()
        return inserted > 0  # True si nouvel article
    except Exception:
        conn.close()
        return False


def get_user_stats(user_id):
    """Recupere les statistiques d'un utilisateur"""
    conn = get_db()
    stats = {
        "total_items": conn.execute("SELECT COUNT(*) FROM found_items WHERE user_id = ?", (user_id,)).fetchone()[0],
        "active_searches": conn.execute("SELECT COUNT(*) FROM searches WHERE user_id = ? AND is_active = 1", (user_id,)).fetchone()[0],
        "notifications_sent": conn.execute("SELECT COUNT(*) FROM notifications_log WHERE user_id = ?", (user_id,)).fetchone()[0],
        "items_today": conn.execute(
            "SELECT COUNT(*) FROM found_items WHERE user_id = ? AND found_at > strftime('%s','now','-1 day')",
            (user_id,)
        ).fetchone()[0],
    }
    conn.close()
    return stats


# ============================================
# MOT DE PASSE OUBLIE
# ============================================
def create_reset_token(email):
    """Cree un token de reinitialisation pour un email"""
    conn = get_db()
    # Recherche insensible a la casse
    user = conn.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email,)).fetchone()
    if not user:
        conn.close()
        return None

    token = secrets.token_urlsafe(48)
    expires_at = time.time() + 3600  # Expire dans 1 heure

    # Invalider les anciens tokens
    conn.execute("UPDATE password_resets SET used = 1 WHERE user_id = ?", (user["id"],))
    # Creer le nouveau
    conn.execute(
        "INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)",
        (user["id"], token, expires_at)
    )
    conn.commit()
    conn.close()
    return {"token": token, "user_id": user["id"], "username": user["username"], "email": email}


def verify_reset_token(token):
    """Verifie si un token de reinitialisation est valide"""
    conn = get_db()
    reset = conn.execute(
        "SELECT * FROM password_resets WHERE token = ? AND used = 0 AND expires_at > ?",
        (token, time.time())
    ).fetchone()
    conn.close()
    return dict(reset) if reset else None


def reset_password(token, new_password):
    """Reinitialise le mot de passe avec un token valide"""
    conn = get_db()
    reset = conn.execute(
        "SELECT * FROM password_resets WHERE token = ? AND used = 0 AND expires_at > ?",
        (token, time.time())
    ).fetchone()

    if not reset:
        conn.close()
        return False

    password_hash, salt = hash_password(new_password)
    conn.execute("UPDATE users SET password_hash = ?, salt = ? WHERE id = ?",
                 (password_hash, salt, reset["user_id"]))
    conn.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (reset["id"],))
    conn.commit()
    conn.close()
    return True


# ============================================
# ADMIN FUNCTIONS
# ============================================
def ensure_admin_columns():
    """Ajoute les colonnes manquantes si elles n'existent pas"""
    conn = get_db()
    try:
        conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Colonne existe deja
    try:
        conn.execute("ALTER TABLE payments ADD COLUMN event_id TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Colonne existe deja
    try:
        conn.execute("ALTER TABLE users ADD COLUMN telegram_chat_id TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Colonne existe deja
    try:
        # is_seeded : 0 = premier scan (pas de notifs), 1 = seede (notifs actives)
        conn.execute("ALTER TABLE searches ADD COLUMN is_seeded INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Colonne existe deja
    try:
        conn.execute("ALTER TABLE users ADD COLUMN subscription_status TEXT DEFAULT 'inactive'")
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Colonne existe deja
    conn.execute(
        """CREATE TABLE IF NOT EXISTS webhook_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            provider TEXT NOT NULL,
            event_id TEXT NOT NULL UNIQUE,
            processed_at REAL DEFAULT (strftime('%s','now'))
        )"""
    )
    conn.commit()
    conn.close()


def make_admin(email):
    """Donne les droits admin a un utilisateur par email"""
    conn = get_db()
    conn.execute("UPDATE users SET is_admin = 1 WHERE email = ?", (email,))
    conn.commit()
    conn.close()


def get_admin_overview():
    """Stats globales pour le dashboard admin"""
    conn = get_db()
    stats = {
        "total_users": conn.execute("SELECT COUNT(*) FROM users").fetchone()[0],
        "active_users": conn.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0],
        "total_searches": conn.execute("SELECT COUNT(*) FROM searches").fetchone()[0],
        "active_searches": conn.execute("SELECT COUNT(*) FROM searches WHERE is_active = 1").fetchone()[0],
        "total_items": conn.execute("SELECT COUNT(*) FROM found_items").fetchone()[0],
        "items_today": conn.execute(
            "SELECT COUNT(*) FROM found_items WHERE found_at > strftime('%s','now','-1 day')"
        ).fetchone()[0],
        "total_notifications": conn.execute("SELECT COUNT(*) FROM notifications_log").fetchone()[0],
        "total_payments": conn.execute("SELECT COUNT(*) FROM payments").fetchone()[0],
        "revenue_total": conn.execute(
            "SELECT COALESCE(SUM(amount), 0) FROM payments WHERE status = 'completed'"
        ).fetchone()[0],
        "plans_breakdown": {},
    }
    # Breakdown par plan
    rows = conn.execute("SELECT plan, COUNT(*) as cnt FROM users GROUP BY plan").fetchall()
    for r in rows:
        stats["plans_breakdown"][r["plan"]] = r["cnt"]

    conn.close()
    return stats


def get_all_users(search_query=None, plan_filter=None, status_filter=None, limit=100, offset=0):
    """Liste tous les utilisateurs pour l'admin"""
    conn = get_db()
    query = "SELECT id, email, username, plan, is_active, created_at, last_login, stripe_customer_id, discord_webhook, telegram_chat_id FROM users WHERE 1=1"
    params = []

    if search_query:
        query += " AND (email LIKE ? OR username LIKE ?)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])
    if plan_filter and plan_filter != "all":
        query += " AND plan = ?"
        params.append(plan_filter)
    if status_filter == "active":
        query += " AND is_active = 1"
    elif status_filter == "blocked":
        query += " AND is_active = 0"

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    users = conn.execute(query, params).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()

    result = []
    for u in users:
        u = dict(u)
        # Ajouter les stats de chaque user
        conn2 = get_db()
        u["searches_count"] = conn2.execute("SELECT COUNT(*) FROM searches WHERE user_id = ?", (u["id"],)).fetchone()[0]
        u["items_count"] = conn2.execute("SELECT COUNT(*) FROM found_items WHERE user_id = ?", (u["id"],)).fetchone()[0]
        conn2.close()
        result.append(u)

    return {"users": result, "total": total}


def get_user_by_stripe_customer_id(customer_id):
    """Recupere un utilisateur a partir de son customer Stripe"""
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE stripe_customer_id = ?",
        (customer_id,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None


def update_user_plan_from_subscription(user_id, plan_key, subscription_id):
    """Met a jour le plan et l'abonnement Stripe de l'utilisateur."""
    conn = get_db()
    conn.execute(
        "UPDATE users SET plan = ?, stripe_subscription_id = ? WHERE id = ?",
        (plan_key, subscription_id, user_id)
    )
    conn.commit()
    conn.close()


def clear_user_subscription(user_id):
    """Repasse l'utilisateur en free suite a annulation/inactivite."""
    conn = get_db()
    conn.execute(
        "UPDATE users SET plan = 'free', stripe_subscription_id = NULL WHERE id = ?",
        (user_id,)
    )
    conn.commit()
    conn.close()


def save_payment_record(user_id, provider, amount, currency, status, provider_id=None, event_id=None):
    """Sauvegarde un evenement de paiement."""
    conn = get_db()
    conn.execute(
        """INSERT INTO payments (user_id, provider, amount, currency, status, provider_id, event_id)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (user_id, provider, amount, currency, status, provider_id, event_id)
    )
    conn.commit()
    conn.close()


def mark_webhook_event_processed(provider, event_id):
    """
    Enregistre un event webhook traite.
    Retourne False si deja traite (idempotence).
    """
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO webhook_events (provider, event_id) VALUES (?, ?)",
            (provider, event_id)
        )
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False


def admin_update_user(user_id, data):
    """Met a jour un utilisateur depuis l'admin"""
    conn = get_db()
    updates = []
    params = []

    if "plan" in data:
        updates.append("plan = ?")
        params.append(data["plan"])
    if "is_active" in data:
        updates.append("is_active = ?")
        params.append(1 if data["is_active"] else 0)
    if "email" in data:
        updates.append("email = ?")
        params.append(data["email"])
    if "username" in data:
        updates.append("username = ?")
        params.append(data["username"])

    if updates:
        params.append(user_id)
        conn.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    return True


def admin_toggle_user(user_id):
    """Active/desactive un utilisateur"""
    conn = get_db()
    conn.execute("UPDATE users SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ?", (user_id,))
    conn.commit()
    user = conn.execute("SELECT is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_searches(limit=100, offset=0):
    """Toutes les recherches pour l'admin"""
    conn = get_db()
    searches = conn.execute(
        """SELECT s.*, u.username, u.email FROM searches s
           JOIN users u ON s.user_id = u.id
           ORDER BY s.created_at DESC LIMIT ? OFFSET ?""",
        (limit, offset)
    ).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM searches").fetchone()[0]
    conn.close()
    return {"searches": [dict(s) for s in searches], "total": total}


def get_all_items(limit=100, offset=0):
    """Tous les articles trouves pour l'admin"""
    conn = get_db()
    items = conn.execute(
        """SELECT fi.*, u.username, s.name as search_name FROM found_items fi
           JOIN users u ON fi.user_id = u.id
           JOIN searches s ON fi.search_id = s.id
           ORDER BY fi.found_at DESC LIMIT ? OFFSET ?""",
        (limit, offset)
    ).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM found_items").fetchone()[0]
    conn.close()
    return {"items": [dict(i) for i in items], "total": total}


def get_system_logs(limit=100, offset=0):
    """Logs du systeme (notifications)"""
    conn = get_db()
    logs = conn.execute(
        """SELECT nl.*, u.username FROM notifications_log nl
           JOIN users u ON nl.user_id = u.id
           ORDER BY nl.sent_at DESC LIMIT ? OFFSET ?""",
        (limit, offset)
    ).fetchall()
    total = conn.execute("SELECT COUNT(*) FROM notifications_log").fetchone()[0]
    conn.close()
    return {"logs": [dict(l) for l in logs], "total": total}


# Note: appeler init_db() au demarrage de l'app
