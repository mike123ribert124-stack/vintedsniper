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
            created_at REAL DEFAULT (strftime('%s','now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

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
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
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


# Note: appeler init_db() au demarrage de l'app
