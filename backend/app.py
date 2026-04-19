"""
==============================================
  VINTEDSNIPER - Backend API (Flask)
==============================================
API REST pour la plateforme VintedSniper
"""
import os
import sys
import json
import time
import secrets
import threading
from queue import Queue
from functools import wraps

from flask import (Flask, request, jsonify, render_template,
                   redirect, session, Response, send_from_directory)
from flask_cors import CORS

from config import APP_NAME, SECRET_KEY, PLANS
from database import (init_db, create_user, verify_user, get_user_by_api_key,
                       get_user_searches, create_search, save_found_item,
                       get_user_stats, get_db, ensure_admin_columns, make_admin,
                       get_admin_overview, get_all_users, admin_update_user,
                       admin_toggle_user, get_all_searches, get_all_items,
                       get_system_logs, create_reset_token, verify_reset_token,
                       reset_password)
from vinted_engine import VintedEngine
from notifications import notification_manager
from payments import payment_manager

# ============================================
# APP FLASK
# ============================================
app = Flask(__name__,
            template_folder="../frontend",
            static_folder="../static")
app.secret_key = SECRET_KEY
app.config['SESSION_COOKIE_HTTPONLY'] = True      # Empeche le vol de cookie via JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'     # Protection CSRF basique
app.config['PERMANENT_SESSION_LIFETIME'] = 86400   # Session expire apres 24h
CORS(app)

# ============================================
# PROTECTION ANTI-BRUTE-FORCE
# ============================================
login_attempts = {}  # {ip: {"count": int, "last_attempt": float}}
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_TIME = 300  # 5 minutes de blocage


def check_rate_limit(ip):
    """Verifie si l'IP est bloquee apres trop de tentatives"""
    if ip not in login_attempts:
        return True
    info = login_attempts[ip]
    if time.time() - info["last_attempt"] > LOCKOUT_TIME:
        del login_attempts[ip]
        return True
    if info["count"] >= MAX_LOGIN_ATTEMPTS:
        return False
    return True


def record_failed_attempt(ip):
    """Enregistre une tentative echouee"""
    if ip not in login_attempts:
        login_attempts[ip] = {"count": 0, "last_attempt": 0}
    login_attempts[ip]["count"] += 1
    login_attempts[ip]["last_attempt"] = time.time()


def reset_attempts(ip):
    """Remet le compteur a zero apres connexion reussie"""
    if ip in login_attempts:
        del login_attempts[ip]

# Init
init_db()
ensure_admin_columns()
vinted = VintedEngine(max_workers=5)

# Email admin configurable (premier admin)
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "mike123.ribert124@gmail.com")

# Scanner en arriere-plan
scanner_threads = {}


# ============================================
# AUTH MIDDLEWARE
# ============================================
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check API key
        api_key = request.headers.get("X-API-Key")
        if api_key:
            user = get_user_by_api_key(api_key)
            if user:
                request.user = user
                return f(*args, **kwargs)

        # Check session
        user_id = session.get("user_id")
        if user_id:
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
            db.close()
            if user:
                request.user = dict(user)
                return f(*args, **kwargs)

        return jsonify({"error": "Non authentifie"}), 401
    return decorated


# ============================================
# PAGES
# ============================================
@app.route("/")
def index():
    return render_template("landing.html", plans=PLANS)


@app.route("/dashboard")
def dashboard_page():
    if not session.get("user_id"):
        return redirect("/login")
    return render_template("dashboard.html")


@app.route("/login")
def login_page():
    return render_template("login.html")


@app.route("/register")
def register_page():
    return render_template("register.html")


@app.route("/forgot-password")
def forgot_password_page():
    return render_template("forgot_password.html")


@app.route("/reset-password")
def reset_password_page():
    token = request.args.get("token", "")
    if not token:
        return redirect("/forgot-password")
    return render_template("reset_password.html", token=token)


# ============================================
# API AUTH
# ============================================
@app.route("/api/register", methods=["POST"])
def api_register():
    # Protection anti-spam
    if not check_rate_limit(request.remote_addr):
        return jsonify({"error": "Trop de tentatives. Reessaye dans 5 minutes."}), 429

    data = request.json or {}
    email = data.get("email", "").strip().lower()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not email or not username or not password:
        return jsonify({"error": "Tous les champs sont requis"}), 400
    if len(password) < 6:
        return jsonify({"error": "Le mot de passe doit faire au moins 6 caracteres"}), 400
    if len(username) < 3 or len(username) > 30:
        return jsonify({"error": "Le nom d'utilisateur doit faire entre 3 et 30 caracteres"}), 400
    if "@" not in email or "." not in email:
        return jsonify({"error": "Email invalide"}), 400

    try:
        user = create_user(email, username, password)
        session["user_id"] = user["id"]
        session.permanent = True
        return jsonify({"success": True, "user": user})
    except ValueError as e:
        return jsonify({"error": str(e)}), 409


@app.route("/api/login", methods=["POST"])
def api_login():
    # Protection anti-brute-force
    if not check_rate_limit(request.remote_addr):
        return jsonify({"error": "Trop de tentatives. Reessaye dans 5 minutes."}), 429

    data = request.json or {}
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    user = verify_user(email, password)
    if not user:
        record_failed_attempt(request.remote_addr)
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401

    reset_attempts(request.remote_addr)
    session["user_id"] = user["id"]
    session.permanent = True
    db = get_db()
    db.execute("UPDATE users SET last_login = strftime('%s','now') WHERE id = ?", (user["id"],))
    db.commit()
    db.close()

    return jsonify({
        "success": True,
        "user": {
            "id": user["id"],
            "email": user["email"],
            "username": user["username"],
            "plan": user["plan"],
            "api_key": user["api_key"],
        }
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})


# ============================================
# API MOT DE PASSE OUBLIE
# ============================================
@app.route("/api/forgot-password", methods=["POST"])
def api_forgot_password():
    # Protection anti-spam
    if not check_rate_limit(request.remote_addr):
        return jsonify({"error": "Trop de tentatives. Reessaye dans 5 minutes."}), 429

    data = request.json or {}
    email = data.get("email", "").strip().lower()

    if not email:
        return jsonify({"error": "Email requis"}), 400

    result = create_reset_token(email)

    # On repond toujours succes (securite : ne pas reveler si l'email existe)
    if result:
        # Envoyer l'email avec le lien
        reset_url = f"{request.host_url}reset-password?token={result['token']}"
        try:
            notification_manager.send_reset_email(email, result["username"], reset_url)
        except Exception as e:
            print(f"[Reset] Erreur envoi email: {e}")
            # Meme si l'email echoue, on donne le lien dans la reponse (mode dev)
            return jsonify({
                "success": True,
                "message": "Si cet email existe, un lien de reinitialisation a ete envoye.",
                "debug_url": reset_url  # A retirer en production
            })

    return jsonify({
        "success": True,
        "message": "Si cet email existe, un lien de reinitialisation a ete envoye."
    })


@app.route("/api/reset-password", methods=["POST"])
def api_reset_password():
    data = request.json or {}
    token = data.get("token", "")
    new_password = data.get("password", "")

    if not token or not new_password:
        return jsonify({"error": "Token et mot de passe requis"}), 400
    if len(new_password) < 6:
        return jsonify({"error": "Le mot de passe doit faire au moins 6 caracteres"}), 400

    success = reset_password(token, new_password)
    if success:
        return jsonify({"success": True, "message": "Mot de passe modifie avec succes !"})
    else:
        return jsonify({"error": "Lien expire ou invalide. Demande un nouveau lien."}), 400


# ============================================
# API UTILISATEUR
# ============================================
@app.route("/api/me")
@login_required
def api_me():
    user = request.user
    stats = get_user_stats(user["id"])
    plan = PLANS.get(user["plan"], PLANS["free"])

    return jsonify({
        "user": {
            "id": user["id"],
            "email": user["email"],
            "username": user["username"],
            "plan": user["plan"],
            "plan_name": plan["name"],
            "api_key": user["api_key"],
            "discord_webhook": user.get("discord_webhook", ""),
        },
        "plan": plan,
        "stats": stats,
    })


@app.route("/api/me/settings", methods=["PUT"])
@login_required
def api_update_settings():
    user = request.user
    data = request.json or {}
    db = get_db()

    if "discord_webhook" in data:
        db.execute("UPDATE users SET discord_webhook = ? WHERE id = ?",
                   (data["discord_webhook"], user["id"]))

    db.commit()
    db.close()
    return jsonify({"success": True})


# ============================================
# API RECHERCHES
# ============================================
@app.route("/api/searches")
@login_required
def api_list_searches():
    searches = get_user_searches(request.user["id"])
    for s in searches:
        s["brand_ids"] = json.loads(s.get("brand_ids", "[]"))
        s["catalog_ids"] = json.loads(s.get("catalog_ids", "[]"))
        s["size_ids"] = json.loads(s.get("size_ids", "[]"))
    return jsonify({"searches": searches})


@app.route("/api/searches", methods=["POST"])
@login_required
def api_create_search():
    user = request.user
    data = request.json or {}

    # Verifier la limite du plan
    current_count = len(get_user_searches(user["id"]))
    if not payment_manager.can_add_search(user["plan"], current_count):
        plan = PLANS.get(user["plan"], PLANS["free"])
        return jsonify({
            "error": f"Limite de {plan['max_searches']} recherches atteinte. Passe au plan superieur !"
        }), 403

    search_id = create_search(
        user_id=user["id"],
        name=data.get("name", "Ma recherche"),
        keywords=data.get("keywords", ""),
        price_from=data.get("price_from", 0),
        price_to=data.get("price_to", 50),
        brand_ids=data.get("brand_ids"),
        catalog_ids=data.get("catalog_ids"),
        size_ids=data.get("size_ids"),
        sort_order=data.get("sort_order", "newest_first"),
    )

    return jsonify({"success": True, "search_id": search_id})


@app.route("/api/searches/<int:search_id>", methods=["DELETE"])
@login_required
def api_delete_search(search_id):
    db = get_db()
    db.execute("DELETE FROM searches WHERE id = ? AND user_id = ?",
               (search_id, request.user["id"]))
    db.commit()
    db.close()
    return jsonify({"success": True})


@app.route("/api/searches/<int:search_id>/toggle", methods=["POST"])
@login_required
def api_toggle_search(search_id):
    db = get_db()
    db.execute(
        "UPDATE searches SET is_active = CASE WHEN is_active = 1 THEN 0 ELSE 1 END WHERE id = ? AND user_id = ?",
        (search_id, request.user["id"])
    )
    db.commit()
    db.close()
    return jsonify({"success": True})


# ============================================
# API RECHERCHE MANUELLE
# ============================================
@app.route("/api/search/test", methods=["POST"])
@login_required
def api_test_search():
    data = request.json or {}
    results = vinted.search(
        keywords=data.get("keywords", ""),
        brand_ids=data.get("brand_ids"),
        price_from=data.get("price_from"),
        price_to=data.get("price_to"),
        per_page=10,
    )
    return jsonify({"items": results, "count": len(results)})


# ============================================
# API ARTICLES TROUVES
# ============================================
@app.route("/api/items")
@login_required
def api_list_items():
    user = request.user
    limit = request.args.get("limit", 50, type=int)
    db = get_db()
    items = db.execute(
        """SELECT fi.*, s.name as search_name FROM found_items fi
           JOIN searches s ON fi.search_id = s.id
           WHERE fi.user_id = ?
           ORDER BY fi.found_at DESC LIMIT ?""",
        (user["id"], limit)
    ).fetchall()
    db.close()
    return jsonify({"items": [dict(i) for i in items]})


# ============================================
# SSE - Notifications temps reel navigateur
# ============================================
@app.route("/api/events")
@login_required
def api_events():
    user = request.user
    q = Queue()
    notification_manager.register_sse_client(user["id"], q)

    def event_stream():
        try:
            while True:
                data = q.get(timeout=30)
                yield f"data: {data}\n\n"
        except Exception:
            pass
        finally:
            notification_manager.unregister_sse_client(user["id"], q)

    return Response(event_stream(), mimetype="text/event-stream")


# ============================================
# API PAIEMENTS
# ============================================
@app.route("/api/plans")
def api_plans():
    return jsonify({"plans": PLANS})


@app.route("/api/checkout", methods=["POST"])
@login_required
def api_checkout():
    user = request.user
    data = request.json or {}
    plan_key = data.get("plan")

    if plan_key not in PLANS or PLANS[plan_key]["price_monthly"] == 0:
        return jsonify({"error": "Plan invalide"}), 400

    # Creer client Stripe si pas encore fait
    db = get_db()
    if not user.get("stripe_customer_id"):
        customer_id = payment_manager.create_stripe_customer(user["email"], user["username"])
        if customer_id:
            db.execute("UPDATE users SET stripe_customer_id = ? WHERE id = ?",
                       (customer_id, user["id"]))
            db.commit()
            user["stripe_customer_id"] = customer_id
    db.close()

    checkout_url = payment_manager.create_checkout_session(
        user.get("stripe_customer_id"),
        plan_key,
        success_url=request.host_url + "dashboard?payment=success",
        cancel_url=request.host_url + "dashboard?payment=cancelled",
    )

    if checkout_url:
        return jsonify({"url": checkout_url})
    else:
        return jsonify({"error": "Erreur de paiement"}), 500


# ============================================
# ADMIN MIDDLEWARE
# ============================================
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check session
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "Non authentifie"}), 401

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        db.close()

        if not user:
            return jsonify({"error": "Utilisateur introuvable"}), 401

        user = dict(user)
        # Admin si is_admin=1 OU si email = ADMIN_EMAIL
        if not user.get("is_admin") and user["email"] != ADMIN_EMAIL:
            return jsonify({"error": "Acces refuse - Admin uniquement"}), 403

        # Auto-promote si email admin mais pas encore flag
        if user["email"] == ADMIN_EMAIL and not user.get("is_admin"):
            make_admin(user["email"])

        request.user = user
        return f(*args, **kwargs)
    return decorated


# ============================================
# ADMIN PAGES
# ============================================
@app.route("/admin")
def admin_page():
    if not session.get("user_id"):
        return redirect("/login")
    # Verifier admin
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    db.close()
    if not user:
        return redirect("/login")
    user = dict(user)
    if not user.get("is_admin") and user["email"] != ADMIN_EMAIL:
        return redirect("/dashboard")
    return render_template("admin.html")


# ============================================
# API ADMIN
# ============================================
@app.route("/api/admin/overview")
@admin_required
def api_admin_overview():
    stats = get_admin_overview()
    return jsonify(stats)


@app.route("/api/admin/users")
@admin_required
def api_admin_users():
    search_query = request.args.get("search", "")
    plan_filter = request.args.get("plan", "all")
    status_filter = request.args.get("status", "all")
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)

    result = get_all_users(search_query, plan_filter, status_filter, limit, offset)
    return jsonify(result)


@app.route("/api/admin/users/<int:user_id>", methods=["PUT"])
@admin_required
def api_admin_update_user(user_id):
    data = request.json or {}
    admin_update_user(user_id, data)
    return jsonify({"success": True})


@app.route("/api/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def api_admin_toggle_user(user_id):
    result = admin_toggle_user(user_id)
    if result:
        return jsonify({"success": True, "is_active": result["is_active"]})
    return jsonify({"error": "Utilisateur introuvable"}), 404


@app.route("/api/admin/searches")
@admin_required
def api_admin_searches():
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    result = get_all_searches(limit, offset)
    return jsonify(result)


@app.route("/api/admin/items")
@admin_required
def api_admin_items():
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    result = get_all_items(limit, offset)
    return jsonify(result)


@app.route("/api/admin/logs")
@admin_required
def api_admin_logs():
    limit = request.args.get("limit", 100, type=int)
    offset = request.args.get("offset", 0, type=int)
    result = get_system_logs(limit, offset)
    return jsonify(result)


@app.route("/api/admin/make-admin", methods=["POST"])
@admin_required
def api_admin_make_admin():
    data = request.json or {}
    email = data.get("email", "")
    if not email:
        return jsonify({"error": "Email requis"}), 400
    make_admin(email)
    return jsonify({"success": True})


# ============================================
# SCANNER EN ARRIERE-PLAN
# ============================================
# Suivi du dernier scan par utilisateur
last_scan_time = {}  # {user_id: timestamp}


def run_scanner():
    """
    Boucle de scan en arriere-plan pour tous les utilisateurs.
    Respecte l'intervalle de scan de chaque plan :
    - VIP : scan continu (quasi-instantane)
    - Pro : toutes les 10 secondes
    - Basic : toutes les 30 secondes
    - Free : toutes les 2 minutes
    """
    print(f"[Scanner] Demarre - Mode adaptatif par plan")

    while True:
        try:
            db = get_db()
            users = db.execute("SELECT * FROM users WHERE is_active = 1").fetchall()
            db.close()

            for user in users:
                user = dict(user)
                user_plan = user.get("plan", "free")
                plan = PLANS.get(user_plan, PLANS["free"])
                scan_interval = plan.get("scan_interval", 120)

                # Verifier si c'est le moment de scanner cet utilisateur
                now = time.time()
                last_scan = last_scan_time.get(user["id"], 0)
                if (now - last_scan) < scan_interval:
                    continue  # Pas encore le moment pour cet utilisateur

                searches = get_user_searches(user["id"])
                active_searches = [s for s in searches if s.get("is_active")]

                if not active_searches:
                    continue

                # Preparer les configs de recherche
                search_configs = []
                for s in active_searches:
                    search_configs.append({
                        "name": s["name"],
                        "keywords": s.get("keywords", ""),
                        "brand_ids": json.loads(s.get("brand_ids", "[]")),
                        "catalog_ids": json.loads(s.get("catalog_ids", "[]")),
                        "size_ids": json.loads(s.get("size_ids", "[]")),
                        "price_from": s.get("price_from"),
                        "price_to": s.get("price_to"),
                        "sort_order": s.get("sort_order", "newest_first"),
                        "is_active": True,
                        "_search_id": s["id"],
                    })

                # Recherche batch multi-thread (vitesse adaptee au plan)
                results = vinted.search_batch(search_configs, plan=user_plan)

                # Marquer le scan comme effectue
                last_scan_time[user["id"]] = time.time()

                # Traiter les resultats
                for config in search_configs:
                    name = config["name"]
                    items = results.get(name, [])

                    for item in items:
                        is_new = save_found_item(user["id"], config["_search_id"], item)
                        if is_new:
                            # Notification multi-canal
                            notification_manager.notify_user(user, item, name)

            # Boucle rapide pour ne pas rater les VIP
            # On verifie toutes les 2 secondes s'il y a des utilisateurs a scanner
            time.sleep(2)

        except Exception as e:
            print(f"[Scanner] Erreur: {e}")
            time.sleep(5)


# ============================================
# DEMARRAGE
# ============================================
def start_app():
    """Demarre l'application et le scanner"""
    # Lancer le scanner en arriere-plan
    scanner = threading.Thread(target=run_scanner, daemon=True)
    scanner.start()

    # Lancer Flask
    port = int(os.environ.get("PORT", 5000))
    print(f"\n{'='*50}")
    print(f"  {APP_NAME} v2.0")
    print(f"  http://localhost:{port}")
    print(f"{'='*50}\n")

    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    start_app()
