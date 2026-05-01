"""
==============================================
  VINTEDSNIPER - Backend API (Flask)
==============================================
API REST pour la plateforme VintedSniper
"""
import os
import json
import time
import threading
import logging
from queue import Queue
from functools import wraps

from flask import (Flask, request, jsonify, render_template,
                   redirect, session, Response)
from flask_cors import CORS

from config import (
    APP_NAME,
    SECRET_KEY,
    PLANS,
    CORS_ALLOWED_ORIGINS,
    ENVIRONMENT,
    ADMIN_EMAIL,
    ADMIN_SECRET,
    RUN_SCANNER_IN_WEB
)
from database import (init_db, create_user, verify_user, get_user_by_api_key,
                       get_user_searches, create_search, save_found_item,
                       get_user_stats, get_db, ensure_admin_columns, make_admin,
                       get_admin_overview, get_all_users, admin_update_user,
                       admin_toggle_user, get_all_searches, get_all_items,
                       get_system_logs, create_reset_token, verify_reset_token,
                       reset_password, get_user_by_stripe_customer_id,
                       update_user_plan_from_subscription, clear_user_subscription,
                       save_payment_record, mark_webhook_event_processed, get_user_by_id)
from vinted_engine import VintedEngine
from notifications import notification_manager
from payments import payment_manager
from auto_buyer import auto_buyer
from maintenance import start_maintenance_thread

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
app.config['SESSION_COOKIE_SECURE'] = ENVIRONMENT == "production"

if ENVIRONMENT == "production" and SECRET_KEY == "change-this-secret-key-in-production":
    raise RuntimeError("SECRET_KEY non configuree en production")
if ENVIRONMENT == "production" and not ADMIN_EMAIL:
    raise RuntimeError("ADMIN_EMAIL doit etre configure en production")

# Restreint les appels cross-origin au domaine officiel + localhost (dev)
CORS(
    app,
    resources={r"/api/*": {"origins": CORS_ALLOWED_ORIGINS}},
    supports_credentials=True
)

logging.basicConfig(
    level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}'
)
logger = logging.getLogger(APP_NAME)


@app.after_request
def add_security_headers(response):
    """Ajoute des en-tetes de securite de base a toutes les reponses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if request.is_secure:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Evite le cache des endpoints sensibles
    if request.path in ("/api/login", "/api/register", "/api/forgot-password", "/api/reset-password"):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"

    return response

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
if ADMIN_EMAIL:
    make_admin(ADMIN_EMAIL)

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

    # Toujours la meme reponse (anti-enumeration d'emails)
    if result:
        reset_url = f"{request.host_url}reset-password?token={result['token']}"
        try:
            notification_manager.send_reset_email(email, result["username"], reset_url)
        except Exception as e:
            print(f"[Reset] Erreur envoi email: {e}")

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
            "discord_webhook": user.get("discord_webhook", ""),
            "telegram_chat_id": user.get("telegram_chat_id", ""),
            "is_admin": bool(user.get("is_admin", 0)),
            "auto_buy_allowed": bool(plan.get("auto_buy") or user.get("is_admin")),
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
        webhook = data["discord_webhook"].strip()
        if webhook and not webhook.startswith("http"):
            db.close()
            return jsonify({"error": "Le webhook Discord doit commencer par https://"}), 400
        db.execute("UPDATE users SET discord_webhook = ? WHERE id = ?",
                   (webhook, user["id"]))

    if "telegram_chat_id" in data:
        db.execute("UPDATE users SET telegram_chat_id = ? WHERE id = ?",
                   (data["telegram_chat_id"], user["id"]))

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
        status_ids=data.get("status_ids"),
        sort_order=data.get("sort_order", "newest_first"),
    )

    return jsonify({"success": True, "search_id": search_id})


@app.route("/api/searches/<int:search_id>", methods=["DELETE"])
@login_required
def api_delete_search(search_id):
    db = get_db()
    # Vérifier que la recherche appartient bien à l'utilisateur
    search = db.execute("SELECT id FROM searches WHERE id = ? AND user_id = ?",
                        (search_id, request.user["id"])).fetchone()
    if not search:
        db.close()
        return jsonify({"error": "Recherche introuvable"}), 404
    # Supprimer les articles trouvés liés (FK constraint)
    db.execute("DELETE FROM found_items WHERE search_id = ?", (search_id,))
    db.execute("DELETE FROM searches WHERE id = ?", (search_id,))
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
@app.route("/api/vinted/catalogs")
@login_required
def api_vinted_catalogs():
    """Recupere les categories Vinted"""
    cats = vinted.get_catalogs()
    return jsonify({"catalogs": cats})


@app.route("/api/vinted/brands")
@login_required
def api_vinted_brands():
    """Recherche les marques Vinted"""
    q = request.args.get("q", "")
    brands = vinted.search_brands(query=q)
    return jsonify({"brands": brands})


@app.route("/api/vinted/sizes")
@login_required
def api_vinted_sizes():
    """Recupere les tailles Vinted"""
    catalog_id = request.args.get("catalog_id", type=int)
    sizes = vinted.get_sizes(catalog_id=catalog_id)
    return jsonify({"sizes": sizes})


@app.route("/api/search/test", methods=["POST"])
@login_required
def api_test_search():
    data = request.json or {}
    try:
        results = vinted.search(
            keywords=data.get("keywords", ""),
            brand_ids=data.get("brand_ids"),
            price_from=data.get("price_from"),
            price_to=data.get("price_to"),
            sort_order=data.get("sort_order", "newest_first"),
            per_page=10,
        )
        return jsonify({"items": results, "count": len(results)})
    except Exception as e:
        logger.error(f"api_test_search_error={e}")
        return jsonify({"error": "Erreur lors de la recherche", "items": [], "count": 0}), 500


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


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "service": APP_NAME})




@app.route("/readyz")
def readyz():
    try:
        db = get_db()
        db.execute("SELECT 1").fetchone()
        db.close()
        return jsonify({"ready": True})
    except Exception as e:
        logger.error(f"readiness_error={e}")
        return jsonify({"ready": False}), 503


@app.route("/api/checkout", methods=["POST"])
@login_required
def api_checkout():
    user = request.user
    data = request.json or {}
    plan_key = data.get("plan")
    yearly = data.get("yearly", False)

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
        yearly=yearly,
    )

    if checkout_url:
        return jsonify({"url": checkout_url})
    else:
        return jsonify({"error": "Erreur de paiement"}), 500


@app.route("/api/stripe/webhook", methods=["POST"])
def api_stripe_webhook():
    """Webhook Stripe signe et idempotent pour sync des abonnements."""
    payload = request.get_data(as_text=True)
    signature = request.headers.get("Stripe-Signature", "")
    event = payment_manager.handle_webhook(payload, signature)
    if not event:
        return jsonify({"error": "Webhook invalide"}), 400

    event_id = event.get("id", "")
    if not event_id:
        return jsonify({"error": "Event sans ID"}), 400
    if not mark_webhook_event_processed("stripe", event_id):
        return jsonify({"success": True, "duplicate": True})

    event_type = event.get("type", "")
    event_data = event.get("data", {}).get("object", {})
    logger.info(f"stripe_webhook type={event_type} id={event_id}")

    if event_type == "checkout.session.completed":
        customer_id = event_data.get("customer")
        subscription_id = event_data.get("subscription")
        user = get_user_by_stripe_customer_id(customer_id) if customer_id else None
        if user and subscription_id:
            try:
                subscription = payment_manager.get_subscription(subscription_id)
            except Exception:
                subscription = None
            if subscription and subscription.get("items", {}).get("data"):
                price_id = subscription["items"]["data"][0]["price"]["id"]
                plan_key = payment_manager.get_plan_key_by_price_id(price_id)
                if plan_key:
                    update_user_plan_from_subscription(user["id"], plan_key, subscription_id)
                    amount = (event_data.get("amount_total") or 0) / 100
                    currency = (event_data.get("currency") or "eur").upper()
                    save_payment_record(
                        user_id=user["id"],
                        provider="stripe",
                        amount=amount,
                        currency=currency,
                        status="completed",
                        provider_id=subscription_id,
                        event_id=event_id
                    )

    elif event_type in ("customer.subscription.updated", "customer.subscription.created"):
        customer_id = event_data.get("customer")
        subscription_id = event_data.get("id")
        status = event_data.get("status")
        user = get_user_by_stripe_customer_id(customer_id) if customer_id else None
        if user and subscription_id:
            if status in ("active", "trialing"):
                items = event_data.get("items", {}).get("data", [])
                if items:
                    price_id = items[0].get("price", {}).get("id")
                    plan_key = payment_manager.get_plan_key_by_price_id(price_id)
                    if plan_key:
                        update_user_plan_from_subscription(user["id"], plan_key, subscription_id)
            else:
                clear_user_subscription(user["id"])

    elif event_type in ("customer.subscription.deleted",):
        customer_id = event_data.get("customer")
        user = get_user_by_stripe_customer_id(customer_id) if customer_id else None
        if user:
            clear_user_subscription(user["id"])

    return jsonify({"success": True})


@app.route("/api/portal", methods=["POST"])
@login_required
def api_portal():
    """Redirige vers le portail Stripe pour gérer/annuler l'abonnement."""
    user = request.user
    customer_id = user.get("stripe_customer_id")
    if not customer_id:
        return jsonify({"error": "Aucun abonnement actif"}), 400

    portal_url = payment_manager.create_portal_session(
        customer_id,
        return_url=request.host_url + "dashboard"
    )
    if portal_url:
        return jsonify({"url": portal_url})
    else:
        return jsonify({"error": "Erreur portail Stripe"}), 500


@app.route("/pricing")
def pricing_page():
    """Page de choix de plan après inscription."""
    return render_template("pricing.html", plans=PLANS)


# ============================================
# ADMIN MIDDLEWARE
# ============================================
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1. Verifier le token secret admin (2eme facteur)
        if ADMIN_SECRET:
            provided = (
                request.headers.get("X-Admin-Secret") or
                request.cookies.get("admin_secret") or
                request.args.get("admin_secret")
            )
            if provided != ADMIN_SECRET:
                return jsonify({"error": "Acces refuse"}), 403

        # 2. Verifier la session
        user_id = session.get("user_id")
        if not user_id:
            return jsonify({"error": "Non authentifie"}), 401

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        db.close()

        if not user:
            return jsonify({"error": "Utilisateur introuvable"}), 401

        user = dict(user)
        # 3. Verifier le flag is_admin
        if not user.get("is_admin"):
            return jsonify({"error": "Acces refuse - Admin uniquement"}), 403

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

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    db.close()
    if not user:
        return redirect("/login")
    user = dict(user)
    if not user.get("is_admin"):
        return redirect("/dashboard")

    # Verifier le secret admin si configure
    if ADMIN_SECRET:
        provided = request.args.get("s") or request.cookies.get("admin_secret")
        if provided != ADMIN_SECRET:
            return redirect("/dashboard")

    # Stocker le secret dans un cookie HttpOnly pour les appels API suivants
    resp = app.make_response(render_template("admin.html"))
    if ADMIN_SECRET:
        resp.set_cookie(
            "admin_secret", ADMIN_SECRET,
            httponly=True, samesite="Strict",
            secure=(ENVIRONMENT == "production"),
            max_age=3600  # 1 heure
        )
    return resp


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


@app.route("/api/admin/set-plan", methods=["POST"])
@admin_required
def api_admin_set_plan():
    """
    Permet a l'admin de changer le plan d'un utilisateur sans passer par Stripe.
    Utile pour tester toutes les fonctionnalites en local ou en prod.
    Body: { "user_id": int (optionnel, defaut = soi-meme), "plan": "free|basic|pro|vip" }
    """
    data = request.json or {}
    plan = data.get("plan", "")
    user_id = data.get("user_id") or request.user.get("id")

    if plan not in PLANS:
        return jsonify({"error": f"Plan invalide. Valeurs acceptees: {list(PLANS.keys())}"}), 400

    db = get_db()
    try:
        db.execute(
            "UPDATE users SET plan = ?, subscription_status = 'admin_override' WHERE id = ?",
            (plan, user_id)
        )
        db.commit()
        plan_info = PLANS[plan]
        logger.info(f"admin_set_plan user_id={user_id} plan={plan}")
        return jsonify({
            "success": True,
            "user_id": user_id,
            "plan": plan,
            "plan_name": plan_info["name"],
            "scan_interval": plan_info["scan_interval"],
            "max_searches": plan_info["max_searches"],
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        db.close()


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
# API AUTO-BUYER
# ============================================
@app.route("/api/autobuy/settings", methods=["GET"])
@login_required
def api_autobuy_settings():
    """Recupere les parametres d'achat automatique de l'utilisateur"""
    user = request.user
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])

    if not plan.get("auto_buy") and not user.get("is_admin"):
        return jsonify({"error": "L'achat automatique est reserve aux plans Pro et VIP"}), 403

    db = get_db()
    settings = db.execute(
        "SELECT autobuy_enabled, autobuy_max_price, autobuy_brands, autobuy_daily_limit, autobuy_mode FROM users WHERE id = ?",
        (user["id"],)
    ).fetchone()
    db.close()

    if settings:
        settings = dict(settings)
    else:
        settings = {}

    # Verifier le cookie Vinted
    vinted_cookie = user.get("vinted_cookie", "")
    cookie_valid = False
    if vinted_cookie:
        auth = auto_buyer.check_auth(user["id"], vinted_cookie)
        cookie_valid = auth.get("valid", False)

    return jsonify({
        "enabled": bool(settings.get("autobuy_enabled", 0)),
        "max_price": settings.get("autobuy_max_price", 0),
        "brands": json.loads(settings.get("autobuy_brands", "[]") or "[]"),
        "daily_limit": settings.get("autobuy_daily_limit", 5),
        "mode": settings.get("autobuy_mode", "offer"),
        "cookie_valid": cookie_valid,
        "plan_allowed": True,
    })


@app.route("/api/autobuy/settings", methods=["PUT"])
@login_required
def api_update_autobuy_settings():
    """Met a jour les parametres d'achat automatique"""
    user = request.user
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])

    if not plan.get("auto_buy") and not user.get("is_admin"):
        return jsonify({"error": "L'achat automatique est reserve aux plans Pro et VIP"}), 403

    data = request.json or {}
    db = get_db()

    updates = []
    params = []

    if "enabled" in data:
        updates.append("autobuy_enabled = ?")
        params.append(1 if data["enabled"] else 0)
    if "max_price" in data:
        updates.append("autobuy_max_price = ?")
        params.append(float(data["max_price"]))
    if "brands" in data:
        updates.append("autobuy_brands = ?")
        params.append(json.dumps(data["brands"]))
    if "daily_limit" in data:
        updates.append("autobuy_daily_limit = ?")
        params.append(int(data["daily_limit"]))
    if "mode" in data:
        mode = data["mode"]
        if mode not in ("offer", "buy"):
            return jsonify({"error": "Mode invalide (offer ou buy)"}), 400
        updates.append("autobuy_mode = ?")
        params.append(mode)

    if updates:
        params.append(user["id"])
        db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        db.commit()
    db.close()

    return jsonify({"success": True})


@app.route("/api/autobuy/cookie", methods=["PUT"])
@login_required
def api_update_vinted_cookie():
    """Met a jour le cookie Vinted pour l'achat automatique"""
    user = request.user
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])

    if not plan.get("auto_buy") and not user.get("is_admin"):
        return jsonify({"error": "L'achat automatique est reserve aux plans Pro et VIP"}), 403

    data = request.json or {}
    cookie = data.get("cookie", "").strip()

    if not cookie:
        return jsonify({"error": "Cookie requis"}), 400

    # Verifier que le cookie est valide
    auth = auto_buyer.check_auth(user["id"], cookie)
    if not auth.get("valid"):
        return jsonify({"error": auth.get("error", "Cookie invalide")}), 400

    db = get_db()
    db.execute("UPDATE users SET vinted_cookie = ? WHERE id = ?", (cookie, user["id"]))
    db.commit()
    db.close()

    return jsonify({
        "success": True,
        "vinted_username": auth.get("vinted_username", ""),
        "balance": auth.get("balance", "0"),
    })


@app.route("/api/autobuy/buy", methods=["POST"])
@login_required
def api_manual_buy():
    """Achat ou offre manuelle sur un article"""
    user = request.user
    plan = PLANS.get(user.get("plan", "free"), PLANS["free"])

    if not plan.get("auto_buy") and not user.get("is_admin"):
        return jsonify({"error": "L'achat automatique est reserve aux plans Pro et VIP"}), 403

    vinted_cookie = user.get("vinted_cookie", "")
    if not vinted_cookie:
        return jsonify({"error": "Cookie Vinted non configure"}), 400

    data = request.json or {}
    item_id = data.get("item_id")
    mode = data.get("mode", "offer")
    offer_price = data.get("offer_price")

    if not item_id:
        return jsonify({"error": "item_id requis"}), 400

    if mode == "offer":
        if not offer_price:
            return jsonify({"error": "offer_price requis pour une offre"}), 400
        result = auto_buyer.send_offer(user["id"], vinted_cookie, item_id, float(offer_price))
    elif mode == "buy":
        result = auto_buyer.auto_buy(user["id"], vinted_cookie, item_id)
    else:
        return jsonify({"error": "Mode invalide (offer ou buy)"}), 400

    return jsonify(result)


@app.route("/api/autobuy/history")
@login_required
def api_autobuy_history():
    """Historique des achats automatiques"""
    user = request.user
    limit = request.args.get("limit", 20, type=int)
    history = auto_buyer.get_purchase_history(user["id"], limit)
    return jsonify({"history": history})


# ============================================
# BOT D'ASSISTANCE (plans payants uniquement)
# ============================================
SUPPORT_FAQ = [
    {
        "q": "C'est quoi VintedSniper ?",
        "a": "VintedSniper est un bot qui scanne Vinted en continu pour trouver les meilleures affaires selon tes criteres (mots-cles, marques, prix, taille). Tu recois des alertes instantanees sur Discord, Telegram ou dans ton navigateur.",
        "keywords": ["quoi", "c'est quoi", "comment ca marche", "fonctionnement", "explication"]
    },
    {
        "q": "Comment creer une recherche ?",
        "a": "Va dans l'onglet 'Recherches' de ton dashboard, clique sur '+ Nouvelle recherche'. Remplis les mots-cles, le budget min/max, les marques et tailles souhaitees. Le bot commencera a scanner immediatement.",
        "keywords": ["recherche", "creer", "ajouter", "nouvelle", "comment"]
    },
    {
        "q": "Comment configurer les notifications Discord ?",
        "a": "Dans Parametres, colle ton URL de webhook Discord. Pour obtenir un webhook : Serveur Discord > Parametres > Integrations > Webhooks > Nouveau webhook > Copier l'URL.",
        "keywords": ["discord", "webhook", "notification", "configurer", "alertes"]
    },
    {
        "q": "Comment configurer Telegram ?",
        "a": "1) Ouvre Telegram et cherche @userinfobot. 2) Envoie /start pour obtenir ton Chat ID. 3) Colle ce numero dans Parametres > Telegram Chat ID. 4) Cherche aussi @VintedSniperBot et envoie /start pour activer les alertes.",
        "keywords": ["telegram", "chat id", "configurer", "bot telegram"]
    },
    {
        "q": "Comment fonctionne l'achat automatique ?",
        "a": "L'achat auto (Pro/VIP) envoie automatiquement une offre ou achete directement quand un article correspond a tes criteres. Configure ton cookie Vinted dans l'onglet 'Achat auto', choisis le mode (offre ou achat direct), et definis un prix max.",
        "keywords": ["achat", "automatique", "auto", "acheter", "offre", "snipe"]
    },
    {
        "q": "Mon cookie Vinted ne marche pas",
        "a": "Le cookie Vinted expire regulierement (environ toutes les 24h). Reconnecte-toi sur vinted.fr, ouvre les outils dev (F12) > Application > Cookies > copie la valeur de '_vinted_fr_session' et colle-la a nouveau.",
        "keywords": ["cookie", "expire", "invalide", "marche pas", "erreur"]
    },
    {
        "q": "Je ne recois pas de notifications",
        "a": "Verifie que : 1) Ta recherche est bien active (point vert). 2) Ton webhook Discord ou Chat ID Telegram est correct. 3) Ton plan inclut le canal souhaite. 4) Le bot a besoin d'un premier scan (seeding) avant d'envoyer des alertes.",
        "keywords": ["notification", "recois pas", "alerte", "rien", "pas de notif"]
    },
    {
        "q": "Comment changer mon plan ?",
        "a": "Va dans Parametres > Mon plan > 'Changer de plan'. Tu seras redirige vers la page de tarifs. Le changement est immediat apres paiement via Stripe.",
        "keywords": ["plan", "changer", "upgrade", "abonnement", "payer"]
    },
    {
        "q": "Comment annuler mon abonnement ?",
        "a": "Va dans Parametres > Mon plan > 'Gerer / Annuler'. Tu seras redirige vers le portail Stripe ou tu peux annuler. Ton plan reste actif jusqu'a la fin de la periode payee.",
        "keywords": ["annuler", "resilier", "abonnement", "arreter"]
    },
    {
        "q": "Le scanner est lent",
        "a": "La vitesse du scanner depend de ton plan. Free: 2min, Basic: 30s, Pro: 5s, VIP: 1s. Passe a un plan superieur pour un scan plus rapide. Le plan VIP utilise 10 threads en parallele pour une vitesse maximale.",
        "keywords": ["lent", "vitesse", "rapide", "scanner", "temps"]
    },
]


@app.route("/api/support/faq")
@login_required
def api_support_faq():
    """Retourne la FAQ complete (plans payants uniquement)"""
    user = request.user
    if user.get("plan", "free") == "free" and not user.get("is_admin"):
        return jsonify({"error": "Le support est reserve aux abonnes"}), 403
    return jsonify({"faq": [{"q": f["q"], "a": f["a"]} for f in SUPPORT_FAQ]})


@app.route("/api/support/ask", methods=["POST"])
@login_required
def api_support_ask():
    """Cherche une reponse dans la FAQ pour la question de l'utilisateur"""
    user = request.user
    if user.get("plan", "free") == "free" and not user.get("is_admin"):
        return jsonify({"error": "Le support est reserve aux abonnes"}), 403

    data = request.json or {}
    question = (data.get("question", "")).lower().strip()

    if not question:
        return jsonify({"error": "Question vide"}), 400

    # Recherche par mots-cles
    best_match = None
    best_score = 0
    for faq in SUPPORT_FAQ:
        score = sum(1 for kw in faq["keywords"] if kw in question)
        if score > best_score:
            best_score = score
            best_match = faq

    if best_match and best_score > 0:
        return jsonify({
            "found": True,
            "question": best_match["q"],
            "answer": best_match["a"],
        })
    else:
        return jsonify({
            "found": False,
            "message": "Je n'ai pas trouve de reponse. Tu peux contacter le support humain.",
        })


@app.route("/api/support/escalate", methods=["POST"])
@login_required
def api_support_escalate():
    """Escalade un probleme vers le support humain (envoie un message Telegram au support)"""
    user = request.user
    if user.get("plan", "free") == "free" and not user.get("is_admin"):
        return jsonify({"error": "Le support est reserve aux abonnes"}), 403

    data = request.json or {}
    message = data.get("message", "").strip()
    history = data.get("history", [])

    if not message:
        return jsonify({"error": "Message vide"}), 400

    # Formater le rapport d'escalade
    report = (
        f"📩 SUPPORT ESCALADE\n"
        f"User: {user.get('username', '?')} ({user.get('email', '?')})\n"
        f"Plan: {user.get('plan', 'free')}\n"
        f"Message: {message}\n"
    )
    if history:
        report += "\n--- Historique ---\n"
        for h in history[-5:]:  # Derniers 5 messages max
            report += f"{'User' if h.get('from') == 'user' else 'Bot'}: {h.get('text', '')}\n"

    # Envoyer au support via Telegram (si configure)
    support_sent = False
    if ADMIN_EMAIL:
        # On utilise le chat_id admin s'il existe
        db = get_db()
        admin = db.execute(
            "SELECT telegram_chat_id FROM users WHERE email = ? AND is_admin = 1",
            (ADMIN_EMAIL,)
        ).fetchone()
        db.close()

        if admin and admin[0]:
            from notifications import notification_manager
            try:
                import requests as req
                from config import TELEGRAM_BOT_TOKEN
                if TELEGRAM_BOT_TOKEN:
                    req.post(
                        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
                        json={"chat_id": admin[0], "text": report, "parse_mode": "HTML"},
                        timeout=8
                    )
                    support_sent = True
            except Exception:
                pass

    return jsonify({
        "success": True,
        "sent_telegram": support_sent,
        "message": "Ton message a ete transmis au support. On te recontacte rapidement !",
        "contact": {
            "email": ADMIN_EMAIL or "support@vintedsniper.fr",
            "discord": "discord.gg/vintedsniper",
            "telegram": "@VintedSniperSupport",
        }
    })


# ============================================
# STATS VIP - Performance du scanner
# ============================================
_scan_stats = {"total_scans": 0, "items_found": 0, "start_time": time.time(), "last_scan": 0}
_scan_stats_lock = threading.Lock()


def record_scan_event(items_count=0):
    """Enregistre un event de scan pour les stats VIP"""
    with _scan_stats_lock:
        _scan_stats["total_scans"] += 1
        _scan_stats["items_found"] += items_count
        _scan_stats["last_scan"] = time.time()


@app.route("/api/stats/performance")
@login_required
def api_stats_performance():
    """Stats de performance pour VIP (vitesse scanner, taux succes)"""
    try:
        user = request.user
        user_id = user.get("id") or user.get("user_id")

        # Stats utilisateur
        db = get_db()
        try:
            cutoff_24h = time.time() - 86400
            user_stats = db.execute("""
                SELECT
                    COUNT(*) as total_items,
                    COUNT(CASE WHEN found_at > ? THEN 1 END) as items_today
                FROM found_items
                WHERE user_id = ?
            """, (cutoff_24h, user_id)).fetchone()

            search_count = db.execute(
                "SELECT COUNT(*) FROM searches WHERE user_id = ? AND is_active = 1",
                (user_id,)
            ).fetchone()[0]
        except Exception as e:
            logger.error(f"stats/performance db error: {e}")
            user_stats = (0, 0)
            search_count = 0
        finally:
            db.close()

        # Achats auto
        autobuy_stats = {"total": 0, "success": 0}
        try:
            purchase_log = auto_buyer.get_purchase_history(user_id, 100)
            autobuy_stats["total"] = len(purchase_log)
            autobuy_stats["success"] = sum(1 for p in purchase_log if p.get("status") in ("completed", "sent"))
        except Exception:
            pass

        with _scan_stats_lock:
            uptime = time.time() - _scan_stats["start_time"]
            scans_total = _scan_stats["total_scans"]
            scans_per_min = round(scans_total / max(uptime / 60, 1), 1)

        return jsonify({
            "scanner": {
                "scans_total": scans_total,
                "scans_per_min": scans_per_min,
                "uptime_hours": round(uptime / 3600, 1),
                "last_scan_ago": round(time.time() - _scan_stats["last_scan"]) if _scan_stats["last_scan"] else None,
            },
            "user": {
                "total_items": user_stats[0] if user_stats else 0,
                "items_today": user_stats[1] if user_stats else 0,
                "active_searches": search_count,
            },
            "autobuy": autobuy_stats,
            "plan_speed": {
                "delay": {"free": 0.5, "basic": 0.3, "pro": 0.1, "vip": 0}.get(user.get("plan", "free"), 0.5),
                "threads": {"free": 3, "basic": 5, "pro": 8, "vip": 10}.get(user.get("plan", "free"), 3),
            },
        })
    except Exception as e:
        logger.error(f"stats/performance error: {e}")
        return jsonify({"error": "Erreur interne", "scanner": {}, "user": {}, "autobuy": {}, "plan_speed": {}}), 200


# ============================================
# ADMIN - Systeme et controles
# ============================================
@app.route("/api/admin/system")
@admin_required
def api_admin_system():
    """Stats systeme pour le terminal admin"""
    import platform

    db = get_db()
    total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active_users = db.execute("SELECT COUNT(*) FROM users WHERE is_active = 1").fetchone()[0]
    total_items = db.execute("SELECT COUNT(*) FROM found_items").fetchone()[0]
    items_today = db.execute(
        "SELECT COUNT(*) FROM found_items WHERE found_at > strftime('%s','now','-1 day')"
    ).fetchone()[0]
    total_searches = db.execute("SELECT COUNT(*) FROM searches WHERE is_active = 1").fetchone()[0]
    plan_dist = {}
    for row in db.execute("SELECT plan, COUNT(*) as c FROM users GROUP BY plan").fetchall():
        plan_dist[row[0]] = row[1]

    # Revenue estimee
    revenue = 0
    for plan_key, count in plan_dist.items():
        p = PLANS.get(plan_key, {})
        revenue += p.get("price_monthly", 0) * count

    db.close()

    with _scan_stats_lock:
        uptime = time.time() - _scan_stats["start_time"]
        scans_total = _scan_stats["total_scans"]
        scans_per_min = round(scans_total / max(uptime / 60, 1), 1)

    return jsonify({
        "system": {
            "python": platform.python_version(),
            "os": platform.system(),
            "uptime_hours": round(uptime / 3600, 1),
            "uptime_str": f"{int(uptime//3600)}h {int((uptime%3600)//60)}m",
        },
        "users": {
            "total": total_users,
            "active": active_users,
            "plan_distribution": plan_dist,
        },
        "scanner": {
            "scans_total": scans_total,
            "scans_per_min": scans_per_min,
            "items_total": total_items,
            "items_today": items_today,
            "active_searches": total_searches,
        },
        "revenue": {
            "monthly_estimate": revenue,
        },
    })


@app.route("/api/admin/live-logs")
@admin_required
def api_admin_live_logs():
    """Derniers logs systeme pour le terminal Matrix"""
    db = get_db()

    # Derniers articles trouves
    items = db.execute("""
        SELECT fi.title, fi.price, fi.found_at, u.username, s.name as search_name
        FROM found_items fi
        JOIN users u ON fi.user_id = u.id
        LEFT JOIN searches s ON fi.search_id = s.id
        ORDER BY fi.found_at DESC LIMIT 20
    """).fetchall()

    # Derniers users inscrits
    users = db.execute("""
        SELECT username, email, plan, created_at
        FROM users ORDER BY created_at DESC LIMIT 10
    """).fetchall()

    # Derniers paiements
    payments = db.execute("""
        SELECT p.amount, p.plan, p.created_at, u.username
        FROM payments p
        LEFT JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC LIMIT 10
    """).fetchall()

    db.close()

    logs = []
    for item in items:
        item = dict(item)
        logs.append({
            "type": "item",
            "time": item.get("found_at", ""),
            "msg": f"ITEM_FOUND: {item.get('title','')} | {item.get('price',0)}EUR | user:{item.get('username','')} | search:{item.get('search_name','')}",
        })
    for u in users:
        u = dict(u)
        logs.append({
            "type": "user",
            "time": u.get("created_at", ""),
            "msg": f"USER_REGISTER: {u.get('username','')} | {u.get('email','')} | plan:{u.get('plan','free')}",
        })
    for p in payments:
        p = dict(p)
        logs.append({
            "type": "payment",
            "time": p.get("created_at", ""),
            "msg": f"PAYMENT: {p.get('amount',0)}EUR | plan:{p.get('plan','')} | user:{p.get('username','')}",
        })

    # Trier par date desc
    logs.sort(key=lambda x: x.get("time", ""), reverse=True)

    return jsonify({"logs": logs[:30]})


@app.route("/api/admin/force-scan", methods=["POST"])
@admin_required
def api_admin_force_scan():
    """Force un scan immediat pour un utilisateur"""
    data = request.json or {}
    user_id = data.get("user_id")
    if not user_id:
        return jsonify({"error": "user_id requis"}), 400
    # Reset le last_scan pour forcer un scan immediat
    with _scan_stats_lock:
        _scan_stats["total_scans"] += 1
    return jsonify({"success": True, "msg": f"Scan force pour user {user_id}"})


# ============================================
# SCANNER EN ARRIERE-PLAN
# ============================================
# Suivi du dernier scan par utilisateur (protégé par lock)
last_scan_time = {}  # {user_id: timestamp}
_scan_lock = threading.Lock()


def run_scanner():
    """
    Boucle de scan en arriere-plan pour tous les utilisateurs.
    Respecte l'intervalle de scan de chaque plan :
    - VIP : toutes les 1 seconde
    - Pro : toutes les 5 secondes
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
                with _scan_lock:
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
                        "brand_ids": json.loads(s.get("brand_ids", "[]") or "[]"),
                        "catalog_ids": json.loads(s.get("catalog_ids", "[]") or "[]"),
                        "size_ids": json.loads(s.get("size_ids", "[]") or "[]"),
                        "status_ids": json.loads(s.get("status_ids", "[]") or "[]"),
                        "price_from": s.get("price_from"),
                        "price_to": s.get("price_to"),
                        "sort_order": s.get("sort_order", "newest_first"),
                        "is_active": True,
                        "_search_id": s["id"],
                        "is_seeded": s.get("is_seeded", 0),
                    })

                # Recherche batch multi-thread (vitesse adaptee au plan)
                results = vinted.search_batch(search_configs, plan=user_plan)
                total_items_found = sum(len(v) for v in results.values())
                record_scan_event(total_items_found)

                # Marquer le scan comme effectue
                with _scan_lock:
                    last_scan_time[user["id"]] = time.time()

                # Traiter les resultats
                for config in search_configs:
                    name = config["name"]
                    items = results.get(name, [])
                    search_id = config["_search_id"]
                    is_seeded = config.get("is_seeded", 0)

                    if not is_seeded:
                        # Premier scan : on sauvegarde tous les articles existants
                        # sans envoyer de notification (seeding)
                        for item in items:
                            save_found_item(user["id"], search_id, item)
                        # Marquer la recherche comme seedee
                        _db = get_db()
                        _db.execute("UPDATE searches SET is_seeded = 1 WHERE id = ?", (search_id,))
                        _db.commit()
                        _db.close()
                        print(f"[Scanner] Recherche '{name}' seedee ({len(items)} articles existants ignores)")
                        continue

                    # Scans suivants : notifier uniquement les vrais nouveaux articles
                    # Limite a 5 notifications par scan pour eviter le flood
                    notif_count = 0
                    for item in items:
                        is_new = save_found_item(user["id"], search_id, item)
                        if is_new and notif_count < 5:
                            notification_manager.notify_user(user, item, name)
                            notif_count += 1

                            # Auto-buy si active et plan le permet
                            if plan.get("auto_buy") and user.get("autobuy_enabled") and user.get("vinted_cookie"):
                                buy_rules = {
                                    "enabled": True,
                                    "max_price": user.get("autobuy_max_price", 0),
                                    "brands": json.loads(user.get("autobuy_brands", "[]") or "[]"),
                                    "daily_limit": user.get("autobuy_daily_limit", 5),
                                    "user_id": user["id"],
                                }
                                if auto_buyer.should_auto_buy(item, buy_rules):
                                    mode = user.get("autobuy_mode", "offer")
                                    if mode == "buy":
                                        result = auto_buyer.auto_buy(user["id"], user["vinted_cookie"], item["id"])
                                    else:
                                        offer_price = item.get("price", 0)
                                        result = auto_buyer.send_offer(user["id"], user["vinted_cookie"], item["id"], offer_price)
                                    if result.get("success"):
                                        logger.info(f"autobuy user={user['id']} item={item['id']} mode={mode}")
                                    else:
                                        logger.warning(f"autobuy_fail user={user['id']} item={item['id']} error={result.get('error')}")

            # Boucle rapide pour ne pas rater les VIP (scan_interval=1s)
            # 0.5s = on respecte bien les intervalles 1s VIP et 5s Pro
            time.sleep(0.5)

        except Exception as e:
            print(f"[Scanner] Erreur: {e}")
            time.sleep(5)


# ============================================
# DEMARRAGE DU SCANNER (module-level, apres definition de run_scanner)
# Compatible Gunicorn : s'execute au chargement du module dans le worker
# ============================================
if RUN_SCANNER_IN_WEB:
    _scanner_thread = threading.Thread(target=run_scanner, daemon=True, name="VintedScanner")
    _scanner_thread.start()
    logger.info("scanner_started=true")
else:
    logger.info("scanner_started=false (RUN_SCANNER_IN_WEB=0)")

# Demarrage maintenance automatique (nettoyage DB, purge logs, etc.)
_maintenance_thread = start_maintenance_thread()
logger.info("maintenance_thread_started=true")


# ============================================
# DEMARRAGE
# ============================================
def start_app():
    """Demarre l'application (dev local uniquement - Gunicorn gère le démarrage en production)"""
    port = int(os.environ.get("PORT", 5000))
    print(f"\n{'='*50}")
    print(f"  {APP_NAME} v2.0")
    print(f"  http://localhost:{port}")
    print(f"{'='*50}\n")
    app.run(host="0.0.0.0", port=port, debug=False)


if __name__ == "__main__":
    start_app()
