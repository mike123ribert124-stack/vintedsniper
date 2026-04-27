"""
Configuration globale de la plateforme VintedSniper
"""
import os

# ============================================
# CONFIGURATION GENERALE
# ============================================
APP_NAME = "VintedSniper"
APP_VERSION = "2.0.0"
SECRET_KEY = os.environ.get("SECRET_KEY", "change-this-secret-key-in-production")
ENVIRONMENT = os.environ.get("ENVIRONMENT", "production").strip().lower()
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "").strip().lower()
RUN_SCANNER_IN_WEB = os.environ.get("RUN_SCANNER_IN_WEB", "1").strip() == "1"

# Origines autorisees pour les appels API navigateur
# Format attendu: "https://vintedsniper.fr,https://www.vintedsniper.fr"
_origins_raw = os.environ.get(
    "CORS_ALLOWED_ORIGINS",
    "https://vintedsniper.fr,https://www.vintedsniper.fr,http://localhost:5000,http://127.0.0.1:5000"
)
CORS_ALLOWED_ORIGINS = [o.strip() for o in _origins_raw.split(",") if o.strip()]

# ============================================
# BASE DE DONNEES
# ============================================
DATABASE_PATH = os.environ.get("DATABASE_PATH", os.path.join(os.path.expanduser("~"), "vintedsniper.db"))

# ============================================
# PLANS D'ABONNEMENT
# ============================================
PLANS = {
    "free": {
        "name": "Starter",
        "price_monthly": 0,
        "price_yearly": 0,
        "max_searches": 2,
        "scan_interval": 120,       # 2 minutes
        "notifications": ["discord"],
        "auto_buy": False,
        "max_favorites": 10,
        "description": "Parfait pour decouvrir",
    },
    "basic": {
        "name": "Basic",
        "price_monthly": 15,
        "price_yearly": 144,        # 12€/mois = -20%
        "max_searches": 10,
        "scan_interval": 30,        # 30 secondes
        "notifications": ["discord", "email"],
        "auto_buy": False,
        "max_favorites": 50,
        "stripe_price_id": os.environ.get("STRIPE_BASIC_PRICE_ID", ""),
        "stripe_yearly_price_id": os.environ.get("STRIPE_BASIC_YEARLY_PRICE_ID", ""),
        "description": "Pour les revendeurs serieux",
    },
    "pro": {
        "name": "Pro",
        "price_monthly": 50,
        "price_yearly": 480,        # 40€/mois = -20%
        "max_searches": 30,
        "scan_interval": 10,        # 10 secondes
        "notifications": ["discord", "email", "browser"],
        "auto_buy": True,
        "max_favorites": 200,
        "stripe_price_id": os.environ.get("STRIPE_PRO_PRICE_ID", ""),
        "stripe_yearly_price_id": os.environ.get("STRIPE_PRO_YEARLY_PRICE_ID", ""),
        "description": "Pour les pros du resell",
    },
    "vip": {
        "name": "VIP",
        "price_monthly": 90,
        "price_yearly": 864,        # 72€/mois = -20%
        "max_searches": 100,
        "scan_interval": 5,         # 5 secondes
        "notifications": ["discord", "email", "sms", "browser"],
        "auto_buy": True,
        "max_favorites": -1,        # Illimite
        "stripe_price_id": os.environ.get("STRIPE_VIP_PRICE_ID", ""),
        "stripe_yearly_price_id": os.environ.get("STRIPE_VIP_YEARLY_PRICE_ID", ""),
        "description": "Puissance maximale",
    },
}

# ============================================
# STRIPE
# ============================================
STRIPE_SECRET_KEY = os.environ.get("STRIPE_SECRET_KEY", "")
STRIPE_PUBLISHABLE_KEY = os.environ.get("STRIPE_PUBLISHABLE_KEY", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

# ============================================
# PAYPAL
# ============================================
PAYPAL_CLIENT_ID = os.environ.get("PAYPAL_CLIENT_ID", "")
PAYPAL_CLIENT_SECRET = os.environ.get("PAYPAL_CLIENT_SECRET", "")
PAYPAL_MODE = os.environ.get("PAYPAL_MODE", "sandbox")  # sandbox ou live

# ============================================
# EMAIL (Brevo API HTTP - contourne les restrictions SMTP de Railway)
# ============================================
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")

# ============================================
# VINTED
# ============================================
VINTED_BASE_URL = "https://www.vinted.fr"
VINTED_API_URL = f"{VINTED_BASE_URL}/api/v2"
