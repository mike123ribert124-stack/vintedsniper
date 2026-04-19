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
        "max_searches": 10,
        "scan_interval": 30,        # 30 secondes
        "notifications": ["discord", "email"],
        "auto_buy": False,
        "max_favorites": 50,
        "stripe_price_id": os.environ.get("STRIPE_BASIC_PRICE_ID", ""),
        "description": "Pour les revendeurs serieux",
    },
    "pro": {
        "name": "Pro",
        "price_monthly": 50,
        "max_searches": 30,
        "scan_interval": 10,        # 10 secondes
        "notifications": ["discord", "email", "browser"],
        "auto_buy": True,
        "max_favorites": 200,
        "stripe_price_id": os.environ.get("STRIPE_PRO_PRICE_ID", ""),
        "description": "Pour les pros du resell",
    },
    "vip": {
        "name": "VIP",
        "price_monthly": 90,
        "max_searches": 100,
        "scan_interval": 5,         # 5 secondes
        "notifications": ["discord", "email", "sms", "browser"],
        "auto_buy": True,
        "max_favorites": -1,        # Illimite
        "stripe_price_id": os.environ.get("STRIPE_VIP_PRICE_ID", ""),
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
# EMAIL (SMTP)
# ============================================
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")

# ============================================
# VINTED
# ============================================
VINTED_BASE_URL = "https://www.vinted.fr"
VINTED_API_URL = f"{VINTED_BASE_URL}/api/v2"
