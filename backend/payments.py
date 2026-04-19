"""
Systeme de paiement - Stripe + PayPal
Gestion des abonnements et upgrades de plan
"""
import time
from config import (
    STRIPE_SECRET_KEY, STRIPE_PUBLISHABLE_KEY, STRIPE_WEBHOOK_SECRET,
    PAYPAL_CLIENT_ID, PAYPAL_CLIENT_SECRET, PAYPAL_MODE, PLANS
)

# ============================================
# Stripe sera initialise si la cle est configuree
# ============================================
stripe = None
try:
    import stripe as stripe_module
    if STRIPE_SECRET_KEY:
        stripe_module.api_key = STRIPE_SECRET_KEY
        stripe = stripe_module
        print("[Payments] Stripe initialise")
except ImportError:
    print("[Payments] Module stripe non installe (pip install stripe)")


class PaymentManager:
    """Gere les paiements Stripe et PayPal"""

    # ==========================================
    # STRIPE
    # ==========================================
    def create_stripe_customer(self, email, username):
        """Cree un client Stripe"""
        if not stripe:
            return None
        try:
            customer = stripe.Customer.create(
                email=email,
                name=username,
                metadata={"source": "vintedsniper"}
            )
            return customer.id
        except Exception as e:
            print(f"[Stripe] Erreur creation client: {e}")
            return None

    def create_checkout_session(self, customer_id, plan_key, success_url, cancel_url):
        """Cree une session de paiement Stripe Checkout"""
        if not stripe:
            return None

        plan = PLANS.get(plan_key)
        if not plan or plan.get("price_monthly", 0) == 0:
            return None

        try:
            session = stripe.checkout.Session.create(
                customer=customer_id,
                payment_method_types=["card"],
                line_items=[{
                    "price": plan.get("stripe_price_id"),
                    "quantity": 1,
                }],
                mode="subscription",
                success_url=success_url + "?session_id={CHECKOUT_SESSION_ID}",
                cancel_url=cancel_url,
                metadata={"plan": plan_key},
            )
            return session.url
        except Exception as e:
            print(f"[Stripe] Erreur checkout: {e}")
            return None

    def create_portal_session(self, customer_id, return_url):
        """Cree un portail client Stripe pour gerer l'abonnement"""
        if not stripe:
            return None
        try:
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=return_url,
            )
            return session.url
        except Exception as e:
            print(f"[Stripe] Erreur portail: {e}")
            return None

    def handle_webhook(self, payload, signature):
        """Traite un webhook Stripe"""
        if not stripe:
            return None
        try:
            event = stripe.Webhook.construct_event(
                payload, signature, STRIPE_WEBHOOK_SECRET
            )
            return event
        except Exception as e:
            print(f"[Stripe] Erreur webhook: {e}")
            return None

    # ==========================================
    # PAYPAL
    # ==========================================
    def get_paypal_config(self):
        """Retourne la config PayPal pour le frontend"""
        return {
            "client_id": PAYPAL_CLIENT_ID,
            "mode": PAYPAL_MODE,
            "plans": {
                key: {
                    "name": plan["name"],
                    "price": plan["price_monthly"],
                }
                for key, plan in PLANS.items()
                if plan["price_monthly"] > 0
            }
        }

    # ==========================================
    # GESTION DES PLANS
    # ==========================================
    def get_plan_features(self, plan_key):
        """Retourne les fonctionnalites d'un plan"""
        return PLANS.get(plan_key, PLANS["free"])

    def can_add_search(self, plan_key, current_count):
        """Verifie si l'utilisateur peut ajouter une recherche"""
        plan = PLANS.get(plan_key, PLANS["free"])
        max_searches = plan["max_searches"]
        return max_searches == -1 or current_count < max_searches

    def get_scan_interval(self, plan_key):
        """Retourne l'intervalle de scan pour un plan"""
        plan = PLANS.get(plan_key, PLANS["free"])
        return plan.get("scan_interval", 120)

    def can_auto_buy(self, plan_key):
        """Verifie si l'achat auto est disponible"""
        plan = PLANS.get(plan_key, PLANS["free"])
        return plan.get("auto_buy", False)


payment_manager = PaymentManager()
