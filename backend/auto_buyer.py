"""
Module d'achat automatique Vinted
Permet d'acheter automatiquement des articles selon les criteres definis
"""
import requests
import time
import json
import threading
from config import VINTED_BASE_URL, PLANS


class AutoBuyer:
    """
    Systeme d'achat automatique sur Vinted.

    IMPORTANT: Pour que l'achat automatique fonctionne, l'utilisateur
    doit fournir son cookie de session Vinted (connecte a son compte).
    Ce cookie est stocke de maniere chiffree dans la base de donnees.

    Fonctionnement:
    1. L'utilisateur configure ses criteres d'achat (prix max, marques, etc.)
    2. Quand un article match, le bot envoie un message au vendeur OU procede a l'achat
    3. L'utilisateur recoit une notification de confirmation

    Modes:
    - "offer": Envoie une offre au vendeur (plus sur)
    - "buy": Achat direct (necessite un moyen de paiement configure sur Vinted)
    """

    def __init__(self):
        self._sessions = {}
        self._lock = threading.Lock()
        self._purchase_log = []

    def _get_session(self, user_id, vinted_cookie):
        """Cree une session authentifiee pour un utilisateur"""
        with self._lock:
            if user_id not in self._sessions or not self._sessions[user_id].get("valid"):
                session = requests.Session()
                session.headers.update({
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/json",
                    "Accept-Language": "fr-FR,fr;q=0.9",
                    "Referer": VINTED_BASE_URL,
                    "Origin": VINTED_BASE_URL,
                })
                # Ajouter le cookie de session Vinted
                session.cookies.set("_vinted_fr_session", vinted_cookie, domain=".vinted.fr")
                self._sessions[user_id] = {"session": session, "valid": True}

            return self._sessions[user_id]["session"]

    def check_auth(self, user_id, vinted_cookie):
        """Verifie si le cookie Vinted est valide"""
        try:
            session = self._get_session(user_id, vinted_cookie)
            resp = session.get(f"{VINTED_BASE_URL}/api/v2/users/current", timeout=10)

            if resp.status_code == 200:
                data = resp.json()
                user = data.get("user", {})
                return {
                    "valid": True,
                    "vinted_username": user.get("login", ""),
                    "balance": user.get("balance", {}).get("amount", "0"),
                }
            else:
                with self._lock:
                    if user_id in self._sessions:
                        self._sessions[user_id]["valid"] = False
                return {"valid": False, "error": "Cookie expire ou invalide"}

        except Exception as e:
            return {"valid": False, "error": str(e)}

    def send_offer(self, user_id, vinted_cookie, item_id, offer_price):
        """
        Envoie une offre a un vendeur.

        Args:
            user_id: ID utilisateur dans notre systeme
            vinted_cookie: Cookie de session Vinted
            item_id: ID de l'article sur Vinted
            offer_price: Prix de l'offre en EUR

        Returns:
            Dict avec le resultat
        """
        try:
            session = self._get_session(user_id, vinted_cookie)

            # Recuperer les infos de l'article
            resp = session.get(
                f"{VINTED_BASE_URL}/api/v2/items/{item_id}",
                timeout=10
            )
            if resp.status_code != 200:
                return {"success": False, "error": "Article introuvable"}

            item_data = resp.json().get("item", {})
            seller_id = item_data.get("user", {}).get("id")

            if not seller_id:
                return {"success": False, "error": "Vendeur introuvable"}

            # Envoyer l'offre via la conversation
            payload = {
                "offer": {
                    "item_id": item_id,
                    "price": offer_price,
                }
            }

            resp = session.post(
                f"{VINTED_BASE_URL}/api/v2/conversations",
                json={
                    "recipient_id": seller_id,
                    "item_id": item_id,
                    "message": f"Bonjour, je suis interesse par cet article. Je vous propose {offer_price}EUR.",
                },
                timeout=10
            )

            if resp.status_code in (200, 201):
                self._log_purchase(user_id, item_id, offer_price, "offer", "sent")
                return {
                    "success": True,
                    "type": "offer",
                    "item_title": item_data.get("title", ""),
                    "offer_price": offer_price,
                }
            else:
                return {"success": False, "error": f"Erreur Vinted: {resp.status_code}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def auto_buy(self, user_id, vinted_cookie, item_id):
        """
        Achat direct d'un article.

        Args:
            user_id: ID utilisateur
            vinted_cookie: Cookie de session
            item_id: ID de l'article

        Returns:
            Dict avec le resultat
        """
        try:
            session = self._get_session(user_id, vinted_cookie)

            # Etape 1: Recuperer les details de l'article
            resp = session.get(
                f"{VINTED_BASE_URL}/api/v2/items/{item_id}",
                timeout=10
            )
            if resp.status_code != 200:
                return {"success": False, "error": "Article introuvable"}

            item_data = resp.json().get("item", {})

            # Etape 2: Initier la transaction
            resp = session.post(
                f"{VINTED_BASE_URL}/api/v2/transactions",
                json={
                    "item_id": item_id,
                    "buyer_id": "current",
                },
                timeout=15
            )

            if resp.status_code in (200, 201):
                transaction = resp.json()
                price = item_data.get("price", {})
                actual_price = float(price.get("amount", "0") if isinstance(price, dict) else price)

                self._log_purchase(user_id, item_id, actual_price, "buy", "completed")

                return {
                    "success": True,
                    "type": "buy",
                    "item_title": item_data.get("title", ""),
                    "price": actual_price,
                    "transaction_id": transaction.get("id"),
                }
            else:
                return {"success": False, "error": f"Achat impossible: {resp.status_code}"}

        except Exception as e:
            return {"success": False, "error": str(e)}

    def should_auto_buy(self, item, buy_rules):
        """
        Determine si un article doit etre achete automatiquement
        selon les regles definies par l'utilisateur.

        Args:
            item: Dict avec les infos de l'article
            buy_rules: Dict avec les criteres d'achat

        Returns:
            Bool
        """
        if not buy_rules.get("enabled", False):
            return False

        price = item.get("price", 0)
        max_price = buy_rules.get("max_price", 0)

        if max_price > 0 and price > max_price:
            return False

        # Verifier les marques autorisees
        allowed_brands = buy_rules.get("brands", [])
        if allowed_brands:
            item_brand = (item.get("brand") or "").lower()
            if not any(b.lower() in item_brand for b in allowed_brands):
                return False

        # Verifier le nombre max d'achats par jour
        daily_limit = buy_rules.get("daily_limit", 5)
        today_purchases = sum(
            1 for p in self._purchase_log
            if p.get("user_id") == buy_rules.get("user_id")
            and p.get("timestamp", 0) > time.time() - 86400
        )
        if today_purchases >= daily_limit:
            return False

        return True

    def _log_purchase(self, user_id, item_id, price, type_, status):
        """Log un achat/offre"""
        self._purchase_log.append({
            "user_id": user_id,
            "item_id": item_id,
            "price": price,
            "type": type_,
            "status": status,
            "timestamp": time.time(),
        })

        # Garder les 1000 derniers logs
        if len(self._purchase_log) > 1000:
            self._purchase_log = self._purchase_log[-1000:]

    def get_purchase_history(self, user_id, limit=20):
        """Recupere l'historique des achats d'un utilisateur"""
        user_logs = [
            p for p in reversed(self._purchase_log)
            if p.get("user_id") == user_id
        ]
        return user_logs[:limit]


# Singleton
auto_buyer = AutoBuyer()
