"""
Systeme de notifications multi-canal
Discord, Email, Notifications navigateur (SSE)
"""
import requests
import smtplib
import time
import json
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from collections import defaultdict
from config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, APP_NAME


class NotificationManager:
    """Gere l'envoi de notifications sur tous les canaux"""

    def __init__(self):
        self._sse_clients = defaultdict(list)  # user_id -> [queue]
        self._lock = threading.Lock()

    # ==========================================
    # DISCORD
    # ==========================================
    def send_discord(self, webhook_url, item, search_name=""):
        """Envoie une alerte Discord avec embed riche"""
        if not webhook_url:
            return False

        price = item.get("price", 0)

        if price <= 5:
            color = 0x2ECC71
            tag = "ULTRA DEAL"
        elif price <= 15:
            color = 0x2ECC71
            tag = "BONNE AFFAIRE"
        else:
            color = 0xE67E22
            tag = "A VOIR"

        embed = {
            "title": item.get("title", "Article"),
            "url": item.get("url", ""),
            "color": color,
            "fields": [
                {"name": "Prix", "value": f"**{price:.2f} EUR**", "inline": True},
                {"name": "Marque", "value": item.get("brand") or "N/A", "inline": True},
                {"name": "Taille", "value": item.get("size") or "N/A", "inline": True},
                {"name": "Vendeur", "value": item.get("user", "?"), "inline": True},
                {"name": "Favoris", "value": str(item.get("favourite_count", 0)), "inline": True},
                {"name": "Tag", "value": f"`{tag}`", "inline": True},
            ],
            "footer": {"text": f"{search_name} | {APP_NAME}"},
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        photo = item.get("photo", "")
        if photo:
            embed["thumbnail"] = {"url": photo}

        payload = {
            "content": f"**Nouvel article !**",
            "embeds": [embed]
        }

        try:
            resp = requests.post(webhook_url, json=payload, timeout=10)
            if resp.status_code == 429:
                retry = resp.json().get("retry_after", 3)
                time.sleep(retry)
                resp = requests.post(webhook_url, json=payload, timeout=10)
            return resp.status_code in (200, 204)
        except Exception as e:
            print(f"[Notif] Discord erreur: {e}")
            return False

    # ==========================================
    # EMAIL
    # ==========================================
    def send_email(self, to_email, item, search_name=""):
        """Envoie une alerte par email"""
        if not SMTP_USER or not to_email:
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"[{APP_NAME}] {item.get('title', 'Nouvel article')} - {item.get('price', '?')}EUR"
            msg["From"] = f"{APP_NAME} <{SMTP_USER}>"
            msg["To"] = to_email

            price = item.get("price", 0)
            html = f"""
            <html>
            <body style="font-family: Arial, sans-serif; background: #1a1a2e; color: #fff; padding: 20px;">
                <div style="max-width: 500px; margin: 0 auto; background: #16213e; border-radius: 12px; padding: 20px;">
                    <h2 style="color: #00d4ff;">{APP_NAME}</h2>
                    <h3>Nouvel article trouve !</h3>
                    <p><strong>Recherche:</strong> {search_name}</p>
                    <hr style="border-color: #333;">
                    <h3><a href="{item.get('url', '#')}" style="color: #00d4ff;">{item.get('title', 'Article')}</a></h3>
                    <p style="font-size: 24px; color: #2ecc71;"><strong>{price:.2f} EUR</strong></p>
                    <p>Marque: {item.get('brand', 'N/A')} | Taille: {item.get('size', 'N/A')}</p>
                    <p>Vendeur: {item.get('user', '?')} | Favoris: {item.get('favourite_count', 0)}</p>
                    <a href="{item.get('url', '#')}" style="display:inline-block; background:#00d4ff; color:#000; padding:12px 24px; border-radius:8px; text-decoration:none; font-weight:bold; margin-top:10px;">
                        Voir sur Vinted
                    </a>
                </div>
            </body>
            </html>
            """

            msg.attach(MIMEText(html, "html"))

            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.sendmail(SMTP_USER, to_email, msg.as_string())

            return True
        except Exception as e:
            print(f"[Notif] Email erreur: {e}")
            return False

    # ==========================================
    # SSE (Server-Sent Events) - Navigateur
    # ==========================================
    def register_sse_client(self, user_id, queue):
        """Enregistre un client SSE"""
        with self._lock:
            self._sse_clients[user_id].append(queue)

    def unregister_sse_client(self, user_id, queue):
        """Desenregistre un client SSE"""
        with self._lock:
            if user_id in self._sse_clients:
                self._sse_clients[user_id] = [
                    q for q in self._sse_clients[user_id] if q is not queue
                ]

    def send_browser(self, user_id, item, search_name=""):
        """Envoie une notification en temps reel au navigateur via SSE"""
        with self._lock:
            clients = self._sse_clients.get(user_id, [])

        event_data = json.dumps({
            "type": "new_item",
            "search_name": search_name,
            "item": {
                "id": item.get("id"),
                "title": item.get("title"),
                "price": item.get("price"),
                "brand": item.get("brand"),
                "size": item.get("size"),
                "url": item.get("url"),
                "photo": item.get("photo"),
                "user": item.get("user"),
            }
        })

        for queue in clients:
            try:
                queue.put_nowait(event_data)
            except Exception:
                pass

        return len(clients) > 0

    # ==========================================
    # ENVOI MULTI-CANAL
    # ==========================================
    def notify_user(self, user, item, search_name="", channels=None):
        """
        Envoie des notifications sur tous les canaux actifs de l'utilisateur.

        Args:
            user: Dict avec les infos utilisateur (plan, webhook, email...)
            item: Dict avec les infos de l'article
            search_name: Nom de la recherche
            channels: Liste de canaux a utiliser (None = tous)

        Returns:
            Dict {canal: success_bool}
        """
        results = {}

        if channels is None:
            from config import PLANS
            plan = PLANS.get(user.get("plan", "free"), PLANS["free"])
            channels = plan.get("notifications", ["discord"])

        if "discord" in channels and user.get("discord_webhook"):
            results["discord"] = self.send_discord(
                user["discord_webhook"], item, search_name
            )

        if "email" in channels and user.get("email"):
            results["email"] = self.send_email(
                user["email"], item, search_name
            )

        if "browser" in channels:
            results["browser"] = self.send_browser(
                user.get("id"), item, search_name
            )

        return results


    # ==========================================
    # EMAIL REINITIALISATION MOT DE PASSE
    # ==========================================
    def send_reset_email(self, to_email, username, reset_url):
        """Envoie un email de reinitialisation de mot de passe"""
        if not SMTP_USER or not to_email:
            raise Exception("SMTP non configure")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{APP_NAME}] Reinitialisation de ton mot de passe"
        msg["From"] = f"{APP_NAME} <{SMTP_USER}>"
        msg["To"] = to_email

        html = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background: #1a1a2e; color: #fff; padding: 20px;">
            <div style="max-width: 500px; margin: 0 auto; background: #16213e; border-radius: 12px; padding: 30px;">
                <h2 style="color: #00d4ff; text-align: center;">{APP_NAME}</h2>
                <h3 style="text-align: center;">Reinitialisation du mot de passe</h3>
                <p>Salut <strong>{username}</strong>,</p>
                <p>Tu as demande a reinitialiser ton mot de passe. Clique sur le bouton ci-dessous :</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{reset_url}" style="display:inline-block; background:linear-gradient(135deg,#00d4ff,#7c3aed); color:#fff; padding:14px 32px; border-radius:10px; text-decoration:none; font-weight:bold; font-size:16px;">
                        Changer mon mot de passe
                    </a>
                </div>
                <p style="font-size:13px; color:#888;">Ce lien expire dans 1 heure.</p>
                <p style="font-size:13px; color:#888;">Si tu n'as pas fait cette demande, ignore cet email.</p>
                <hr style="border-color: #333; margin-top: 20px;">
                <p style="font-size:12px; color:#666; text-align:center;">{APP_NAME} - Ne reponds pas a cet email</p>
            </div>
        </body>
        </html>
        """

        msg.attach(MIMEText(html, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(SMTP_USER, to_email, msg.as_string())

        return True


# Singleton
notification_manager = NotificationManager()
