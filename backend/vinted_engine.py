"""
Moteur de recherche Vinted ultra-rapide
Multi-thread avec gestion de cookies intelligente
"""
import requests
import time
import random
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from config import VINTED_BASE_URL, VINTED_API_URL


class VintedEngine:
    """Moteur de recherche Vinted haute performance"""

    # Delai entre requetes selon le plan (en secondes)
    PLAN_DELAYS = {
        "vip": 0,          # Instantane - aucun delai
        "pro": 0.1,        # Quasi-instantane
        "basic": 0.3,      # Leger delai
        "free": 0.5,       # Delai standard
    }

    def __init__(self, max_workers=5):
        self.max_workers = max_workers
        self._sessions = {}
        self._session_lock = threading.Lock()

    def _get_session(self, thread_id=None):
        """Recupere ou cree une session HTTP par thread"""
        tid = thread_id or threading.current_thread().ident

        with self._session_lock:
            if tid not in self._sessions:
                session = requests.Session()
                session.headers.update({
                    "User-Agent": self._random_user_agent(),
                    "Accept": "application/json, text/plain, */*",
                    "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8",
                    "Referer": VINTED_BASE_URL,
                    "Origin": VINTED_BASE_URL,
                })
                self._sessions[tid] = {
                    "session": session,
                    "cookies_ok": False,
                    "last_refresh": 0,
                }
            return self._sessions[tid]

    def _random_user_agent(self):
        """Genere un User-Agent aleatoire"""
        agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        ]
        return random.choice(agents)

    def _ensure_cookies(self, session_data):
        """S'assure que les cookies sont valides (refresh toutes les 5 min)"""
        now = time.time()
        if session_data["cookies_ok"] and (now - session_data["last_refresh"]) < 300:
            return True

        try:
            resp = session_data["session"].get(VINTED_BASE_URL, timeout=10)
            resp.raise_for_status()
            session_data["cookies_ok"] = True
            session_data["last_refresh"] = now
            return True
        except Exception as e:
            print(f"[VintedEngine] Erreur cookies: {e}")
            session_data["cookies_ok"] = False
            return False

    def get_catalogs(self):
        """Recupere les categories Vinted (essaie l'API, fallback sur categories hardcodees)"""
        session_data = self._get_session()
        if self._ensure_cookies(session_data):
            # Vinted utilise /catalog/categories (pas /catalogs)
            for url in [f"{VINTED_API_URL}/catalog/categories", f"{VINTED_API_URL}/catalogs"]:
                try:
                    resp = session_data["session"].get(url, timeout=10)
                    if resp.status_code != 200:
                        continue
                    data = resp.json()
                    raw = data.get("catalogs", data.get("categories", []))
                    if not raw:
                        continue
                    result = []
                    for cat in raw:
                        result.append({"id": cat.get("id"), "title": cat.get("title", ""), "parent_id": None})
                        for sub in cat.get("catalogs", cat.get("categories", [])):
                            result.append({"id": sub.get("id"), "title": sub.get("title", ""), "parent_id": cat.get("id"), "parent_title": cat.get("title", "")})
                            for subsub in sub.get("catalogs", sub.get("categories", [])):
                                result.append({"id": subsub.get("id"), "title": subsub.get("title", ""), "parent_id": sub.get("id"), "parent_title": f"{cat.get('title','')} > {sub.get('title','')}"})
                    if result:
                        return result
                except Exception as e:
                    print(f"[VintedEngine] Erreur catalogs ({url}): {e}")

        # Fallback : categories populaires hardcodees (IDs Vinted FR)
        return [
            {"id": 4,    "title": "Hommes",                    "parent_id": None},
            {"id": 15,   "title": "Vêtements",                 "parent_id": 4,   "parent_title": "Hommes"},
            {"id": 116,  "title": "Chaussures",                "parent_id": 4,   "parent_title": "Hommes"},
            {"id": 220,  "title": "Sacs & Accessoires",        "parent_id": 4,   "parent_title": "Hommes"},
            {"id": 5,    "title": "Femmes",                    "parent_id": None},
            {"id": 1904, "title": "Vêtements",                 "parent_id": 5,   "parent_title": "Femmes"},
            {"id": 16,   "title": "Chaussures",                "parent_id": 5,   "parent_title": "Femmes"},
            {"id": 54,   "title": "Sacs",                      "parent_id": 5,   "parent_title": "Femmes"},
            {"id": 2,    "title": "Enfants",                   "parent_id": None},
            {"id": 3,    "title": "Vêtements enfants",         "parent_id": 2,   "parent_title": "Enfants"},
            {"id": 139,  "title": "Chaussures enfants",        "parent_id": 2,   "parent_title": "Enfants"},
            {"id": 1231, "title": "Maison",                    "parent_id": None},
            {"id": 2066, "title": "Informatique & Téléphonie", "parent_id": None},
            {"id": 2050, "title": "Beauté & Bien-être",        "parent_id": None},
        ]

    def search_brands(self, query="", per_page=25):
        """Recherche les marques Vinted"""
        session_data = self._get_session()
        if not self._ensure_cookies(session_data):
            return []
        try:
            params = {"per_page": per_page, "search_text": query}
            resp = session_data["session"].get(f"{VINTED_API_URL}/brands", params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            return [{"id": b.get("id"), "title": b.get("title", "")} for b in data.get("brands", [])]
        except Exception as e:
            print(f"[VintedEngine] Erreur brands: {e}")
            return []

    def get_sizes(self, catalog_id=None):
        """Recupere les tailles disponibles, optionnellement pour une categorie"""
        session_data = self._get_session()
        if not self._ensure_cookies(session_data):
            return []
        try:
            params = {}
            if catalog_id:
                params["catalog_id"] = catalog_id
            resp = session_data["session"].get(f"{VINTED_API_URL}/sizes", params=params, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            sizes = data.get("sizes", [])
            result = []
            for group in sizes:
                group_title = group.get("title", "")
                for s in group.get("sizes", []):
                    result.append({
                        "id": s.get("id"),
                        "title": s.get("title", ""),
                        "group": group_title,
                    })
            return result
        except Exception as e:
            print(f"[VintedEngine] Erreur sizes: {e}")
            return []

    def search(self, keywords="", catalog_ids=None, brand_ids=None,
               price_from=None, price_to=None, size_ids=None,
               status_ids=None, order="newest_first", per_page=20, plan="free",
               sort_order=None):
        """Recherche sur Vinted - vitesse adaptee au plan"""
        session_data = self._get_session()

        if not self._ensure_cookies(session_data):
            return []

        # sort_order est un alias de order pour compat avec search_batch
        if sort_order and not order:
            order = sort_order

        params = {
            "page": 1,
            "per_page": per_page,
            "order": order,
            "currency": "EUR",
            "search_text": keywords,
        }

        if catalog_ids:
            params["catalog_ids"] = ",".join(str(i) for i in catalog_ids)
        if brand_ids:
            params["brand_ids"] = ",".join(str(i) for i in brand_ids)
        if price_from is not None:
            params["price_from"] = price_from
        if price_to is not None:
            params["price_to"] = price_to
        if size_ids:
            params["size_ids"] = ",".join(str(i) for i in size_ids)
        if status_ids:
            params["status_ids"] = ",".join(str(i) for i in status_ids)

        try:
            # Delai adapte au plan - VIP = 0 = instantane
            delay = self.PLAN_DELAYS.get(plan, 0.5)
            if delay > 0:
                time.sleep(delay)

            url = f"{VINTED_API_URL}/catalog/items"
            resp = session_data["session"].get(url, params=params, timeout=15)

            if resp.status_code == 401:
                session_data["cookies_ok"] = False
                self._ensure_cookies(session_data)
                resp = session_data["session"].get(url, params=params, timeout=15)

            resp.raise_for_status()
            data = resp.json()
            return self._parse_items(data.get("items", []))

        except Exception as e:
            print(f"[VintedEngine] Erreur recherche: {e}")
            return []

    def search_batch(self, search_configs, plan="free"):
        """
        Recherche en batch multi-thread.
        Lance plusieurs recherches en parallele pour un temps de reponse minimal.
        VIP/Pro = plus de threads paralleles pour une vitesse maximale.

        Args:
            search_configs: Liste de dicts avec les params de chaque recherche
            plan: Plan de l'utilisateur (adapte le nombre de workers)

        Returns:
            Dict {search_name: [items]}
        """
        results = {}

        # Plus de workers pour les plans premium = scan plus rapide
        plan_workers = {
            "vip": 10,      # 10 threads paralleles
            "pro": 8,       # 8 threads
            "basic": 5,     # 5 threads
            "free": 3,      # 3 threads
        }
        workers = plan_workers.get(plan, self.max_workers)

        with ThreadPoolExecutor(max_workers=workers) as executor:
            future_to_name = {}

            for config in search_configs:
                if not config.get("is_active", True):
                    continue

                future = executor.submit(
                    self.search,
                    keywords=config.get("keywords", ""),
                    catalog_ids=config.get("catalog_ids"),
                    brand_ids=config.get("brand_ids"),
                    price_from=config.get("price_from"),
                    price_to=config.get("price_to"),
                    size_ids=config.get("size_ids"),
                    status_ids=config.get("status_ids"),
                    order=config.get("sort_order", "newest_first"),
                    per_page=config.get("per_page", 20),
                    plan=plan,
                )
                future_to_name[future] = config.get("name", "Recherche")

            for future in as_completed(future_to_name):
                name = future_to_name[future]
                try:
                    items = future.result(timeout=30)
                    results[name] = items
                except Exception as e:
                    print(f"[VintedEngine] Erreur batch '{name}': {e}")
                    results[name] = []

        return results

    def get_item_details(self, item_id):
        """Recupere les details complets d'un article"""
        session_data = self._get_session()

        if not self._ensure_cookies(session_data):
            return None

        try:
            url = f"{VINTED_API_URL}/items/{item_id}"
            resp = session_data["session"].get(url, timeout=15)
            resp.raise_for_status()
            data = resp.json()
            item = data.get("item", {})
            return {
                "id": item.get("id"),
                "title": item.get("title"),
                "description": item.get("description", ""),
                "price": float(item.get("price", {}).get("amount", "0") if isinstance(item.get("price"), dict) else item.get("price", "0")),
                "brand": item.get("brand_title", ""),
                "size": item.get("size_title", ""),
                "condition": item.get("status", ""),
                "color": item.get("color1", ""),
                "url": item.get("url", ""),
                "photos": [p.get("url", "") for p in item.get("photos", [])],
                "user": {
                    "login": item.get("user", {}).get("login", ""),
                    "rating": item.get("user", {}).get("feedback_reputation", 0),
                    "items_count": item.get("user", {}).get("items_count", 0),
                },
                "favourite_count": item.get("favourite_count", 0),
                "view_count": item.get("view_count", 0),
            }
        except Exception as e:
            print(f"[VintedEngine] Erreur details item {item_id}: {e}")
            return None

    def _parse_items(self, raw_items):
        """Parse les articles en format standardise"""
        parsed = []
        for item in raw_items:
            try:
                price_data = item.get("price", {})
                if isinstance(price_data, dict):
                    price = float(price_data.get("amount", "0"))
                    currency = price_data.get("currency_code", "EUR")
                else:
                    price = float(price_data or 0)
                    currency = "EUR"

                parsed.append({
                    "id": item.get("id"),
                    "title": item.get("title", "Sans titre"),
                    "price": price,
                    "currency": currency,
                    "brand": item.get("brand_title", ""),
                    "size": item.get("size_title", ""),
                    "url": item.get("url", f"{VINTED_BASE_URL}/items/{item.get('id')}"),
                    "photo": item.get("photo", {}).get("url", "") if item.get("photo") else "",
                    "user": item.get("user", {}).get("login", "Inconnu") if item.get("user") else "Inconnu",
                    "favourite_count": item.get("favourite_count", 0),
                    "view_count": item.get("view_count", 0),
                    "timestamp": time.time(),
                })
            except Exception:
                continue
        return parsed
