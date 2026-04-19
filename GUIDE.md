# VintedSniper - Guide complet

## Structure du projet

```
vinted-saas/
├── backend/
│   ├── app.py              # Serveur Flask (routes API + pages)
│   ├── config.py           # Configuration (plans, cles, prix)
│   ├── database.py         # Base de donnees SQLite (users, recherches, articles)
│   ├── vinted_engine.py    # Moteur de scan Vinted multi-thread
│   ├── notifications.py    # Notifications (Discord, Email, navigateur)
│   ├── payments.py         # Paiements Stripe
│   └── auto_buyer.py       # Achat automatique sur Vinted
├── frontend/
│   ├── landing.html        # Page d'accueil publique
│   ├── login.html          # Page de connexion
│   ├── register.html       # Page d'inscription
│   ├── dashboard.html      # Tableau de bord utilisateur
│   ├── admin.html          # Panneau administrateur
│   ├── forgot_password.html # Mot de passe oublie
│   └── reset_password.html  # Reinitialisation du mot de passe
├── Procfile                # Config Railway (demarrage serveur)
├── requirements.txt        # Dependances Python
├── runtime.txt             # Version Python
├── nixpacks.toml           # Config build Railway
└── GUIDE.md                # Ce fichier
```

## Pages disponibles

| URL | Description | Acces |
|-----|-------------|-------|
| `/` | Page d'accueil avec tarifs | Public |
| `/login` | Connexion | Public |
| `/register` | Inscription | Public |
| `/forgot-password` | Mot de passe oublie | Public |
| `/reset-password?token=xxx` | Nouveau mot de passe | Lien email |
| `/dashboard` | Tableau de bord | Connecte |
| `/admin` | Panneau administrateur | Admin |

## API disponibles

### Authentification
- `POST /api/register` - Inscription (email, username, password)
- `POST /api/login` - Connexion (email, password)
- `POST /api/logout` - Deconnexion
- `POST /api/forgot-password` - Demander un lien de reinitialisation
- `POST /api/reset-password` - Changer le mot de passe (token, password)

### Utilisateur
- `GET /api/me` - Profil et stats
- `PUT /api/me/settings` - Modifier ses parametres (discord_webhook)

### Recherches
- `GET /api/searches` - Lister ses recherches
- `POST /api/searches` - Creer une recherche
- `DELETE /api/searches/:id` - Supprimer une recherche
- `POST /api/searches/:id/toggle` - Activer/desactiver une recherche
- `POST /api/search/test` - Tester une recherche manuellement

### Articles
- `GET /api/items` - Lister les articles trouves

### Paiements
- `GET /api/plans` - Voir les plans disponibles
- `POST /api/checkout` - Demarrer un paiement Stripe

### Administration
- `GET /api/admin/overview` - Stats globales
- `GET /api/admin/users` - Lister les utilisateurs
- `PUT /api/admin/users/:id` - Modifier un utilisateur
- `POST /api/admin/users/:id/toggle` - Bloquer/activer un utilisateur
- `GET /api/admin/searches` - Toutes les recherches
- `GET /api/admin/items` - Tous les articles
- `GET /api/admin/logs` - Logs systeme

## Variables d'environnement (Railway)

| Variable | Description | Obligatoire |
|----------|-------------|-------------|
| `SECRET_KEY` | Cle secrete Flask | Oui |
| `STRIPE_SECRET_KEY` | Cle secrete Stripe | Oui |
| `STRIPE_PUBLISHABLE_KEY` | Cle publique Stripe | Oui |
| `STRIPE_BASIC_PRICE_ID` | ID prix Stripe plan Basic | Oui |
| `STRIPE_PRO_PRICE_ID` | ID prix Stripe plan Pro | Oui |
| `STRIPE_VIP_PRICE_ID` | ID prix Stripe plan VIP | Oui |
| `ADMIN_EMAIL` | Email de l'administrateur | Non (defaut: mike123.ribert124@gmail.com) |
| `SMTP_HOST` | Serveur email | Non (defaut: smtp.gmail.com) |
| `SMTP_PORT` | Port email | Non (defaut: 587) |
| `SMTP_USER` | Email d'envoi | Non |
| `SMTP_PASSWORD` | Mot de passe email | Non |

## Plans d'abonnement

| Plan | Prix | Recherches | Scan | Notifications | Achat auto |
|------|------|-----------|------|---------------|------------|
| Starter | Gratuit | 2 | 2 min | Discord | Non |
| Basic | 15 EUR/mois | 10 | 30s | Discord + Email | Non |
| Pro | 50 EUR/mois | 30 | 10s | Discord + Email + Navigateur | Oui |
| VIP | 90 EUR/mois | 100 | 5s | Tous les canaux + SMS | Oui |

## Securite en place

- Mots de passe haches avec PBKDF2 (SHA-256, 100 000 iterations)
- Protection anti-brute-force (5 tentatives max, blocage 5 min)
- Sessions securisees (HttpOnly, SameSite=Lax, expire 24h)
- Validation des emails et mots de passe
- Tokens de reinitialisation uniques (expirent en 1h)
- Panneau admin protege par email + flag is_admin
- Requetes SQL parametrees (protection injection SQL)

## Lancer en local

```bash
cd backend
pip install -r ../requirements.txt
python app.py
```

Le site sera sur http://localhost:5000

## Deployer sur Railway

1. Pousser sur GitHub : `git add . && git commit -m "message" && git push`
2. Railway redploie automatiquement
3. Configurer les variables d'environnement dans Railway > Variables
