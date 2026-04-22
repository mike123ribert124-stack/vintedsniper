# VintedSniper - Go Live Checklist

## 1) Variables d'environnement (production)
- `ENVIRONMENT=production`
- `SECRET_KEY=<long random secret>`
- `ADMIN_EMAIL=<your-admin-email>`
- `CORS_ALLOWED_ORIGINS=https://vintedsniper.fr,https://www.vintedsniper.fr`
- `RUN_SCANNER_IN_WEB=1` (mettre `0` si scanner deplace dans un worker dedie)
- `STRIPE_SECRET_KEY=<stripe secret key>`
- `STRIPE_WEBHOOK_SECRET=<stripe webhook signing secret>`
- `STRIPE_BASIC_PRICE_ID=<price id>`
- `STRIPE_PRO_PRICE_ID=<price id>`
- `STRIPE_VIP_PRICE_ID=<price id>`
- `SMTP_HOST=<smtp host>`
- `SMTP_PORT=<587 or 465>`
- `SMTP_USER=<smtp user>`
- `SMTP_PASSWORD=<smtp app password>`

## 2) Pre-flight securite
- Verifier que `/api/forgot-password` ne retourne jamais de token/lien.
- Verifier que `/api/me` ne retourne pas `api_key`.
- Verifier que `/admin` est accessible uniquement avec `is_admin=1`.
- Verifier presence des headers securite (`X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).

## 3) Pre-flight paiements
- Configurer le webhook Stripe vers: `/api/stripe/webhook`.
- Ecouter au minimum:
  - `checkout.session.completed`
  - `customer.subscription.updated`
  - `customer.subscription.deleted`
- Verifier qu'un paiement met a jour `users.plan`.
- Verifier qu'une annulation repasse `users.plan` a `free`.

## 4) Smoke tests fonctionnels
- `GET /healthz` retourne 200.
- `GET /readyz` retourne 200.
- Inscription utilisateur -> connexion -> dashboard.
- Mot de passe oublie -> email recu -> reset effectif.
- Creation recherche -> recherche active visible dashboard.
- Reception d'au moins une notification.
- Upgrade plan -> plan visible dans dashboard apres webhook.

## 5) Validation UX avant ouverture trafic
- Landing lisible mobile + desktop.
- CTA principal visible sans scroll.
- Formulaires login/register/reset sans erreur front.
- Dashboard: checklist onboarding visible et actionable.

## 6) Rollback minimal
- Snapshot base SQLite avant deploy.
- Conserver build precedent deployable.
- Procedure rollback testee (revenir version N-1 + restaurer DB snapshot).
