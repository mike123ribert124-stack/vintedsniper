"""
============================================
  VINTEDSNIPER - Maintenance automatique
============================================
Taches de nettoyage executees periodiquement :
- Purge des sessions expirees (password_resets > 1h)
- Purge des anciens articles (found_items > 30 jours)
- Purge des anciens logs de notifications (> 30 jours)
- Purge des anciens paiements webhook (> 90 jours)
- Verification integrite SQLite (PRAGMA integrity_check)
- Nettoyage des recherches inactives sans articles

Frequence : toutes les 6 heures (configurable)
"""
import time
import threading
import logging

from database import get_db

logger = logging.getLogger("VintedSniper.maintenance")

# Intervalle entre chaque cycle de maintenance (en secondes)
MAINTENANCE_INTERVAL = 6 * 3600  # 6 heures


def purge_expired_resets():
    """Supprime les tokens de reset de mot de passe expires (> 1 heure)"""
    db = get_db()
    try:
        cursor = db.execute(
            "DELETE FROM password_resets WHERE expires_at < ?",
            (time.time(),)
        )
        db.commit()
        count = cursor.rowcount
        if count > 0:
            logger.info(f"maintenance: purge_resets deleted={count}")
        return count
    except Exception as e:
        logger.error(f"maintenance: purge_resets error={e}")
        return 0
    finally:
        db.close()


def purge_old_items(days=30):
    """Supprime les articles trouves il y a plus de N jours"""
    db = get_db()
    try:
        cutoff = time.time() - (days * 86400)
        cursor = db.execute(
            "DELETE FROM found_items WHERE found_at < ?",
            (cutoff,)
        )
        db.commit()
        count = cursor.rowcount
        if count > 0:
            logger.info(f"maintenance: purge_items deleted={count} (older than {days}d)")
        return count
    except Exception as e:
        logger.error(f"maintenance: purge_items error={e}")
        return 0
    finally:
        db.close()


def purge_old_notifications(days=30):
    """Supprime les logs de notifications de plus de N jours"""
    db = get_db()
    try:
        cutoff = time.time() - (days * 86400)
        cursor = db.execute(
            "DELETE FROM notifications_log WHERE sent_at < ?",
            (cutoff,)
        )
        db.commit()
        count = cursor.rowcount
        if count > 0:
            logger.info(f"maintenance: purge_notifs deleted={count}")
        return count
    except Exception as e:
        logger.error(f"maintenance: purge_notifs error={e}")
        return 0
    finally:
        db.close()


def purge_old_webhook_events(days=90):
    """Supprime les evenements webhook Stripe traites de plus de N jours"""
    db = get_db()
    try:
        cutoff = time.time() - (days * 86400)
        cursor = db.execute(
            "DELETE FROM webhook_events WHERE processed_at < ?",
            (cutoff,)
        )
        db.commit()
        count = cursor.rowcount
        if count > 0:
            logger.info(f"maintenance: purge_webhooks deleted={count}")
        return count
    except Exception as e:
        logger.error(f"maintenance: purge_webhooks error={e}")
        return 0
    finally:
        db.close()


def check_db_integrity():
    """Verifie l'integrite de la base de donnees SQLite"""
    db = get_db()
    try:
        result = db.execute("PRAGMA integrity_check").fetchone()
        status = result[0] if result else "unknown"
        if status == "ok":
            logger.info("maintenance: db_integrity=ok")
        else:
            logger.warning(f"maintenance: db_integrity={status}")
        return status
    except Exception as e:
        logger.error(f"maintenance: db_integrity error={e}")
        return "error"
    finally:
        db.close()


def optimize_db():
    """Optimise la base SQLite (VACUUM et ANALYZE)"""
    db = get_db()
    try:
        db.execute("PRAGMA optimize")
        db.commit()
        logger.info("maintenance: db_optimize=done")
    except Exception as e:
        logger.error(f"maintenance: db_optimize error={e}")
    finally:
        db.close()


def run_maintenance_cycle():
    """Execute un cycle complet de maintenance"""
    logger.info("maintenance: cycle_start")
    start = time.time()

    results = {
        "resets_purged": purge_expired_resets(),
        "items_purged": purge_old_items(30),
        "notifs_purged": purge_old_notifications(30),
        "webhooks_purged": purge_old_webhook_events(90),
        "db_integrity": check_db_integrity(),
    }

    # Optimisation DB une fois par cycle
    optimize_db()

    elapsed = round(time.time() - start, 2)
    logger.info(f"maintenance: cycle_done duration={elapsed}s results={results}")
    return results


def start_maintenance_thread():
    """
    Demarre le thread de maintenance en arriere-plan.
    Le premier cycle s'execute 60 secondes apres le demarrage
    pour laisser l'application s'initialiser.
    """
    def maintenance_loop():
        # Attendre 60s apres le demarrage avant le premier cycle
        time.sleep(60)
        logger.info("maintenance: thread_started")

        while True:
            try:
                run_maintenance_cycle()
            except Exception as e:
                logger.error(f"maintenance: unexpected_error={e}")

            time.sleep(MAINTENANCE_INTERVAL)

    thread = threading.Thread(
        target=maintenance_loop,
        daemon=True,
        name="MaintenanceWorker"
    )
    thread.start()
    return thread
