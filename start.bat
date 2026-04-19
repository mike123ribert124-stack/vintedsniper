@echo off
echo ============================================
echo   VintedSniper - Demarrage
echo ============================================
echo.

REM Installer les dependances
echo [1/2] Installation des dependances...
pip install -r requirements.txt --quiet

echo.
echo [2/2] Lancement du serveur...
echo.
echo  Ouvre ton navigateur sur: http://localhost:5000
echo  Ctrl+C pour arreter
echo.

cd backend
python app.py
pause
