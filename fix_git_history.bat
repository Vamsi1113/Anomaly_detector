@echo off
echo ========================================
echo Git History Fix - Remove Secret Commit
echo ========================================
echo.
echo This will remove the commit with the exposed API key
echo.
echo WARNING: This rewrites Git history!
echo.
pause

echo.
echo Step 1: Showing recent commits...
git log --oneline -10

echo.
echo Step 2: Finding the bad commit...
git log --oneline | findstr "85b73cb1"

echo.
echo Step 3: Resetting to commit before the secret...
echo.
echo Enter the commit hash BEFORE 85b73cb1 (from the list above):
set /p SAFE_COMMIT="Commit hash: "

echo.
echo Resetting to %SAFE_COMMIT%...
git reset --hard %SAFE_COMMIT%

echo.
echo Step 4: Re-adding your changes (without secrets)...
git add .
git commit -m "Update code - removed secrets from history"

echo.
echo Step 5: Force pushing to GitHub...
echo WARNING: This will overwrite remote history!
pause

git push origin main --force

echo.
echo ========================================
echo Done! Now ROTATE YOUR API KEY!
echo ========================================
echo.
echo Go to Azure Portal and regenerate your key!
pause
