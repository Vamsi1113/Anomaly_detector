@echo off
echo ========================================
echo Secret Detection - Pre-Commit Check
echo ========================================
echo.

echo Checking for hardcoded API keys...
echo.

echo 1. Checking staged files...
git diff --cached --name-only
echo.

echo 2. Scanning for potential secrets...
git diff --cached | findstr /i "api_key API_KEY secret password token sk-"
if %ERRORLEVEL% EQU 0 (
    echo.
    echo ❌ WARNING: Potential secrets found in staged files!
    echo Review the output above carefully.
    echo.
    pause
) else (
    echo ✅ No obvious secrets detected in staged files
    echo.
)

echo 3. Checking if .env is staged (should NOT be)...
git diff --cached --name-only | findstr ".env"
if %ERRORLEVEL% EQU 0 (
    echo ❌ ERROR: .env file is staged! This should NOT be committed!
    echo Run: git reset HEAD .env
    pause
    exit /b 1
) else (
    echo ✅ .env is not staged (good)
    echo.
)

echo 4. Checking if test files are staged (should NOT be)...
git diff --cached --name-only | findstr "llmtest.py test_env_key.py test_azure_openai.py"
if %ERRORLEVEL% EQU 0 (
    echo ❌ WARNING: Test files are staged!
    echo These files may contain secrets.
    echo Consider adding them to .gitignore
    pause
) else (
    echo ✅ No test files staged
    echo.
)

echo ========================================
echo Verification Complete
echo ========================================
echo.
echo If all checks passed, you can safely commit:
echo   git commit -m "Your message"
echo   git push origin main
echo.
pause
