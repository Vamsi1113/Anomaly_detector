@echo off
echo ==================================================================
echo GIT SETUP - PUSH TO GITHUB
echo ==================================================================
echo.

echo Step 1: Configuring Git...
echo.
set /p email="Enter your GitHub email: "
git config --global user.name "Vamsi"
git config --global user.email "%email%"
echo ✓ Git configured
echo.

echo Step 2: Checking status...
git status
echo.
pause

echo Step 3: Adding files...
git add .
echo ✓ Files added
echo.

echo Step 4: Creating first commit...
git commit -m "Initial commit: Enterprise Log Anomaly Detection System - Multi-layer threat detection with ML models"
echo ✓ Commit created
echo.

echo Step 5: Connecting to GitHub repository...
git remote add origin https://github.com/Vamsi1113/Anomaly_detector.git
echo ✓ Remote added
echo.

echo Step 6: Pushing to GitHub...
git branch -M main
git push -u origin main
echo.

echo ==================================================================
echo DONE! Check your repository at:
echo https://github.com/Vamsi1113/Anomaly_detector
echo ==================================================================
pause
