@echo off
setlocal
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$project = '%~dp0';" ^
  "$url = 'http://127.0.0.1:8000/api/products';" ^
  "$ready = $false;" ^
  "try { $null = Invoke-WebRequest -Uri $url -TimeoutSec 2 -UseBasicParsing; $ready = $true } catch {};" ^
  "if (-not $ready) { Start-Process -FilePath 'cmd.exe' -ArgumentList '/k','python server.py' -WorkingDirectory $project -WindowStyle Minimized };" ^
  "for ($i = 0; $i -lt 30; $i++) { try { $null = Invoke-WebRequest -Uri $url -TimeoutSec 2 -UseBasicParsing; $ready = $true; break } catch { Start-Sleep -Seconds 1 } };" ^
  "if (-not $ready) { Write-Error 'Fresh Vegbox did not start. Check the minimized server window for the error.'; exit 1 }"
if errorlevel 1 (
  echo Fresh Vegbox could not start. Check Python and the minimized server window.
  pause
  exit /b 1
)
start "" "http://127.0.0.1:8000/"
echo Fresh Vegbox is running at http://127.0.0.1:8000/
echo Leave the minimized "Fresh Vegbox Server" window open while using the shop.
pause
