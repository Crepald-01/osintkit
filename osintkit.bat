@echo off
where python >nul 2>nul && (python "%~dp0osintkit.py" %*) || (py "%~dp0osintkit.py" %*)
