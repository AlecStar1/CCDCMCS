import os, sys
print(sys.platform)
os.system('bash ./linux/main.sh' if sys.platform != 'win32' else 'powershell -ExecutionPolicy Bypass -File ./windows/main.ps1')
