FROM python:3.12-slim

# Installer dépendances
RUN pip install --no-cache-dir yagmail

# Copie du script
COPY canary_watcher.py /watcher.py

CMD ["python", "/watcher.py"]