VENV := .venv
PY   := $(VENV)/bin/python
PIP  := $(VENV)/bin/pip

# Create the venv on first install. Everything else assumes it exists.
$(VENV)/bin/activate:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip

install-backend: $(VENV)/bin/activate
	$(PIP) install -r backend/requirements.txt
	$(PIP) install httpx ruff

serve-backend: install-backend
	cd backend && ../$(VENV)/bin/uvicorn main:app --reload --port 8000

install-frontend:
	cd frontend && npm install

serve-frontend:
	cd frontend && npm run dev

install: install-backend install-frontend

# Local Docker (mirrors what runs on Vultr).
up:
	docker compose up --build

down:
	docker compose down

logs:
	docker compose logs -f

# Smoke tests run from the venv so K2_API_KEY from .env loads cleanly.
smoke-k2: install-backend
	$(PY) scripts/smoke.py k2

smoke-api: install-backend
	$(PY) scripts/smoke.py api

lint: install-backend
	cd backend && ../$(VENV)/bin/ruff check .

clean:
	rm -rf $(VENV) backend/__pycache__ scripts/__pycache__

.PHONY: install install-backend install-frontend serve-backend serve-frontend up down logs smoke-k2 smoke-api lint clean
