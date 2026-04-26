install-backend:
	cd backend && pip install -r requirements.txt

serve-backend:
	cd backend && uvicorn main:app --reload --port 8000

install-frontend:
	cd frontend && npm install

serve-frontend:
	cd frontend && npm run dev

install: install-backend install-frontend

up:
	docker-compose up --build

down:
	docker-compose down

logs:
	docker-compose logs -f

smoke-k2:
	python3 scripts/smoke.py k2

smoke-api:
	python3 scripts/smoke.py api

.PHONY: install install-backend install-frontend serve-backend serve-frontend up down logs smoke-k2 smoke-api
