.PHONY: dev typecheck build up down logs ps clean

dev:            ## Run local dev (Vite HMR + tsx, in-memory store)
	npm run dev

typecheck:      ## Type-check the whole project
	npm run lint

build:          ## Build production bundle (frontend + server)
	npm run build

up:             ## Start full stack (Postgres + Redis + app + nginx)
	docker compose up -d --build

down:           ## Stop the stack (keep volumes)
	docker compose down

logs:           ## Tail all service logs
	docker compose logs -f --tail=100

ps:             ## Show stack status
	docker compose ps

test-e2e:       ## Run the API E2E suite against the running stack
	bash scripts/e2e-test.sh

clean:          ## Stop the stack and wipe volumes (drops all data)
	docker compose down -v