IMAGE ?= gm-pqc-dev
TAG ?= latest
SERVICE ?= pqc-dev
COMPOSE ?= docker compose -f infra/compose/docker-compose.yml
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: help up down build shell verify logs build-image buildx-push clean

help:
	@echo "Targets:"
	@echo "  make up            - docker compose up -d --build"
	@echo "  make down          - docker compose down"
	@echo "  make shell         - attach to running container bash"
	@echo "  make verify        - run infra/scripts/verify_env.sh in container"
	@echo "  make logs          - follow container logs"
	@echo "  make build-image   - docker build .devcontainer/Dockerfile to $(IMAGE):$(TAG)"
	@echo "  make buildx-push   - multi-arch buildx and push to registry"

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

shell:
	docker exec -it $(SERVICE) bash || (echo "container not running, try 'make up'" && false)

verify:
	docker exec -i $(SERVICE) bash -lc 'bash infra/scripts/verify_env.sh'

logs:
	$(COMPOSE) logs -f

build-image:
	docker build -f .devcontainer/Dockerfile -t $(IMAGE):$(TAG) .

buildx-push:
	docker buildx build --platform $(PLATFORMS) -f .devcontainer/Dockerfile -t $(IMAGE):$(TAG) . --push

clean:
	$(COMPOSE) down -v || true

