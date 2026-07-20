SHELL := /bin/bash
.PHONY: setup up down test security-audit attack-tests control-checks logs dashboard clean
setup:
	./scripts/setup.sh
up:
	docker compose up -d --wait --wait-timeout 180
down:
	./scripts/teardown.sh
test:
	.venv/bin/pytest -v --junitxml=reports/tests.xml
security-audit:
	./scripts/security-audit.sh
attack-tests:
	.venv/bin/pytest -v tests/test_attacks.py --junitxml=reports/attacks.xml
control-checks:
	.venv/bin/python scripts/control-checks.py
logs:
	docker compose logs --tail=60
dashboard:
	python3 scripts/dashboard.py
clean:
	./scripts/teardown.sh --volumes
	@echo 'Database/index removed. Source logs and secrets retained in runtime/.'
