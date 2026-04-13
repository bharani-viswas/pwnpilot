.PHONY: help install-deps install dev test lint format clean build deb release

help:
	@echo "PwnPilot Build System"
	@echo "===================="
	@echo "Available targets:"
	@echo "  make install-deps     Install system dependencies (requires sudo)"
	@echo "  make install          Install pwnpilot in development mode"
	@echo "  make dev              Install with development dependencies"
	@echo "  make test             Run test suite"
	@echo "  make lint             Run linters (ruff, mypy)"
	@echo "  make format           Format code with ruff"
	@echo "  make clean            Remove build artifacts"
	@echo "  make build            Build Python distribution"
	@echo "  make deb              Build Debian package (.deb)"
	@echo "  make release          Create release tarball"
	@echo "  make quick-install    Quick install from source (no system deps)"

install-deps:
	@echo "Installing system dependencies..."
	sudo apt-get update
	sudo apt-get install -y \
		python3.10 python3.11 python3-pip python3-venv \
		build-essential python3-dev \
		nmap nikto zaproxy \
		git curl wget
	@echo "Install the full required security toolchain: 'sudo bash scripts/install_security_tools.sh'"

quick-install: 
	@echo "Installing PwnPilot (quick - Python deps only)..."
	python -m venv .venv || python3 -m venv .venv
	. .venv/bin/activate && pip install --upgrade pip setuptools wheel
	. .venv/bin/activate && pip install -e .
	. .venv/bin/activate && alembic upgrade head
	. .venv/bin/activate && pwnpilot keys --generate
	@echo "✓ Installation complete!"
	@echo "Activate with: source .venv/bin/activate"

install: install-deps quick-install

dev:
	@echo "Installing PwnPilot with development dependencies..."
	python -m venv .venv || python3 -m venv .venv
	. .venv/bin/activate && pip install --upgrade pip setuptools wheel
	. .venv/bin/activate && pip install -e ".[dev]"
	. .venv/bin/activate && alembic upgrade head
	. .venv/bin/activate && pwnpilot keys --generate
	@echo "✓ Development installation complete!"

test:
	. .venv/bin/activate && pytest tests/ -v

lint:
	. .venv/bin/activate && ruff check pwnpilot tests
	. .venv/bin/activate && mypy pwnpilot

format:
	. .venv/bin/activate && ruff format pwnpilot tests

build: clean
	python -m pip install --upgrade build
	python -m build

clean:
	rm -rf build dist *.egg-info .pytest_cache .coverage .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

deb: clean
	@echo "Building Debian package..."
	bash scripts/build-deb.sh

release: clean build
	@echo "Creating release tarball..."
	mkdir -p dist/release
	tar -czf dist/release/pwnpilot-$(shell python -c "import tomllib; print(tomllib.loads(open('pyproject.toml').read())['project']['version'])" 2>/dev/null || echo "0.1.0").tar.gz \
		--exclude='.venv' \
		--exclude='.git' \
		--exclude='__pycache__' \
		--exclude='*.egg-info' \
		.
	@echo "✓ Release tarball created in dist/release/"
