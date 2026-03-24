.PHONY: generate test test-integration help

generate:
	go generate ./...

test:
	go test ./...

test-integration:
	./scripts/run_tests.sh

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  generate  - Run go generate for all packages"
	@echo "  test      - Run all tests"
	@echo "  test-integration - Run automation script for integration tests"
	@echo "  help      - Show this help message"
