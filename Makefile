.PHONY: generate test help

generate:
	go generate ./...

test:
	go test ./...

help:
	@echo "Usage: make [target]"
	@echo "Targets:"
	@echo "  generate  - Run go generate for all packages"
	@echo "  test      - Run all tests"
	@echo "  help      - Show this help message"
