#!/usr/bin/env bash

# pre-commit.sh
# Ensure code is formatted, vetted, and tested before allowing commit

echo "Running go fmt..."
unformatted=$(gofmt -s -l .)
if [ -n "$unformatted" ]; then
    echo "The following files are not formatted properly:"
    echo "$unformatted"
    echo "Please run 'go fmt ./...' before committing."
    exit 1
fi

echo "Running go vet..."
if ! go vet ./...; then
    echo "go vet failed."
    exit 1
fi

echo "Running mock tests (short)..."
if ! go test -short ./...; then
    echo "Tests failed."
    exit 1
fi

echo "All checks passed! Ready to commit."
exit 0
