#!/usr/bin/env bash

# pre-commit.sh
# Strict engineering pipeline: Format, Mod Tidy, CVE Scan, Lints, Complexity, and Race Tests

echo "Running go fmt..."
unformatted=$(gofmt -s -l .)
if [ -n "$unformatted" ]; then
    echo "❌ The following files are not formatted properly:"
    echo "$unformatted"
    echo "Please run 'go fmt ./...' before committing."
    exit 1
fi

echo "Checking go.mod tidiness..."
go mod tidy
if [ -n "$(git status --porcelain go.mod go.sum)" ]; then
    echo "❌ go.mod or go.sum is not clean."
    echo "Please commit the changes made by 'go mod tidy' before proceeding."
    exit 1
fi

echo "Running golangci-lint (Static Analysis & Complexity)..."
if ! command -v golangci-lint &> /dev/null; then
    echo "⚠️ golangci-lint could not be found. Please install it:"
    echo "curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b \$(go env GOPATH)/bin v1.60.3"
    exit 1
fi
if ! golangci-lint run ./...; then
    echo "❌ golangci-lint failed. Fix the warnings above ( complexity must not grow )."
    exit 1
fi

echo "Running govulncheck (CVE Scan)..."
if ! command -v govulncheck &> /dev/null; then
    echo "⚠️ govulncheck could not be found. Please install it:"
    echo "go install golang.org/x/vuln/cmd/govulncheck@latest"
    exit 1
fi
if ! govulncheck ./...; then
    echo "❌ govulncheck detected known vulnerabilities in dependencies!"
    exit 1
fi

echo "Running Unit Tests with Race Detector..."
if ! go test -race -v ./...; then
    echo "❌ Tests failed."
    exit 1
fi

echo "✅ All checks passed! Ready to commit."
exit 0
