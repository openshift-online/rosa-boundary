# Makefile for building multi-arch ROSA Boundary container
IMAGE_NAME := rosa-boundary
TAG := latest
FULL_IMAGE := $(IMAGE_NAME):$(TAG)

# Architecture-specific image tags
AMD64_IMAGE := $(IMAGE_NAME):$(TAG)-amd64
ARM64_IMAGE := $(IMAGE_NAME):$(TAG)-arm64

.PHONY: all build build-amd64 build-arm64 manifest clean help

# Default target: build both architectures and create manifest
all: build manifest

# Build both architectures
build: build-amd64 build-arm64

# Build AMD64/x86_64 variant
build-amd64:
	@echo "Building AMD64 variant..."
	podman build --platform linux/amd64 -t $(AMD64_IMAGE) -f Containerfile .

# Build ARM64 variant
build-arm64:
	@echo "Building ARM64 variant..."
	podman build --platform linux/arm64 -t $(ARM64_IMAGE) -f Containerfile .

# Create manifest list combining both architectures
manifest: build
	@echo "Creating manifest list..."
	podman manifest rm $(FULL_IMAGE) 2>/dev/null || true
	podman manifest create $(FULL_IMAGE)
	podman manifest add $(FULL_IMAGE) $(AMD64_IMAGE)
	podman manifest add $(FULL_IMAGE) $(ARM64_IMAGE)
	@echo "Manifest created: $(FULL_IMAGE)"
	@echo "Inspect with: podman manifest inspect $(FULL_IMAGE)"

# Clean up all images and manifests
clean:
	@echo "Removing images and manifests..."
	podman manifest rm $(FULL_IMAGE) 2>/dev/null || true
	podman rmi $(AMD64_IMAGE) 2>/dev/null || true
	podman rmi $(ARM64_IMAGE) 2>/dev/null || true
	@echo "Cleanup complete"

# Show help
help:
	@echo "ROSA Boundary Container Build Targets:"
	@echo "  make all          - Build both architectures and create manifest (default)"
	@echo "  make build        - Build both AMD64 and ARM64 variants"
	@echo "  make build-amd64  - Build only AMD64 variant"
	@echo "  make build-arm64  - Build only ARM64 variant"
	@echo "  make manifest     - Create multi-arch manifest list"
	@echo "  make clean        - Remove all images and manifests"
	@echo "  make help         - Show this help message"
	@echo ""
	@echo "Current configuration:"
	@echo "  Image name: $(FULL_IMAGE)"
	@echo "  AMD64 tag:  $(AMD64_IMAGE)"
	@echo "  ARM64 tag:  $(ARM64_IMAGE)"
