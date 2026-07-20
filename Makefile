BINARY  := aegis
VERSION ?= 1.8.0
MODULE  := github.com/andreipaciurca/aegis
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
LDFLAGS := -s -w -X $(MODULE)/internal/ui.Version=$(VERSION)

.PHONY: build install install-system uninstall-system run release archives clean test checksums sign-checksums sign-darwin sign-windows verify-release

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

install:
	go install -ldflags "$(LDFLAGS)" .

install-system: build
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 "$(BINARY)" "$(DESTDIR)$(BINDIR)/$(BINARY)"
	@echo "installed $(BINARY) to $(DESTDIR)$(BINDIR)/$(BINARY)"

uninstall-system:
	rm -f "$(DESTDIR)$(BINDIR)/$(BINARY)"
	@echo "removed $(DESTDIR)$(BINDIR)/$(BINARY)"

run: build
	./$(BINARY)

test:
	go vet ./...
	go test ./...

# Cross-compiled release binaries for every supported platform.
release:
	mkdir -p dist
	GOOS=darwin  GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-$(VERSION)-darwin-arm64 .
	GOOS=darwin  GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-$(VERSION)-darwin-amd64 .
	GOOS=linux   GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-$(VERSION)-linux-amd64 .
	GOOS=linux   GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-$(VERSION)-linux-arm64 .
	GOOS=windows GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-$(VERSION)-windows-amd64.exe .
	@ls -la dist

archives: release
	rm -rf dist/pkg
	mkdir -p dist/pkg
	mkdir -p dist/pkg/$(BINARY)-$(VERSION)-darwin-arm64
	cp dist/$(BINARY)-$(VERSION)-darwin-arm64 dist/pkg/$(BINARY)-$(VERSION)-darwin-arm64/$(BINARY)
	cp README.md SECURITY.md LICENSE NOTICE dist/pkg/$(BINARY)-$(VERSION)-darwin-arm64/
	cd dist/pkg && tar -czf ../$(BINARY)-$(VERSION)-darwin-arm64.tar.gz $(BINARY)-$(VERSION)-darwin-arm64
	mkdir -p dist/pkg/$(BINARY)-$(VERSION)-darwin-amd64
	cp dist/$(BINARY)-$(VERSION)-darwin-amd64 dist/pkg/$(BINARY)-$(VERSION)-darwin-amd64/$(BINARY)
	cp README.md SECURITY.md LICENSE NOTICE dist/pkg/$(BINARY)-$(VERSION)-darwin-amd64/
	cd dist/pkg && tar -czf ../$(BINARY)-$(VERSION)-darwin-amd64.tar.gz $(BINARY)-$(VERSION)-darwin-amd64
	mkdir -p dist/pkg/$(BINARY)-$(VERSION)-linux-amd64
	cp dist/$(BINARY)-$(VERSION)-linux-amd64 dist/pkg/$(BINARY)-$(VERSION)-linux-amd64/$(BINARY)
	cp README.md SECURITY.md LICENSE NOTICE dist/pkg/$(BINARY)-$(VERSION)-linux-amd64/
	cd dist/pkg && tar -czf ../$(BINARY)-$(VERSION)-linux-amd64.tar.gz $(BINARY)-$(VERSION)-linux-amd64
	mkdir -p dist/pkg/$(BINARY)-$(VERSION)-linux-arm64
	cp dist/$(BINARY)-$(VERSION)-linux-arm64 dist/pkg/$(BINARY)-$(VERSION)-linux-arm64/$(BINARY)
	cp README.md SECURITY.md LICENSE NOTICE dist/pkg/$(BINARY)-$(VERSION)-linux-arm64/
	cd dist/pkg && tar -czf ../$(BINARY)-$(VERSION)-linux-arm64.tar.gz $(BINARY)-$(VERSION)-linux-arm64
	mkdir -p dist/pkg/$(BINARY)-$(VERSION)-windows-amd64
	cp dist/$(BINARY)-$(VERSION)-windows-amd64.exe dist/pkg/$(BINARY)-$(VERSION)-windows-amd64/$(BINARY).exe
	cp README.md SECURITY.md LICENSE NOTICE dist/pkg/$(BINARY)-$(VERSION)-windows-amd64/
	cd dist/pkg && zip -qr ../$(BINARY)-$(VERSION)-windows-amd64.zip $(BINARY)-$(VERSION)-windows-amd64
	rm -rf dist/pkg
	@ls -la dist/*.tar.gz dist/*.zip

checksums: archives
	cd dist && find . -maxdepth 1 -type f \( -name '*.tar.gz' -o -name '*.zip' \) -print | sed 's#^\./##' | sort | xargs shasum -a 256 > SHA256SUMS
	@cat dist/SHA256SUMS

sign-checksums: checksums
	@if [ -z "$$GPG_KEY" ]; then echo "set GPG_KEY to the signing key id"; exit 2; fi
	gpg --batch --yes --local-user "$$GPG_KEY" --detach-sign --armor dist/SHA256SUMS

sign-darwin:
	@if [ -z "$$CODESIGN_IDENTITY" ]; then echo "set CODESIGN_IDENTITY, e.g. 'Developer ID Application: Name (TEAMID)'"; exit 2; fi
	codesign --force --timestamp --options runtime --sign "$$CODESIGN_IDENTITY" dist/$(BINARY)-$(VERSION)-darwin-arm64
	codesign --force --timestamp --options runtime --sign "$$CODESIGN_IDENTITY" dist/$(BINARY)-$(VERSION)-darwin-amd64

sign-windows:
	@if [ -z "$$SIGNTOOL" ]; then echo "set SIGNTOOL to signtool.exe path"; exit 2; fi
	@if [ -z "$$WINDOWS_CERT_SHA1" ]; then echo "set WINDOWS_CERT_SHA1 to the certificate thumbprint"; exit 2; fi
	"$$SIGNTOOL" sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /sha1 "$$WINDOWS_CERT_SHA1" dist/$(BINARY)-$(VERSION)-windows-amd64.exe

verify-release:
	cd dist && shasum -a 256 -c SHA256SUMS

clean:
	rm -rf $(BINARY) dist
