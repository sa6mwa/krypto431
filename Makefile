NAME = krypto431
MODULE = github.com/sa6mwa/krypto431
VF = VERSION
SEMVEREIS = github.com/sa6mwa/semvereis@v0.1.2
NEXTMINOR = go run $(SEMVEREIS) next minor -nd v0.0.0
NEXTMINORTAG = go run $(SEMVEREIS) next minor -vnd v0.0.0
NEXTPATCH = go run $(SEMVEREIS) next patch -nd v0.0.0
NEXTPATCHTAG = go run $(SEMVEREIS) next patch -vnd v0.0.0
DESTDIR = /usr/local/bin
SRC = $(MODULE)/cmd/$(NAME)
GO = CGO_ENABLED=0 go
build = $(GO) build -v -ldflags=-s
crossCompile = GOOS=$(1) GOARCH=$(2) $(build) -o $(NAME)-$(1)-$(2) $(SRC)
crossCompileWindows = GOOS=windows GOARCH=$(1) $(build) -o $(NAME)-$(1).exe $(SRC)
armCompile = GOOS=$(1) GOARCH=arm GOARM=$(2) $(build) -o $(NAME)-$(1)-arm$(2) $(SRC)
sha = sha1sum $(NAME)-*-* $(NAME)-*.exe > $(NAME)-$(1).sha1sum
tar = tar --owner=0 --group=0 -czf $(NAME)-$(1).tar.gz --transform 's|^|$(NAME)-$(1)/|' *.go LICENSE AUTHORS VERSION Makefile README.md cmd/ crand/ diana/ fonts/ vendor/ $(NAME)-$(1).sha1sum $(NAME)-*-* $(NAME)-*.exe
tagmsg = @echo "Commit, tag and push when done: git commit -a ; git tag $(1) ; git push origin $(1)"

.PHONY: all release releaseMinor releasePatch upgrade install clean build dependencies test amd64 arm64 386 arm% %bsd darwin linux

all: build

release: releaseMinor

releaseMinor:
	$(NEXTMINOR) -so $(VF)
	$(MAKE) clean dependencies test linux darwin freebsd netbsd openbsd windows
	$(call sha,$(shell $(NEXTMINOR)))
	$(call tar,$(shell $(NEXTMINOR)))
	$(call tagmsg,$(shell $(NEXTMINORTAG)))

releasePatch:
	$(NEXTPATCH) -so $(VF)
	$(MAKE) clean dependencies test linux darwin freebsd netbsd openbsd windows
	$(call sha,$(shell $(NEXTPATCH)))
	$(call tar,$(shell $(NEXTPATCH)))
	$(call tagmsg,$(shell $(NEXTPATCHTAG)))

install:
	@if [ `id -u` -ne 0 ]; then echo "You may need to sudo to install $(NAME)." ; fi
	for f in $(NAME) $(NAME)-*-* ; do if test -x $$f ; then install $$f $(DESTDIR)/$$f ; fi ; done

clean:
	for f in $(NAME) $(NAME)-*-* $(NAME)-*.exe ; do if test -x $$f ; then rm -f $$f ; fi; done
	rm -f $(NAME)-*.tar.gz $(NAME)-*.sha1sum

build: dependencies test $(NAME)

dependencies:
	$(GO) get -v -d ./...

test:
	$(GO) test -cover ./...

$(VF):
	git describe --tags --abbrev=0 | sed 's/^v//' > $(VF)

go.mod:
	go mod init $(MODULE)
	go mod tidy -v

upgrade: go.mod
	go get -v -u all
	go mod tidy -v
	go mod vendor -v

linux: amd64 arm64 arm6 arm7 386

windows: $(NAME)-amd64.exe $(NAME)-386.exe

amd64: $(NAME)-linux-amd64

arm64: $(NAME)-linux-arm64

386: $(NAME)-linux-386

arm%:
	$(MAKE) $(NAME)-linux-arm6 $(NAME)-linux-$@

%bsd:
	$(MAKE) $(NAME)-$@-amd64 $(NAME)-$@-arm64

darwin: $(NAME)-darwin-amd64 $(NAME)-darwin-arm64

$(NAME):
	$(build) -o $(NAME) $(SRC)

$(NAME)-linux-amd64:
	$(call crossCompile,linux,amd64)

$(NAME)-linux-arm64:
	$(call crossCompile,linux,arm64)

$(NAME)-linux-arm6:
	$(call armCompile,linux,6)

$(NAME)-linux-arm7:
	$(call armCompile,linux,7)

$(NAME)-linux-386:
	$(call crossCompile,linux,386)

$(NAME)-darwin-amd64:
	$(call crossCompile,darwin,amd64)

$(NAME)-darwin-arm64:
	$(call crossCompile,darwin,amd64)

$(NAME)-freebsd-amd64:
	$(call crossCompile,freebsd,amd64)

$(NAME)-freebsd-arm64:
	$(call crossCompile,freebsd,arm64)

$(NAME)-netbsd-amd64:
	$(call crossCompile,netbsd,amd64)

$(NAME)-netbsd-arm64:
	$(call crossCompile,netbsd,arm64)

$(NAME)-openbsd-amd64:
	$(call crossCompile,openbsd,amd64)

$(NAME)-openbsd-arm64:
	$(call crossCompile,openbsd,arm64)

$(NAME)-amd64.exe:
	$(call crossCompileWindows,amd64)

$(NAME)-386.exe:
	$(call crossCompileWindows,386)
