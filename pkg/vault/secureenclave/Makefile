PKG = cryptokit/macos
LIB = $(PKG)/.build/release/libmacos.a
SRC = $(PKG)/Sources/macos/macos.swift

.PHONY: all lib module

all: module

lib: $(LIB)

$(LIB): $(SRC)
	swift build --package-path $(PKG) -c release

module: $(LIB)
	go build