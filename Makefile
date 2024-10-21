BINDIR = $(DESTDIR)/usr/local/bin
BINLOCAL = ~/.local/bin
NAME = colorhash

default: build

build:
	cargo build --release

install: target/release/$(NAME)
	@if ! [ "$(shell id -u)" = 0 ];then \
  	echo "You are not root, run this target as root please"; \
    exit 1; \
	else \
		install --mode=755 target/release/$(NAME) $(BINDIR)/; \
	fi

local: target/release/$(NAME)
	install --mode=755 target/release/$(NAME) $(BINLOCAL)

clean:
	cargo clean

test:
	clear
	cargo test

doc:
	cargo doc

uninstall:
	@if ! [ "$(shell id -u)" = 0 ];then \
  	echo "You are not root, run this target as root please"; \
    exit 1; \
	else \
		rm $(BINDIR)/$(NAME); \
	fi

