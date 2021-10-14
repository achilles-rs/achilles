all: libsocket.a

libsocket.a: src/lib.rs Cargo.toml
	cargo build --release

clean:
	rm -rf target
	rm -rf Cargo.lock