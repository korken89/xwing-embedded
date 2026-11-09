# Host tests, lints and the QEMU measurements
.PHONY: test test-host test-qemu size lint bless

# A failing command before a pipe fails the recipe
SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c

# `x25519-cortex-m` needs the DSP extension, so these builds are for a Cortex-M33
m33 := CARGO_TARGET_DIR=target/cortex-m33 \
	CARGO_TARGET_THUMBV8M_MAIN_NONE_EABIHF_RUSTFLAGS=-Ctarget-cpu=cortex-m33 cargo
m4 := --bin x25519 --target thumbv7em-none-eabihf
# The Cortex-M33 rows, the `CortexMX25519` rows on a Cortex-M4 and the positive controls of the
# `DalekX25519` scrub on both
checks := cargo run --release --quiet && cargo run --release --quiet $(m4) \
	&& cargo run --release --quiet --bin scrub-control \
	&& cargo run --release --quiet --bin scrub-control --target thumbv7em-none-eabihf
# These and the `x-wing` rows
measure := $(checks) && cargo run --release --quiet --bin x-wing --features x-wing

# Panic locations in .rodata hold the paths of registry crates, so the measured .rodata sizes
# would depend on the length of the CARGO_HOME path
cargo_home := $(or $(CARGO_HOME),$(HOME)/.cargo)
remap := --remap-path-prefix=$(cargo_home)=/cargo
test-qemu bless size: export CARGO_TARGET_THUMBV8M_MAIN_NONE_EABIHF_RUSTFLAGS := $(remap)
test-qemu bless size: export CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUSTFLAGS := $(remap)

QEMU_INCLUDE = $(shell dirname $$(dirname $$(readlink -f $$(command -v qemu-system-arm))))/include
PLUGIN := qemu/target/libicount.so

test: test-host test-qemu

test-host:
	cargo test --release
	cargo test --release --features defmt --test secret_types

# Fails if the measurements differ from qemu/measurements.txt, if an operation leaves a secret
# on the stack, or if an operation that must take constant time takes another number of
# instructions for another input. The residue and constant-time checks run at opt-level 2, 3 and z
# too.
test-qemu: $(PLUGIN)
	cd qemu && ($(measure)) | tee target/measurements.txt
	diff -u qemu/measurements.txt qemu/target/measurements.txt
	for opt in 2 3 z; do \
		(cd qemu && export CARGO_PROFILE_RELEASE_OPT_LEVEL=$$opt \
			CARGO_TARGET_DIR=target/opt-$$opt && $(checks)) \
			> qemu/target/opt-$$opt.txt || { cat qemu/target/opt-$$opt.txt; exit 1; }; \
		echo "opt-level $$opt: no residue, constant time"; \
	done

# Prints the code size of each operation
size: $(PLUGIN)
	qemu/text-size.sh

lint:
	cargo fmt --check
	cargo clippy --all-targets -- -D warnings
	cargo clippy --target thumbv8m.main-none-eabihf --no-default-features -- -D warnings
	cargo clippy --target thumbv8m.main-none-eabihf --no-default-features --features mlkem-otf -- -D warnings
	cargo clippy --target thumbv8m.main-none-eabihf --no-default-features --features ml-kem -- -D warnings
	cargo clippy --target thumbv8m.main-none-eabihf --no-default-features --features x25519-dalek -- -D warnings
	$(m33) clippy --target thumbv8m.main-none-eabihf --all-features -- -D warnings
	$(m33) build --target thumbv8m.main-none-eabihf --no-default-features --features x25519-cortex-m
	cargo clippy --target thumbv7em-none-eabihf --all-features -- -D warnings
	cargo build --target thumbv7em-none-eabihf --no-default-features --features x25519-cortex-m
	RUSTDOCFLAGS=-Dwarnings cargo doc --no-deps --features defmt,zerocopy
	RUSTDOCFLAGS=-Dwarnings $(m33) doc --target thumbv8m.main-none-eabihf --no-deps --all-features
	cd qemu && cargo fmt --check
	cd qemu && cargo clippy --release --bins -- -D warnings
	cd qemu && cargo clippy --release --bins --all-features -- -D warnings
	cd qemu && cargo clippy --release $(m4) -- -D warnings

# Overwrites qemu/measurements.txt with the current measurements
bless: $(PLUGIN)
	cd qemu && ($(measure)) | tee measurements.txt

$(PLUGIN): qemu/icount.c
	mkdir -p qemu/target
	$(CC) -shared -fPIC -O2 -Wall -Werror $$(pkg-config --cflags glib-2.0) -I$(QEMU_INCLUDE) -o $@ $<
