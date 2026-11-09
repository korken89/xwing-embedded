#!/usr/bin/env bash
# Prints the .text bytes that each X-Wing operation adds to an empty Cortex-M33 binary, with
# opt-level "s" and LTO, for each ML-KEM-768 and X25519 backend. Each operation includes
# everything it calls, such as SHA-3 and X25519. Encapsulation includes the key check and
# decapsulation the key expansion, which they need.
set -euo pipefail
cd "$(dirname "$0")"

text() {
    cargo run --release --quiet --bin text-size "$@"
}

echo "Code size in bytes (.text) on a Cortex-M33, opt-level s:"
for mlkem in mlkem-otf ml-kem; do
    for x25519 in dalek cortex-m; do
        features=""
        if [ "$mlkem" = ml-kem ]; then features="rustcrypto,"; fi
        if [ "$x25519" = cortex-m ]; then features="${features}cortex-m,"; fi
        name="$mlkem/$x25519"
        base=$(text --features "$features")
        for op in encapsulation-key expand check encapsulate decapsulate; do
            printf "  %-18s %-18s %6d\n" "$name" "$op" $(($(text --features "$features$op") - base))
        done
        all="${features}encapsulation-key,expand,check,encapsulate,decapsulate"
        printf "  %-18s %-18s %6d\n" "$name" all $(($(text --features "$all") - base))
    done
done
for x25519 in dalek cortex-m; do
    features=""
    if [ "$x25519" = cortex-m ]; then features="cortex-m,"; fi
    base=$(text --features "$features")
    printf "  %-18s %-18s %6d\n" "$x25519" "one X25519" $(($(text --features "${features}x25519") - base))
done
