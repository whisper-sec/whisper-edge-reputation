# SPDX-License-Identifier: MIT
# Copyright (c) 2026, viaGraph B.V.
# shellcheck shell=bash
# curl-asis.sh - the module gates send every request exactly as the row writes it. Sourced by
# nginx/nginx-gate.sh, apache/apache-gate.sh and litespeed/litespeed-gate.sh after ROOT is set.
#
# curl normalises the URL it is handed, and how far depends on its release: 8.18 (Ubuntu 26.04's) drops
# an empty query (`tok?` goes out as `tok`) and resolves a `%2e` dot segment, both of which 8.5 sent as
# written. A row that asks whether `tok?` is exempt then asked a 26.04 server a different question from
# a 24.04 one, and read the wrong answer as the module's. So within the gates curl is this function: a
# test URL (http:// to 127.0.0.1 or localhost) becomes its origin plus --request-target carrying the
# path and query byte for byte, on every curl since 7.55, and every other argument passes untouched. A call
# that names its own --request-target (the absolute-form rows) has said exactly what to send, and is left
# whole.
curl() {
    local a r out=()
    for a in "$@"; do
        [ "$a" != --request-target ] || { command curl "$@"; return; }
    done
    for a in "$@"; do
        case "$a" in
            http://127.0.0.1:*/* | http://127.0.0.1/* | http://localhost:*/* | http://localhost/*)
                r=${a#http://}
                out+=(--request-target "/${r#*/}" "http://${r%%/*}/") ;;
            *) out+=("$a") ;;
        esac
    done
    command curl "${out[@]}"
}
