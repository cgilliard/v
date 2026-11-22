#!/usr/bin/env bash
# Code coverage of the test suite, measured with the Rust toolchain's own
# LLVM tools (no cargo plugin): builds the tests instrumented, runs them,
# and writes under target/coverage:
#
#   report.txt   llvm-cov's table, per file (also printed)
#   summary.txt  the same as a Markdown table with its columns lined up, to paste
#   summary.md   that table and a copy of it in a code block, for the CI run's page
#   html/        the source annotated line by line; open html/index.html
#
# Needs the llvm-tools component: rustup component add llvm-tools
#
# The figures include the tests' own code (the `mod tests` of each file),
# which always runs; src/tests/util.rs, only ever test code, is left out,
# and so are tests/binary.rs and tests/scale.rs.
set -euo pipefail
cd "$(dirname "$0")/.."

out=target/coverage
host=$(rustc -vV | sed -n 's/^host: //p')
bin="$(rustc --print sysroot)/lib/rustlib/$host/bin"
if [ ! -x "$bin/llvm-cov" ] || [ ! -x "$bin/llvm-profdata" ]; then
    echo "llvm-cov not found in the toolchain: run 'rustup component add llvm-tools'" >&2
    exit 1
fi

rm -rf "$out/prof" "$out/html"
mkdir -p "$out/prof"

# The code has two paths where it matters for speed: the processor's own
# instructions (the field's multiplication, the hash) and a portable one.
# A build has one or the other, so on x86-64 there are two builds, for
# this CPU and for the plainest x86-64, and a line counts as covered if
# a run of either reached it. Each build has its own target directory:
# instrumented objects do not mix with ordinary ones, nor the two with
# each other.
case "$host" in
    x86_64-*) variants="native x86-64" ;;
    *) variants="native" ;;
esac
export LLVM_PROFILE_FILE="$PWD/$out/prof/%p-%m.profraw"

# The tests are hash after hash, and an unoptimized, instrumented build of
# them is many times slower than a debug build: too slow for CI's runners.
# So this build is optimized, with debug assertions and overflow checks
# still on (the test profile's), and the decoder fuzzers run a fraction
# of their iterations: they reach their lines in the first few hundred,
# and the test jobs run them in full.
#
# (Built with the dev feature: the dev networks, where the program's
# tests run nodes whose blocks are unproven, in moments.)
#
# What is measured is the tests of a debug build: the unit tests. The
# tests that prove blocks, which a debug build leaves to the release
# job, are not run here: they are minutes each, and what only they
# reach is counted as missed, to be reached by a test that is quick.
#
# But for those a debug build leaves out only because it is not
# optimized, and that an optimized build runs in seconds: this build is
# optimized, and they are named below (QUICK), each measured at under
# seven seconds in a release build (most of them under one). A test is
# added to them by name, when it is as quick; one that is named and is
# not there fails the run.
QUICK=(
    alg::tests::a_proof_is_verified_by_rows
    alg::tests::the_verifier_s_program_is_the_same_for_every_proof
    argument::tests::a_proof_that_hides_is_of_a_witness_that_holds
    argument::tests::a_proof_that_hides_its_witness_verifies
    argument::tests::what_a_hiding_proof_sends_is_the_pads_to_choose
    arith::tests::a_computation_counts_with_it
    chain_proof::tests::a_block_that_pays_itself_too_much_is_no_block
    hidden::tests::the_corners_and_the_cover_hide_together
    net::node::tests::a_new_node_takes_the_state_and_goes_on_from_it
    net::node::tests::a_node_long_away_takes_the_state
    net::node::tests::a_node_restarted_while_taking_a_state_goes_on
    net::node::tests::a_state_is_gone_on_with_as_of_a_later_block
    net::node::tests::each_piece_of_a_state_is_checked_as_it_arrives
    net::node::tests::over_real_sockets_a_state_is_taken
    net::node::tests::several_workers_take_a_state
    net::node::tests::the_state_is_taken_only_when_blocks_cannot_be_had
    net::node::tests::wrong_pieces_of_a_state_are_refused
    proof::tests::a_proof_that_hides_is_verified_by_a_computation
    segment::tests::two_runs_are_joined_and_a_transaction_may_lie_across_them
    signature::tests::a_proof_of_signatures_is_verified_by_rows
    signature::tests::chains_in_several_tables_are_one_proof
    signature::tests::keys_of_any_height_are_checked_by_one_program
    signature::tests::signatures_are_checked_by_three_tables
    signature::tests::two_proofs_of_signatures_are_joined
)
export CARGO_PROFILE_TEST_OPT_LEVEL=2
export CARGO_PROFILE_DEV_OPT_LEVEL=2
export TABMINER_FUZZ_ITERS="${TABMINER_FUZZ_ITERS:-500}"
#
# An instrumented build counts in memory every thread shares, and threads
# that run the same hot code (every test hashes) spend their time taking
# the counters from each other: measured, twelve threads on one test used
# twelve times the processor time of one. So no two threads of a process
# run tests here. The tests are dealt out among as many processes as
# there are cores, each running its share one at a time with the crate's
# own worker threads held to one: a process has its own counters.
#
# The second build differs from the first only in the files that have two
# paths (field.rs and blake3.rs), so it runs only the tests that reach
# those: the whole suite twice is twice the time for the same lines.
# (COVERAGE_PROCESSES: fewer, where the machine has other work.)
cores=${COVERAGE_PROCESSES:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)}
objects=""
for cpu in $variants; do
    export RUSTFLAGS="-C instrument-coverage -C target-cpu=$cpu"
    # What cargo built that can be run, as it names them: the test
    # binaries, and the node itself, which the tests of the program run
    # (its lines are counted too, but it is no test binary, and is not
    # asked for a list of tests: it would take that for an option it
    # does not know, and fail).
    built=$(cargo test --locked --features dev --target-dir "$out/$cpu" --no-run --message-format=json \
        | grep '"executable":"[^"]')
    others=$(echo "$built" | grep -v '"profile":{[^}]*"test":true' | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 || true)
    for binary in $others; do
        objects="$objects --object=$binary"
    done
    binaries=$(echo "$built" | grep '"profile":{[^}]*"test":true' | grep -o '"executable":"[^"]*"' | cut -d'"' -f4)
    for binary in $binaries; do
        objects="$objects --object=$binary"
        # (A binary may have no test at all: the node's own has none.)
        "$binary" --list --format terse 2>/dev/null | sed -n 's/: test$//p' > "$out/all.txt" || true
        if [ "$cpu" = native ]; then
            cp "$out/all.txt" "$out/tests.txt"
        else
            grep -E '^(field|blake3|merkle|hash)::' "$out/all.txt" > "$out/tests.txt" || true
        fi
        total=$(wc -l < "$out/tests.txt")
        [ "$total" -gt 0 ] || continue
        echo "$binary: $total tests in $cores processes"
        pids=""
        # The quick ones of those an unoptimized build leaves out: in a
        # process of their own, one at a time.
        if [ "$cpu" = native ] && grep -qxF "${QUICK[0]}" "$out/all.txt"; then
            for t in "${QUICK[@]}"; do
                grep -qxF "$t" "$out/all.txt" || { echo "named as quick, and no such test: $t" >&2; exit 1; }
            done
            TABMINER_THREADS=1 "$binary" --ignored --test-threads=1 --exact "${QUICK[@]}" > "$out/shard.quick.log" 2>&1 &
            pids="$pids $!"
        fi
        for k in $(seq 0 $((cores - 1))); do
            # Every cores-th test from the k-th: neighbours, which are of
            # one module and cost alike, go to different processes.
            awk -v n="$cores" -v k="$k" 'NR % n == k' "$out/tests.txt" > "$out/shard.$k.txt"
            [ -s "$out/shard.$k.txt" ] || continue
            # shellcheck disable=SC2046
            TABMINER_THREADS=1 "$binary" --test-threads=1 --exact $(cat "$out/shard.$k.txt") \
                > "$out/shard.$k.log" 2>&1 &
            pids="$pids $!"
        done
        failed=0
        for pid in $pids; do
            wait "$pid" || failed=1
        done
        grep -h '^test result' "$out"/shard.*.log
        if [ "$failed" -ne 0 ]; then
            cat "$out"/shard.*.log
            echo "a test failed" >&2
            exit 1
        fi
        rm -f "$out"/shard.*
        # The code that splits work among threads, with threads to split
        # it among.
        if [ "$cpu" = native ] && grep -q '^parallel::' "$out/tests.txt"; then
            "$binary" parallel:: store::backend:: | grep '^test result'
        fi
    done
done
unset RUSTFLAGS

"$bin/llvm-profdata" merge -sparse "$out"/prof/*.profraw -o "$out/coverage.profdata"

# Only this crate's code: not the dependencies', nor the standard library's.
# Nor the files that are tests and nothing else (src/tests, the node's
# and the wallet's): what is measured is the program.
# Nor the program's own tests and the scale tests: nearly all of them
# run nodes that prove blocks, or a state the size of years, which is
# not done here, and what they would have reached of themselves is not
# what is measured.
ignore='(/\.cargo/|/rustc/|/src/tests/|/src/net/node_tests\.rs$|/src/wallet/tests\.rs$|/tests/(binary|scale)\.rs$)'
# shellcheck disable=SC2086
"$bin/llvm-cov" report --instr-profile="$out/coverage.profdata" $objects \
    --ignore-filename-regex="$ignore" > "$out/report.txt"
# shellcheck disable=SC2086
"$bin/llvm-cov" show --format=html --output-dir="$out/html" \
    --instr-profile="$out/coverage.profdata" $objects --ignore-filename-regex="$ignore" > /dev/null

# The table as Markdown. A row of the report is the file name, then for
# regions, functions, lines and branches: the count, the missed, the percent.
#
# summary.txt is the table for pasting elsewhere: Markdown with its columns
# lined up, so it reads as plain text and renders as a table where Markdown
# does. summary.md shows the table, then summary.txt in a code block, which
# GitHub gives a copy button.
commit=$(git rev-parse --short HEAD 2>/dev/null || echo "no commit")
awk -v commit="$commit" '
    /^-+$/ || /^Filename/ || NF < 10 { next }
    {
        n++
        cell[n, 1] = ($1 == "TOTAL") ? "Total" : $1
        cell[n, 2] = $8; cell[n, 3] = $9; cell[n, 4] = $10; cell[n, 5] = $7; cell[n, 6] = $4
        if ($1 == "TOTAL") lines = $10
    }
    END {
        split("File,Lines,Missed,Line coverage,Function coverage,Region coverage", head, ",")
        for (c = 1; c <= 6; c++) {
            width[c] = length(head[c])
            for (r = 1; r <= n; r++) if (length(cell[r, c]) > width[c]) width[c] = length(cell[r, c])
        }
        print "Code coverage: " lines " of lines (" commit ")\n"
        line = "|"; rule = "|"
        for (c = 1; c <= 6; c++) {
            line = line sprintf(c == 1 ? " %-*s |" : " %*s |", width[c], head[c])
            dashes = sprintf("%*s", width[c] + 1, ""); gsub(/ /, "-", dashes)
            rule = rule (c == 1 ? dashes "-|" : dashes ":|")
        }
        print line; print rule
        for (r = 1; r <= n; r++) {
            line = "|"
            for (c = 1; c <= 6; c++) line = line sprintf(c == 1 ? " %-*s |" : " %*s |", width[c], cell[r, c])
            print line
        }
    }
' "$out/report.txt" > "$out/summary.txt"

{
    sed -n '1s/^/## /p' "$out/summary.txt"
    sed '1d' "$out/summary.txt"
    printf '\nIncludes each file'"'"'s own tests. The annotated source is in the `coverage-html` artifact.\n'
    printf '\n### To paste elsewhere\n\n```text\n'
    cat "$out/summary.txt"
    printf '```\n'
} > "$out/summary.md"

cat "$out/report.txt"
echo
cat "$out/summary.txt"
echo
echo "to paste: $out/summary.txt   annotated source: $out/html/index.html"
