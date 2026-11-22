#!/usr/bin/env bash
# The benchmarks: the timing tests marked #[ignore], built with --release
# for this machine's processor (as .cargo/config.toml builds) and run
# one at a time so that none competes with another. Writes under
# target/bench:
#
#   bench.txt    what each printed, headed by the commit, compiler and CPU
#   summary.md   the same in a code block, for the CI run's page
#
# A timing test is added to BENCHES below by name: other ignored tests
# are not benchmarks and are not run here; each of those has a job of
# its own in .github/workflows, and tools/ignored.sh sees that no
# ignored test is in neither.
#
# The figures depend on the machine. Compare runs on the same one only;
# CI runners are shared and vary from run to run.
set -euo pipefail
cd "$(dirname "$0")/.."

BENCHES=(
    alg::tests::fixed_point_timing
    argument::tests::proven_timing
    block_proof::tests::payments_block_timing
    chain_proof::tests::full_small_block_timing
    chain_proof::tests::reward_block_timing
    machine::tests::machine_timing
    mempool::tests::throughput
    pcs::tests::proven_timing
    recursion::tests::fixed_point_timing
    segment::tests::joining_timing
    segment::tests::payments_timing
    signature::tests::joining_timing
    signature::tests::signatures_timing
    signature::tests::verifying_costs
    store::outputs::tests::cost
    store::state::tests::cost_at_scale
    structure::tests::reading_costs
)
# Run after the others: it reads the chain's proof the reward's block's
# timing leaves in the file DUMP names.
AFTER=chain_proof::tests::a_chain_s_proof_is_verified

out=target/bench
mkdir -p "$out"
export DUMP="$PWD/$out/chain.proof"

host=$(rustc -vV | sed -n 's/^host: //p')
commit=$(git rev-parse --short HEAD 2>/dev/null || echo "no commit")
if [ -r /proc/cpuinfo ]; then
    cpu_name=$(sed -n 's/^model name[^:]*: *//p' /proc/cpuinfo | head -1)
    cores=$(grep -c '^processor' /proc/cpuinfo)
else
    cpu_name=$(sysctl -n machdep.cpu.brand_string 2>/dev/null || echo "unknown CPU")
    cores=$(sysctl -n hw.ncpu 2>/dev/null || echo "?")
fi

{
    echo "Benchmarks ($commit)"
    echo "$(rustc --version), $host"
    echo "${cpu_name:-unknown CPU}, $cores cores"
} > "$out/bench.txt"

cargo test --locked --release --lib --no-run
# A test's own output is on both streams; cargo's progress is not wanted.
for tests in "${BENCHES[*]}" "$AFTER"; do
    # shellcheck disable=SC2086
    cargo test --locked --release --lib -- --ignored --exact --nocapture --test-threads=1 $tests 2>&1 \
        | grep -vE '^(running [0-9]+ tests?|test result:|\s*Finished|\s*Running|\s*Compiling|warning|$)' \
        | tee -a "$out/bench.txt"
done

{
    echo '## Benchmarks'
    echo
    echo '```text'
    cat "$out/bench.txt"
    echo '```'
} > "$out/summary.md"
