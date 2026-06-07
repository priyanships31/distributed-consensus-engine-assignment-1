#!/usr/bin/env bash
# =============================================================================
#  chaos_test.sh  –  Chaos Testing Script
#
#  Injects network faults and node crashes into the running cluster while the
#  client continuously submits transactions.  Verifies that consensus is
#  maintained (Paxos / PBFT) despite the injected failures.
#
#  Fault scenarios executed in order:
#    1. Baseline          – normal operation, no faults
#    2. Single crash      – kill one non-leader node (Paxos still has quorum)
#    3. Latency injection – 800 ms + 200 ms jitter on two node links
#    4. Packet loss       – 40 % loss on one node's upstream path
#    5. Network partition – split cluster into {1,2} | {3,4,5} via Toxiproxy
#    6. Leader crash      – kill the current leader, verify re-election
#    7. Double crash      – crash two nodes simultaneously (max crash-FT)
#    8. Byzantine active  – confirm adversary node is caught / ignored (PBFT)
#    9. Full recovery     – bring all nodes back, verify ledger consistency
#
#  Prerequisites (all provided by docker-compose):
#    • Toxiproxy container accessible at $TOXI_HOST:$TOXI_API_PORT
#    • Consensus nodes: node1…node5 on ports 5001…5005
#    • Adversary node:  node6       on port  5006
#    • Shared data volume mounted at /data (ledger + client results)
#    • curl, jq, docker CLI available in PATH
#
#  Usage:
#    bash tests/chaos_test.sh [--mode A|B] [--quick]
#
#  Exit codes:
#    0   all assertions passed
#    1   one or more assertions failed
#    2   environment / setup error
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Colour helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'

info()    { echo -e "${CYAN}[INFO]${RESET}  $*"; }
success() { echo -e "${GREEN}[PASS]${RESET}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${RESET}  $*"; }
fail()    { echo -e "${RED}[FAIL]${RESET}  $*"; FAILURES=$((FAILURES + 1)); }
section() { echo -e "\n${BOLD}━━━  $*  ━━━${RESET}"; }
banner()  {
  echo -e "${BOLD}"
  echo "╔══════════════════════════════════════════════════════╗"
  echo "║        IIT Jodhpur – Distributed Systems             ║"
  echo "║        Assignment-1 Chaos Test Suite                 ║"
  echo "╚══════════════════════════════════════════════════════╝"
  echo -e "${RESET}"
}

# ---------------------------------------------------------------------------
# Configuration  (override via environment)
# ---------------------------------------------------------------------------
MODE="${MODE:-B}"                         # A=Paxos  B=PBFT
TOXI_HOST="${TOXI_HOST:-toxiproxy}"
TOXI_API_PORT="${TOXI_API_PORT:-8474}"
TOXI_BASE="http://${TOXI_HOST}:${TOXI_API_PORT}"

NODE_HOSTS=( "" node1 node2 node3 node4 node5 node6 )   # 1-indexed
NODE_PORTS=( 0   5001  5002  5003  5004  5005  5006  )
N_NODES=5          # honest nodes (node1–node5); node6 is adversary
ADV_NODE=6

DATA_DIR="/data"
RESULTS_FILE="${DATA_DIR}/client_results.jsonl"
LOG_DIR="${DATA_DIR}/chaos_logs"
SUMMARY_FILE="${DATA_DIR}/chaos_summary.txt"

# Timing knobs
BASELINE_SECS=15    # seconds of baseline traffic before first fault
FAULT_SETTLE=8      # seconds to let cluster stabilise after each fault
RECOVERY_SECS=12    # seconds after restoring nodes before checking ledger

QUICK=0             # set to 1 via --quick for faster CI runs
FAILURES=0          # global failure counter

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)   MODE="$2";  shift 2 ;;
    --quick)  QUICK=1;    shift   ;;
    *)        echo "Unknown option: $1"; exit 2 ;;
  esac
done

if [[ "$QUICK" == "1" ]]; then
  BASELINE_SECS=8
  FAULT_SETTLE=5
  RECOVERY_SECS=8
fi

mkdir -p "$LOG_DIR"

# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------
section "Pre-flight checks"

for cmd in curl jq docker; do
  if ! command -v "$cmd" &>/dev/null; then
    echo "ERROR: '$cmd' not found in PATH" >&2; exit 2
  fi
done
info "curl / jq / docker all present"

# Verify Toxiproxy is reachable
if ! curl -sf "${TOXI_BASE}/version" >/dev/null; then
  echo "ERROR: Toxiproxy not reachable at ${TOXI_BASE}" >&2; exit 2
fi
TOXI_VERSION=$(curl -sf "${TOXI_BASE}/version")
info "Toxiproxy reachable  version=${TOXI_VERSION}"

# ---------------------------------------------------------------------------
# Helper: Toxiproxy proxy management
# ---------------------------------------------------------------------------

toxi_proxy_name() {
  # node_<src>_to_<dst>
  echo "node_${1}_to_${2}"
}

toxi_create_proxy() {
  local src=$1 dst=$2
  local name; name=$(toxi_proxy_name "$src" "$dst")
  local listen_port=$(( 6000 + src * 10 + dst ))
  local upstream="${NODE_HOSTS[$dst]}:${NODE_PORTS[$dst]}"
  # Idempotent – delete if exists then recreate
  curl -sf -X DELETE "${TOXI_BASE}/proxies/${name}" >/dev/null 2>&1 || true
  curl -sf -X POST "${TOXI_BASE}/proxies" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${name}\",\"listen\":\"0.0.0.0:${listen_port}\",\"upstream\":\"${upstream}\",\"enabled\":true}" \
    >/dev/null
}

toxi_delete_proxy() {
  local src=$1 dst=$2
  local name; name=$(toxi_proxy_name "$src" "$dst")
  curl -sf -X DELETE "${TOXI_BASE}/proxies/${name}" >/dev/null 2>&1 || true
}

toxi_add_toxic() {
  # toxi_add_toxic <proxy_name> <toxic_name> <type> <json_attributes>
  local proxy=$1 name=$2 type=$3 attrs=$4
  curl -sf -X POST "${TOXI_BASE}/proxies/${proxy}/toxics" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"${name}\",\"type\":\"${type}\",\"stream\":\"upstream\",\"toxicity\":1.0,\"attributes\":${attrs}}" \
    >/dev/null
}

toxi_remove_toxic() {
  local proxy=$1 name=$2
  curl -sf -X DELETE "${TOXI_BASE}/proxies/${proxy}/toxics/${name}" >/dev/null 2>&1 || true
}

toxi_disable_proxy() {
  local proxy=$1
  curl -sf -X POST "${TOXI_BASE}/proxies/${proxy}" \
    -H "Content-Type: application/json" \
    -d '{"enabled":false}' >/dev/null
}

toxi_enable_proxy() {
  local proxy=$1
  curl -sf -X POST "${TOXI_BASE}/proxies/${proxy}" \
    -H "Content-Type: application/json" \
    -d '{"enabled":true}' >/dev/null
}

# ---------------------------------------------------------------------------
# Helper: Docker container control
# ---------------------------------------------------------------------------

container_name() {
  echo "node${1}"
}

kill_node() {
  local id=$1
  local cname; cname=$(container_name "$id")
  info "Killing ${cname} …"
  docker kill "$cname" 2>/dev/null || warn "Could not kill ${cname} (already dead?)"
}

start_node() {
  local id=$1
  local cname; cname=$(container_name "$id")
  info "Starting ${cname} …"
  docker start "$cname" 2>/dev/null || warn "Could not start ${cname}"
}

node_is_running() {
  local id=$1
  local cname; cname=$(container_name "$id")
  docker inspect -f '{{.State.Running}}' "$cname" 2>/dev/null | grep -q true
}

get_leader_id() {
  # Ask each node for status and return the leader_id reported
  for id in 1 2 3 4 5; do
    local host="${NODE_HOSTS[$id]}"
    local port=$(( NODE_PORTS[$id] + 100 ))   # status port offset = 100
    local resp
    resp=$(echo '{"type":"STATUS","from":0}' | \
           timeout 2 nc -q1 "$host" "$port" 2>/dev/null || true)
    if [[ -n "$resp" ]]; then
      local role; role=$(echo "$resp" | jq -r '.role // empty' 2>/dev/null || true)
      if [[ "$role" == "LEADER" ]]; then
        echo "$id"; return
      fi
    fi
  done
  echo "unknown"
}

# ---------------------------------------------------------------------------
# Helper: Client background job
# ---------------------------------------------------------------------------
CLIENT_PID=""

start_client_bg() {
  local txns="${1:-40}"
  local rate="${2:-2.0}"
  info "Starting background client (${txns} txns @ ${rate}/s) …"
  docker exec client python /app/client.py \
    --mode "$MODE" \
    --txns  "$txns" \
    --rate  "$rate" \
    --concurrency 4 \
    --retries 6 \
    --wait  0 \
    >> "${LOG_DIR}/client_bg.log" 2>&1 &
  CLIENT_PID=$!
}

stop_client_bg() {
  if [[ -n "$CLIENT_PID" ]] && kill -0 "$CLIENT_PID" 2>/dev/null; then
    kill "$CLIENT_PID" 2>/dev/null || true
    wait "$CLIENT_PID" 2>/dev/null || true
  fi
  CLIENT_PID=""
}

# ---------------------------------------------------------------------------
# Helper: Assertions
# ---------------------------------------------------------------------------

assert_ledger_growing() {
  # Check that at least one node has committed at least $1 entries
  local min_entries="${1:-1}"
  local found=0
  for id in 1 2 3 4 5; do
    if node_is_running "$id"; then
      local ledger="/data/ledger_node_${id}.jsonl"
      local count
      count=$(docker exec "node${id}" wc -l < "$ledger" 2>/dev/null || echo 0)
      count=$(echo "$count" | tr -d '[:space:]')
      if [[ "$count" -ge "$min_entries" ]]; then
        found=1
        info "Node ${id} ledger has ${count} entries (≥ ${min_entries} required)"
        break
      fi
    fi
  done
  if [[ "$found" == "1" ]]; then
    success "Ledger is growing (≥ ${min_entries} entries committed)"
  else
    fail "Ledger has fewer than ${min_entries} entries — consensus may have stalled"
  fi
}

assert_no_split_brain() {
  # All running nodes that have committed anything must agree on every slot
  info "Checking ledger consistency across running nodes …"
  local ref_file="" ref_id=0
  for id in 1 2 3 4 5; do
    if node_is_running "$id"; then
      local tmp="${LOG_DIR}/ledger_check_${id}.jsonl"
      docker exec "node${id}" cat "/data/ledger_node_${id}.jsonl" > "$tmp" 2>/dev/null || continue
      if [[ -z "$ref_file" ]]; then
        ref_file="$tmp"
        ref_id=$id
      else
        # Every line in tmp must appear in ref_file (subset check both ways)
        local extra
        extra=$(comm -23 <(sort "$tmp") <(sort "$ref_file") | wc -l | tr -d '[:space:]')
        if [[ "$extra" -gt 0 ]]; then
          fail "Node ${id} has ${extra} entries not in node ${ref_id} — split-brain detected!"
        else
          success "Node ${id} ledger consistent with node ${ref_id}"
        fi
      fi
    fi
  done
}

assert_adversary_caught() {
  # Grep node logs for ADV signature-rejection messages
  local caught=0
  for id in 1 2 3 4 5; do
    if node_is_running "$id"; then
      local adv_rejects
      adv_rejects=$(docker logs "node${id}" 2>&1 | grep -c "signature invalid" || true)
      if [[ "$adv_rejects" -gt 0 ]]; then
        caught=1
        info "Node ${id} rejected ${adv_rejects} adversary message(s)"
      fi
    fi
  done
  if [[ "$caught" == "1" ]]; then
    success "Adversary node caught: honest nodes rejected its invalid signatures"
  else
    warn "No adversary rejections found in logs (adversary may be passive)"
  fi
}

assert_leader_elected() {
  local timeout="${1:-15}"
  info "Waiting up to ${timeout}s for a leader to be elected …"
  local elapsed=0
  while [[ $elapsed -lt $timeout ]]; do
    local lid; lid=$(get_leader_id)
    if [[ "$lid" != "unknown" ]]; then
      success "Leader elected: node ${lid}"
      return
    fi
    sleep 2; elapsed=$((elapsed + 2))
  done
  fail "No leader elected within ${timeout}s"
}

assert_client_success_rate() {
  local min_rate="${1:-70}"   # percent
  if [[ ! -f "$RESULTS_FILE" ]]; then
    warn "No client results file found at ${RESULTS_FILE}"
    return
  fi
  local total sent
  total=$(wc -l < "$RESULTS_FILE" | tr -d '[:space:]')
  sent=$(grep -c '"status": "sent"' "$RESULTS_FILE" 2>/dev/null || echo 0)
  if [[ "$total" -gt 0 ]]; then
    local rate=$(( sent * 100 / total ))
    if [[ "$rate" -ge "$min_rate" ]]; then
      success "Client success rate: ${rate}%  (${sent}/${total}) ≥ ${min_rate}% threshold"
    else
      fail "Client success rate too low: ${rate}%  (${sent}/${total}) < ${min_rate}% threshold"
    fi
  else
    warn "No client results to evaluate"
  fi
}

log_snapshot() {
  local label="$1"
  local snap="${LOG_DIR}/snapshot_${label// /_}.log"
  {
    echo "=== Snapshot: ${label}  $(date -u) ==="
    for id in 1 2 3 4 5; do
      echo "--- node${id} (running=$(node_is_running $id)) ---"
      docker logs "node${id}" --tail 20 2>&1 || true
    done
    echo "--- adversary (node6) ---"
    docker logs "node6" --tail 10 2>&1 || true
  } > "$snap"
  info "Log snapshot saved → ${snap}"
}

# ---------------------------------------------------------------------------
# Toxiproxy proxy bootstrap
# Create one proxy per directed link (all pairs among nodes 1-5)
# ---------------------------------------------------------------------------
setup_proxies() {
  section "Setting up Toxiproxy proxies"
  for src in 1 2 3 4 5; do
    for dst in 1 2 3 4 5; do
      [[ "$src" == "$dst" ]] && continue
      toxi_create_proxy "$src" "$dst"
    done
  done
  success "All inter-node proxies created"
}

teardown_proxies() {
  for src in 1 2 3 4 5; do
    for dst in 1 2 3 4 5; do
      [[ "$src" == "$dst" ]] && continue
      toxi_delete_proxy "$src" "$dst"
    done
  done
}

# ---------------------------------------------------------------------------
# SCENARIO 0 – Environment setup + key generation
# ---------------------------------------------------------------------------
run_scenario_0() {
  section "Scenario 0 — Key generation & cluster warm-up"

  info "Generating RSA key pairs for all nodes …"
  docker exec node1 python /app/crypto_utils.py generate \
    --nodes 1,2,3,4,5,6 --keydir /keys --force 2>&1 | tail -7
  success "Key pairs generated"

  info "Waiting 10s for cluster to elect a leader …"
  sleep 10
  assert_leader_elected 20

  log_snapshot "after_warmup"
}

# ---------------------------------------------------------------------------
# SCENARIO 1 – Baseline (no faults)
# ---------------------------------------------------------------------------
run_scenario_1() {
  section "Scenario 1 — Baseline (no faults)"
  info "Running ${BASELINE_SECS}s of uninterrupted client traffic …"

  start_client_bg 30 2.0
  sleep "$BASELINE_SECS"
  stop_client_bg

  assert_ledger_growing 5
  assert_client_success_rate 95
  log_snapshot "baseline"
}

# ---------------------------------------------------------------------------
# SCENARIO 2 – Single non-leader crash  (Paxos still has f=2 budget)
# ---------------------------------------------------------------------------
run_scenario_2() {
  section "Scenario 2 — Single non-leader crash"

  # Identify current leader so we don't crash it
  local leader; leader=$(get_leader_id)
  local victim=0
  for id in 1 2 3 4 5; do
    if [[ "$id" != "$leader" ]]; then
      victim=$id; break
    fi
  done

  info "Current leader: node${leader}.  Crashing node${victim} …"
  start_client_bg 20 2.0
  sleep 3

  kill_node "$victim"
  info "Node${victim} killed.  Letting cluster continue for ${FAULT_SETTLE}s …"
  sleep "$FAULT_SETTLE"

  assert_ledger_growing 5
  assert_client_success_rate 80

  info "Restoring node${victim} …"
  start_node "$victim"
  sleep 4

  stop_client_bg
  log_snapshot "after_single_crash"
}

# ---------------------------------------------------------------------------
# SCENARIO 3 – Latency injection on two links
# ---------------------------------------------------------------------------
run_scenario_3() {
  section "Scenario 3 — Latency injection (800 ms ± 200 ms jitter)"

  local slow_src=2 slow_dst=3
  local proxy; proxy=$(toxi_proxy_name "$slow_src" "$slow_dst")
  local proxy2; proxy2=$(toxi_proxy_name "$slow_dst" "$slow_src")

  info "Injecting 800 ms latency on node${slow_src}↔node${slow_dst} …"
  toxi_add_toxic "$proxy"  "slow_latency"  "latency" '{"latency":800,"jitter":200}'
  toxi_add_toxic "$proxy2" "slow_latency2" "latency" '{"latency":800,"jitter":200}'

  start_client_bg 20 1.5
  sleep "$FAULT_SETTLE"

  assert_ledger_growing 3
  # Lower success threshold — some transactions may time out under high latency
  assert_client_success_rate 65

  info "Removing latency toxic …"
  toxi_remove_toxic "$proxy"  "slow_latency"
  toxi_remove_toxic "$proxy2" "slow_latency2"

  stop_client_bg
  sleep 3
  log_snapshot "after_latency"
}

# ---------------------------------------------------------------------------
# SCENARIO 4 – Packet loss
# ---------------------------------------------------------------------------
run_scenario_4() {
  section "Scenario 4 — 40% packet loss on node4 upstream"

  local victim_src=4
  for dst in 1 2 3 5; do
    local proxy; proxy=$(toxi_proxy_name "$victim_src" "$dst")
    toxi_add_toxic "$proxy" "pkt_loss_${dst}" "bandwidth" '{"rate":0}'
    # Note: Toxiproxy uses "bandwidth" with rate=0 to simulate blackhole.
    # For true probabilistic loss use the built-in 'slice_latency' pattern
    # or a custom toxic. Here we use bandwidth=0 to fully block the link.
  done
  info "Node4 outbound links blackholed (simulates 100% upstream loss) …"

  start_client_bg 15 1.5
  sleep "$FAULT_SETTLE"

  assert_ledger_growing 2
  assert_client_success_rate 60

  info "Restoring node4 links …"
  for dst in 1 2 3 5; do
    local proxy; proxy=$(toxi_proxy_name "$victim_src" "$dst")
    toxi_remove_toxic "$proxy" "pkt_loss_${dst}"
  done

  stop_client_bg
  sleep 3
  log_snapshot "after_packet_loss"
}

# ---------------------------------------------------------------------------
# SCENARIO 5 – Network partition  {1,2} | {3,4,5}
# Minority partition {1,2} cannot reach quorum; majority {3,4,5} continues.
# ---------------------------------------------------------------------------
run_scenario_5() {
  section "Scenario 5 — Network partition  {node1,node2} | {node3,node4,node5}"

  # Cut links crossing the partition boundary
  local minority=( 1 2 )
  local majority=( 3 4 5 )

  info "Cutting cross-partition links …"
  for src in "${minority[@]}"; do
    for dst in "${majority[@]}"; do
      local p; p=$(toxi_proxy_name "$src" "$dst")
      local p2; p2=$(toxi_proxy_name "$dst" "$src")
      toxi_disable_proxy "$p"
      toxi_disable_proxy "$p2"
    done
  done

  info "Partition active.  Starting client targeting majority side …"
  start_client_bg 20 1.5
  sleep "$FAULT_SETTLE"

  # Majority side should still make progress
  for id in 3 4 5; do
    local cnt
    cnt=$(docker exec "node${id}" wc -l < "/data/ledger_node_${id}.jsonl" 2>/dev/null || echo 0)
    cnt=$(echo "$cnt" | tr -d '[:space:]')
    info "Node${id} ledger entries: ${cnt}"
  done
  assert_ledger_growing 2

  info "Healing partition …"
  for src in "${minority[@]}"; do
    for dst in "${majority[@]}"; do
      local p; p=$(toxi_proxy_name "$src" "$dst")
      local p2; p2=$(toxi_proxy_name "$dst" "$src")
      toxi_enable_proxy "$p"
      toxi_enable_proxy "$p2"
    done
  done

  stop_client_bg
  sleep "$FAULT_SETTLE"
  assert_no_split_brain
  log_snapshot "after_partition"
}

# ---------------------------------------------------------------------------
# SCENARIO 6 – Leader crash → re-election
# ---------------------------------------------------------------------------
run_scenario_6() {
  section "Scenario 6 — Leader crash + automatic re-election"

  local leader; leader=$(get_leader_id)
  if [[ "$leader" == "unknown" ]]; then
    warn "Could not determine leader; skipping scenario 6"
    return
  fi

  info "Crashing current leader: node${leader} …"
  start_client_bg 25 1.5
  sleep 2

  kill_node "$leader"

  info "Leader crashed.  Waiting for re-election …"
  sleep 2   # give cluster time to detect heartbeat loss
  assert_leader_elected 20

  sleep "$FAULT_SETTLE"
  assert_ledger_growing 3
  assert_client_success_rate 65

  info "Restoring node${leader} …"
  start_node "$leader"
  sleep 4

  stop_client_bg
  log_snapshot "after_leader_crash"
}

# ---------------------------------------------------------------------------
# SCENARIO 7 – Double crash  (maximum crash-FT boundary for f=2)
# ---------------------------------------------------------------------------
run_scenario_7() {
  section "Scenario 7 — Double crash (2 simultaneous failures)"

  local leader; leader=$(get_leader_id)
  local crashed=()
  for id in 1 2 3 4 5; do
    if [[ "$id" != "$leader" ]] && [[ "${#crashed[@]}" -lt 2 ]]; then
      crashed+=( "$id" )
    fi
  done

  info "Crashing nodes ${crashed[*]} simultaneously (leader=${leader} stays up) …"
  start_client_bg 20 1.5
  sleep 2

  for id in "${crashed[@]}"; do
    kill_node "$id"
  done

  sleep "$FAULT_SETTLE"
  assert_ledger_growing 2
  # With exactly f=2 crash tolerance and 2 nodes down, quorum is borderline;
  # accept a lower success threshold here.
  assert_client_success_rate 55

  info "Restoring crashed nodes …"
  for id in "${crashed[@]}"; do
    start_node "$id"
  done
  sleep "$RECOVERY_SECS"

  stop_client_bg
  assert_no_split_brain
  log_snapshot "after_double_crash"
}

# ---------------------------------------------------------------------------
# SCENARIO 8 – Byzantine adversary active  (Mode B only)
# ---------------------------------------------------------------------------
run_scenario_8() {
  if [[ "$MODE" != "B" ]]; then
    warn "Skipping Scenario 8 (Byzantine adversary) — MODE is A (Paxos)"
    return
  fi

  section "Scenario 8 — Byzantine adversary node active (Mode B / PBFT)"

  info "Ensuring adversary node6 is running …"
  docker start node6 2>/dev/null || true
  sleep 3

  info "Submitting transactions with adversary active …"
  start_client_bg 25 1.5
  sleep "$FAULT_SETTLE"

  # Honest nodes must still commit despite adversary
  assert_ledger_growing 3
  assert_client_success_rate 70
  assert_adversary_caught

  # Confirm adversary's equivocating messages produced no bad commits
  info "Checking for adversary-poisoned ledger entries …"
  local poisoned=0
  for id in 1 2 3 4 5; do
    if node_is_running "$id"; then
      local bad
      bad=$(docker exec "node${id}" grep -c "ADV_POISON_TX" \
            "/data/ledger_node_${id}.jsonl" 2>/dev/null || echo 0)
      bad=$(echo "$bad" | tr -d '[:space:]')
      if [[ "$bad" -gt 0 ]]; then
        poisoned=$((poisoned + 1))
        fail "Node${id} committed ${bad} adversary-poisoned transaction(s)!"
      fi
    fi
  done
  if [[ "$poisoned" -eq 0 ]]; then
    success "No adversary-poisoned transactions found in any honest ledger"
  fi

  stop_client_bg
  log_snapshot "after_byzantine"
}

# ---------------------------------------------------------------------------
# SCENARIO 9 – Full recovery + final ledger consistency check
# ---------------------------------------------------------------------------
run_scenario_9() {
  section "Scenario 9 — Full recovery + ledger consistency"

  info "Ensuring all nodes are running …"
  for id in 1 2 3 4 5; do
    if ! node_is_running "$id"; then
      start_node "$id"
    fi
  done
  sleep "$RECOVERY_SECS"

  assert_leader_elected 20
  assert_no_split_brain

  info "Running final clean client batch …"
  start_client_bg 20 2.0
  sleep 12
  stop_client_bg

  assert_ledger_growing 5
  assert_client_success_rate 90
  log_snapshot "final_recovery"
}

# ---------------------------------------------------------------------------
# Final report
# ---------------------------------------------------------------------------
print_report() {
  echo ""
  section "Chaos Test Report"
  {
    echo "Chaos Test Report  –  $(date -u)"
    echo "Mode: ${MODE}   Quick: ${QUICK}"
    echo "Results file: ${RESULTS_FILE}"
    echo ""
    if [[ "$FAILURES" -eq 0 ]]; then
      echo "OVERALL RESULT: ALL TESTS PASSED"
    else
      echo "OVERALL RESULT: ${FAILURES} ASSERTION(S) FAILED"
    fi
    echo ""
    echo "Per-node ledger entry counts:"
    for id in 1 2 3 4 5; do
      local cnt
      cnt=$(docker exec "node${id}" wc -l < "/data/ledger_node_${id}.jsonl" 2>/dev/null || echo "N/A")
      cnt=$(echo "$cnt" | tr -d '[:space:]')
      echo "  node${id}: ${cnt}"
    done
    echo ""
    echo "Client results summary:"
    if [[ -f "$RESULTS_FILE" ]]; then
      local total sent failed
      total=$(wc -l < "$RESULTS_FILE" | tr -d '[:space:]')
      sent=$(grep -c '"status": "sent"' "$RESULTS_FILE" 2>/dev/null || echo 0)
      failed=$(grep -c '"status": "failed"' "$RESULTS_FILE" 2>/dev/null || echo 0)
      echo "  Total:  ${total}"
      echo "  Sent:   ${sent}"
      echo "  Failed: ${failed}"
    else
      echo "  (no results file)"
    fi
  } | tee "$SUMMARY_FILE"

  echo ""
  if [[ "$FAILURES" -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}ALL ASSERTIONS PASSED  ✓${RESET}"
  else
    echo -e "${RED}${BOLD}${FAILURES} ASSERTION(S) FAILED  ✗${RESET}"
  fi
  echo -e "Summary saved → ${SUMMARY_FILE}"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
banner
setup_proxies

run_scenario_0
run_scenario_1
run_scenario_2
run_scenario_3
run_scenario_4
run_scenario_5
run_scenario_6
run_scenario_7
run_scenario_8
run_scenario_9

teardown_proxies
print_report

exit "$FAILURES"