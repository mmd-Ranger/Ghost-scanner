#!/usr/bin/env bash
#
# ghost_scanner.sh — Ghost Scanner
# Single entry point. Run this file every time:
#   bash ghost_scanner.sh
#
# Menu:
#   1) Xray Setup       - shows Installed/Not installed, installs on demand
#   2) Server Config    - enter/edit address, port, UUID; validates format
#                         and can run a real connection test
#   3) Domains          - opens domains.txt in nano to add/remove domains
#   4) Run Scan         - locked until Xray is installed AND config is
#                         tested OK
#   5) Exit
#

INSTALL_DIR="$HOME/xray-core"
BIN_PATH="$INSTALL_DIR/xray"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOMAINS_FILE="$SCRIPT_DIR/domains.txt"
SCANNER_PY="$SCRIPT_DIR/sni_scanner.py"
CONFIG_FILE="$SCRIPT_DIR/server_config.conf"
VALID_MARKER="$SCRIPT_DIR/.config_validated"

C_RESET="\033[0m"
C_TITLE="\033[1;36m"
C_OK="\033[1;32m"
C_WARN="\033[1;33m"
C_ERR="\033[1;31m"
C_DIM="\033[2m"
C_MENU="\033[1;37m"

pause() { read -rp "$(echo -e "${C_DIM}Press Enter to continue...${C_RESET}")"; }

# Print a block of lines with ONE shared left margin so the whole block
# moves to the center of the terminal as a unit, while keeping the exact
# same relative alignment between lines (no per-line "staircase" effect).
# Lines that are themselves longer than the terminal width are ignored
# when computing the shared margin, so a single long status line can't
# collapse centering for the rest of the block.
print_block() {
    local -a lines=("$@")
    local l plain len maxlen=0 width pad
    width=$(tput cols 2>/dev/null || echo 60)
    for l in "${lines[@]}"; do
        plain=$(printf '%b' "$l" | sed -r 's/\x1b\[[0-9;]*m//g')
        len=${#plain}
        if [ "$len" -le "$width" ] && [ "$len" -gt "$maxlen" ]; then
            maxlen=$len
        fi
    done
    pad=$(( (width - maxlen) / 2 ))
    [ "$pad" -lt 0 ] && pad=0
    for l in "${lines[@]}"; do
        printf '%*s' "$pad" ''
        echo -e "$l"
    done
}

banner() {
    clear
    local width bar
    width=$(tput cols 2>/dev/null || echo 60)
    local bar_len=50
    [ "$bar_len" -gt "$((width - 4))" ] && bar_len=$((width - 4))
    [ "$bar_len" -lt 10 ] && bar_len=10
    bar=$(printf '=%.0s' $(seq 1 "$bar_len"))
    print_block \
        "${C_TITLE}${bar}" \
        "        👻 Ghost Scanner" \
        "${bar}${C_RESET}"
}

# ---------- write out the python scanner (only once) ----------
ensure_scanner_py() {
    [ -f "$SCANNER_PY" ] && return
    cat > "$SCANNER_PY" << 'PYEOF'
#!/usr/bin/env python3
"""
sni_scanner.py — Ghost Scanner engine
Domain/Host-header scanner for VLESS + TCP + HTTP-header-obfuscation configs.
Tests each candidate Host header through a REAL Xray tunnel.

Server address/port/UUID are read from server_config.conf (same folder),
which is managed by ghost_scanner.sh -> option 2 (Server Config).

Usage:
  python sni_scanner.py domains.txt      -> full scan
  python sni_scanner.py --test           -> quick single-domain connection test
"""
import json, subprocess, time, sys, os, socket, signal

XRAY_BIN = os.path.expanduser("~/xray-core/xray")
SOCKS_PORT = 10808

QUICK_URL = "http://cp.cloudflare.com/generate_204"
THROUGHPUT_URL = "http://speed.cloudflare.com/__down?bytes=2000000"

STARTUP_WAIT = 2
ROUNDS = 3
ROUND_GAP = 0.5
QUICK_TIMEOUT = 4
THROUGHPUT_TIMEOUT = 6
HARD_DOMAIN_TIMEOUT = 20

TEST_DOMAIN = "www.google.com"


class DomainTimeout(Exception):
    pass


def alarm_handler(signum, frame):
    raise DomainTimeout()


def load_server_config():
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "server_config.conf")
    cfg = {"SERVER_ADDRESS": "", "SERVER_PORT": "", "UUID": ""}
    if os.path.exists(config_path):
        with open(config_path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k in cfg:
                    cfg[k] = v.strip()
    return cfg


def kill_leftover_xray():
    try:
        subprocess.run(["pkill", "-9", "-f", "xray run"], stderr=subprocess.DEVNULL)
    except Exception:
        pass
    time.sleep(0.5)


def build_config(host, address, port, uuid):
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "tag": "socks", "port": SOCKS_PORT, "listen": "127.0.0.1",
            "protocol": "socks", "settings": {"auth": "noauth", "udp": True}
        }],
        "outbounds": [{
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": address, "port": port,
                "users": [{"id": uuid, "encryption": "none"}]
            }]},
            "streamSettings": {
                "network": "tcp",
                "tcpSettings": {"header": {
                    "type": "http",
                    "request": {
                        "version": "1.1", "method": "GET", "path": ["/"],
                        "headers": {
                            "Host": [host],
                            "Accept-Encoding": ["gzip, deflate"],
                            "Connection": ["keep-alive"],
                            "Pragma": "no-cache"
                        }
                    }
                }}
            }
        }]
    }


def is_port_open(port, timeout=1):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except Exception:
        return False


def curl_test(url, timeout, want_speed=False):
    start = time.time()
    try:
        fmt = "%{http_code}|%{speed_download}" if want_speed else "%{http_code}"
        result = subprocess.run(
            ["curl", "-s", "-o", "/dev/null", "-w", fmt,
             "--socks5-hostname", f"127.0.0.1:{SOCKS_PORT}",
             "--max-time", str(timeout), url],
            capture_output=True, text=True, timeout=timeout + 2
        )
        elapsed = round((time.time() - start) * 1000, 1)
        out = result.stdout.strip()
        if want_speed:
            parts = out.split("|")
            code = parts[0] if parts else ""
            speed = float(parts[1]) if len(parts) > 1 and parts[1] else 0.0
        else:
            code = out
            speed = None
        ok = code in ("200", "204", "301", "302")
        return {"ok": ok, "ms": elapsed, "code": code,
                "speed_kBps": round(speed / 1024, 1) if speed else 0}
    except subprocess.TimeoutExpired:
        return {"ok": False, "ms": round((time.time() - start) * 1000, 1),
                "code": "timeout", "speed_kBps": 0}
    except Exception as e:
        return {"ok": False, "ms": round((time.time() - start) * 1000, 1),
                "code": str(e)[:30], "speed_kBps": 0}


def _test_domain_inner(host, address, port, uuid):
    config_path = os.path.expanduser("~/xray_test_config.json")
    with open(config_path, "w") as f:
        json.dump(build_config(host, address, port, uuid), f)

    proc = subprocess.Popen([XRAY_BIN, "run", "-c", config_path],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(STARTUP_WAIT)

        if not is_port_open(SOCKS_PORT):
            return {"domain": host, "success_rate": 0, "avg_ms": None, "avg_speed": 0,
                    "rounds": [], "verdict": "❌ FAILED (xray did not start)"}

        rounds = []
        for i in range(ROUNDS):
            r = curl_test(QUICK_URL, QUICK_TIMEOUT)
            rounds.append(r)
            time.sleep(ROUND_GAP)

        speed_result = curl_test(THROUGHPUT_URL, THROUGHPUT_TIMEOUT, want_speed=True)

        ok_rounds = [r for r in rounds if r["ok"]]
        success_rate = len(ok_rounds) / len(rounds)
        avg_ms = round(sum(r["ms"] for r in ok_rounds) / len(ok_rounds), 1) if ok_rounds else None

        if success_rate == 1.0 and speed_result["ok"] and speed_result["speed_kBps"] > 50:
            verdict = "🎯 STABLE & FAST"
        elif success_rate >= 0.75:
            verdict = "⚠️ SOMEWHAT STABLE"
        elif success_rate > 0:
            verdict = "❌ UNSTABLE"
        else:
            verdict = "❌ DEAD"

        return {
            "domain": host, "success_rate": round(success_rate * 100),
            "avg_ms": avg_ms, "avg_speed": speed_result["speed_kBps"],
            "rounds": rounds, "verdict": verdict
        }
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:
                pass


def test_domain_safe(host, address, port, uuid):
    kill_leftover_xray()
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(HARD_DOMAIN_TIMEOUT)
    try:
        result = _test_domain_inner(host, address, port, uuid)
        signal.alarm(0)
        return result
    except DomainTimeout:
        kill_leftover_xray()
        return {"domain": host, "success_rate": 0, "avg_ms": None, "avg_speed": 0,
                "rounds": [], "verdict": f"❌ STUCK (>{HARD_DOMAIN_TIMEOUT}s, skipped)"}
    except Exception as e:
        signal.alarm(0)
        kill_leftover_xray()
        return {"domain": host, "success_rate": 0, "avg_ms": None, "avg_speed": 0,
                "rounds": [], "verdict": f"❌ ERROR: {str(e)[:40]}"}


def run_quick_test():
    """Used by ghost_scanner.sh option 2 to validate a freshly entered config
    with one real (short) VLESS connection attempt."""
    global ROUNDS
    cfg = load_server_config()
    if not cfg["SERVER_ADDRESS"] or not cfg["SERVER_PORT"] or not cfg["UUID"]:
        print("ERROR: config is incomplete (address/port/uuid).")
        return False
    try:
        port = int(cfg["SERVER_PORT"])
    except ValueError:
        print("ERROR: invalid port in config.")
        return False
    if not os.path.exists(XRAY_BIN):
        print(f"ERROR: xray binary not found at {XRAY_BIN}")
        return False

    ROUNDS = 2
    print(f"Testing connection to {cfg['SERVER_ADDRESS']}:{port} "
          f"(host header: {TEST_DOMAIN}) ...")
    r = test_domain_safe(TEST_DOMAIN, cfg["SERVER_ADDRESS"], port, cfg["UUID"])
    print(f"Result: success_rate={r['success_rate']}%  avg_ms={r['avg_ms']}  "
          f"speed={r['avg_speed']}KB/s  verdict={r['verdict']}")
    return r["success_rate"] > 0


def main():
    if len(sys.argv) < 2:
        print("Usage: python sni_scanner.py domains.txt")
        sys.exit(1)

    if sys.argv[1] == "--test":
        ok = run_quick_test()
        sys.exit(0 if ok else 1)

    domains_file = sys.argv[1]
    cfg = load_server_config()
    if not cfg["SERVER_ADDRESS"] or not cfg["SERVER_PORT"] or not cfg["UUID"]:
        print("ERROR: server config not set. Use ghost_scanner.sh option 2 first.")
        sys.exit(1)
    server_address = cfg["SERVER_ADDRESS"]
    server_port = int(cfg["SERVER_PORT"])
    uuid_val = cfg["UUID"]

    with open(domains_file) as f:
        domains = [line.strip() for line in f if line.strip()]

    if not os.path.exists(XRAY_BIN):
        print(f"ERROR: xray binary not found at {XRAY_BIN}")
        sys.exit(1)

    print(f"\nTesting {len(domains)} domains ({ROUNDS} rounds + throughput check, "
          f"max {HARD_DOMAIN_TIMEOUT}s each)...\n")
    print(f"Server: {server_address}:{server_port}\n")

    results = []
    start_all = time.time()
    for i, d in enumerate(domains, 1):
        t0 = time.time()
        print(f"[{i}/{len(domains)}] {d} ...", flush=True)
        r = test_domain_safe(d, server_address, server_port, uuid_val)
        results.append(r)
        dt = round(time.time() - t0, 1)
        round_summary = " ".join("✅" if x["ok"] else "❌" for x in r["rounds"]) or "-"
        print(f"   rounds: {round_summary}   avg: {r['avg_ms']}ms   "
              f"speed: {r['avg_speed']}KB/s   {r['verdict']}   (took {dt}s)\n")

    total_time = round(time.time() - start_all, 1)
    results.sort(key=lambda r: (-r["success_rate"], r["avg_ms"] if r["avg_ms"] else 999999))

    print("=" * 82)
    print(f"  FINAL RESULTS (total time: {total_time}s)")
    print("=" * 82)
    print(f"{'Domain':<45} {'Success%':<10} {'AvgMs':<10} {'SpeedKB/s':<12} {'Verdict'}")
    print("-" * 82)
    for r in results:
        print(f"{r['domain']:<45} {r['success_rate']:<10} {str(r['avg_ms']):<10} "
              f"{r['avg_speed']:<12} {r['verdict']}")

    stable = [r for r in results if r["success_rate"] == 100 and r["avg_speed"] > 50]
    print("\n" + "=" * 82)
    if stable:
        print("🏆 BEST OPTIONS (stable & fast):")
        for r in stable[:10]:
            print(f"   - {r['domain']}  ({r['avg_ms']}ms, {r['avg_speed']}KB/s)")
    else:
        print("No domain was 100% stable & fast. Closest options:")
        for r in results[:5]:
            print(f"   - {r['domain']}  (success {r['success_rate']}%, {r['avg_speed']}KB/s)")
    print("=" * 82 + "\n")


if __name__ == "__main__":
    main()
PYEOF
}

# ---------- write default domains.txt (only once) ----------
ensure_domains_file() {
    [ -f "$DOMAINS_FILE" ] && return
    cat > "$DOMAINS_FILE" << 'DOMEOF'
config.office.com
signup.live.com
ctldl.windowsupdate.com
storage.live.com
odc.officeapps.live.com
c.s-microsoft.com
device.login.microsoftonline.com
account.live.com
r1.res.office365.com
login.live.com
play-apps-features.googleusercontent.com
drive.google.com
outlook.office365.com
login.microsoftonline.com
www.office.com
DOMEOF
}

# ---------- write empty config file (only once) ----------
ensure_config_file() {
    [ -f "$CONFIG_FILE" ] && return
    cat > "$CONFIG_FILE" << 'CFGEOF'
SERVER_ADDRESS=
SERVER_PORT=
UUID=
CFGEOF
}

load_config() {
    SERVER_ADDRESS=""
    SERVER_PORT=""
    UUID_VAL=""
    if [ -f "$CONFIG_FILE" ]; then
        while IFS='=' read -r key val; do
            case "$key" in
                SERVER_ADDRESS) SERVER_ADDRESS="$val" ;;
                SERVER_PORT) SERVER_PORT="$val" ;;
                UUID) UUID_VAL="$val" ;;
            esac
        done < "$CONFIG_FILE"
    fi
}

xray_status_line() {
    if [ -x "$BIN_PATH" ]; then
        echo -e "  Xray status:   ${C_OK}Installed${C_RESET}"
    else
        echo -e "  Xray status:   ${C_ERR}Not installed${C_RESET}"
    fi
}

config_status_line() {
    ensure_config_file
    load_config
    local addr_short="$SERVER_ADDRESS"
    if [ "${#addr_short}" -gt 18 ]; then
        addr_short="${addr_short:0:15}..."
    fi
    if [ -n "$SERVER_ADDRESS" ] && [ -n "$SERVER_PORT" ] && [ -n "$UUID_VAL" ]; then
        if [ -f "$VALID_MARKER" ]; then
            echo -e "  Config: ${C_OK}OK${C_RESET} ($addr_short:$SERVER_PORT)"
        else
            echo -e "  Config: ${C_WARN}Untested${C_RESET} ($addr_short:$SERVER_PORT)"
        fi
    else
        echo -e "  Config: ${C_ERR}Not set${C_RESET}"
    fi
}

domains_status_line() {
    if [ -f "$DOMAINS_FILE" ]; then
        local n
        n=$(grep -cve '^\s*$' "$DOMAINS_FILE" 2>/dev/null || echo 0)
        echo -e "  Domains file:  ${C_OK}$n domain(s)${C_RESET}"
    else
        echo -e "  Domains file:  ${C_WARN}not created yet${C_RESET}"
    fi
}

# ---------- option 1: xray setup ----------
xray_setup() {
    banner
    echo -e "${C_MENU}Xray Setup${C_RESET}\n"
    xray_status_line
    echo ""

    if [ -x "$BIN_PATH" ]; then
        read -rp "Xray is already installed. Reinstall/update? (y/N): " ans
        if [[ ! "$ans" =~ ^[Yy]$ ]]; then
            return
        fi
    fi

    if [ -d "/data/data/com.termux" ] || [ -n "$TERMUX_VERSION" ]; then
        OS="termux"
        echo "Platform: Termux"
    else
        OS="linux"
        echo "Platform: Linux"
    fi

    ARCH_RAW=$(uname -m)
    echo "Architecture: $ARCH_RAW"

    if [ "$OS" = "termux" ]; then
        case "$ARCH_RAW" in
            aarch64) ASSET="Xray-android-arm64-v8a.zip" ;;
            armv7l|armv8l) ASSET="Xray-android-arm32-v7a.zip" ;;
            *) echo -e "${C_ERR}Unsupported architecture: $ARCH_RAW${C_RESET}"; pause; return ;;
        esac
    else
        case "$ARCH_RAW" in
            x86_64) ASSET="Xray-linux-64.zip" ;;
            aarch64) ASSET="Xray-linux-arm64-v8a.zip" ;;
            armv7l) ASSET="Xray-linux-arm32-v7a.zip" ;;
            *) echo -e "${C_ERR}Unsupported architecture: $ARCH_RAW${C_RESET}"; pause; return ;;
        esac
    fi

    echo "Downloading: $ASSET"

    if [ "$OS" = "termux" ]; then
        command -v curl >/dev/null 2>&1 || pkg install -y curl
        command -v unzip >/dev/null 2>&1 || pkg install -y unzip
    else
        if ! command -v curl >/dev/null 2>&1 || ! command -v unzip >/dev/null 2>&1; then
            if command -v apt >/dev/null 2>&1; then
                sudo apt update && sudo apt install -y curl unzip
            elif command -v pacman >/dev/null 2>&1; then
                sudo pacman -Sy --noconfirm curl unzip
            elif command -v dnf >/dev/null 2>&1; then
                sudo dnf install -y curl unzip
            fi
        fi
    fi

    mkdir -p "$INSTALL_DIR"
    cd "$INSTALL_DIR" || return
    curl -L -o xray.zip "https://github.com/XTLS/Xray-core/releases/latest/download/$ASSET"
    unzip -o xray.zip
    chmod +x xray
    rm -f xray.zip geoip.dat geosite.dat 2>/dev/null

    echo ""
    if [ -x "$BIN_PATH" ]; then
        echo -e "${C_OK}Xray installed successfully.${C_RESET}"
        "$BIN_PATH" version
    else
        echo -e "${C_ERR}Installation failed.${C_RESET}"
    fi
    pause
}

# ---------- option 2: server config submenu ----------
config_menu() {
    while true; do
        banner
        ensure_config_file
        load_config
        print_block \
            "$(config_status_line)" \
            "" \
            "${C_MENU}1) Edit config (enter/change values)" \
            "2) Delete current config" \
            "3) Back${C_RESET}"
        echo ""
        read -rp "Choose [1-3]: " c
        case "$c" in
            1) do_edit_config ;;
            2) do_delete_config ;;
            3) return ;;
            *) echo -e "${C_ERR}Invalid option${C_RESET}"; sleep 1 ;;
        esac
    done
}

do_edit_config() {
    banner
    ensure_config_file
    load_config

    echo -e "${C_MENU}Server Config (VLESS over TCP, HTTP header obfuscation)${C_RESET}\n"
    echo "Current values (press Enter to keep current):"
    echo "  Address : ${SERVER_ADDRESS:-<empty>}"
    echo "  Port    : ${SERVER_PORT:-<empty>}"
    echo "  UUID    : ${UUID_VAL:-<empty>}"
    echo ""

    read -rp "Server address/domain: " in_addr
    read -rp "Server port: " in_port
    read -rp "UUID: " in_uuid

    [ -z "$in_addr" ] && in_addr="$SERVER_ADDRESS"
    [ -z "$in_port" ] && in_port="$SERVER_PORT"
    [ -z "$in_uuid" ] && in_uuid="$UUID_VAL"

    local err=0
    echo ""
    if [ -z "$in_addr" ] || [[ "$in_addr" =~ [[:space:]] ]]; then
        echo -e "${C_ERR}Invalid address: cannot be empty or contain spaces.${C_RESET}"
        err=1
    fi
    if ! [[ "$in_port" =~ ^[0-9]{1,5}$ ]] || [ "$in_port" -lt 1 ] || [ "$in_port" -gt 65535 ]; then
        echo -e "${C_ERR}Invalid port: must be a number between 1 and 65535.${C_RESET}"
        err=1
    fi
    if ! [[ "$in_uuid" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ ]]; then
        echo -e "${C_ERR}Invalid UUID: expected format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.${C_RESET}"
        err=1
    fi

    if [ "$err" -eq 1 ]; then
        echo -e "\n${C_ERR}Config NOT saved because of the errors above.${C_RESET}"
        pause
        return
    fi

    cat > "$CONFIG_FILE" << CFGEOF
SERVER_ADDRESS=$in_addr
SERVER_PORT=$in_port
UUID=$in_uuid
CFGEOF

    rm -f "$VALID_MARKER"
    echo -e "${C_OK}Config saved.${C_RESET}"

    if [ ! -x "$BIN_PATH" ]; then
        echo -e "${C_WARN}Xray is not installed, so it cannot be tested right now.${C_RESET}"
        echo -e "${C_WARN}Install Xray first (option 1), then come back here to test.${C_RESET}"
        pause
        return
    fi

    echo ""
    read -rp "Test this config now with a real connection? (Y/n): " do_test
    if [[ "$do_test" =~ ^[Nn]$ ]]; then
        echo -e "${C_WARN}Skipped. Run Scan stays locked until this config is tested successfully.${C_RESET}"
        pause
        return
    fi

    echo -e "\nTesting connection, please wait...\n"
    ensure_scanner_py
    command -v python >/dev/null 2>&1 && PY=python || PY=python3
    if "$PY" "$SCANNER_PY" --test; then
        touch "$VALID_MARKER"
        echo -e "\n${C_OK}Config test PASSED. Run Scan is now unlocked.${C_RESET}"
    else
        echo -e "\n${C_ERR}Config test FAILED. Double-check address/port/UUID and try again.${C_RESET}"
    fi
    pause
}

do_delete_config() {
    banner
    load_config
    if [ -z "$SERVER_ADDRESS" ] && [ -z "$SERVER_PORT" ] && [ -z "$UUID_VAL" ]; then
        echo -e "${C_WARN}Config is already empty.${C_RESET}"
        pause
        return
    fi
    read -rp "Delete the current server config? This cannot be undone. (y/N): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        cat > "$CONFIG_FILE" << 'CFGEOF'
SERVER_ADDRESS=
SERVER_PORT=
UUID=
CFGEOF
        rm -f "$VALID_MARKER"
        echo -e "${C_OK}Config deleted. Run Scan is locked until a new config is entered and tested.${C_RESET}"
    else
        echo "Cancelled."
    fi
    pause
}

# ---------- option 3: domains submenu ----------
domains_menu() {
    while true; do
        banner
        ensure_domains_file
        print_block \
            "$(domains_status_line)" \
            "" \
            "${C_MENU}1) Edit domains (opens nano)" \
            "2) Delete all domains" \
            "3) Back${C_RESET}"
        echo ""
        read -rp "Choose [1-3]: " c
        case "$c" in
            1) do_edit_domains ;;
            2) do_delete_domains ;;
            3) return ;;
            *) echo -e "${C_ERR}Invalid option${C_RESET}"; sleep 1 ;;
        esac
    done
}

do_edit_domains() {
    ensure_domains_file
    command -v nano >/dev/null 2>&1 && nano "$DOMAINS_FILE" || vi "$DOMAINS_FILE"
}

do_delete_domains() {
    banner
    ensure_domains_file
    local n
    n=$(grep -cve '^\s*$' "$DOMAINS_FILE" 2>/dev/null || echo 0)
    if [ "$n" -eq 0 ]; then
        echo -e "${C_WARN}Domain list is already empty.${C_RESET}"
        pause
        return
    fi
    read -rp "Delete all $n domain(s) from the list? This cannot be undone. (y/N): " ans
    if [[ "$ans" =~ ^[Yy]$ ]]; then
        : > "$DOMAINS_FILE"
        echo -e "${C_OK}All domains deleted. Use 'Edit domains' to add new ones.${C_RESET}"
    else
        echo "Cancelled."
    fi
    pause
}

# ---------- option 4: run scan ----------
run_scan() {
    banner
    ensure_scanner_py
    ensure_config_file
    load_config

    if [ ! -x "$BIN_PATH" ]; then
        echo -e "${C_ERR}Xray is not installed yet. Use option 1 first.${C_RESET}"
        pause
        return
    fi
    if [ -z "$SERVER_ADDRESS" ] || [ -z "$SERVER_PORT" ] || [ -z "$UUID_VAL" ]; then
        echo -e "${C_ERR}Server config is not set. Use option 2 first.${C_RESET}"
        pause
        return
    fi
    if [ ! -f "$VALID_MARKER" ]; then
        echo -e "${C_ERR}This config has not been tested successfully yet.${C_RESET}"
        echo -e "${C_ERR}Use option 2 and run the connection test first.${C_RESET}"
        pause
        return
    fi

    ensure_domains_file
    command -v python >/dev/null 2>&1 && PY=python || PY=python3
    "$PY" "$SCANNER_PY" "$DOMAINS_FILE"
    echo ""
    pause
}

# ---------- main menu ----------
ensure_scanner_py
ensure_domains_file
ensure_config_file

while true; do
    banner
    print_block \
        "$(xray_status_line)" \
        "$(config_status_line)" \
        "$(domains_status_line)" \
        "" \
        "${C_MENU}1) Xray Setup" \
        "2) Server Config" \
        "3) Domains" \
        "4) Run Scan" \
        "5) Exit${C_RESET}"
    echo ""
    read -rp "Choose [1-5]: " choice

    case "$choice" in
        1) xray_setup ;;
        2) config_menu ;;
        3) domains_menu ;;
        4) run_scan ;;
        5) echo "Bye"; exit 0 ;;
        *) echo -e "${C_ERR}Invalid option${C_RESET}"; sleep 1 ;;
    esac
done
