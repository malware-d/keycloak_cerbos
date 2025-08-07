import subprocess
import json
import time
import select

current_call_id = None
log_buffer = {}
decision_received = False

def reset_state():
    global current_call_id, log_buffer, decision_received
    print(f"[🔁] Reset state. Previous call_id = {current_call_id}")
    current_call_id = None
    log_buffer = {}
    decision_received = False

def print_audit_report(entry):
    print("\n✅ [REPORT] CERBOS AUDIT LOG –", entry.get("timestamp", "N/A"))
    print("🔹 Call ID       :", entry.get("call_id"))
    print("🔹 Request ID    :", entry.get("request_id"))
    print("🔹 Client IP     :", entry.get("client_ip"))
    print("🔹 User Agent    :", entry.get("user_agent"))
    print("🔹 Principal     :", entry.get("principal_id"))
    print("🔹 Roles         :", ", ".join(entry.get("roles", [])))
    print("🔹 Department    :", entry.get("principal_department", "N/A"))

    print("\n📄 Resource      :", f"{entry.get('resource_id')} ({entry.get('resource_kind')})")
    print("🔸 Attributes    :")
    for k, v in entry.get("resource_attrs", {}).items():
        print(f"    - {k}: {v}")

    print("\n🎯 Action        :", entry.get("action"))
    effect = entry.get("effect")
    effect_icon = "✅ ALLOWED" if effect == "EFFECT_ALLOW" else "❌ DENIED"
    print("✅ Result        :", effect_icon)
    print("📚 Matched Policy:", entry.get("matched_policy"))
    print("🔍 Policy Source :", entry.get("policy_source"))
    print("\n" + "-" * 42 + "\n")

def parse_log_line(line):
    global current_call_id, log_buffer, decision_received

    try:
        log = json.loads(line)
    except Exception as e:
        print(f"[✖️] Failed to parse JSON: {e}")
        return

    call_id = log.get("callId")
    if not call_id:
        call_id = log.get("cerbos", {}).get("call_id")
        if not call_id:
            print("[ℹ️] Skipped log: No callId")
            return

    print(f"[📥] Log received for call_id: {call_id}")

    # Call ID đã thay đổi
    if current_call_id is None:
        print(f"[➡️] Tracking new call_id: {call_id}")
        current_call_id = call_id
        log_buffer = {}
        decision_received = False
    elif call_id != current_call_id:
        if not decision_received:
            print(f"[⚠️] New call_id {call_id} arrived but decision for {current_call_id} was never received. Dropping...")
        reset_state()
        current_call_id = call_id
        log_buffer = {}
        decision_received = False
        print(f"[➡️] Tracking new call_id: {call_id}")

    log_buffer.setdefault("call_id", call_id)

    # gRPC log
    if log.get("log.logger") == "cerbos.grpc":
        log_buffer["timestamp"] = log.get("@timestamp")
        log_buffer["request_id"] = log.get("grpc.request.meta", {}).get("request_id")
        log_buffer["client_ip"] = log.get("http", {}).get("x_forwarded_for", ["N/A"])[0]
        log_buffer["user_agent"] = log.get("http", {}).get("user_agent", "N/A")
        print("[🟡] GRPC log parsed")

    # Access log
    elif log.get("log.kind") == "access":
        log_buffer["client_ip"] = log.get("peer", {}).get("address")
        log_buffer["user_agent"] = log.get("peer", {}).get("userAgent", "N/A")
        print("[🟡] Access log parsed")

    # Decision log
    elif log.get("log.kind") == "decision":
        print("[🟢] Decision log received → parsing and reporting")
        decision_received = True
        log_buffer["timestamp"] = log.get("timestamp")

        cr = log.get("checkResources", {})
        if cr.get("inputs"):
            input_data = cr["inputs"][0]
            principal = input_data.get("principal", {})
            resource = input_data.get("resource", {})

            log_buffer["principal_id"] = principal.get("id")
            log_buffer["roles"] = principal.get("roles", [])
            log_buffer["principal_department"] = principal.get("attr", {}).get("department")

            log_buffer["resource_id"] = resource.get("id")
            log_buffer["resource_kind"] = resource.get("kind")
            log_buffer["resource_attrs"] = resource.get("attr", {})
            log_buffer["action"] = input_data.get("actions", [None])[0]

        if cr.get("outputs"):
            output = cr["outputs"][0]
            actions = output.get("actions", {})
            if actions:
                action, action_info = list(actions.items())[0]
                log_buffer["effect"] = action_info.get("effect")
                log_buffer["matched_policy"] = action_info.get("policy")

        log_buffer["policy_source"] = "N/A"
        ep = log.get("auditTrail", {}).get("effectivePolicies", {})
        for p in ep.values():
            src = p.get("attributes", {}).get("source")
            if src:
                log_buffer["policy_source"] = src
                break

        # ✅ In báo cáo & reset
        print_audit_report(log_buffer)
        reset_state()

def follow_cerbos_logs():
    print("[+] CERBOS Monitor Tool v2 is running... Waiting for logs...\n")

    process = subprocess.Popen(
        ["docker", "logs", "-f", "--since", "0s", "cerbos"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    while True:
        reads, _, _ = select.select([process.stdout], [], [], 1.0)
        if reads:
            line = process.stdout.readline().strip()
            if not line:
                continue
            parse_log_line(line)
        time.sleep(0.1)

if __name__ == "__main__":
    follow_cerbos_logs()
