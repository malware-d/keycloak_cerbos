#!/usr/bin/env python3
"""
Cerbos Log Monitor Tool
Monitors Cerbos logs and extracts authorization decisions to send to Django web app
"""

import json
import requests
import time
import subprocess
import threading
from datetime import datetime
from typing import Dict, List, Optional
import logging
import sys
import os
import re
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
    logger.warning("PyYAML not installed. Policy rule parsing will be disabled. Install with: pip install PyYAML")

# Cấu hình
DJANGO_API_ENDPOINT = "http://localhost:8000/api/cerbos-logs/"  # Thay đổi URL của Django app
DOCKER_CONTAINER_NAME = "cerbos"
LOG_CHECK_INTERVAL = 0.5  # Kiểm tra log mỗi 0.5 giây

# Cấu hình logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PolicyParser:
    def __init__(self, policies_root_path: str = "../cerbos/policies"):
        self.policies_root = policies_root_path
        self.policies_cache = {}
        self.enabled = HAS_YAML
        if self.enabled:
            self.load_policies()
        else:
            logger.warning("PolicyParser disabled - PyYAML not available")
    
    def load_policies(self):
        """Load all policy files into cache"""
        try:
            for root, dirs, files in os.walk(self.policies_root):
                for file in files:
                    if file.endswith('.yaml') or file.endswith('.yml'):
                        file_path = os.path.join(root, file)
                        relative_path = os.path.relpath(file_path, self.policies_root)
                        disk_path = f"disk:/policies/{relative_path}"
                        
                        with open(file_path, 'r', encoding='utf-8') as f:
                            policy_data = yaml.safe_load(f)
                            self.policies_cache[disk_path] = policy_data
                            
            logger.info(f"Loaded {len(self.policies_cache)} policy files")
        except Exception as e:
            logger.error(f"Error loading policies: {e}")
    
    def find_matching_rule(self, policy_source: str, action: str, effect: str, principal_roles: List[str]) -> Optional[Dict]:
        """Find the specific rule that matched the decision"""
        if not self.enabled:
            return {"error": "PyYAML not installed - cannot parse policy files"}
            
        if policy_source not in self.policies_cache:
            return {"error": f"Policy file not found: {policy_source}"}
            
        policy = self.policies_cache[policy_source]
        
        # Get rules from resource policy or principal policy
        rules = []
        if 'resourcePolicy' in policy and 'rules' in policy['resourcePolicy']:
            rules = policy['resourcePolicy']['rules']
        elif 'principalPolicy' in policy and 'rules' in policy['principalPolicy']:
            # Principal policy có structure khác: rules -> resource -> actions
            principal_rules = policy['principalPolicy']['rules']
            # Flatten principal policy rules thành format tương tự resource policy
            for rule_group in principal_rules:
                if 'actions' in rule_group:
                    for action_rule in rule_group['actions']:
                        flattened_rule = {
                            'actions': [action_rule['action']],
                            'effect': action_rule['effect'],
                            'condition': action_rule.get('condition', {}),
                            'name': action_rule.get('name', f"principal_rule_{action_rule['action']}"),
                            'resource': rule_group.get('resource', 'unknown')
                        }
                        rules.append(flattened_rule)
        
        # Find matching rule - thử tất cả rules để tìm rule phù hợp nhất
        matching_rules = []
        for rule_index, rule in enumerate(rules):
            match_details = self._check_rule_match(rule, action, effect, principal_roles)
            if match_details['is_match']:
                rule_info = {
                    'rule_index': rule_index,
                    'rule_name': rule.get('name', f'rule_{rule_index}'),
                    'actions': rule.get('actions', []),
                    'effect': rule.get('effect', ''),
                    'roles': rule.get('roles', []),
                    'condition': rule.get('condition', {}),
                    'description': self._extract_rule_description(rule),
                    'match_details': match_details,
                    'policy_file': policy_source
                }
                matching_rules.append(rule_info)
        
        if matching_rules:
            # Trả về rule đầu tiên match (theo thứ tự priority)
            best_match = matching_rules[0]
            # Đơn giản hóa chỉ trả về thông tin cần thiết
            return {
                'rule_name': best_match['rule_name'],
                'rule_index': best_match['rule_index'],
                'actions': best_match['actions'],
                'roles': best_match['roles'],
                'effect': best_match['effect']
            }
        
        return None  # Không tìm thấy rule match
    
    def _check_rule_match(self, rule: Dict, action: str, effect: str, principal_roles: List[str]) -> Dict:
        """Check if rule matches the decision criteria with detailed analysis"""
        match_details = {
            'is_match': False,
            'action_match': False,
            'effect_match': False,
            'role_match': False,
            'details': []
        }
        
        # Check action
        rule_actions = rule.get('actions', [])
        if '*' in rule_actions or action in rule_actions:
            match_details['action_match'] = True
            match_details['details'].append(f"Action '{action}' matches rule actions: {rule_actions}")
        else:
            match_details['details'].append(f"Action '{action}' NOT in rule actions: {rule_actions}")
            return match_details
            
        # Check effect
        rule_effect = rule.get('effect', '')
        if rule_effect == effect:
            match_details['effect_match'] = True
            match_details['details'].append(f"Effect '{effect}' matches rule effect: {rule_effect}")
        else:
            match_details['details'].append(f"Effect '{effect}' NOT matching rule effect: {rule_effect}")
            return match_details
            
        # Check roles (principal policies không có role restrictions)
        rule_roles = rule.get('roles', [])
        if not rule_roles:  # No role restriction (typical for principal policies)
            match_details['role_match'] = True
            match_details['details'].append("No role restriction in rule (principal policy)")
        elif any(role in principal_roles for role in rule_roles):
            match_details['role_match'] = True
            matching_roles = [role for role in rule_roles if role in principal_roles]
            match_details['details'].append(f"Principal roles {principal_roles} match rule roles {rule_roles} (matching: {matching_roles})")
        else:
            match_details['details'].append(f"Principal roles {principal_roles} NOT matching rule roles: {rule_roles}")
            return match_details
            
        # All checks passed
        match_details['is_match'] = True
        return match_details
    
    def _extract_rule_description(self, rule: Dict) -> str:
        """Extract description from rule name or create one"""
        name = rule.get('name', '')
        
        # Convert snake_case to readable description
        if name:
            description = name.replace('_', ' ').title()
            return description
        
        # Fallback description
        actions = ', '.join(rule.get('actions', []))
        roles = ', '.join(rule.get('roles', []))
        return f"Rule for {actions} by {roles}"

class CerbosLogMonitor:
    def __init__(self, django_endpoint: str, container_name: str, policies_path: str = "../cerbos/policies"):
        self.django_endpoint = django_endpoint
        self.container_name = container_name
        self.running = False
        self.last_log_time = None
        self.policy_parser = PolicyParser(policies_path)
        
    def extract_decision_info(self, log_entry: Dict) -> Optional[Dict]:
        """
        Trích xuất thông tin quyết định từ log entry
        """
        try:
            if log_entry.get("log.logger") != "cerbos.audit" or log_entry.get("log.kind") != "decision":
                return None
                
            check_resources = log_entry.get("checkResources", {})
            inputs = check_resources.get("inputs", [])
            outputs = check_resources.get("outputs", [])
            effective_policies = log_entry.get("auditTrail", {}).get("effectivePolicies", {})
            policy_source_info = log_entry.get("policySource", {})
            
            decisions = []
            
            for i, input_data in enumerate(inputs):
                resource = input_data.get("resource", {})
                principal = input_data.get("principal", {})
                actions = input_data.get("actions", [])
                
                # Tìm output tương ứng
                output = None
                if i < len(outputs):
                    output = outputs[i]
                
                if output:
                    for action in actions:
                        action_result = output.get("actions", {}).get(action, {})
                        effect = action_result.get("effect", "")
                        policy = action_result.get("policy", "")
                        
                        # Lấy thông tin policy từ effective policies
                        policy_details = effective_policies.get(policy, {})
                        policy_file_source = policy_details.get("attributes", {}).get("source", "")
                        
                        # Tạo policy_source theo format yêu cầu
                        disk_directory = policy_source_info.get("disk", {}).get("directory", "/policies")
                        policy_source = f"disk:{disk_directory}/{policy_file_source}" if policy_file_source else f"disk:{disk_directory}"
                        
                        # Tìm rule cụ thể đã được áp dụng (nếu có thể)
                        matched_rule_info = None
                        if self.policy_parser.enabled:
                            matched_rule_info = self.policy_parser.find_matching_rule(
                                policy_source=policy_source,
                                action=action, 
                                effect=effect,
                                principal_roles=principal.get("roles", [])
                            )
                        
                        decision = {
                            "timestamp": log_entry.get("timestamp"),
                            "call_id": log_entry.get("callId"),
                            "resource": {
                                "id": resource.get("id"),
                                "kind": resource.get("kind"),
                                "attributes": resource.get("attr", {})
                            },
                            "principal": {
                                "id": principal.get("id"),
                                "roles": principal.get("roles", []),
                                "attributes": principal.get("attr", {})
                            },
                            "action": action,
                            "effect": self.format_effect(effect),
                            "policy_used": policy,
                            "policy_source": policy_source,
                            "is_allowed": effect == "EFFECT_ALLOW"
                        }
                        
                        # Chỉ thêm matched_rule nếu tìm được
                        if matched_rule_info:
                            decision["matched_rule"] = matched_rule_info
                        decisions.append(decision)
            
            return {
                "timestamp": datetime.now().isoformat(),
                "decisions": decisions,
                "total_decisions": len(decisions)
            } if decisions else None
            
        except Exception as e:
            logger.error(f"Error extracting decision info: {e}")
            return None
    
    def format_effect(self, effect: str) -> str:
        """Format effect để dễ đọc hơn"""
        effect_map = {
            "EFFECT_ALLOW": "ALLOWED",
            "EFFECT_DENY": "DENIED",
            "EFFECT_UNSPECIFIED": "UNSPECIFIED"
        }
        return effect_map.get(effect, effect)
    
    def send_to_django(self, decision_data: Dict) -> bool:
        """
        Gửi dữ liệu decision đến Django web app
        """
        try:
            response = requests.post(
                self.django_endpoint,
                json=decision_data,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            
            if response.status_code == 200:
                logger.info(f"Successfully sent decision data to Django")
                return True
            else:
                logger.error(f"Failed to send to Django: {response.status_code} - {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending to Django: {e}")
            return False
    
    def get_docker_logs(self):
        """
        Lấy logs từ Docker container - chỉ log mới từ khi bắt đầu tool
        """
        try:
            # Sử dụng --tail 0 để chỉ lấy log mới từ thời điểm hiện tại
            cmd = [
                "docker", "logs", "-f", "--tail", "0", self.container_name
            ]
            
            # logger.info(f"Starting docker logs command: {' '.join(cmd)}")
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,  # Chuyển stderr về stdout để xử lý chung
                universal_newlines=True,
                bufsize=1
            )
            
            return process
            
        except Exception as e:
            logger.error(f"Error starting docker logs: {e}")
            return None
    
    def process_log_line(self, line: str):
        """
        Xử lý từng dòng log mới
        """
        try:
            # Bỏ qua dòng trống
            line = line.strip()
            if not line:
                return
            
            # Kiểm tra xem có phải JSON không
            if not line.startswith("{"):
                return
            
            # Parse JSON
            log_entry = json.loads(line)
            
            # Chỉ xử lý decision logs
            if (log_entry.get("log.logger") == "cerbos.audit" and 
                log_entry.get("log.kind") == "decision"):
                
                # Trích xuất thông tin decision
                decision_info = self.extract_decision_info(log_entry)
                
                if decision_info:
                    # In ra JSON để debug
                    print(json.dumps(decision_info, ensure_ascii=False))
                    
                    # Gửi đến Django API
                    success = self.send_to_django(decision_info)
                    if not success:
                        logger.warning(f"Failed to send decision data to Django")
                
        except json.JSONDecodeError:
            pass
        except Exception as e:
            pass
    
    def monitor_logs(self):
        """
        Theo dõi logs chính - chỉ xử lý log mới
        """
        print(f"🚀 Starting to monitor NEW logs from container: {self.container_name}")
        print("📌 Only processing logs that appear AFTER tool startup...")
        
        while self.running:
            try:
                # Lấy logs từ Docker (chỉ log mới)
                process = self.get_docker_logs()
                
                if not process:
                    print("❌ Failed to start docker logs process")
                    time.sleep(5)
                    continue
                
                print("✅ Connected to docker logs stream, waiting for new logs...")
                
                # Đọc logs theo thời gian thực
                while self.running and process.poll() is None:
                    line = process.stdout.readline()
                    if line:
                        self.process_log_line(line)
                
                # Nếu process kết thúc, thử kết nối lại
                if process.poll() is not None:
                    print("🔄 Docker logs process ended, reconnecting...")
                    time.sleep(2)
                
            except KeyboardInterrupt:
                print("⏹️ Received keyboard interrupt")
                break
            except Exception as e:
                print(f"❌ Error in monitor loop: {e}")
                time.sleep(5)
                continue
            finally:
                # Cleanup process nếu tồn tại
                if 'process' in locals() and process and process.poll() is None:
                    process.terminate()
    
    def start_monitoring(self):
        """
        Bắt đầu monitoring - chỉ log mới từ thời điểm này
        """
        self.running = True
        print("=" * 60)
        print("🎯 CERBOS LOG MONITOR STARTED")
        print("=" * 60)
        print("📋 Configuration:")
        print(f"   • Django endpoint: {self.django_endpoint}")
        print(f"   • Container name: {self.container_name}")
        print("   • Mode: NEW LOGS ONLY (from now on)")
        print("=" * 60)
        
        try:
            self.monitor_logs()
        except KeyboardInterrupt:
            print("⏹️ Monitoring stopped by user")
        finally:
            self.running = False
            print("🛑 Cerbos Log Monitor stopped")
    
    def stop_monitoring(self):
        """
        Dừng monitoring
        """
        self.running = False

def main():
    """
    Main function
    """
    import argparse
    
    parser = argparse.ArgumentParser(description="Cerbos Log Monitor Tool - Monitor NEW logs only")
    parser.add_argument(
        "--django-endpoint", 
        default=DJANGO_API_ENDPOINT,
        help="Django API endpoint để gửi dữ liệu"
    )
    parser.add_argument(
        "--container-name",
        default=DOCKER_CONTAINER_NAME,
        help="Tên Docker container của Cerbos"
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Bật debug logging"
    )
    parser.add_argument(
        "--policies-path",
        default="../cerbos/policies",
        help="Đường dẫn đến thư mục policies"
    )
    
    args = parser.parse_args()
    
    # Cấu hình log level
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.info("🔍 Debug mode enabled")
    
    # Tạo monitor instance
    monitor = CerbosLogMonitor(
        django_endpoint=args.django_endpoint,
        container_name=args.container_name,
        policies_path=args.policies_path
    )
    
    # Bắt đầu monitoring
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        print("\n⏹️ Stopping monitor...")
        monitor.stop_monitoring()

if __name__ == "__main__":
    main()