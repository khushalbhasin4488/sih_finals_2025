"""
Log Pattern Analyzer
Analyzes attack log files to extract patterns and generate detection rules

This tool analyzes sample attack logs to:
1. Extract common patterns
2. Generate detection rules
3. Validate rule effectiveness
"""
import re
import json
import yaml
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple
from collections import Counter, defaultdict
from datetime import datetime
import structlog

from storage.models import LogEntry

logger = structlog.get_logger()


class LogPatternAnalyzer:
    """
    Analyzes attack logs to extract patterns and generate detection rules
    """
    
    def __init__(self, output_dir: str = "config/signatures"):
        """
        Initialize the pattern analyzer
        
        Args:
            output_dir: Directory to save generated rules
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Pattern storage
        self.patterns = defaultdict(list)
        self.ip_patterns = Counter()
        self.time_patterns = []
        
        logger.info("LogPatternAnalyzer initialized", output_dir=str(self.output_dir))
    
    def analyze_attack_logs(self, log_file: str, attack_type: str) -> Dict[str, Any]:
        """
        Analyze a log file containing attack samples
        
        Args:
            log_file: Path to JSON log file
            attack_type: Type of attack (brute_force, web_attack, network_scan, privilege_abuse)
            
        Returns:
            Analysis results including extracted patterns
        """
        logger.info("Analyzing attack logs", file=log_file, attack_type=attack_type)
        
        # Load logs
        with open(log_file, 'r') as f:
            data = json.load(f)
        
        logs = [LogEntry.from_dict(log) for log in data]
        
        # Extract patterns based on attack type
        if attack_type == "brute_force":
            return self._analyze_brute_force(logs)
        elif attack_type == "web_attack":
            return self._analyze_web_attacks(logs)
        elif attack_type == "network_scan":
            return self._analyze_network_scans(logs)
        elif attack_type == "privilege_abuse":
            return self._analyze_privilege_abuse(logs)
        else:
            logger.error("Unknown attack type", attack_type=attack_type)
            return {}
    
    def _analyze_brute_force(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """Analyze brute force attack logs"""
        analysis = {
            "attack_type": "brute_force",
            "total_logs": len(logs),
            "patterns": [],
            "common_phrases": [],
            "source_ips": [],
            "time_characteristics": {}
        }
        
        # Extract common phrases from failed login attempts
        messages = [log.message for log in logs if log.message]
        common_phrases = self._extract_common_phrases(messages)
        analysis["common_phrases"] = common_phrases[:10]
        
        # Extract regex patterns
        patterns = []
        for phrase in common_phrases:
            # Create regex pattern (escape special chars)
            pattern = re.escape(phrase)
            patterns.append({
                "pattern": f"(?i){pattern}",
                "frequency": common_phrases.count(phrase)
            })
        
        analysis["patterns"] = patterns
        
        # Analyze source IPs
        ips = [log.get_source_ip() for log in logs if log.get_source_ip()]
        ip_counter = Counter(ips)
        analysis["source_ips"] = [
            {"ip": ip, "count": count} 
            for ip, count in ip_counter.most_common(10)
        ]
        
        # Analyze time patterns
        timestamps = [log.get_timestamp() for log in logs if log.get_timestamp()]
        if len(timestamps) > 1:
            time_diffs = []
            sorted_times = sorted(timestamps)
            for i in range(1, len(sorted_times)):
                diff = (sorted_times[i] - sorted_times[i-1]).total_seconds()
                time_diffs.append(diff)
            
            if time_diffs:
                avg_interval = sum(time_diffs) / len(time_diffs)
                analysis["time_characteristics"] = {
                    "average_interval_seconds": round(avg_interval, 2),
                    "min_interval": min(time_diffs),
                    "max_interval": max(time_diffs),
                    "suggested_window": round(max(time_diffs) * 1.5)  # 1.5x max interval
                }
        
        return analysis
    
    def _analyze_web_attacks(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """Analyze web attack logs"""
        analysis = {
            "attack_type": "web_attack",
            "total_logs": len(logs),
            "sql_injection_patterns": [],
            "xss_patterns": [],
            "path_traversal_patterns": [],
            "command_injection_patterns": [],
            "urls": []
        }
        
        # Extract messages and URLs
        messages = [log.message for log in logs if log.message]
        
        # SQL Injection patterns
        sql_patterns = [
            r"(?i)union\s+select",
            r"(?i)'\s*or\s*'1'\s*=\s*'1",
            r"(?i)'\s*or\s*1\s*=\s*1",
            r"(?i);\s*drop\s+table",
            r"(?i)--\s*$",
            r"(?i)#\s*$"
        ]
        
        for pattern in sql_patterns:
            matches = sum(1 for msg in messages if re.search(pattern, msg))
            if matches > 0:
                analysis["sql_injection_patterns"].append({
                    "pattern": pattern,
                    "matches": matches
                })
        
        # XSS patterns
        xss_patterns = [
            r"<script[^>]*>",
            r"javascript:",
            r"on\w+\s*=",
            r"<iframe",
            r"alert\s*\(",
        ]
        
        for pattern in xss_patterns:
            matches = sum(1 for msg in messages if re.search(pattern, msg))
            if matches > 0:
                analysis["xss_patterns"].append({
                    "pattern": pattern,
                    "matches": matches
                })
        
        # Path traversal patterns
        path_patterns = [
            r"\.\./",
            r"\.\.",
            r"%2e%2e",
            r"etc/passwd",
            r"windows/system32"
        ]
        
        for pattern in path_patterns:
            matches = sum(1 for msg in messages if re.search(pattern, msg, re.IGNORECASE))
            if matches > 0:
                analysis["path_traversal_patterns"].append({
                    "pattern": pattern,
                    "matches": matches
                })
        
        # Command injection patterns
        cmd_patterns = [
            r"[;&|]\s*(cat|ls|whoami|id)",
            r"\$\(",
            r"`[^`]+`",
            r"cmd\.exe",
            r"/bin/(ba)?sh"
        ]
        
        for pattern in cmd_patterns:
            matches = sum(1 for msg in messages if re.search(pattern, msg))
            if matches > 0:
                analysis["command_injection_patterns"].append({
                    "pattern": pattern,
                    "matches": matches
                })
        
        return analysis
    
    def _analyze_network_scans(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """Analyze network scanning logs"""
        analysis = {
            "attack_type": "network_scan",
            "total_logs": len(logs),
            "source_ips": [],
            "destination_ports": [],
            "scan_patterns": []
        }
        
        # Extract source IPs
        ips = [log.get_source_ip() for log in logs if log.get_source_ip()]
        ip_counter = Counter(ips)
        analysis["source_ips"] = [
            {"ip": ip, "count": count} 
            for ip, count in ip_counter.most_common(10)
        ]
        
        # Extract destination ports from messages
        ports = []
        for log in logs:
            if log.message:
                # Look for port patterns like "DPT=80" or "port 22"
                port_match = re.search(r'(?:DPT=|port\s+)(\d+)', log.message)
                if port_match:
                    ports.append(int(port_match.group(1)))
        
        port_counter = Counter(ports)
        analysis["destination_ports"] = [
            {"port": port, "count": count}
            for port, count in port_counter.most_common(20)
        ]
        
        # Analyze scan patterns
        if ips and ports:
            # Unique ports per IP
            ip_ports = defaultdict(set)
            for log in logs:
                ip = log.get_source_ip()
                if ip and log.message:
                    port_match = re.search(r'(?:DPT=|port\s+)(\d+)', log.message)
                    if port_match:
                        ip_ports[ip].add(int(port_match.group(1)))
            
            # Find IPs scanning many ports
            for ip, port_set in ip_ports.items():
                if len(port_set) >= 5:  # 5+ unique ports = likely scan
                    analysis["scan_patterns"].append({
                        "source_ip": ip,
                        "unique_ports": len(port_set),
                        "ports": sorted(list(port_set))[:10]  # Sample of ports
                    })
        
        return analysis
    
    def _analyze_privilege_abuse(self, logs: List[LogEntry]) -> Dict[str, Any]:
        """Analyze privilege escalation/abuse logs"""
        analysis = {
            "attack_type": "privilege_abuse",
            "total_logs": len(logs),
            "sudo_commands": [],
            "user_creation": [],
            "privilege_change": [],
            "suspicious_commands": []
        }
        
        messages = [log.message for log in logs if log.message]
        
        # Sudo command patterns
        sudo_patterns = [
            r"sudo\s+su\s*-",
            r"sudo\s+-i",
            r"sudo\s+/bin/(ba)?sh",
            r"sudo\s+.*root"
        ]
        
        for pattern in sudo_patterns:
            matches = [msg for msg in messages if re.search(pattern, msg, re.IGNORECASE)]
            if matches:
                analysis["sudo_commands"].append({
                    "pattern": pattern,
                    "matches": len(matches),
                    "examples": matches[:3]
                })
        
        # User creation patterns
        user_patterns = [
            r"useradd",
            r"adduser",
            r"net\s+user.*add",
            r"user\s+account\s+created"
        ]
        
        for pattern in user_patterns:
            matches = [msg for msg in messages if re.search(pattern, msg, re.IGNORECASE)]
            if matches:
                analysis["user_creation"].append({
                    "pattern": pattern,
                    "matches": len(matches)
                })
        
        # Privilege change patterns
        priv_patterns = [
            r"passwd\s+",
            r"chpasswd",
            r"usermod.*-g\s*root",
            r"privilege.*escalat"
        ]
        
        for pattern in priv_patterns:
            matches = [msg for msg in messages if re.search(pattern, msg, re.IGNORECASE)]
            if matches:
                analysis["privilege_change"].append({
                    "pattern": pattern,
                    "matches": len(matches)
                })
        
        return analysis
    
    def _extract_common_phrases(self, messages: List[str], min_length: int = 10) -> List[str]:
        """
        Extract common phrases from messages
        
        Args:
            messages: List of log messages
            min_length: Minimum phrase length
            
        Returns:
            List of common phrases sorted by frequency
        """
        phrase_counter = Counter()
        
        for message in messages:
            if not message or len(message) < min_length:
                continue
            
            # Extract words
            words = message.lower().split()
            
            # Extract 2-5 word phrases
            for n in range(2, 6):
                for i in range(len(words) - n + 1):
                    phrase = ' '.join(words[i:i+n])
                    if len(phrase) >= min_length:
                        phrase_counter[phrase] += 1
        
        # Return phrases that appear more than once
        return [phrase for phrase, count in phrase_counter.most_common() if count > 1]
    
    def generate_rules(self, analysis: Dict[str, Any], rule_file: str = None) -> Dict[str, Any]:
        """
        Generate detection rules from analysis results
        
        Args:
            analysis: Analysis results from analyze_attack_logs
            rule_file: Optional output file for rules (YAML)
            
        Returns:
            Generated rules in dictionary format
        """
        attack_type = analysis.get("attack_type")
        
        if attack_type == "brute_force":
            rules = self._generate_brute_force_rules(analysis)
        elif attack_type == "web_attack":
            rules = self._generate_web_attack_rules(analysis)
        elif attack_type == "network_scan":
            rules = self._generate_network_scan_rules(analysis)
        elif attack_type == "privilege_abuse":
            rules = self._generate_privilege_abuse_rules(analysis)
        else:
            logger.error("Unknown attack type for rule generation", attack_type=attack_type)
            return {}
        
        # Save to file if specified
        if rule_file:
            output_path = self.output_dir / rule_file
            with open(output_path, 'w') as f:
                yaml.dump(rules, f, default_flow_style=False, sort_keys=False)
            logger.info("Rules saved", file=str(output_path))
        
        return rules
    
    def _generate_brute_force_rules(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate brute force detection rules"""
        rules = {
            "attack_type": "brute_force",
            "detection_method": "pattern_counting",
            "rules": []
        }
        
        # Generate rules from patterns
        for i, pattern_data in enumerate(analysis.get("patterns", [])[:5], 1):
            rule = {
                "id": f"BF-CUSTOM-{i:03d}",
                "name": f"Brute Force Pattern {i}",
                "severity": "high",
                "category": "brute_force",
                "pattern": pattern_data["pattern"],
                "window_seconds": analysis.get("time_characteristics", {}).get("suggested_window", 300),
                "threshold": 5,
                "fields": ["message", "raw"]
            }
            rules["rules"].append(rule)
        
        return rules
    
    def _generate_web_attack_rules(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate web attack detection rules"""
        rules = {
            "attack_type": "web_attack",
            "detection_method": "pattern_matching",
            "rules": []
        }
        
        rule_id = 1
        
        # SQL Injection rules
        for pattern_data in analysis.get("sql_injection_patterns", []):
            rule = {
                "id": f"WEB-SQL-{rule_id:03d}",
                "name": "SQL Injection Detection",
                "severity": "critical",
                "category": "sql_injection",
                "pattern": pattern_data["pattern"],
                "fields": ["message", "url", "query_string"]
            }
            rules["rules"].append(rule)
            rule_id += 1
        
        # XSS rules
        for pattern_data in analysis.get("xss_patterns", []):
            rule = {
                "id": f"WEB-XSS-{rule_id:03d}",
                "name": "XSS Detection",
                "severity": "high",
                "category": "xss",
                "pattern": pattern_data["pattern"],
                "fields": ["message", "url", "query_string"]
            }
            rules["rules"].append(rule)
            rule_id += 1
        
        # Path traversal rules
        for pattern_data in analysis.get("path_traversal_patterns", []):
            rule = {
                "id": f"WEB-PATH-{rule_id:03d}",
                "name": "Path Traversal Detection",
                "severity": "high",
                "category": "path_traversal",
                "pattern": pattern_data["pattern"],
                "fields": ["message", "url", "path"]
            }
            rules["rules"].append(rule)
            rule_id += 1
        
        return rules
    
    def _generate_network_scan_rules(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate network scan detection rules"""
        rules = {
            "attack_type": "network_scan",
            "detection_method": "connection_analysis",
            "rules": []
        }
        
        # Port scan detection rule
        if analysis.get("scan_patterns"):
            rule = {
                "id": "NET-SCAN-001",
                "name": "Port Scan Detection",
                "severity": "medium",
                "category": "network_scan",
                "description": "Detects port scanning activity",
                "window_seconds": 60,
                "threshold": {
                    "unique_ports": 10,
                    "from_single_ip": True
                }
            }
            rules["rules"].append(rule)
        
        return rules
    
    def _generate_privilege_abuse_rules(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate privilege abuse detection rules"""
        rules = {
            "attack_type": "privilege_abuse",
            "detection_method": "pattern_matching",
            "rules": []
        }
        
        rule_id = 1
        
        # Sudo command rules
        for pattern_data in analysis.get("sudo_commands", []):
            rule = {
                "id": f"PRIV-SUDO-{rule_id:03d}",
                "name": "Suspicious Sudo Usage",
                "severity": "critical",
                "category": "privilege_escalation",
                "pattern": pattern_data["pattern"],
                "fields": ["message", "command"]
            }
            rules["rules"].append(rule)
            rule_id += 1
        
        # User creation rules
        for pattern_data in analysis.get("user_creation", []):
            rule = {
                "id": f"PRIV-USER-{rule_id:03d}",
                "name": "User Account Creation",
                "severity": "medium",
                "category": "persistence",
                "pattern": pattern_data["pattern"],
                "fields": ["message", "command"]
            }
            rules["rules"].append(rule)
            rule_id += 1
        
        return rules


def main():
    """Example usage"""
    analyzer = LogPatternAnalyzer()
    
    # Example: Analyze brute force logs
    # analysis = analyzer.analyze_attack_logs("samples/brute_force.json", "brute_force")
    # print(json.dumps(analysis, indent=2))
    
    # Generate rules
    # rules = analyzer.generate_rules(analysis, "brute_force_rules.yaml")
    
    print("LogPatternAnalyzer ready. Use analyze_attack_logs() with your sample logs.")


if __name__ == "__main__":
    main()
