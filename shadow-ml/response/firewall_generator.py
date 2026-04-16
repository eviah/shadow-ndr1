"""
response/firewall_generator.py — LLM-Powered Firewall Rule Generator v10.0

Automatically generates eBPF, Suricata IDS, iptables, and Cisco ACL rules
from ML threat scores and attack intelligence.

Rule types generated:
  • Suricata IDS/IPS rules (alert/drop/reject)
  • Linux iptables / nftables rules
  • eBPF/XDP programs (kernel-level, line-rate)
  • Cisco IOS ACL commands
  • pf (BSD/macOS) rules
  • BGP null-routing commands (RTBH)

Intelligence sources:
  • Neural engine threat score + XAI feature attribution
  • STIX IOC blacklist (known malicious IPs/domains)
  • Protocol micro-model anomaly signatures
  • Attacker behavioral profile from honeypot
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("shadow.response.firewall_generator")


# ---------------------------------------------------------------------------
# Rule types
# ---------------------------------------------------------------------------

class RuleFormat(str, Enum):
    SURICATA  = "suricata"
    IPTABLES  = "iptables"
    NFTABLES  = "nftables"
    EBPF      = "ebpf"
    CISCO_ACL = "cisco_acl"
    PF        = "pf"
    BGP_RTBH  = "bgp_rtbh"


@dataclass
class FirewallRule:
    rule_id: str
    format: RuleFormat
    rule_text: str
    priority: int             # 1=highest
    threat_score: float
    src_ip: Optional[str]
    dst_ip: Optional[str]
    protocol: str
    action: str               # block / alert / drop / reject
    reason: str
    expiry_ts: Optional[float] = None
    generated_at: float = field(default_factory=time.time)
    llm_generated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "format": self.format.value,
            "rule_text": self.rule_text,
            "priority": self.priority,
            "threat_score": round(self.threat_score, 4),
            "action": self.action,
            "reason": self.reason,
            "llm_generated": self.llm_generated,
            "generated_at": self.generated_at,
        }


# ---------------------------------------------------------------------------
# Rule generators per format (template-based)
# ---------------------------------------------------------------------------

class _SuricataGenerator:
    SID_BASE = 9_000_000

    def __init__(self):
        self._next_sid = self.SID_BASE

    def _sid(self) -> int:
        sid = self._next_sid
        self._next_sid += 1
        return sid

    def block_ip(self, ip: str, protocol: str, reason: str, score: float) -> str:
        proto = "tcp" if protocol.lower() == "tcp" else "ip"
        return (
            f'drop {proto} {ip} any -> $HOME_NET any '
            f'(msg:"SHADOW-ML Block {ip} threat={score:.2f} {reason}"; '
            f'sid:{self._sid()}; rev:1; classtype:policy-violation;)'
        )

    def alert_port(self, dst_port: int, protocol: str, reason: str, score: float) -> str:
        proto = "tcp" if protocol.lower() == "tcp" else "udp"
        return (
            f'alert {proto} any any -> $HOME_NET {dst_port} '
            f'(msg:"SHADOW-ML Alert port {dst_port} threat={score:.2f} {reason}"; '
            f'sid:{self._sid()}; rev:1; threshold:type limit,track by_src,count 5,seconds 60;)'
        )

    def alert_content(self, content: str, protocol: str, reason: str, score: float) -> str:
        safe_content = content.replace('"', '\\"')[:50]
        return (
            f'alert {protocol.lower() or "tcp"} any any -> any any '
            f'(msg:"SHADOW-ML Content match threat={score:.2f} {reason}"; '
            f'content:"{safe_content}"; sid:{self._sid()}; rev:1;)'
        )

    def dns_blackhole(self, domain: str, score: float) -> str:
        return (
            f'alert dns any any -> any any '
            f'(msg:"SHADOW-ML DNS Sinkhole {domain} threat={score:.2f}"; '
            f'dns.query; content:"{domain}"; sid:{self._sid()}; rev:1;)'
        )


class _IPTablesGenerator:
    def block_ip(self, ip: str, direction: str = "INPUT") -> str:
        return f"iptables -I {direction} -s {ip} -j DROP -m comment --comment 'shadow-ml-auto'"

    def rate_limit(self, ip: str, rate: int = 10) -> str:
        return (
            f"iptables -I INPUT -s {ip} -m limit --limit {rate}/min "
            f"--limit-burst {rate * 2} -j ACCEPT\n"
            f"iptables -I INPUT -s {ip} -j DROP"
        )

    def block_port(self, dst_port: int, proto: str = "tcp") -> str:
        return f"iptables -I INPUT -p {proto} --dport {dst_port} -j DROP -m comment --comment 'shadow-ml'"

    def remove_rule(self, ip: str) -> str:
        return f"iptables -D INPUT -s {ip} -j DROP 2>/dev/null || true"


class _NftablesGenerator:
    def block_ip(self, ip: str) -> str:
        return f"nft add element inet filter blackhole_v4 {{ {ip} }}"

    def block_range(self, cidr: str) -> str:
        return f"nft add element inet filter blackhole_v4 {{ {cidr} }}"

    def setup_chain(self) -> str:
        return (
            "nft add table inet filter\n"
            "nft add chain inet filter input { type filter hook input priority 0; }\n"
            "nft add set inet filter blackhole_v4 { type ipv4_addr; }\n"
            "nft add rule inet filter input ip saddr @blackhole_v4 drop"
        )


class _eBPFGenerator:
    """Generates eBPF/XDP C programs for kernel-level, line-rate packet filtering."""

    def block_ip_program(self, ips: List[str]) -> str:
        ip_checks = "\n".join(
            f"    if (ip->saddr == {self._ip_to_int(ip)}) return XDP_DROP;"
            for ip in ips[:20]
        )
        return f"""// SHADOW-ML Auto-generated eBPF/XDP filter
// Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}
// Block list: {len(ips)} IPs
#include <linux/bpf.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int shadow_xdp_filter(struct xdp_md *ctx) {{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if ((void*)(ip + 1) > data_end) return XDP_PASS;
{ip_checks}
    return XDP_PASS;
}}
char LICENSE[] SEC("license") = "GPL";
"""

    @staticmethod
    def _ip_to_int(ip: str) -> int:
        try:
            parts = [int(p) for p in ip.split(".")]
            return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        except Exception:
            return 0


class _CiscoACLGenerator:
    def __init__(self, acl_name: str = "SHADOW_ML_BLOCK"):
        self.acl_name = acl_name
        self._seq = 10

    def block_ip(self, ip: str, reason: str = "") -> str:
        self._seq += 10
        return (
            f"ip access-list extended {self.acl_name}\n"
            f" {self._seq} deny ip host {ip} any log   ! shadow-ml {reason}\n"
            f"end"
        )

    def bgp_null_route(self, ip: str) -> str:
        return (
            f"! BGP RTBH null-route for {ip}\n"
            f"ip route {ip} 255.255.255.255 Null0\n"
            f"router bgp 65000\n"
            f" network {ip} mask 255.255.255.255\n"
            f"end"
        )


# ---------------------------------------------------------------------------
# LLM-powered rule generator
# ---------------------------------------------------------------------------

class _LLMRuleGenerator:
    def __init__(self, model: str = "claude-sonnet-4-6"):
        self._model = model
        self._client = None
        try:
            import anthropic
            self._client = anthropic.Anthropic()
        except ImportError:
            pass

    def generate(
        self,
        threat_context: Dict[str, Any],
        target_format: str,
        existing_rules: List[str],
    ) -> Optional[str]:
        if not self._client:
            return None

        system = (
            "You are a senior network security engineer expert in Suricata, iptables, "
            "eBPF/XDP, and Cisco IOS. Generate precise, minimal, effective firewall/IDS rules "
            "to block or alert on the described threat. Output ONLY the rule text, nothing else."
        )

        context_str = json.dumps(threat_context, indent=2, default=str)
        user_msg = (
            f"Generate a {target_format} rule for this threat:\n\n"
            f"{context_str}\n\n"
            f"Existing similar rules (do not duplicate):\n"
            + "\n".join(existing_rules[-5:])
        )

        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=512,
                system=system,
                messages=[{"role": "user", "content": user_msg}],
            )
            return response.content[0].text.strip()
        except Exception as exc:
            logger.warning("LLM rule generation failed: %s", exc)
            return None


# ---------------------------------------------------------------------------
# Main Firewall Generator
# ---------------------------------------------------------------------------

class FirewallRuleGenerator:
    """
    SHADOW-ML Firewall Rule Generator v10.0

    Translates ML threat scores into deployable firewall/IDS rules.
    Supports Suricata, iptables, nftables, eBPF, Cisco ACL, and BGP RTBH.
    """

    VERSION = "10.0.0"
    DEFAULT_BLOCK_TTL = 3600 * 24   # 24 hours

    def __init__(self, use_llm: bool = True):
        self._suricata = _SuricataGenerator()
        self._iptables = _IPTablesGenerator()
        self._nftables = _NftablesGenerator()
        self._ebpf = _eBPFGenerator()
        self._cisco = _CiscoACLGenerator()
        self._llm = _LLMRuleGenerator() if use_llm else None
        self._rules: List[FirewallRule] = []
        self._stats: Dict[str, Any] = {"generated": 0, "llm_generated": 0, "by_format": {}}
        logger.info("FirewallRuleGenerator v%s initialised (llm=%s)", self.VERSION, use_llm)

    def _rule_id(self, prefix: str) -> str:
        return hashlib.sha256(f"{prefix}{time.time()}".encode()).hexdigest()[:12]

    def generate_from_threat(
        self,
        threat: Dict[str, Any],
        formats: Optional[List[str]] = None,
        action: str = "auto",
    ) -> List[FirewallRule]:
        """
        Generate rules for a detected threat event.

        threat: {src_ip, dst_ip, protocol, threat_score, attack_type, description}
        formats: list of RuleFormat values to generate (default: suricata + iptables)
        action: 'block', 'alert', or 'auto' (block if score >= 0.8, else alert)
        """
        score = float(threat.get("threat_score", 0.5))
        if action == "auto":
            action = "block" if score >= 0.8 else "alert"

        target_formats = formats or ["suricata", "iptables"]
        src_ip = threat.get("src_ip", "")
        protocol = str(threat.get("protocol", "tcp")).lower()
        reason = str(threat.get("attack_type", threat.get("description", "")))[:60]

        generated = []

        for fmt in target_formats:
            rule_text = self._generate_for_format(fmt, threat, action, score, src_ip, protocol, reason)
            if not rule_text:
                continue

            # Try LLM enhancement
            llm_text = None
            if self._llm and score >= 0.7:
                existing = [r.rule_text for r in self._rules[-5:] if r.format.value == fmt]
                llm_text = self._llm.generate(threat, fmt, existing)

            final_text = llm_text or rule_text
            is_llm = llm_text is not None

            rule = FirewallRule(
                rule_id=self._rule_id(f"{fmt}_{src_ip}"),
                format=RuleFormat(fmt),
                rule_text=final_text,
                priority=1 if score >= 0.9 else 2 if score >= 0.7 else 3,
                threat_score=score,
                src_ip=src_ip or None,
                dst_ip=threat.get("dst_ip"),
                protocol=protocol,
                action=action,
                reason=reason,
                expiry_ts=time.time() + self.DEFAULT_BLOCK_TTL,
                llm_generated=is_llm,
            )
            self._rules.append(rule)
            generated.append(rule)
            self._stats["generated"] += 1
            if is_llm:
                self._stats["llm_generated"] += 1
            self._stats["by_format"][fmt] = self._stats["by_format"].get(fmt, 0) + 1

            logger.info(
                "Rule generated: format=%s action=%s score=%.2f src=%s llm=%s",
                fmt, action, score, src_ip, is_llm,
            )

        return generated

    def _generate_for_format(
        self, fmt: str, threat: Dict, action: str,
        score: float, src_ip: str, protocol: str, reason: str,
    ) -> Optional[str]:
        try:
            if fmt == "suricata":
                if src_ip:
                    return self._suricata.block_ip(src_ip, protocol, reason, score)
                dst_port = threat.get("dst_port")
                if dst_port:
                    return self._suricata.alert_port(int(dst_port), protocol, reason, score)
                return self._suricata.alert_content(reason, protocol, reason, score)

            elif fmt == "iptables":
                if action == "block" and src_ip:
                    return self._iptables.block_ip(src_ip)
                elif src_ip:
                    return self._iptables.rate_limit(src_ip)
                dst_port = threat.get("dst_port")
                if dst_port:
                    return self._iptables.block_port(int(dst_port), protocol)

            elif fmt == "nftables":
                if src_ip:
                    return self._nftables.block_ip(src_ip)

            elif fmt == "ebpf":
                ips = [src_ip] if src_ip else []
                return self._ebpf.block_ip_program(ips)

            elif fmt == "cisco_acl":
                if src_ip:
                    return self._cisco.block_ip(src_ip, reason)

            elif fmt == "bgp_rtbh":
                if src_ip:
                    return self._cisco.bgp_null_route(src_ip)

        except Exception as exc:
            logger.warning("Rule generation failed for format %s: %s", fmt, exc)
        return None

    def generate_dns_sinkhole(self, domain: str, score: float) -> FirewallRule:
        """Generate DNS sinkhole rule for DGA/C2 domain."""
        rule_text = self._suricata.dns_blackhole(domain, score)
        rule = FirewallRule(
            rule_id=self._rule_id(f"dns_{domain}"),
            format=RuleFormat.SURICATA,
            rule_text=rule_text,
            priority=2,
            threat_score=score,
            src_ip=None,
            dst_ip=None,
            protocol="dns",
            action="alert",
            reason=f"DNS sinkhole: {domain}",
            expiry_ts=time.time() + self.DEFAULT_BLOCK_TTL,
        )
        self._rules.append(rule)
        return rule

    def generate_ebpf_bulk(self, malicious_ips: List[str]) -> FirewallRule:
        """Generate one eBPF program blocking all malicious IPs at once."""
        rule_text = self._ebpf.block_ip_program(malicious_ips)
        rule = FirewallRule(
            rule_id=self._rule_id("ebpf_bulk"),
            format=RuleFormat.EBPF,
            rule_text=rule_text,
            priority=1,
            threat_score=1.0,
            src_ip=None, dst_ip=None,
            protocol="any",
            action="block",
            reason=f"XDP block: {len(malicious_ips)} malicious IPs",
        )
        self._rules.append(rule)
        return rule

    def get_active_rules(self, fmt: Optional[str] = None) -> List[Dict[str, Any]]:
        now = time.time()
        rules = [
            r for r in self._rules
            if r.expiry_ts is None or r.expiry_ts > now
        ]
        if fmt:
            rules = [r for r in rules if r.format.value == fmt]
        return [r.to_dict() for r in rules]

    def export_suricata(self) -> str:
        """Export all active Suricata rules as a .rules file string."""
        now = time.time()
        lines = ["# SHADOW-ML Auto-generated Suricata rules", f"# Generated: {time.ctime(now)}", ""]
        for r in self._rules:
            if r.format == RuleFormat.SURICATA and (r.expiry_ts is None or r.expiry_ts > now):
                lines.append(r.rule_text)
        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        return {**self._stats, "total_rules": len(self._rules), "active_rules": len(self.get_active_rules())}
