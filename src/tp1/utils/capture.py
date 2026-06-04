# src/tp1/utils/capture.py

from tp1.utils.lib import choose_interface
from tp1.utils.config import logger
from collections import Counter
from scapy.all import sniff, IP, TCP, UDP, ARP, ICMP, get_if_addr, get_if_hwaddr


class Capture:
    def __init__(self) -> None:
        self.interface = choose_interface()
        self.my_ip = self._get_my_ip()
        self.my_mac = self._get_my_mac()
        self.packets = []
        self.protocols = Counter()
        self.attack = None
        self.summary = ""
        self.findings = []

    def _get_my_ip(self) -> str:
        """
        Get local ip
        """
        try:
            return get_if_addr(self.interface)
        except Exception:
            return "0.0.0.0"

    def _get_my_mac(self) -> str:
        """
        Get local mac
        """
        try:
            return get_if_hwaddr(self.interface).lower()
        except Exception:
            return ""

    def _is_me(self, ip=None, mac=None) -> bool:
        """
        Check if source is local machine
        """
        if ip and ip == self.my_ip:
            return True
        if mac and mac.lower() == self.my_mac:
            return True
        return False

    def _protocol_name(self, packet) -> str:
        """
        Match protocol
        """
        if ARP in packet:
            return "ARP"
        if TCP in packet:
            return "TCP"
        if UDP in packet:
            return "UDP"
        if ICMP in packet:
            return "ICMP"
        if IP in packet:
            return "IP"
        return "OTHER"

    def capture_traffic(self) -> None:
        """
        Capture network traffic from an interface
        """
        logger.info(f"Capture traffic from interface {self.interface}")
        logger.info(f"Local IP ignored: {self.my_ip}")

        try:
            self.packets = sniff(
                iface=self.interface or None,
                count=100,
                timeout=20,
                store=True
            )
        except Exception as e:
            logger.warning(f"Capture impossible: {e}")
            self.packets = []

    def sort_network_protocols(self) -> str:
        """
        Sort and return all captured network protocols
        """
        self.protocols = Counter(self._protocol_name(p) for p in self.packets)
        return "\n".join(f"{proto}: {count}" for proto, count in self.protocols.most_common())

    def get_all_protocols(self) -> dict:
        """
        Return all protocols captured with total packets number
        """
        if not self.protocols:
            self.sort_network_protocols()
        return dict(self.protocols)

    def _get_ports(self, packet) -> tuple:
        """
        Return source and destination ports
        """
        if TCP in packet:
            return packet[TCP].sport, packet[TCP].dport
        if UDP in packet:
            return packet[UDP].sport, packet[UDP].dport
        return "N/A", "N/A"

    def analyse(self, protocols: str) -> None:
        """
        Analyse all captured data and return statement
        """
        self.sort_network_protocols()
        self.findings = []

        arp_sources = Counter()
        sql_sources = Counter()
        xss_sources = Counter()
        arp_infos = {}

        sql_signatures = (
            "union select",
            "' or '1'='1",
            "\" or \"1\"=\"1",
            "drop table",
            "insert into",
            "update ",
            "delete from",
            "sleep(",
            "benchmark(",
            ";--",
            "/*",
        )

        xss_signatures = (
            "<script",
            "javascript:",
            "onerror=",
            "onload=",
            "onclick=",
            "document.cookie",
        )

        def clean_payload(payload: str) -> str:
            """
            Clean payload
            """
            payload = payload.replace("\r", " ").replace("\n", " ")
            payload = " ".join(payload.split())
            return payload[:500]

        for p in self.packets:
            payload = bytes(p).decode("latin1", errors="ignore").lower()

            if ARP in p:
                arp_ip = p[ARP].psrc
                arp_mac = p[ARP].hwsrc.lower()

                if not self._is_me(arp_ip, arp_mac):
                    arp_sources[arp_ip] += 1
                    arp_infos[arp_ip] = arp_mac

            if IP in p:
                src = p[IP].src
                dst = p[IP].dst
                proto = self._protocol_name(p)
                sport, dport = self._get_ports(p)

                if self._is_me(src):
                    continue

                for sig in sql_signatures:
                    if sig in payload:
                        sql_sources[src] += 1
                        self.findings.append({
                            "type": "SQL Injection",
                            "source": src,
                            "destination": dst,
                            "protocol": proto,
                            "sport": sport,
                            "dport": dport,
                            "signature": sig,
                            "payload": clean_payload(payload)
                        })

                for sig in xss_signatures:
                    if sig in payload:
                        xss_sources[src] += 1
                        self.findings.append({
                            "type": "XSS",
                            "source": src,
                            "destination": dst,
                            "protocol": proto,
                            "sport": sport,
                            "dport": dport,
                            "signature": sig,
                            "payload": clean_payload(payload)
                        })

        suspicious_arp = [ip for ip, count in arp_sources.items() if count >= 5]
        suspicious_sql = [ip for ip, count in sql_sources.items() if count >= 1]
        suspicious_xss = [ip for ip, count in xss_sources.items() if count >= 1]

        for ip in suspicious_arp:
            self.findings.append({
                "type": "ARP Spoofing",
                "source": ip,
                "destination": "Broadcast / LAN",
                "protocol": "ARP",
                "sport": "N/A",
                "dport": "N/A",
                "mac": arp_infos.get(ip, "N/A"),
                "signature": "Plusieurs paquets ARP depuis la même source",
                "payload": f"{arp_sources[ip]} paquets ARP détectés"
            })

        attacks = []

        if suspicious_arp:
            attacks.append(f"Suspicion ARP spoofing depuis {', '.join(suspicious_arp)}")

        if suspicious_sql:
            attacks.append(f"Suspicion SQL injection depuis {', '.join(suspicious_sql)}")

        if suspicious_xss:
            attacks.append(f"Suspicion XSS depuis {', '.join(suspicious_xss)}")

        self.attack = " | ".join(attacks) if attacks else "Aucune attaque détectée"
        self.summary = self._gen_summary()

    def get_summary(self) -> str:
        """
        Return summary
        """
        return self.summary

    def get_findings(self) -> list:
        """
        Return findings
        """
        return self.findings

    def _gen_summary(self) -> str:
        """
        Generate summary
        """
        total = len(self.packets)
        lines = [
            "Résumé de l'analyse réseau",
            f"Interface utilisée : {self.interface}",
            f"Nombre de paquets capturés : {total}",
            f"Nombre d'éléments suspects : {len(self.findings)}",
            "",
            "Protocoles détectés :",
            self.sort_network_protocols() or "Aucun paquet capturé",
            "",
            f"Conclusion : {self.attack or 'Aucune analyse effectuée'}",
            ""
        ]
        return "\n".join(lines)

    def get_stats(self) -> dict:
        """
        Return stats
        """
        src_ips = Counter()
        dst_ips = Counter()
        src_ports = Counter()
        dst_ports = Counter()
        sizes = []

        for p in self.packets:
            sizes.append(len(p))

            if IP in p:
                if not self._is_me(p[IP].src):
                    src_ips[p[IP].src] += 1
                if not self._is_me(p[IP].dst):
                    dst_ips[p[IP].dst] += 1

            sport, dport = self._get_ports(p)

            if sport != "N/A":
                src_ports[sport] += 1
            if dport != "N/A":
                dst_ports[dport] += 1

        def top(counter):
            """
            Get top counter
            """
            return counter.most_common(1)[0][0] if counter else "N/A"

        total_bytes = sum(sizes)

        return {
            "total_packets": len(self.packets),
            "total_bytes": total_bytes,
            "avg_packet_size": round(total_bytes / len(sizes), 2) if sizes else 0,
            "top_src_ip": top(src_ips),
            "top_dst_ip": top(dst_ips),
            "top_src_port": top(src_ports),
            "top_dst_port": top(dst_ports),
        }