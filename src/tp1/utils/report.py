# src/tp1/utils/report.py

from tp1.utils.capture import Capture
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.graphics import renderPDF
from svglib.svglib import svg2rlg
import pygal
import os


class Report:
    def __init__(self, capture: Capture, filename: str, summary: str):
        self.capture = capture
        self.filename = filename
        self.title = "Rapport TP1 - Analyse réseau"
        self.summary = summary
        self.array = ""
        self.graph = ""
        self.graph_file = "protocoles.svg"

    def concat_report(self) -> str:
        """
        Concat all data in report
        """
        return self.title + "\n\n" + self.summary + "\n" + self.array + "\n" + self.graph

    def generate(self, param: str) -> None:
        """
        Generate graph and array
        """
        data = self.capture.get_all_protocols()

        if param == "graph":
            chart = pygal.Bar()
            chart.title = "Protocoles capturés"

            for proto, count in data.items():
                chart.add(proto, count)

            chart.render_to_file(self.graph_file)
            self.graph = f"Graphe Pygal inclus dans le PDF : {self.graph_file}"

        elif param == "array":
            lines = ["Tableau des protocoles :", "Protocole | Nombre"]
            for proto, count in data.items():
                lines.append(f"{proto} | {count}")
            self.array = "\n".join(lines)

    def save(self, filename: str = None) -> None:
        """
        Save report in a PDF file
        """
        pdf_file = filename or self.filename

        c = canvas.Canvas(pdf_file, pagesize=A4)
        width, height = A4
        y = height - 50

        def new_page():
            """
            Create new page
            """
            nonlocal y
            c.showPage()
            y = height - 50

        def write_line(text="", size=10):
            """
            Write line
            """
            nonlocal y
            if y < 60:
                new_page()

            c.setFont("Helvetica", size)
            c.drawString(40, y, str(text)[:120])
            y -= 15

        def write_block(text="", size=10):
            """
            Write block
            """
            for line in str(text).split("\n"):
                write_line(line, size)

        write_line(self.title, 16)
        write_line("=" * 80)
        write_line()

        write_block(self.summary)

        write_line()
        write_line("Statistiques générales", 13)
        write_line("-" * 80)

        stats = self.capture.get_stats()
        write_line(f"Nombre total de paquets : {stats['total_packets']}")
        write_line(f"Taille totale : {stats['total_bytes']} octets")
        write_line(f"Taille moyenne : {stats['avg_packet_size']} octets")
        write_line(f"IP source la plus fréquente : {stats['top_src_ip']}")
        write_line(f"IP destination la plus fréquente : {stats['top_dst_ip']}")
        write_line(f"Port source le plus fréquent : {stats['top_src_port']}")
        write_line(f"Port destination le plus fréquent : {stats['top_dst_port']}")


        write_line()
        write_line("Graphe des protocoles", 13)
        write_line("-" * 80)

        if os.path.exists(self.graph_file):
            try:
                drawing = svg2rlg(self.graph_file)

                max_width = width - 80
                max_height = 250

                scale_x = max_width / drawing.width
                scale_y = max_height / drawing.height
                scale = min(scale_x, scale_y)

                drawing.width *= scale
                drawing.height *= scale
                drawing.scale(scale, scale)

                if y - drawing.height < 60:
                    new_page()

                renderPDF.draw(drawing, c, 40, y - drawing.height)
                y -= drawing.height + 25

            except Exception as e:
                write_line(f"Impossible d'inclure le SVG dans le PDF : {e}")
                write_line(self.graph)
        else:
            write_line("Aucun graphe SVG généré")

        write_line()
        write_line("Éléments problématiques détectés", 13)
        write_line("-" * 80)

        findings = self.capture.get_findings()

        if not findings:
            write_line("Aucun contenu problématique détecté.")
        else:
            for index, finding in enumerate(findings, 1):
                write_line(f"Détection #{index}", 11)
                write_line(f"Type : {finding.get('type')}")
                write_line(f"Source : {finding.get('source')}")
                write_line(f"Destination : {finding.get('destination')}")
                write_line(f"Protocole : {finding.get('protocol')}")
                write_line(f"Port source : {finding.get('sport', 'N/A')}")
                write_line(f"Port destination : {finding.get('dport', 'N/A')}")
                write_line(f"MAC source : {finding.get('mac', 'N/A')}")
                write_line(f"Signature matchée : {finding.get('signature')}")
                write_line("Payload / contenu suspect :")

                payload = finding.get("payload", "")
                chunks = [payload[i:i + 110] for i in range(0, len(payload), 110)]

                for chunk in chunks:
                    write_line(chunk)

                write_line("-" * 80)

        write_line()
        write_line("Conclusion", 13)
        write_line("-" * 80)
        write_line(self.capture.attack or "Aucune attaque détectée")

        c.save()