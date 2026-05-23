import xml.etree.ElementTree as ET
import csv


dateiname_xml = "security_report.xml"
dateiname_csv = "cves_gesamt_report.csv"

try:
    tree = ET.parse(dateiname_xml)
    root = tree.getroot()

    with open(dateiname_csv, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)

    
        writer.writerow(["=== XML-Strukturanalyse ==="])
        writer.writerow(["XML geladen"])
        writer.writerow([f"Root-Element: <{root.tag}>"])
        writer.writerow([""])

        for kind in root:
            writer.writerow([f"<{kind.tag}>"])
            for subkind in kind:
                writer.writerow([f"  <{subkind.tag}>"])

        writer.writerow(["=== Extrahierte CVEs ==="])
        writer.writerow([""])

        writer.writerow(["id", "name", "schweregrad", "cvss_score"])

        schwachstellen = root.find("schwachstellen")
        if schwachstellen is None:
            writer.writerow(["Kein <schwachstellen> Element gefunden"])
            exit(1)

        for vuln in schwachstellen.findall("schwachstelle"):
            cve_id = vuln.get("id")
            schweregrad = vuln.get("schweregrad")
            cvss_score = vuln.get("cvss_score")

            name_elem = vuln.find("name")
            name = name_elem.text if name_elem is not None else "-"

            if not cve_id or not name:
                writer.writerow(["Ungültige CVE -> übersprungen"])
                continue

            writer.writerow([cve_id, name, schweregrad if schweregrad else "-", cvss_score if cvss_score else "-"])



except Exception as e:
    print(f"Fehler: {e}")
    exit(1)

print("\nAbgeschlossen")