import xml.etree.ElementTree as ET
import csv

dateiname_xml = "security_report.xml"
dateiname_csv = "cves_report.csv"

print(f"Lese: {dateiname_xml}")
print(f"Schreibe: {dateiname_csv}\n")


try:
    tree = ET.parse(dateiname_xml)
    root = tree.getroot()
    
    cves = []
    schwachstellen = root.find("schwachstellen")
    
    if schwachstellen is None:
        print("Kein <schwachstellen> Element gefunden - Abbruch")
        exit(1)

    print("CVEs gefunden:")
    print("-" * 80)
    
    for vuln in schwachstellen.findall("schwachstelle"):
        cve_id = vuln.get("id")
        schweregrad = vuln.get("schweregrad")
        cvss_score = vuln.get("cvss_score")
        
        name_elem = vuln.find("name")
        name = name_elem.text if name_elem is not None else "-"
 
        if not cve_id or not name:
            print(f"Ungültige CVE -> übersprungen")
            continue
        
        cves.append({
            "id": cve_id,
            "name": name,
            "schweregrad": schweregrad if schweregrad else "-",
            "cvss_score": cvss_score if cvss_score else "-"
        })
    print(f"{len(cves)} CVEs gelesen\n")
    
    with open(dateiname_csv, "w", newline="", encoding="utf-8") as csvfile:
        fieldnames = ["id", "name", "schweregrad", "cvss_score"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        
        writer.writerows(cves)
    
    print(f"In CSV geschrieben!")

    print(f"\nVerifikation - Inhalt von {dateiname_csv}:")
    print("-" * 100)
    
    with open(dateiname_csv, "r", encoding="utf-8") as f:
        for zeile in f:
            print(zeile.rstrip())
    
    print("-" * 100)

except Exception as e:
    print(f"Fehler: {e}")
    exit(1)

print("\nAbgeschlossen")