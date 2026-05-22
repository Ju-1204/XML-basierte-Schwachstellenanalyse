import xml.etree.ElementTree as ET

dateiname = "security_report.xml"


try:
    tree = ET.parse(dateiname)
    root = tree.getroot()

    print(f"XML geladen")
    print(f"Root-Element: <{root.tag}>\n")
    
    print("Struktur:")
    for kind in root:
        print(f"<{kind.tag}>")
        
        for subkind in kind:
            print(f"<{subkind.tag}>")

except FileNotFoundError:
        print(f"Fehler: Datei '{dateiname}' nicht gefunden.")

except ET.ParseError as e:
        print(f"XML-Parse-Fehler: {e}")

except Exception as e:
         print(f"Fehler: {e}")   

print("\n XML-Datei analyse beendet")