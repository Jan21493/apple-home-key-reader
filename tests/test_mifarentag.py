from get_version_detection import MifareNtagType
 
# --- Test-Szenarien ---

# 1. Ein DESFire EV1 (Storage 0x18 für 4k)
# Antwort-Schema: [Vendor, Type, Subtype, Major, Minor, Storage, Protocol]
resp_desfire = [0x04, 0x01, 0x01, 0x01, 0x00, 0x18, 0x05]
res1 = MifareNtagType.identify(resp_desfire)
print(f"Ergebnis 1: {res1.value.description if res1 else 'Unbekannt'}") 
# Output: MIFARE DESFire EV1 (beliebige Größe)

# 2. Ein NTAG 216 (Storage 0x13)
resp_ntag = [0x04, 0x04, 0x02, 0x01, 0x00, 0x13, 0x03] 
# (Hinweis: Index 6 im echten NTAG GetVersion-Frame ist 0x13)
res2 = MifareNtagType.identify(resp_ntag)
print(f"Ergebnis 2: {res2.value.description if res2 else 'Unbekannt'}")
# Output: NTAG 216

# --- Verwendung ---

# Auch wenn wir später "NTAG_215" zwischen 2 und 3 einfügen, 
# bleibt NTAG_213 über die ID 2 erreichbar.
mein_chip = MifareNtagType.get_by_id(2)
if mein_chip:
    print(f"Chip mit ID 2 gefunden: {mein_chip.value.description}")