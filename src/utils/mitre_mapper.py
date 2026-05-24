MITRE_MAP = {

    "powershell": {
        "technique": "T1059",
        "name": "PowerShell"
    },

    "injection": {
        "technique": "T1055",
        "name": "Process Injection"
    },

    "ransomware": {
        "technique": "T1486",
        "name": "Data Encrypted for Impact"
    },

    "smb": {
        "technique": "T1021",
        "name": "Remote Services"
    }
}


def map_mitre(items):

    mitre_items = []

    for item in items:

        value = str(
            item.get("value", "")
        ).lower()

        for keyword, mapping in MITRE_MAP.items():

            if keyword in value:

                mitre_items.append({

                    "artifact_id":
                        f"mitre_{mapping['technique']}",

                    "evidence_type":
                        "mitre_mapping",

                    "value":
                        mapping,

                    "severity":
                        "medium",

                    "confidence":
                        0.8
                })

    return mitre_items
