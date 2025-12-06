import requests
import time
import base64

class ThreatIntelligence:
    def __init__(self, vt_api_key: str):
        self.vt_api_key = vt_api_key
        self.taxii_base = "https://attack-taxii.mitre.org/api/v21"
        self.vt_base = "https://www.virustotal.com/api/v3"
        self.attack_data = []
        self.collection_id = None

    def get_collections(self):
        url = f"{self.taxii_base}/collections"
        headers = {'Accept': 'application/taxii+json;version=2.1'}
        response = requests.get(url, headers=headers)
        collections = response.json()['collections']
        return collections

    def load_attack_data(self, collection_id: str):
        self.collection_id = collection_id

        print("\nLoading MITRE ATT&CK data...")
        url = f"{self.taxii_base}/collections/{collection_id}/objects"
        headers = {'Accept': 'application/taxii+json;version=2.1'}

        response = requests.get(url, headers=headers, params={'limit': 2000})
        self.attack_data = response.json()['objects']

        malware_count = sum(1 for o in self.attack_data if o['type'] == 'malware')
        print(f"Loaded {len(self.attack_data)} objects ({malware_count} malware)\n")

    def get_malware_list(self):
        malware_list = [o for o in self.attack_data if o['type'] == 'malware']

        print(f"Found {len(malware_list)} malware:")
        for i, mal in enumerate(malware_list[:10]):
            ext = mal.get("external_references", [{}])[0]
            print(f"  {i}. [{ext.get('external_id', 'N/A')}] {mal['name']}")
        
        if len(malware_list) > 10:
            print(f"... and {len(malware_list) - 10} more.\n")

        return malware_list

    def get_malware(self, malware_id: str):
        for obj in self.attack_data:
            if obj["type"] != "malware":
                continue

            ext_refs = obj.get("external_references", [])
            if ext_refs and ext_refs[0].get("external_id") == malware_id:
                return obj
            if obj["id"] == malware_id:
                return obj

        return None

    def check_ioc(self, ioc: str, malware_name: str = None):
        headers = {"x-apikey": self.vt_api_key}

        if ioc.startswith("http://") or ioc.startswith("https://"):
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"{self.vt_base}/urls/{url_id}"
            ioc_type = "url"
        else:
            raise ValueError(f"Invalid IOC: {ioc}")

        print(f"\n[VT] Checking IOC: {ioc}")

        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            print("  VT API Error or no data returned.")
            return {
                "value": ioc,
                "type": ioc_type,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "status": "no_data"
            }

        data = response.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats")

        if not stats:
            print("  No analysis stats available.")
            return {
                "value": ioc,
                "type": ioc_type,
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "status": "no_stats"
            }

        print(f"  Malicious={stats.get('malicious',0)} "
            f"Suspicious={stats.get('suspicious',0)} "
            f"Harmless={stats.get('harmless',0)}")

        return {
            "value": ioc,
            "type": ioc_type,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "status": "ok"
        }

        print(f"  Malicious={stats['malicious']} Suspicious={stats['suspicious']} Harmless={stats['harmless']}")
        return result

    def analyze_iocs_for_malware(self, malware_obj, ioc_list):
        print(f"\n[IOC Analysis for {malware_obj['name']}]")
        results = []

        for i, ioc in enumerate(ioc_list):
            res = self.check_ioc(ioc, malware_obj["name"])
            results.append(res)

            if i < len(ioc_list) - 1:
                time.sleep(8) 


        print("\n===== IOC Summary =====")

        total_iocs = len(results)
        malicious_total = sum(r["malicious"] for r in results)
        suspicious_total = sum(r["suspicious"] for r in results)

        print(f"Total IOCs analyzed: {total_iocs}")
        print(f"Total Malicious detections: {malicious_total}")
        print(f"Total Suspicious detections: {suspicious_total}")
        print("=" * 60)


    def get_attack_patterns_used_by_malware(self, malware_obj):
        malware_id = malware_obj["id"]

        uses_rel = [
            r for r in self.attack_data
            if r["type"] == "relationship"
            and r.get("relationship_type") == "uses"
            and r.get("source_ref") == malware_id
        ]

        technique_ids = [rel["target_ref"] for rel in uses_rel]

        techniques = [
            t for t in self.attack_data
            if t["id"] in technique_ids and t["type"] == "attack-pattern"
        ]

        print(f"\n[Attack Techniques Used by {malware_obj['name']}]")
        for t in techniques:
            ext_id = self._get_external_id(t)
            print(f"- {t['name']} ({ext_id})")

        return techniques

    def _get_external_id(self, obj):
        for ref in obj.get("external_references", []):
            if "external_id" in ref:
                return ref["external_id"]
        return "Unknown"

    def print_attack_pattern_detail(self, attack_pattern):
        ext_id = self._get_external_id(attack_pattern)

        print("\n[Attack Pattern Detail]")
        print(f"Name: {attack_pattern['name']}")
        print(f"ID: {ext_id}")
        print(f"Description: {attack_pattern.get('description', 'N/A')}\n")

        phases = attack_pattern.get("kill_chain_phases", [])
        if phases:
            print("Kill Chain Phases:")
            for ph in phases:
                print(f"  - {ph['phase_name']}")
        else:
            print("Kill Chain Phases: N/A")

    ATTACK_TACTIC_ORDER = [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact",
    ]

    def sort_techniques_by_tactic(self, techniques):
        def get_tactic(t):
            phases = t.get("kill_chain_phases", [])
            for ph in phases:
                if ph["kill_chain_name"] == "mitre-attack":
                    return ph["phase_name"]
            return "unknown"

        sorted_list = sorted(
            techniques,
            key=lambda t: self.ATTACK_TACTIC_ORDER.index(get_tactic(t))
            if get_tactic(t) in self.ATTACK_TACTIC_ORDER else 999
        )

        print("\n[Techniques Sorted by ATT&CK Tactic Order]")
        for t in sorted_list:
            print(f"- {t['name']} ({self._get_external_id(t)}) [{get_tactic(t)}]")

        return sorted_list


def main():
    VT_API_KEY = ""

    cti = ThreatIntelligence(VT_API_KEY)

    collections = cti.get_collections()
    print("Found collections:")
    for i, col in enumerate(collections):
        print(f"{i}. {col['title']} ({col['id']})")
    idx = int(input("\nSelect collection index: "))
    cti.load_attack_data(collections[idx]["id"])

    malware_list = cti.get_malware_list()
    mal_idx = int(input("\nSelect malware index: "))
    malware_obj = malware_list[mal_idx]
    ext_id = malware_obj["external_references"][0]["external_id"]
    malware_obj = cti.get_malware(ext_id)

    print(f"\nSelected malware: {malware_obj['name']} ({ext_id})")

    iocs = [
        "https://www.google.com",
        "http://malware.wicar.org/data/eicar.com"
    ]
    cti.analyze_iocs_for_malware(malware_obj, iocs)

    techniques = cti.get_attack_patterns_used_by_malware(malware_obj)

    sorted_techniques = cti.sort_techniques_by_tactic(techniques)

    if sorted_techniques:
        cti.print_attack_pattern_detail(sorted_techniques[0])


if __name__ == "__main__":
    main()
