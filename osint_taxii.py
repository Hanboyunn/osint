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
        return response.json()['collections']
        
    def load_attack_data(self, collection_id: str):
        print("Loading MITRE ATT&CK data...")
        self.collection_id = collection_id
        url = f"{self.taxii_base}/collections/{collection_id}/objects"
        headers = {'Accept': 'application/taxii+json;version=2.1'}

        time.sleep(5)

        response = requests.get(url, headers=headers, params={'limit': 1000})
        self.attack_data = response.json()['objects']
        malware_count = sum(1 for o in self.attack_data if o['type'] == 'malware')
        print(f"Loaded {len(self.attack_data)} objects ({malware_count} malware)\n")
    
    def get_malware_list(self):
        malware_list = [o for o in self.attack_data if o['type'] == 'malware']
        
        print(f"Found {len(malware_list)} malware:")
        for i, mal in enumerate(malware_list[:10]):
            mal_id = mal['external_references'][0]['external_id']
            print(f"  {i}. [{mal_id}] {mal['name']}")

        if len(malware_list) > 10:
            print(f"  ... and {len(malware_list) - 10} more\n")

        return malware_list
    
    def get_malware(self, malware_id: str):
        for data in self.attack_data:
            if data['type'] == 'malware':
                ext_refs = data['external_references']
                if ext_refs and ext_refs[0]['external_id'] == malware_id:
                    return data
                if data['id'] == malware_id:
                    return data
        return None
    
    def check_ioc(self, ioc: str, malware_name: str = None):
        """IOC를 VirusTotal에서 검사 (IP/URL/Domain 자동 감지)"""
        headers = {"x-apikey": self.vt_api_key}
        
        if ioc.startswith('http://') or ioc.startswith('https://'):
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"{self.vt_base}/urls/{url_id}"
            ioc_type = 'url'
        else: raise ValueError(f"Invalid IOC: {ioc}")
        
        context = f" (related to {malware_name})" if malware_name else ""
        print(f"\n[VT] Checking {ioc_type.upper()}: {ioc}{context}")
        
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            detections = []
            if 'last_analysis_results' in data['data']['attributes']:
                for engine, result in data['data']['attributes']['last_analysis_results'].items():
                    if result.get('result'):
                        detections.append(result['result'].lower())
            
            malware_detected = False
            if malware_name:
                malware_lower = malware_name.lower()
                malware_detected = any(malware_lower in det.lower() for det in detections)
            
            result = {
                'type': ioc_type,
                'value': ioc,
                'malicious': stats['malicious'],
                'suspicious': stats['suspicious'],
                'harmless': stats['harmless'],
                'malware_name': malware_name,
                'malware_detected': malware_detected
            }
            
            status = f"  Malicious: {result['malicious']}, Suspicious: {result['suspicious']}, Harmless: {result['harmless']}"
            if malware_detected:
                status += f" [{malware_name} detected!]"
            print(status)
            return result
            
        return None
    
    def analyze(self, malware_id: str, iocs: list):
        malware = self.get_malware(malware_id)
        if not malware:
            print(f"Malware {malware_id} not found")
            return
        
        mal_id = malware['external_references'][0]['external_id']
        malware_name = malware['name']
        print(f"\n[Malware] {malware_name} ({mal_id})")
        
        print(f"\n[IOC Analysis] Analyzing {len(iocs)} IOCs related to {malware_name}...")
        results = []
        
        for i, ioc in enumerate(iocs):
            result = self.check_ioc(ioc, malware_name)
            if result:
                results.append(result)
            
            if i < len(iocs) - 1:
                time.sleep(10)
        
        print('=' * 60)
        print("Summary")
        print('=' * 60)
        print(f"Malware: {malware_name} ({mal_id})")
        print(f"Related IOCs analyzed: {len(results)}")
        
        total_malicious = sum(r['malicious'] for r in results if r)
        total_suspicious = sum(r['suspicious'] for r in results if r)
        malware_detected_count = sum(1 for r in results if r and r.get('malware_detected'))
        
        print(f"Total malicious: {total_malicious}, suspicious: {total_suspicious}")
        if malware_detected_count > 0:
            print(f"IOCs with {malware_name} detection: {malware_detected_count}")
        
        if total_malicious > 10 or malware_detected_count > 0:
            print("Threat Level: CRITICAL")
        elif total_malicious > 5:
            print("Threat Level: MEDIUM")
        else:
            print("Threat Level: LOW")
        
        print('=' * 60)


def main():
    VT_API_KEY = ' '
    
    cti = ThreatIntelligence(VT_API_KEY)

    collections = cti.get_collections()
    print(f'Found {len(collections)} collections...')
    print('Selected collection:')
    for idx, collection in enumerate(collections):
        print(f'{idx}. {collection['title']}: {collection['id']}')
    col_idx = int(input('> '))
    cti.load_attack_data(collections[col_idx]['id'])

    malware_list = cti.get_malware_list()
    
    if not malware_list:
        print("\nThis collection has no malware entries. Try Enterprise ATT&CK (index 0).")
        return
    
    first_malware = malware_list[0]
    mal_id = first_malware['external_references'][0]['external_id']
    print(mal_id)
    print(f"Analyzing: {first_malware['name']}\n")
    
    iocs = [
        "https://www.google.com", 
        "http://malware.wicar.org/data/eicar.com",
    ]
    
    cti.analyze(mal_id, iocs)


if __name__ == "__main__":
    main()
