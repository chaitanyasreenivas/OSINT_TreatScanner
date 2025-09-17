import socket, requests, re, dns.resolver, whois, hashlib, config, time, ssl, google.generativeai as genai, json, yaml
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

class BaseScanner:
    def __init__(self, target): self.target = target
    def scan(self): raise NotImplementedError("Each scanner must implement its own scan method.")

class DnsScanner(BaseScanner):
    def scan(self):
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records[record_type] = [answer.to_text() for answer in answers]
            except Exception: records[record_type] = []
        return records

class WhoisScanner(BaseScanner):
    def scan(self):
        try:
            domain_info = whois.whois(self.target)
            processed_info = {}
            for key, value in domain_info.items():
                if value:
                    if isinstance(value, list) and all(isinstance(item, datetime) for item in value):
                        processed_info[key] = [item.strftime('%Y-%m-%d %H:%M:%S') for item in value]
                    elif isinstance(value, datetime):
                        processed_info[key] = value.strftime('%Y-%m-%d %H:%M:%S')
                    else: processed_info[key] = value
            return processed_info
        except Exception as e: return {"Error": f"Could not fetch WHOIS info: {e}"}

class IpGeolocationScanner(BaseScanner):
    def scan(self):
        try:
            response = requests.get(f"http://ip-api.com/json/{self.target}", timeout=15)
            response.raise_for_status()
            return response.json() if response.json().get('status') == 'success' else {"error": "Failed to retrieve geolocation data."}
        except requests.exceptions.RequestException as e: return {"error": f"API request failed: {e}"}

class ReverseDnsScanner(BaseScanner):
    def scan(self):
        try:
            hostname = socket.gethostbyaddr(self.target)
            return {"hostname": hostname[0]}
        except socket.herror as e: return {"error": f"Could not resolve hostname: {e}"}
            
class GravatarScanner(BaseScanner):
    def scan(self):
        normalized_email = self.target.strip().lower()
        email_hash = hashlib.md5(normalized_email.encode('utf-8')).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
        try:
            response = requests.get(gravatar_url, timeout=15)
            if response.status_code == 200: return {"status": "Found", "message": "A public Gravatar profile was found."}
            else: return {"status": "Not Found", "message": "No public Gravatar profile exists for this email."}
        except requests.exceptions.RequestException as e: return {"status": "Error", "message": f"Request failed: {e}"}

class VirusTotalScanner(BaseScanner):
    def __init__(self, target, target_type):
        super().__init__(target)
        self.target_type = target_type
        self.api_key = config.VT_API_KEY
    def scan(self):
        if not self.api_key or "PASTE" in self.api_key: return {"error": "VirusTotal API key is not set."}
        url = f"https://www.virustotal.com/api/v3/{self.target_type}s/{self.target}"
        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status() 
            data = response.json().get('data', {}).get('attributes', {})
            stats = data.get('last_analysis_stats', {})
            return {"Malicious": stats.get('malicious', 0), "Suspicious": stats.get('suspicious', 0), "Harmless": stats.get('harmless', 0), "Undetected": stats.get('undetected', 0)}
        except requests.exceptions.HTTPError as e:
            return {"error": f"API Error: {e.response.json().get('error', {}).get('message')}"}
        except requests.exceptions.RequestException as e: return {"error": f"Network Error: {e}"}

class ShodanScanner(BaseScanner):
    def __init__(self, target):
        super().__init__(target)
        self.api_key = config.SHODAN_API_KEY
    def scan(self):
        if not self.api_key or "PASTE" in self.api_key: return {"error": "Shodan API key is not set."}
        try:
            url = f"https://api.shodan.io/shodan/host/{self.target}?key={self.api_key}"
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            data = response.json()
            return {"Organization": data.get('org', 'N/A'), "OS": data.get('os', 'N/A'), "Ports": data.get('ports', [])}
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404: return {"status": "Not Found"}
            return {"error": f"API request failed: {e}"}
        except requests.exceptions.RequestException as e: return {"error": f"Request failed: {e}"}

class UrlScanScanner(BaseScanner):
    def scan(self):
        api_key = config.URLSCAN_API_KEY
        if not api_key or "PASTE" in api_key: return {"error": "urlscan.io API key is not set."}
        headers = {'API-Key': api_key, 'Content-Type': 'application/json'}
        data = {"url": self.target, "visibility": "public"}
        try:
            submit_response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, json=data, timeout=15)
            submit_response.raise_for_status()
            scan_uuid = submit_response.json()['uuid']
            
            result_url = f"https://urlscan.io/api/v1/result/{scan_uuid}/"
            for _ in range(10):  # Poll up to 10 times
                time.sleep(5) # Wait 5 seconds between polls
                result_response = requests.get(result_url, timeout=20)
                if result_response.status_code == 200:
                    result_data = result_response.json()
                    page = result_data.get('page', {})
                    return {"verdict": "Malicious" if result_data.get('verdicts', {}).get('overall', {}).get('malicious') else "Clean", "ip": page.get('ip'), "country": page.get('country')}
            return {"error": "Scan timed out and the result was not ready."}
        except requests.exceptions.RequestException as e: return {"error": f"API request failed: {e}"}

class OTXScanner(BaseScanner):
    def __init__(self, target, target_type):
        super().__init__(target)
        self.target_type = target_type.replace('ip', 'IPv4')
        self.api_key = config.OTX_API_KEY
    def scan(self):
        if not self.api_key or "PASTE" in self.api_key: return {"error": "OTX API key is not set."}
        url = f"https://otx.alienvault.com/api/v1/indicators/{self.target_type}/{self.target}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        try:
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 404: return {"pulse_count": 0, "pulse_names": []}
            response.raise_for_status()
            pulses = response.json().get('pulse_info', {}).get('pulses', [])
            return {"pulse_count": len(pulses), "pulse_names": [p.get('name') for p in pulses][:5]}
        except requests.exceptions.RequestException as e: return {"error": f"API request failed: {e}"}

class CertificateScanner(BaseScanner):
    def scan(self):
        context = ssl.create_default_context()
        try:
            with socket.create_connection((self.target, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
            return {"subject": dict(x[0] for x in cert.get('subject', [])), "issuer": dict(x[0] for x in cert.get('issuer', [])), "valid_from": cert.get('notBefore'), "valid_until": cert.get('notAfter'), "subject_alt_names": [name[1] for name in cert.get('subjectAltName', [])]}
        except Exception: return {"error": "Could not retrieve SSL certificate."}

class TimelineGenerator:
    def __init__(self, all_scan_results):
        self.results = all_scan_results
    def generate_timeline(self):
        events = []
        report_data = self.results.get('domain_scan', self.results)
        whois_info = report_data.get('whois_info', {})
        if whois_info and not whois_info.get('Error'):
            if whois_info.get('creation_date'):
                date = self._parse_date(whois_info['creation_date'])
                if date: events.append({'date': date, 'event': 'Domain Creation', 'source': 'WHOIS'})
            if whois_info.get('updated_date'):
                date = self._parse_date(whois_info['updated_date'])
                if date: events.append({'date': date, 'event': 'Domain Last Updated', 'source': 'WHOIS'})
        cert_info = report_data.get('certificate', {})
        if cert_info and not cert_info.get('error'):
            if cert_info.get('valid_from'):
                date = self._parse_date(cert_info['valid_from'])
                if date: events.append({'date': date, 'event': 'SSL Certificate Issued', 'source': 'SSL'})
        events.sort(key=lambda x: x['date'], reverse=True)
        return events
    def _parse_date(self, date_input):
        if isinstance(date_input, list): date_input = date_input[0]
        if isinstance(date_input, datetime): return date_input.strftime('%Y-%m-%d')
        try:
            if isinstance(date_input, str) and '+' in date_input:
                return datetime.fromisoformat(date_input).strftime('%Y-%m-%d')
            return datetime.strptime(str(date_input), '%Y-%m-%d %H:%M:%S').strftime('%Y-%m-%d')
        except (ValueError, TypeError): return str(date_input)

class SigmaRuleGenerator:
    def __init__(self, all_scan_results, target, target_type):
        self.results = all_scan_results
        self.target = target
        self.target_type = target_type
    def generate_rules(self):
        rules = []
        report_data = self.results.get('domain_scan', self.results)
        if self.target_type == "domain" or 'domain_scan' in self.results:
            ips = report_data.get('dns_records', {}).get('A', [])
            if ips:
                ip_list_str = '\n'.join([f"    - '{ip.strip('.')}'" for ip in ips])
                rule_yaml = f"""title: Network Connection to {self.target} Associated IP
id: {hashlib.md5(self.target.encode()).hexdigest()}
description: Detects network connections to IP addresses resolved from the domain {self.target}.
author: TreatScan
date: {datetime.now().strftime('%Y/%m/%d')}
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
{ip_list_str}
    condition: selection
level: medium"""
                rules.append(rule_yaml)
        return rules

class IntelligenceAnalyzer:
    def __init__(self, all_scan_results):
        self.results = all_scan_results
        self.api_key = config.GOOGLE_API_KEY
    def analyze(self):
        return { "mitre_attack": self._map_mitre_with_ai(), "threat_types": self._classify_threats() }
    def _classify_threats(self):
        threats_found = set()
        report_data = self.results.get('domain_scan', self.results)
        if 'otx' in report_data and not report_data['otx'].get('error'):
            threat_keywords = {"phishing": "Phishing", "ransomware": "Ransomware", "botnet": "Botnet", "malware": "Malware", "c2": "C2 Server", "icedid": "IcedID Malware", "cobalt strike": "Cobalt Strike"}
            for name in report_data['otx'].get('pulse_names', []):
                for keyword, threat_type in threat_keywords.items():
                    if keyword in name.lower(): threats_found.add(threat_type)
        return list(threats_found)
    def _map_mitre_with_ai(self):
        if not self.api_key or "PASTE" in self.api_key: return {"error": "Google API key not set."}
        report_data = self.results.get('domain_scan', self.results)
        if report_data.get('virustotal', {}).get('Malicious', 0) == 0 and not report_data.get('otx', {}).get('pulse_names'):
            return {"info": "Target appears clean. No adversary techniques mapped."}
        try:
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel('gemini-1.5-flash-latest', generation_config={"response_mime_type": "application/json"})
            prompt = f"As a cybersecurity threat analyst specializing in MITRE ATT&CK, analyze the OSINT data. Identify the top 3-5 probable ATT&CK techniques an adversary might use. For each, provide its ID, name, tactic, and a brief, one-sentence justification. Return ONLY a valid JSON array of objects. Example: [ {{\"id\": \"T1566\", \"name\": \"Phishing\", \"tactic\": \"Initial Access\", \"justification\": \"OTX pulses indicate phishing activity.\"}} ]\n\nOSINT Data: {json.dumps(report_data)}"
            response = model.generate_content(prompt)
            return json.loads(response.text)
        except Exception as e:
            if "429" in str(e) and "quota" in str(e): return {"error": "AI mapping failed: Daily free quota exceeded."}
            return {"error": f"AI mapping failed: {e}"}

class AIRecommender:
    def __init__(self, threat_types):
        self.threat_types = threat_types
        self.api_key = config.GOOGLE_API_KEY
    def get_recommendations(self):
        if not self.api_key or "PASTE" in self.api_key: return "AI recommendations not available: Google API key is not set."
        if not self.threat_types: return "No specific threats were identified. Standard security best practices should be followed."
        try:
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel('gemini-1.5-flash-latest')
            prompt = f"As a cybersecurity advisor, for the threat types: {', '.join(self.threat_types)}, provide 2-3 concise, actionable security recommendations for an analyst. Use markdown bullet points."
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            if "429" in str(e) and "quota" in str(e): return "AI recommendations failed: Daily free quota for the API has been exceeded."
            return f"AI recommendations could not be generated: {e}"

class LLMSummarizer:
    def __init__(self, all_scan_results, target, target_type):
        self.results = all_scan_results; self.target = target; self.target_type = target_type
        self.api_key = config.GOOGLE_API_KEY
    def summarize(self):
        if not self.api_key or "PASTE" in self.api_key: return "AI summary not available: Google API key is not set."
        data_string = str(self.results)
        try:
            genai.configure(api_key=self.api_key)
            model = genai.GenerativeModel('gemini-1.5-flash-latest')
            prompt = f"As a senior cybersecurity analyst, review OSINT data for '{self.target}' ({self.target_type}). Provide a concise, 2-3 sentence executive summary, focusing on critical findings. Interpret the data. If no major risks found, state it appears clean. Data: {data_string} Executive Summary:"
            response = model.generate_content(prompt)
            return response.text
        except Exception as e:
            if "429" in str(e) and "quota" in str(e): return "AI summary failed: Daily free quota for the API has been exceeded."
            return f"AI summary could not be generated: {e}"

class Orchestrator:
    def __init__(self, target):
        self.target = target.strip()
        self.target_type = self._detect_target_type()
    def _detect_target_type(self):
        target = self.target.lower()
        if re.match(r"^[a-f0-9]{64}$", target) or re.match(r"^[a-f0-9]{40}$", target) or re.match(r"^[a-f0-9]{32}$", target): return "hash"
        if re.match(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}$", self.target): return "domain"
        if re.match(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", self.target): return "ip"
        if re.match(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)", self.target): return "email"
        return "unknown" # Fallback
        
    def _run_scans_concurrently(self, scanners):
        results = {}
        with ThreadPoolExecutor(max_workers=len(scanners)) as executor:
            future_to_scanner = {executor.submit(scanner.scan): name for name, scanner in scanners.items()}
            for future in future_to_scanner:
                scanner_name = future_to_scanner[future]
                try:
                    results[scanner_name] = future.result()
                except Exception as exc:
                    print(f'{scanner_name} generated an exception: {exc}')
                    results[scanner_name] = {'error': 'An unexpected error occurred.'}
        return results

    def _scan_domain(self):
        scanners = {
            'dns_records': DnsScanner(self.target), 'whois_info': WhoisScanner(self.target),
            'virustotal': VirusTotalScanner(self.target, 'domain'), 'urlscan': UrlScanScanner(self.target),
            'otx': OTXScanner(self.target, 'domain'), 'certificate': CertificateScanner(self.target)
        }
        return self._run_scans_concurrently(scanners)

    def _scan_ip(self):
        scanners = {
            'geolocation': IpGeolocationScanner(self.target), 'reverse_dns': ReverseDnsScanner(self.target),
            'virustotal': VirusTotalScanner(self.target, 'ip'), 'shodan': ShodanScanner(self.target),
            'otx': OTXScanner(self.target, 'ip')
        }
        return self._run_scans_concurrently(scanners)
        
    def _get_reverse_resolutions(self, ip_address):
        api_key = config.VT_API_KEY
        if not api_key or "PASTE" in api_key: return []
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/resolutions"
        headers = {"x-apikey": api_key}
        try:
            response = requests.get(url, headers=headers, timeout=15)
            response.raise_for_status()
            data = response.json().get('data', [])
            return [item['attributes']['host_name'] for item in data[:5]] # Limit to 5 for cleaner graph
        except requests.exceptions.RequestException: return []

    def run_scans(self):
        results = {}
        if self.target_type == "domain": results = self._scan_domain()
        elif self.target_type == "ip": results = self._scan_ip()
        elif self.target_type == "email":
            results['gravatar'] = GravatarScanner(self.target).scan()
            try:
                email_domain = self.target.split('@')[1]
                domain_orchestrator = Orchestrator(email_domain)
                results['domain_scan'] = domain_orchestrator._scan_domain()
            except IndexError: results['domain_scan'] = {"error": "Invalid email format."}
        elif self.target_type == "hash":
            results['error'] = "File hash scanning is not implemented in this version."
        else: results['error'] = "Unknown or invalid target type."
        
        if 'error' not in results:
            analyzer = IntelligenceAnalyzer(results)
            analysis_results = analyzer.analyze()
            results.update(analysis_results)

            timeline_generator = TimelineGenerator(results)
            results['timeline'] = timeline_generator.generate_timeline()
            
            sigma_generator = SigmaRuleGenerator(results, self.target, self.target_type)
            results['sigma_rules'] = sigma_generator.generate_rules()
            
            recommender = AIRecommender(results.get('threat_types', []))
            results['ai_recommendations'] = recommender.get_recommendations()
            
            summarizer = LLMSummarizer(results, self.target, self.target_type)
            results['ai_summary'] = summarizer.summarize()
            
            # Generate data for the interactive network graph
            graph_data = {'nodes': [], 'edges': []}
            added_nodes = set()
            def add_node(node_id, label, group):
                if node_id not in added_nodes:
                    graph_data['nodes'].append({'id': node_id, 'label': label, 'group': group})
                    added_nodes.add(node_id)
            def add_edge(from_node, to_node):
                graph_data['edges'].append({'from': from_node, 'to': to_node})
            
            add_node(self.target, self.target, self.target_type)
            resolved_ips = results.get('dns_records', {}).get('A', [])
            for ip in resolved_ips:
                add_node(ip, ip, 'ip')
                add_edge(self.target, ip)
                co_hosted_domains = self._get_reverse_resolutions(ip)
                for domain in co_hosted_domains:
                    if domain != self.target:
                        add_node(domain, domain, 'co-hosted')
                        add_edge(ip, domain)
            
            if graph_data['nodes']: results['graph_data'] = graph_data
            
        return results