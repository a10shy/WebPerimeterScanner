"""
Modified Security Assessment Runner for Flask Integration
"""

import os
import json
import threading
import time
import datetime
import subprocess
import requests
import dns.resolver
import socket
import ssl
import whois
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import logging

# Timeout settings
TIMEOUT = 15  # Increased timeout for subdomain enumeration
MAX_WORKERS = 5

class SecurityAssessmentRunner:
    def __init__(self, domain, assessment_id, update_callback):
        self.domain = domain
        self.assessment_id = assessment_id
        self.update_callback = update_callback
        self.logger = logging.getLogger(__name__)
        
        # Create results directory
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        self.results_dir = os.path.join('results', f"{domain}_{timestamp}")
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Initialize data structures
        self.subdomains = set()
        self.ips = set()
        self.vulnerabilities = []
        self.misconfigurations = []
        self.exposed_data = []
        self.scores = {}
        
    def run_assessment(self):
        """Run the complete 18-phase security assessment"""
        phases = [
            ('Subdomain Enumeration', self.enumerate_subdomains),
            ('Amass Discovery', self.run_amass),
            ('IP Identification', self.identify_ip_addresses),
            ('DNS Security', self.check_dns_security),
            ('Email Security', self.check_email_security),
            ('Network Security', self.check_network_security),
            ('Vulnerability Scan', self.scan_vulnerabilities),
            ('Nuclei Scan', self.run_nuclei_scan),
            ('Data Exposure', self.check_data_exposure),
            ('Misconfiguration Detection', self.detect_misconfigurations),
            ('Email Compromises', self.detect_email_compromises),
            ('Credential Leaks', self.check_credential_leaks),
            ('Reputation Check', self.check_reputation),
            ('Web Technologies', self.detect_web_technologies),
            ('CVE Gathering', self.gather_cve_info),
            ('Shodan Scan', self.run_shodan_scan),
            ('Trufflehog Scan', self.run_trufflehog_scan),
            ('Risk Assessment', self.assess_risks)
        ]
        
        for i, (phase_name, phase_func) in enumerate(phases, 1):
            try:
                self.logger.info(f"Starting phase {i}/18: {phase_name}")
                self.update_callback(self.assessment_id, phase_name, 'running', 0)
                
                # Run the phase
                results = phase_func()
                
                # Save phase results
                self.save_phase_results(phase_name, results)
                
                # Update progress
                progress = int((i / len(phases)) * 100)
                findings = self.format_findings(results)
                self.update_callback(self.assessment_id, phase_name, 'completed', 100, findings)
                
                self.logger.info(f"Completed phase {i}/18: {phase_name}")
                
            except Exception as e:
                self.logger.error(f"Error in phase {phase_name}: {str(e)}")
                self.update_callback(self.assessment_id, phase_name, 'error', 0, [f"Error: {str(e)}"])
        
        # Generate final summary
        self.generate_summary()
        
        return self.results_dir
    
    def enumerate_subdomains(self):
        """Phase 1: Enumerate subdomains with timeout protection"""
        results = {
            'subdomains': [],
            'method': 'dns_enumeration',
            'timeout_used': TIMEOUT
        }
        
        # Common subdomain prefixes
        subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'app', 'dev', 'test', 'staging',
            'blog', 'shop', 'store', 'secure', 'vpn', 'remote', 'portal', 'login',
            'dashboard', 'panel', 'cpanel', 'webmail', 'email', 'smtp', 'pop',
            'imap', 'ns1', 'ns2', 'dns', 'mx', 'cdn', 'static', 'assets', 'img',
            'images', 'js', 'css', 'media', 'files', 'download', 'upload', 'cloud',
            'git', 'svn', 'jenkins', 'ci', 'build', 'deploy', 'status', 'monitor'
        ]
        
        def check_subdomain(subdomain):
            """Check if subdomain exists with timeout"""
            full_domain = f"{subdomain}.{self.domain}"
            try:
                # Use socket with timeout for faster resolution
                socket.setdefaulttimeout(TIMEOUT)
                socket.gethostbyname(full_domain)
                return full_domain
            except (socket.gaierror, socket.timeout):
                return None
            finally:
                socket.setdefaulttimeout(None)
        
        # Use ThreadPoolExecutor for concurrent subdomain checking
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_subdomain = {
                executor.submit(check_subdomain, sub): sub 
                for sub in subdomains
            }
            
            for future in as_completed(future_to_subdomain, timeout=300):  # 5 min total timeout
                try:
                    result = future.result(timeout=TIMEOUT)
                    if result:
                        self.subdomains.add(result)
                        results['subdomains'].append(result)
                except Exception as e:
                    self.logger.debug(f"Subdomain check failed: {str(e)}")
        
        # Also check the main domain
        try:
            socket.gethostbyname(self.domain)
            self.subdomains.add(self.domain)
            results['subdomains'].append(self.domain)
        except:
            pass
        
        return results
    
    def run_amass(self):
        """Phase 2: Enhanced subdomain discovery using external sources"""
        results = {
            'method': 'external_sources',
            'subdomains': [],
            'sources_used': []
        }
        
        # Check if amass is available
        try:
            subprocess.run(['amass', '-version'], capture_output=True, timeout=5)
            # If amass is available, run it
            cmd = f"amass enum -d {self.domain} -timeout 60"
            output = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=180)
            
            if output.returncode == 0:
                amass_subdomains = output.stdout.strip().split('\n')
                for subdomain in amass_subdomains:
                    if subdomain and '.' in subdomain:
                        self.subdomains.add(subdomain.strip())
                        results['subdomains'].append(subdomain.strip())
                results['sources_used'].append('amass')
            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            # Fallback to alternative subdomain discovery
            self.logger.info("Amass not available, using fallback method")
            
            # Try common subdomain enumeration via DNS
            try:
                # Use crt.sh certificate transparency logs
                url = f"https://crt.sh/?q=%.{self.domain}&output=json"
                response = requests.get(url, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    for entry in data:
                        name = entry.get('name_value', '')
                        if name and name not in results['subdomains']:
                            # Clean up the domain name
                            domains = name.split('\n')
                            for domain in domains:
                                domain = domain.strip()
                                if domain.endswith(f".{self.domain}") or domain == self.domain:
                                    self.subdomains.add(domain)
                                    results['subdomains'].append(domain)
                    
                    results['sources_used'].append('crt.sh')
            except Exception as e:
                self.logger.error(f"Certificate transparency lookup failed: {str(e)}")
        
        return results
    
    def identify_ip_addresses(self):
        """Phase 3: Identify IP addresses and blocks"""
        results = {
            'ips': [],
            'ip_blocks': [],
            'reverse_dns': {}
        }
        
        for subdomain in self.subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                self.ips.add(ip)
                results['ips'].append({'domain': subdomain, 'ip': ip})
                
                # Try reverse DNS lookup
                try:
                    reverse = socket.gethostbyaddr(ip)[0]
                    results['reverse_dns'][ip] = reverse
                except:
                    pass
                    
            except socket.gaierror:
                continue
        
        return results
    
    def check_dns_security(self):
        """Phase 4: Check DNS security configurations"""
        results = {
            'dnssec': False,
            'dns_records': {},
            'nameservers': []
        }
        
        try:
            # Check for DNSSEC
            resolver = dns.resolver.Resolver()
            try:
                answers = resolver.resolve(self.domain, 'DNSKEY')
                results['dnssec'] = len(answers) > 0
            except:
                results['dnssec'] = False
            
            # Get nameservers
            try:
                ns_answers = resolver.resolve(self.domain, 'NS')
                results['nameservers'] = [str(ns) for ns in ns_answers]
            except:
                pass
            
            # Check common DNS records
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'CNAME']
            for record_type in record_types:
                try:
                    answers = resolver.resolve(self.domain, record_type)
                    results['dns_records'][record_type] = [str(answer) for answer in answers]
                except:
                    results['dns_records'][record_type] = []
            
        except Exception as e:
            self.logger.error(f"DNS security check failed: {str(e)}")
        
        return results
    
    def check_email_security(self):
        """Phase 5: Assess email security"""
        results = {
            'spf': None,
            'dmarc': None,
            'dkim': None,
            'mx_records': []
        }
        
        try:
            resolver = dns.resolver.Resolver()
            
            # Check SPF record
            try:
                txt_answers = resolver.resolve(self.domain, 'TXT')
                for answer in txt_answers:
                    txt_record = str(answer).strip('"')
                    if txt_record.startswith('v=spf1'):
                        results['spf'] = txt_record
                        break
            except:
                pass
            
            # Check DMARC record
            try:
                dmarc_answers = resolver.resolve(f'_dmarc.{self.domain}', 'TXT')
                for answer in dmarc_answers:
                    txt_record = str(answer).strip('"')
                    if txt_record.startswith('v=DMARC1'):
                        results['dmarc'] = txt_record
                        break
            except:
                pass
            
            # Check MX records
            try:
                mx_answers = resolver.resolve(self.domain, 'MX')
                results['mx_records'] = [str(mx) for mx in mx_answers]
            except:
                pass
            
        except Exception as e:
            self.logger.error(f"Email security check failed: {str(e)}")
        
        return results
    
    def check_network_security(self):
        """Phase 6: Evaluate network security"""
        results = {
            'open_ports': {},
            'ssl_info': {},
            'http_headers': {}
        }
        
        # Port scan common ports for each IP
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443]
        
        for ip in list(self.ips)[:5]:  # Limit to first 5 IPs
            open_ports = []
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(3)
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                    sock.close()
                except:
                    pass
            
            if open_ports:
                results['open_ports'][ip] = open_ports
        
        # Check SSL/TLS for HTTPS services
        for subdomain in list(self.subdomains)[:5]:  # Limit to first 5 subdomains
            try:
                context = ssl.create_default_context()
                with socket.create_connection((subdomain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=subdomain) as ssock:
                        cert = ssock.getpeercert()
                        results['ssl_info'][subdomain] = {
                            'version': ssock.version(),
                            'cipher': ssock.cipher(),
                            'cert_subject': dict(x[0] for x in cert['subject']),
                            'cert_issuer': dict(x[0] for x in cert['issuer']),
                            'not_after': cert['notAfter']
                        }
            except:
                pass
        
        return results
    
    def scan_vulnerabilities(self):
        """Phase 7: Scan for vulnerabilities"""
        results = {
            'vulnerabilities': [],
            'scan_method': 'basic_checks'
        }
        
        # Basic vulnerability checks
        for subdomain in list(self.subdomains)[:3]:  # Limit for performance
            try:
                # Check for common web vulnerabilities
                test_urls = [
                    f"http://{subdomain}/admin",
                    f"http://{subdomain}/.git",
                    f"http://{subdomain}/wp-admin",
                    f"http://{subdomain}/.env",
                    f"https://{subdomain}/admin",
                    f"https://{subdomain}/.git",
                    f"https://{subdomain}/wp-admin",
                    f"https://{subdomain}/.env"
                ]
                
                for url in test_urls:
                    try:
                        response = requests.get(url, timeout=10, allow_redirects=False)
                        if response.status_code in [200, 301, 302, 403]:
                            vuln = {
                                'type': 'Information Disclosure',
                                'url': url,
                                'status_code': response.status_code,
                                'description': f"Accessible endpoint: {url}"
                            }
                            results['vulnerabilities'].append(vuln)
                            self.vulnerabilities.append(vuln)
                    except:
                        pass
                        
            except Exception as e:
                self.logger.debug(f"Vulnerability scan error for {subdomain}: {str(e)}")
        
        return results
    
    def run_nuclei_scan(self):
        """Phase 8: Run Nuclei vulnerability scanner"""
        results = {
            'nuclei_available': False,
            'vulnerabilities': [],
            'scan_targets': list(self.subdomains)[:5]
        }
        
        try:
            # Check if nuclei is available
            subprocess.run(['nuclei', '-version'], capture_output=True, timeout=5)
            results['nuclei_available'] = True
            
            # Create target file
            target_file = os.path.join(self.results_dir, 'nuclei_targets.txt')
            with open(target_file, 'w') as f:
                for subdomain in results['scan_targets']:
                    f.write(f"https://{subdomain}\n")
                    f.write(f"http://{subdomain}\n")
            
            # Run nuclei scan
            output_file = os.path.join(self.results_dir, 'nuclei_results.json')
            cmd = [
                'nuclei', '-l', target_file, '-j', '-o', output_file,
                '-timeout', '10', '-retries', '1', '-rate-limit', '50'
            ]
            
            subprocess.run(cmd, timeout=300, capture_output=True)
            
            # Parse results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    for line in f:
                        try:
                            vuln = json.loads(line.strip())
                            results['vulnerabilities'].append(vuln)
                        except:
                            pass
            
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.logger.info("Nuclei not available, skipping nuclei scan")
        except Exception as e:
            self.logger.error(f"Nuclei scan failed: {str(e)}")
        
        return results
    
    def check_data_exposure(self):
        """Phase 9: Check for data exposure"""
        results = {
            'exposed_files': [],
            'directory_listings': [],
            'sensitive_endpoints': []
        }
        
        # Check for exposed sensitive files
        sensitive_files = [
            '.env', '.git/config', 'wp-config.php', 'config.php',
            'database.yml', 'settings.py', '.htaccess', 'web.config',
            'backup.sql', 'dump.sql', 'phpinfo.php'
        ]
        
        for subdomain in list(self.subdomains)[:3]:
            for file in sensitive_files:
                for protocol in ['http', 'https']:
                    url = f"{protocol}://{subdomain}/{file}"
                    try:
                        response = requests.get(url, timeout=10)
                        if response.status_code == 200:
                            exposure = {
                                'url': url,
                                'file': file,
                                'size': len(response.content),
                                'content_type': response.headers.get('content-type', 'unknown')
                            }
                            results['exposed_files'].append(exposure)
                            self.exposed_data.append(exposure)
                    except:
                        pass
        
        return results
    
    def detect_misconfigurations(self):
        """Phase 10: Detect security misconfigurations"""
        results = {
            'misconfigurations': [],
            'security_headers': {}
        }
        
        # Check security headers
        for subdomain in list(self.subdomains)[:3]:
            try:
                response = requests.get(f"https://{subdomain}", timeout=10)
                headers = response.headers
                
                security_headers = {
                    'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
                    'Content-Security-Policy': headers.get('Content-Security-Policy'),
                    'X-Frame-Options': headers.get('X-Frame-Options'),
                    'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
                    'Referrer-Policy': headers.get('Referrer-Policy')
                }
                
                results['security_headers'][subdomain] = security_headers
                
                # Check for missing security headers
                for header, value in security_headers.items():
                    if not value:
                        misconfiguration = {
                            'type': 'Missing Security Header',
                            'domain': subdomain,
                            'header': header,
                            'description': f"Missing {header} security header"
                        }
                        results['misconfigurations'].append(misconfiguration)
                        self.misconfigurations.append(misconfiguration)
                        
            except:
                pass
        
        return results
    
    def detect_email_compromises(self):
        """Phase 11: Detect email compromises"""
        results = {
            'method': 'basic_check',
            'compromises': [],
            'note': 'Limited to basic checks without API access'
        }
        
        # Basic email pattern generation
        common_patterns = [
            f"admin@{self.domain}",
            f"info@{self.domain}",
            f"contact@{self.domain}",
            f"support@{self.domain}",
            f"sales@{self.domain}"
        ]
        
        results['email_patterns'] = common_patterns
        return results
    
    def check_credential_leaks(self):
        """Phase 12: Check for credential leaks"""
        results = {
            'method': 'basic_search',
            'leaks': [],
            'sources_checked': ['github_public']
        }
        
        # Basic GitHub search (without API)
        try:
            # Search for potential credential files
            search_terms = [
                f'"{self.domain}" password',
                f'"{self.domain}" api_key',
                f'"{self.domain}" secret'
            ]
            
            for term in search_terms:
                # This would normally use GitHub API, but we'll simulate
                results['leaks'].append({
                    'search_term': term,
                    'method': 'github_search',
                    'note': 'Requires GitHub API for full functionality'
                })
                
        except Exception as e:
            self.logger.error(f"Credential leak check failed: {str(e)}")
        
        return results
    
    def check_reputation(self):
        """Phase 13: Evaluate domain reputation"""
        results = {
            'domain_age': None,
            'whois_info': {},
            'reputation_sources': []
        }
        
        try:
            # Get WHOIS information
            w = whois.whois(self.domain)
            if w:
                results['whois_info'] = {
                    'creation_date': str(w.creation_date) if w.creation_date else None,
                    'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                    'registrar': w.registrar,
                    'name_servers': w.name_servers
                }
                
                # Calculate domain age
                if w.creation_date:
                    if isinstance(w.creation_date, list):
                        creation_date = w.creation_date[0]
                    else:
                        creation_date = w.creation_date
                    
                    age = datetime.datetime.now() - creation_date
                    results['domain_age'] = age.days
                    
        except Exception as e:
            self.logger.error(f"Reputation check failed: {str(e)}")
        
        return results
    
    def detect_web_technologies(self):
        """Phase 14: Detect web technologies"""
        results = {
            'technologies': {},
            'servers': {},
            'frameworks': {}
        }
        
        for subdomain in list(self.subdomains)[:3]:
            try:
                response = requests.get(f"https://{subdomain}", timeout=10)
                headers = response.headers
                
                tech_info = {
                    'server': headers.get('Server', 'Unknown'),
                    'x_powered_by': headers.get('X-Powered-By'),
                    'content_type': headers.get('Content-Type'),
                    'status_code': response.status_code
                }
                
                results['technologies'][subdomain] = tech_info
                
            except:
                try:
                    response = requests.get(f"http://{subdomain}", timeout=10)
                    headers = response.headers
                    
                    tech_info = {
                        'server': headers.get('Server', 'Unknown'),
                        'x_powered_by': headers.get('X-Powered-By'),
                        'content_type': headers.get('Content-Type'),
                        'status_code': response.status_code
                    }
                    
                    results['technologies'][subdomain] = tech_info
                except:
                    pass
        
        return results
    
    def gather_cve_info(self):
        """Phase 15: Gather CVE information"""
        results = {
            'cves': [],
            'method': 'basic_lookup',
            'note': 'Limited CVE information without specialized databases'
        }
        
        # This would normally query CVE databases
        # For now, we'll just note the need for this functionality
        results['cves'] = []
        
        return results
    
    def run_shodan_scan(self):
        """Phase 16: Run Shodan scans"""
        results = {
            'shodan_available': False,
            'api_key_found': False,
            'scan_results': {}
        }
        
        # Check for Shodan API key
        shodan_api_key = os.getenv('SHODAN_API_KEY')
        
        if shodan_api_key:
            results['api_key_found'] = True
            try:
                import shodan
                api = shodan.Shodan(shodan_api_key)
                
                # Search for IPs
                for ip in list(self.ips)[:3]:
                    try:
                        host_info = api.host(ip)
                        results['scan_results'][ip] = {
                            'ports': host_info.get('ports', []),
                            'services': host_info.get('data', []),
                            'vulnerabilities': host_info.get('vulns', []),
                            'country': host_info.get('country_name'),
                            'org': host_info.get('org')
                        }
                    except Exception as e:
                        self.logger.debug(f"Shodan lookup failed for {ip}: {str(e)}")
                
                results['shodan_available'] = True
                
            except ImportError:
                self.logger.info("Shodan library not available")
            except Exception as e:
                self.logger.error(f"Shodan scan failed: {str(e)}")
        else:
            self.logger.info("Shodan API key not found, skipping Shodan scan")
        
        return results
    
    def run_trufflehog_scan(self):
        """Phase 17: Run Trufflehog for sensitive data"""
        results = {
            'trufflehog_available': False,
            'github_token_found': False,
            'secrets_found': [],
            'repositories_scanned': []
        }
        
        # Check for GitHub token
        github_token = os.getenv('GITHUB_TOKEN')
        results['github_token_found'] = bool(github_token)
        
        try:
            # Use Python truffleHog library
            from truffleHog import truffleHog
            results['trufflehog_available'] = True
            
            if github_token:
                import requests
                
                # Search for repositories related to the domain
                search_terms = [
                    self.domain,
                    self.domain.replace('.', ''),
                    self.domain.split('.')[0] if '.' in self.domain else self.domain
                ]
                
                headers = {'Authorization': f'token {github_token}'}
                
                for search_term in search_terms[:2]:  # Limit searches
                    try:
                        search_url = f"https://api.github.com/search/repositories?q={search_term}&sort=updated&per_page=3"
                        response = requests.get(search_url, headers=headers, timeout=30)
                        
                        if response.status_code == 200:
                            repos = response.json().get('items', [])
                            
                            for repo in repos:
                                repo_url = repo['clone_url']
                                repo_name = repo['full_name']
                                results['repositories_scanned'].append(repo_name)
                                
                                try:
                                    # Scan repository for secrets
                                    secrets = truffleHog.find_strings(repo_url, printJson=False, surpress_output=True)
                                    if secrets:
                                        for secret in secrets[:5]:  # Limit findings
                                            results['secrets_found'].append({
                                                'repository': repo_name,
                                                'reason': secret.get('reason', 'Unknown pattern'),
                                                'path': secret.get('path', 'unknown'),
                                                'branch': secret.get('branch', 'unknown')
                                            })
                                except Exception as e:
                                    self.logger.debug(f"Failed to scan {repo_name}: {str(e)}")
                        
                    except Exception as e:
                        self.logger.debug(f"GitHub search failed for {search_term}: {str(e)}")
            
        except ImportError:
            self.logger.info("TruffleHog library not available")
        except Exception as e:
            self.logger.error(f"Trufflehog scan failed: {str(e)}")
        
        return results
    
    def assess_risks(self):
        """Phase 18: Perform risk assessment"""
        results = {
            'risk_score': 0,
            'risk_categories': {},
            'recommendations': []
        }
        
        # Calculate basic risk score
        risk_factors = 0
        
        # Check vulnerabilities
        if self.vulnerabilities:
            risk_factors += len(self.vulnerabilities) * 10
            results['recommendations'].append("Address identified vulnerabilities")
        
        # Check misconfigurations
        if self.misconfigurations:
            risk_factors += len(self.misconfigurations) * 5
            results['recommendations'].append("Fix security misconfigurations")
        
        # Check exposed data
        if self.exposed_data:
            risk_factors += len(self.exposed_data) * 15
            results['recommendations'].append("Secure exposed data and files")
        
        # Check subdomains
        if len(self.subdomains) > 10:
            risk_factors += 10
            results['recommendations'].append("Review and secure large attack surface")
        
        results['risk_score'] = min(risk_factors, 100)
        
        # Risk categories
        results['risk_categories'] = {
            'Data Breach': min(len(self.exposed_data) * 20, 100),
            'Compliance': min(len(self.misconfigurations) * 15, 100),
            'Reputation': min(len(self.vulnerabilities) * 10, 100),
            'Operational': min(risk_factors // 2, 100)
        }
        
        return results
    
    def save_phase_results(self, phase_name, results):
        """Save individual phase results to JSON file"""
        filename = f"{phase_name.lower().replace(' ', '_')}.json"
        filepath = os.path.join(self.results_dir, filename)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2, default=str)
        except Exception as e:
            self.logger.error(f"Failed to save phase results for {phase_name}: {str(e)}")
    
    def generate_summary(self):
        """Generate assessment summary"""
        summary = {
            'domain': self.domain,
            'assessment_id': self.assessment_id,
            'timestamp': datetime.datetime.now().isoformat(),
            'summary_stats': {
                'subdomains_found': len(self.subdomains),
                'ips_identified': len(self.ips),
                'vulnerabilities_found': len(self.vulnerabilities),
                'misconfigurations_found': len(self.misconfigurations),
                'exposed_data_items': len(self.exposed_data)
            },
            'overall_score': self.calculate_overall_score(),
            'risk_level': self.get_risk_level()
        }
        
        # Save summary
        summary_file = os.path.join(self.results_dir, 'assessment_summary.json')
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2, default=str)
    
    def calculate_overall_score(self):
        """Calculate overall security score (0-100)"""
        base_score = 100
        
        # Deduct points for issues
        base_score -= len(self.vulnerabilities) * 5
        base_score -= len(self.misconfigurations) * 3
        base_score -= len(self.exposed_data) * 8
        
        # Large attack surface penalty
        if len(self.subdomains) > 20:
            base_score -= 10
        elif len(self.subdomains) > 10:
            base_score -= 5
        
        return max(0, base_score)
    
    def get_risk_level(self):
        """Get risk level based on overall score"""
        score = self.calculate_overall_score()
        
        if score >= 80:
            return "Low"
        elif score >= 60:
            return "Medium"
        elif score >= 40:
            return "High"
        else:
            return "Critical"
    
    def format_findings(self, results):
        """Format findings for display in UI"""
        findings = []
        
        if isinstance(results, dict):
            for key, value in results.items():
                if isinstance(value, list) and value:
                    findings.append(f"{key.title()}: {len(value)} items found")
                elif isinstance(value, dict) and value:
                    findings.append(f"{key.title()}: {len(value)} entries")
                elif value and not isinstance(value, (dict, list)):
                    findings.append(f"{key.title()}: {str(value)[:100]}")
        
        return findings[:5]  # Limit to 5 findings for UI
