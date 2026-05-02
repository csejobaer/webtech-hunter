#!/usr/bin/env python3
"""
Complete Web Technology Detector & Bug Hunter Assistant
Author: Security Tool
Features: Technology Detection, CMS Detection, Framework Detection, Bug Hunting Path Suggestions
"""

import requests
import re
import json
import hashlib
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
import datetime
import argparse
import sys
import ssl
from collections import defaultdict
import warnings

warnings.filterwarnings('ignore')

class WebTechDetector:
    def __init__(self, target_url):
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else f'https://{target_url}'
        self.parsed_url = urlparse(self.target_url)
        self.domain = self.parsed_url.netloc
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive'
        })
        self.technologies = defaultdict(dict)
        self.vulnerability_suggestions = []
        
        # Technology detection patterns
        self.patterns = {
            'Web Servers': {
                'Apache': [r'apache', r'apache\/[\d\.]+', r'Apache/[\d\.]+'],
                'Nginx': [r'nginx', r'nginx/[\d\.]+', r'Nginx'],
                'IIS': [r'iis', r'microsoft-iis', r'IIS/[\d\.]+'],
                'Tomcat': [r'tomcat', r'Apache Tomcat', r'Catalina'],
                'Node.js': [r'node\.js', r'NodeJS', r'express'],
                'Gunicorn': [r'gunicorn', r'Gunicorn'],
            },
            'Programming Languages': {
                'PHP': [r'php', r'PHP/[\d\.]+', r'X-Powered-By: PHP'],
                'Python': [r'python', r'wsgi', r'django', r'flask', r'fastapi'],
                'Java': [r'java', r'jsp', r'jsessionid', r'Java/[\d\.]+'],
                'Ruby': [r'ruby', r'rails', r'rack'],
                'ASP.NET': [r'asp\.net', r'aspx', r'__VIEWSTATE', r'__EVENTVALIDATION'],
                'Go': [r'go\/', r'golang', r'fasthttp'],
                'Rust': [r'rust', r'actix', r'rocket\.rs'],
            },
            'Frameworks': {
                'Laravel': [r'laravel', r'laravel_session', r'X-Laravel'],
                'Django': [r'django', r'csrftoken', r'__admin_media_prefix__'],
                'Flask': [r'flask', r'flask-session'],
                'Express.js': [r'express', r'x-powered-by: express'],
                'Ruby on Rails': [r'rails', r'ruby on rails', r'csrf-param', r'_rails_admin'],
                'Spring Boot': [r'spring-boot', r'spring framework', r'x-application-context'],
                'React': [r'react', r'react-dom', r'react\/', r'__react', r'_reactRootContainer'],
                'Vue.js': [r'vue', r'vue\.js', r'vue-router', r'v\-'],
                'Angular': [r'angular', r'ng-', r'ngversion', r'_ngcontent'],
                'Next.js': [r'next\.js', r'__NEXT_DATA__', r'_next/static'],
                'Nuxt.js': [r'nuxt', r'__NUXT__', r'_nuxt/'],
                'Bootstrap': [r'bootstrap', r'popper\.js', r'data-toggle'],
                'jQuery': [r'jquery', r'\$\.', r'jQuery'],
            },
            'CMS': {
                'WordPress': [r'wordpress', r'wp-content', r'wp-includes', r'wp-json', r'wordpress/'],
                'Drupal': [r'drupal', r'sites/default/files', r'drupal\.js', r'Drupal\.'],
                'Joomla': [r'joomla', r'media/system/js', r'com_content', r'option=com_'],
                'Magento': [r'magento', r'skin/frontend', r'Mage\.', r'checkout/cart'],
                'Shopify': [r'shopify', r'myshopify\.com', r'cdn\.shopify', r'shopify\.'],
                'PrestaShop': [r'prestashop', r'presta\.', r'controller=product'],
                'Ghost': [r'ghost', r'ghost\/', r'public\/ghost'],
                'Concrete5': [r'concrete5', r'tools/required', r'concrete\.js'],
                'October CMS': [r'october', r'octobercms', r'combine/'],
            },
            'Databases': {
                'MySQL': [r'mysql', r'mariadb', r'phpmyadmin'],
                'PostgreSQL': [r'postgresql', r'pgsql', r'postgres'],
                'MongoDB': [r'mongodb', r'amazon\.documentdb'],
                'Redis': [r'redis', r'x-redis'],
                'ElasticSearch': [r'elasticsearch', r'elastic-search'],
            },
            'JavaScript Libraries': {
                'React': [r'react', r'react-dom', r'react\/'],
                'Vue.js': [r'vue', r'vue\.js', r'vue-router'],
                'Angular': [r'angular', r'@angular', r'angularjs'],
                'jQuery': [r'jquery', r'\$\(', r'sizzle'],
                'Bootstrap': [r'bootstrap', r'@popperjs'],
                'Tailwind CSS': [r'tailwindcss', r'tailwind-css'],
                'D3.js': [r'd3\.js', r'data-visualization'],
                'Three.js': [r'three\.js', r'webgl'],
            },
            'Cloud Services & CDN': {
                'CloudFlare': [r'cloudflare', r'cf-ray', r'__cfduid', r'cf-cache-status'],
                'AWS': [r'amazonaws', r'aws', r's3.amazonaws', r'cloudfront'],
                'Google Cloud': [r'appspot', r'googleapis', r'cloud.google'],
                'Azure': [r'azurewebsites', r'windows\.net', r'azure'],
                'Akamai': [r'akamai', r'akamaitech', r'akamaihd'],
                'Fastly': [r'fastly', r'x-fastly'],
                'Incapsula': [r'incapsula', r'visid_incap'],
            },
            'Security Tools': {
                'ModSecurity': [r'mod_security', r'ModSecurity'],
                'Sucuri': [r'sucuri', r'x-sucuri'],
                'Wordfence': [r'wordfence', r'wfwaf'],
                'CloudFlare WAF': [r'cloudflare.*waf', r'cf-chl', r'cf-browser-verification'],
            }
        }
        
        # Bug hunting suggestions based on technologies
        self.bug_hunting_suggestions = {
            'WordPress': [
                "Check wp-config.php backup files (wp-config.bak, wp-config.old)",
                "Test for XML-RPC exploitation (system.multicall)",
                "Check for vulnerable plugins via wpscan",
                "Look for user enumeration via /?author=1",
                "Check wp-json for exposed user data",
                "Test for unrestricted file upload in media library",
                "Check theme file inclusion vulnerabilities"
            ],
            'Laravel': [
                "Check debug mode enabled (.env exposure)",
                "Test for unserialize vulnerabilities",
                "Look for API route parameter injection",
                "Check mass assignment in Eloquent models",
                "Test for misconfigured CORS",
                "Look for SQL injection in query builder",
                "Check queue worker vulnerabilities"
            ],
            'Django': [
                "Test for SQL injection in raw queries",
                "Check DEBUG mode enabled (error pages)",
                "Look for insecure SECRET_KEY exposure",
                "Test for CSRF bypass techniques",
                "Check session security configuration",
                "Look for template injection",
                "Test for mass assignment vulnerabilities"
            ],
            'React': [
                "Check for XSS in dangerouslySetInnerHTML",
                "Look for exposed API keys in bundle.js",
                "Test for insecure React Router configurations",
                "Check for prototype pollution",
                "Verify input validation on client-side",
                "Look for insecure state management",
                "Test for server-side rendering vulnerabilities"
            ],
            'PHP': [
                "Check for Local File Inclusion (LFI)",
                "Test for Remote File Inclusion (RFI)",
                "Look for session fixation vulnerabilities",
                "Check for insecure unserialize calls",
                "Test for SQL injection in legacy code",
                "Verify upload restrictions bypass",
                "Check for eval() injection"
            ],
            'ASP.NET': [
                "Test for ViewState tampering",
                "Check for insecure machineKey configuration",
                "Look for file upload restrictions bypass",
                "Test for XXE in XML processing",
                "Check for deserialization vulnerabilities",
                "Verify request validation bypass",
                "Look for session fixation"
            ],
            'Node.js/Express': [
                "Check for prototype pollution",
                "Test for NoSQL injection in MongoDB",
                "Look for insecure direct object references",
                "Check for XSS in template engines",
                "Verify Helmet.js security headers",
                "Test for regex denial of service",
                "Look for command injection in child_process"
            ],
            'Spring Boot': [
                "Check /actuator endpoint exposure",
                "Test for Spring EL injection",
                "Look for insecure Jackson deserialization",
                "Check for path traversal in static resources",
                "Test for SQL injection in JPA/Hibernate",
                "Verify authentication bypass vulnerabilities",
                "Look for log injection"
            ],
            'Cloudflare': [
                "Find origin IP via Cloudflare bypass techniques",
                "Test for WAF bypass using payload obfuscation",
                "Use historical DNS records to find real IP",
                "Check for misconfigured cache poisoning",
                "Test for rate limiting bypass",
                "Look for Cloudflare Workers vulnerabilities"
            ]
        }

    def make_request(self, path='/'):
        """Make HTTP request to target"""
        url = urljoin(self.target_url, path)
        try:
            response = self.session.get(url, timeout=10, verify=False)
            return response
        except Exception as e:
            return None

    def detect_from_headers(self, response):
        """Detect technologies from HTTP headers"""
        if not response:
            return
        
        headers = response.headers
        for header, value in headers.items():
            value_lower = value.lower()
            
            # Server header
            if header.lower() == 'server':
                for tech, patterns in self.patterns['Web Servers'].items():
                    for pattern in patterns:
                        if re.search(pattern, value_lower, re.IGNORECASE):
                            self.technologies['Web Servers'][tech] = value
            
            # X-Powered-By header
            if header.lower() == 'x-powered-by':
                for tech, patterns in self.patterns['Programming Languages'].items():
                    for pattern in patterns:
                        if re.search(pattern, value_lower, re.IGNORECASE):
                            self.technologies['Programming Languages'][tech] = value
                for tech, patterns in self.patterns['Frameworks'].items():
                    for pattern in patterns:
                        if re.search(pattern, value_lower, re.IGNORECASE):
                            self.technologies['Frameworks'][tech] = value
            
            # Other security headers
            if header.lower() == 'x-generator':
                for tech, patterns in self.patterns['CMS'].items():
                    for pattern in patterns:
                        if re.search(pattern, value_lower, re.IGNORECASE):
                            self.technologies['CMS'][tech] = value
            
            # Cloudflare headers
            if 'cloudflare' in header.lower() or 'cf-' in header.lower():
                self.technologies['Cloud Services & CDN']['CloudFlare'] = 'Detected via headers'

    def detect_from_html(self, response):
        """Detect technologies from HTML content"""
        if not response:
            return
        
        soup = BeautifulSoup(response.text, 'html.parser')
        html_lower = response.text.lower()
        
        # Check meta tags
        meta_generator = soup.find('meta', {'name': 'generator'})
        if meta_generator and meta_generator.get('content'):
            content = meta_generator['content'].lower()
            for tech, patterns in self.patterns['CMS'].items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self.technologies['CMS'][tech] = content
        
        # Check JavaScript files
        script_tags = soup.find_all('script', src=True)
        for script in script_tags:
            src = script['src'].lower()
            for tech, patterns in self.patterns['JavaScript Libraries'].items():
                for pattern in patterns:
                    if re.search(pattern, src, re.IGNORECASE):
                        self.technologies['JavaScript Libraries'][tech] = src
            
            # Framework detection from scripts
            for tech, patterns in self.patterns['Frameworks'].items():
                for pattern in patterns:
                    if re.search(pattern, src, re.IGNORECASE) and tech not in self.technologies.get('Frameworks', {}):
                        self.technologies['Frameworks'][tech] = src
        
        # Check CSS files
        link_tags = soup.find_all('link', rel='stylesheet')
        for link in link_tags:
            href = link.get('href', '').lower()
            for tech, patterns in self.patterns['Frameworks'].items():
                for pattern in patterns:
                    if re.search(pattern, href, re.IGNORECASE):
                        self.technologies['Frameworks'][tech] = href
        
        # Check for specific HTML elements and comments
        if 'wp-content' in html_lower or 'wp-includes' in html_lower:
            self.technologies['CMS']['WordPress'] = 'Detected via paths in HTML'
        
        if 'joomla' in html_lower:
            self.technologies['CMS']['Joomla'] = 'Detected via HTML content'
        
        if 'drupal' in html_lower:
            self.technologies['CMS']['Drupal'] = 'Detected via HTML content'
        
        # Check for React
        if '_reactRootContainer' in html_lower or 'reactRoot' in html_lower:
            self.technologies['JavaScript Libraries']['React'] = 'Detected via React root container'
        
        # Check for Vue
        if 'vue-app' in html_lower or 'v-' in html_lower and 'vue' in html_lower:
            self.technologies['JavaScript Libraries']['Vue.js'] = 'Detected via Vue attributes'
        
        # Check for Angular
        if 'ng-app' in html_lower or 'ng-controller' in html_lower:
            self.technologies['JavaScript Libraries']['Angular'] = 'Detected via Angular directives'

    def detect_from_cookies(self, response):
        """Detect technologies from cookies"""
        if not response or 'cookies' not in dir(response):
            return
        
        for cookie in response.cookies:
            cookie_name = cookie.name.lower()
            
            # PHP detection
            if 'php' in cookie_name or cookie_name == 'phpsessid':
                self.technologies['Programming Languages']['PHP'] = f'Cookie: {cookie.name}'
            
            # Laravel detection
            if 'laravel_session' in cookie_name:
                self.technologies['Frameworks']['Laravel'] = f'Cookie: {cookie.name}'
            
            # ASP.NET detection
            if 'asp.net' in cookie_name or '__requestverificationtoken' in cookie_name:
                self.technologies['Programming Languages']['ASP.NET'] = f'Cookie: {cookie.name}'
            
            # Django detection
            if 'csrftoken' in cookie_name or 'sessionid' in cookie_name:
                self.technologies['Frameworks']['Django'] = f'Cookie: {cookie.name}'
            
            # Rails detection
            if '_rails_admin' in cookie_name or '_session_id' in cookie_name:
                self.technologies['Frameworks']['Ruby on Rails'] = f'Cookie: {cookie.name}'
            
            # Cloudflare detection
            if '__cfduid' in cookie_name or 'cf_clearance' in cookie_name:
                self.technologies['Cloud Services & CDN']['CloudFlare'] = f'Cookie: {cookie.name}'

    def detect_from_url_patterns(self):
        """Detect technologies from URL patterns and common paths"""
        common_paths = [
            '/wp-admin', '/wp-login.php', '/wp-json',           # WordPress
            '/administrator', '/joomla',                        # Joomla
            '/admin', '/user', '/login',                         # Generic
            '/.git/HEAD', '/.env', '/config.php',               # Config exposure
            '/phpinfo.php', '/info.php', '/phpinfo',            # PHP info
            '/server-status', '/server-info',                   # Apache status
            '/actuator', '/actuator/health',                    # Spring Boot
            '/robots.txt', '/sitemap.xml',                      # Common files
            '/backup', '/backups', '/temp',                     # Backup directories
        ]
        
        for path in common_paths:
            response = self.make_request(path)
            if response and response.status_code == 200:
                # WordPress detection
                if 'wp-' in path or 'wordpress' in path:
                    self.technologies['CMS']['WordPress'] = f'Path exists: {path}'
                
                # Git exposure
                if '.git/HEAD' in path and 'ref:' in response.text:
                    self.technologies['Vulnerabilities'] = {'Git Exposure': '.git directory accessible'}
                
                # Environment file exposure
                if '.env' in path:
                    self.technologies['Vulnerabilities'] = {'ENV Exposure': 'Environment file accessible'}
                
                # PHP info exposure
                if 'phpinfo' in path:
                    self.technologies['Vulnerabilities'] = {'PHP Info Exposure': 'phpinfo() accessible'}
                
                # Spring Boot actuator
                if 'actuator' in path:
                    self.technologies['Frameworks']['Spring Boot'] = f'Path exists: {path}'

    def generate_bug_hunting_suggestions(self):
        """Generate bug hunting suggestions based on detected technologies"""
        suggestions = []
        
        # Check for detected technologies and add relevant suggestions
        categories = ['CMS', 'Frameworks', 'Programming Languages', 'JavaScript Libraries', 'Security Tools']
        
        for category in categories:
            if category in self.technologies:
                for tech in self.technologies[category]:
                    # Look for suggestions for this technology (case-insensitive)
                    for known_tech, tech_suggestions in self.bug_hunting_suggestions.items():
                        if known_tech.lower() in tech.lower() or tech.lower() in known_tech.lower():
                            suggestions.extend(tech_suggestions)
        
        # Add WAF detection suggestions
        if 'Cloud Services & CDN' in self.technologies:
            if 'CloudFlare' in self.technologies['Cloud Services & CDN']:
                suggestions.extend(self.bug_hunting_suggestions.get('Cloudflare', []))
        
        # Add generic suggestions
        suggestions.append("Check for CORS misconfiguration")
        suggestions.append("Test for Rate Limiting bypass")
        suggestions.append("Check for exposed .git/config file")
        suggestions.append("Look for backup files (index.bak, config.old)")
        suggestions.append("Test for Host Header injection")
        suggestions.append("Check for HTTP methods (PUT, DELETE, OPTIONS)")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_suggestions = []
        for suggestion in suggestions:
            if suggestion not in seen:
                seen.add(suggestion)
                unique_suggestions.append(suggestion)
        
        return unique_suggestions[:15]  # Limit to top 15 suggestions

    def scan(self):
        """Main scanning function"""
        print(f"[+] Scanning target: {self.target_url}")
        print("[+] This may take a few moments...\n")
        
        # Make initial request
        response = self.make_request()
        
        if not response:
            print("[-] Failed to connect to target")
            return False
        
        print(f"[+] Status code: {response.status_code}")
        
        # Run all detection methods
        self.detect_from_headers(response)
        self.detect_from_html(response)
        self.detect_from_cookies(response)
        self.detect_from_url_patterns()
        
        # Generate suggestions
        self.vulnerability_suggestions = self.generate_bug_hunting_suggestions()
        
        return True

    def generate_html_report(self):
        """Generate complete HTML report"""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Web Technology Detector & Bug Hunter Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .target {{
            font-size: 1.2em;
            background: rgba(255,255,255,0.2);
            display: inline-block;
            padding: 10px 20px;
            border-radius: 10px;
            margin-top: 10px;
        }}
        
        .timestamp {{
            margin-top: 15px;
            font-size: 0.9em;
            opacity: 0.9;
        }}
        
        .summary {{
            background: #f7f9fc;
            padding: 20px 30px;
            border-bottom: 1px solid #e1e8ed;
        }}
        
        .stats {{
            display: flex;
            justify-content: space-around;
            gap: 20px;
            flex-wrap: wrap;
        }}
        
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            flex: 1;
            text-align: center;
            min-width: 150px;
        }}
        
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        
        .stat-label {{
            color: #657786;
            margin-top: 5px;
            font-size: 0.9em;
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .category {{
            margin-bottom: 30px;
            background: #f8f9fa;
            border-radius: 10px;
            overflow: hidden;
        }}
        
        .category-title {{
            background: #667eea;
            color: white;
            padding: 15px 20px;
            font-size: 1.3em;
            font-weight: bold;
        }}
        
        .tech-grid {{
            padding: 20px;
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
        }}
        
        .tech-item {{
            background: white;
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        .tech-name {{
            font-weight: bold;
            color: #333;
            font-size: 1.1em;
            margin-bottom: 5px;
        }}
        
        .tech-detail {{
            color: #666;
            font-size: 0.85em;
            font-family: monospace;
            word-break: break-all;
        }}
        
        .suggestions {{
            background: #fff3e0;
            border-left: 4px solid #ff9800;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
        }}
        
        .suggestions h3 {{
            color: #ff9800;
            margin-bottom: 15px;
        }}
        
        .suggestions ul {{
            list-style: none;
            padding-left: 0;
        }}
        
        .suggestions li {{
            padding: 8px 0;
            padding-left: 25px;
            position: relative;
            color: #333;
        }}
        
        .suggestions li:before {{
            content: "→";
            position: absolute;
            left: 0;
            color: #ff9800;
            font-weight: bold;
        }}
        
        .footer {{
            background: #f7f9fc;
            padding: 20px;
            text-align: center;
            color: #657786;
            border-top: 1px solid #e1e8ed;
        }}
        
        .empty-state {{
            text-align: center;
            padding: 40px;
            color: #999;
        }}
        
        @media (max-width: 768px) {{
            .tech-grid {{
                grid-template-columns: 1fr;
            }}
            
            .stats {{
                flex-direction: column;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Web Technology Detector & Bug Hunter</h1>
            <div class="target">Target: {self.target_url}</div>
            <div class="timestamp">Scan Date: {timestamp}</div>
        </div>
        
        <div class="summary">
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-number">{sum(len(techs) for techs in self.technologies.values())}</div>
                    <div class="stat-label">Technologies Detected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(self.technologies)}</div>
                    <div class="stat-label">Categories</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{len(self.vulnerability_suggestions)}</div>
                    <div class="stat-label">Bug Hunting Paths</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{self.domain}</div>
                    <div class="stat-label">Domain</div>
                </div>
            </div>
        </div>
        
        <div class="content">
"""
        
        # Add technology categories
        categories_order = ['Web Servers', 'Programming Languages', 'Frameworks', 'CMS', 'Databases', 
                           'JavaScript Libraries', 'Cloud Services & CDN', 'Security Tools', 'Vulnerabilities']
        
        for category in categories_order:
            if category in self.technologies and self.technologies[category]:
                html_content += f"""
            <div class="category">
                <div class="category-title">📦 {category}</div>
                <div class="tech-grid">
"""
                for tech_name, tech_detail in self.technologies[category].items():
                    html_content += f"""
                    <div class="tech-item">
                        <div class="tech-name">{tech_name}</div>
                        <div class="tech-detail">{tech_detail}</div>
                    </div>
"""
                html_content += """
                </div>
            </div>
"""
        
        # Add bug hunting suggestions
        if self.vulnerability_suggestions:
            html_content += """
            <div class="suggestions">
                <h3>🎯 Recommended Bug Hunting Paths</h3>
                <ul>
"""
            for suggestion in self.vulnerability_suggestions:
                html_content += f"<li>{suggestion}</li>\n"
            
            html_content += """
                </ul>
            </div>
"""
        
        # Add additional testing tips
        html_content += """
            <div class="suggestions" style="background: #e8f5e9; border-left-color: #4caf50;">
                <h3>🛠️ Manual Testing Checklist</h3>
                <ul>
                    <li>Check robots.txt and sitemap.xml for exposed paths</li>
                    <li>Test for SQL injection using sqlmap</li>
                    <li>Run directory brute-forcing (dirb, gobuster, ffuf)</li>
                    <li>Check for exposed admin panels</li>
                    <li>Test for Cross-Site Scripting (XSS) in input fields</li>
                    <li>Verify file upload functionality security</li>
                    <li>Check for IDOR (Insecure Direct Object References)</li>
                    <li>Test for Path Traversal vulnerabilities</li>
                    <li>Check for Server-Side Request Forgery (SSRF)</li>
                    <li>Test for Insecure Deserialization</li>
                </ul>
            </div>
            
            <div class="suggestions" style="background: #e3f2fd; border-left-color: #2196f3;">
                <h3>🔧 Recommended Tools for Further Testing</h3>
                <ul>
                    <li><strong>Burp Suite</strong> - Web vulnerability scanner and proxy</li>
                    <li><strong>Nmap</strong> - Network discovery and service enumeration</li>
                    <li><strong>Nikto</strong> - Web server scanner</li>
                    <li><strong>WPScan</strong> - WordPress vulnerability scanner</li>
                    <li><strong>SQLmap</strong> - Automated SQL injection tool</li>
                    <li><strong>XSStrike</strong> - Advanced XSS detection suite</li>
                    <li><strong>FFUF</strong> - Fast web fuzzer written in Go</li>
                    <li><strong>Nuclei</strong> - Fast and customizable vulnerability scanner</li>
                </ul>
            </div>
        </div>
        
        <div class="footer">
            <p>⚠️ Disclaimer: This tool is for authorized security testing and educational purposes only.</p>
            <p>Always ensure you have proper permission before testing any website.</p>
            <p>Generated by Web Technology Detector & Bug Hunter Tool v1.0</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html_content

def main():
    parser = argparse.ArgumentParser(description='Web Technology Detector & Bug Hunter Tool')
    parser.add_argument('url', help='Target website URL (e.g., https://example.com)')
    parser.add_argument('-o', '--output', help='Output HTML report file name', default='report.html')
    
    args = parser.parse_args()
    
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║     Web Technology Detector & Bug Hunter Tool v1.0      ║
    ║         Complete Security Analysis & Reporting          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    # Create scanner instance
    scanner = WebTechDetector(args.url)
    
    # Run scan
    if scanner.scan():
        # Generate and save report
        html_report = scanner.generate_html_report()
        
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(html_report)
        
        print(f"\n[✓] Scan completed successfully!")
        print(f"[✓] HTML report saved to: {args.output}")
        print(f"\n📊 Scan Summary:")
        print(f"   • Technologies found: {sum(len(techs) for techs in scanner.technologies.values())}")
        print(f"   • Categories: {len(scanner.technologies)}")
        print(f"   • Bug hunting paths: {len(scanner.vulnerability_suggestions)}")
        print(f"\n🔍 Open '{args.output}' in your browser to view detailed report")
    else:
        print("[-] Scan failed. Please check the URL and try again.")
        sys.exit(1)

if __name__ == "__main__":
    main()