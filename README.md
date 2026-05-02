
# Web Technology Detector & Bug Hunter Tool

A comprehensive Python tool to detect website technologies (frameworks, CMS, libraries) and generate bug hunting path suggestions with HTML reports.

## 🚀 Quick Installation

```bash
git clone https://github.com/csejobaer/WTFinder.git
cd webtech-hunter
pip install requests beautifulsoup4
```

## 💻 Usage

```bash
# Basic scan
python webtech_hunter.py https://example.com

# Save report with custom name
python webtech_hunter.py https://target.com -o my_report.html

# Scan localhost
python webtech_hunter.py http://localhost:3000
```

## ✨ Features

- 🔍 Detects 50+ technologies (Web Servers, Frameworks, CMS, Languages, Databases, Cloud Services)
- 🎯 Generates technology-specific bug hunting suggestions
- 📊 Beautiful HTML report with executive summary
- 🔐 Identifies security misconfigurations (exposed .env, phpinfo, .git, etc.)
- 🍪 Cookie-based detection
- 📄 HTTP header analysis
- 🔗 URL pattern scanning

## 📋 What It Detects

| Category | Examples |
|----------|----------|
| Web Servers | Apache, Nginx, IIS, Tomcat |
| Languages | PHP, Python, Java, ASP.NET, Go |
| Frameworks | Laravel, Django, React, Vue, Angular, Spring Boot |
| CMS | WordPress, Drupal, Joomla, Shopify |
| Cloud/CDN | CloudFlare, AWS, Azure, Fastly |
| Databases | MySQL, PostgreSQL, MongoDB, Redis |

## 📊 Sample Report Output

The tool generates an interactive HTML report containing:
- Summary statistics (total technologies detected)
- Categorized technology listing
- Bug hunting path suggestions (15+ recommendations)
- Manual testing checklist
- Recommended security tools

## ⚠️ Disclaimer

This tool is for **authorized security testing and educational purposes only**. Always obtain proper permission before scanning any website.

## 📝 Command Line Arguments

```
positional arguments:
  url                   Target website URL

optional arguments:
  -o, --output          Output HTML report filename (default: report.html)
  -h, --help            Show help message
```

## 🛠️ Requirements

- Python 3.6+
- requests
- beautifulsoup4

## 📄 License

For educational and authorized security testing purposes only.
