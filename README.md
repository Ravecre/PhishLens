PhishLens is an open-source phishing detection and URL threat analysis tool written in Python. It is designed to identify suspicious URLs, analyze domain characteristics, inspect redirect chains, and evaluate potential security threats through an explainable risk assessment engine.

Unlike traditional URL scanners that only provide a safe or malicious verdict, PhishLens focuses on transparency. Every detection is supported by technical evidence, an explanation, and a risk score, allowing users to understand why a URL may be suspicious.

The project aims to provide a modular, extensible, and privacy-oriented security analysis framework suitable for cybersecurity research, educational purposes, network security auditing, and developer workflows.

PhishLens is designed to operate locally without requiring external services or API keys for its core functionality. Optional threat intelligence integrations can extend its detection capabilities.

The main features include URL structure analysis, suspicious pattern detection, domain extraction, Unicode homograph detection, IP-based URL identification, suspicious subdomain analysis, URL encoding inspection, DNS record analysis, TLS certificate inspection, HTTP redirect analysis, domain reputation checks, and explainable risk scoring.

The detection engine uses a modular rule-based architecture. Each detection rule produces structured evidence containing the rule identifier, severity, description, detected value, and associated risk contribution. Results are processed by the risk assessment engine and converted into a consolidated security report.

The risk assessment system assigns a score between 0 and 100 based on the indicators identified during analysis. Results are classified into four categories: Low, Medium, High, and Critical. Risk scores represent heuristic assessments rather than statistically calibrated probabilities. The absence of suspicious indicators does not guarantee that a URL is safe.

PhishLens is built with Python and uses a modular architecture to facilitate maintenance and future development. The planned technology stack includes Python 3.12+, httpx, dnspython, tldextract, Pydantic, Typer, Rich, FastAPI, and pytest.

The project is organized into independent components for URL analysis, domain intelligence, DNS inspection, TLS analysis, redirect handling, threat intelligence, risk assessment, and report generation. This architecture allows new detection rules, intelligence providers, and reporting formats to be integrated without modifying the entire application.

PhishLens is intended to support command-line analysis, structured JSON output, HTML security reports, and future web-based interfaces.

The development roadmap includes the implementation of the core analysis engine, URL parsing, domain identification, suspicious pattern detection, Unicode homograph analysis, an initial risk scoring system, and automated testing. Subsequent releases will introduce DNS and TLS inspection, secure redirect analysis, external threat intelligence integrations, improved reporting capabilities, and a web dashboard.

External integrations such as VirusTotal, Google Safe Browsing, URLhaus, and OpenPhish are planned as optional intelligence sources. Their availability and functionality will depend on their respective APIs, access requirements, and service terms.

Security and privacy are fundamental design considerations. PhishLens should avoid transmitting submitted URLs to external providers unless the user explicitly enables the corresponding integration. Network-based analysis must implement request timeouts, response size limits, redirect restrictions, and protections against server-side request forgery (SSRF). Private, loopback, link-local, and reserved IP ranges must be restricted when processing remote destinations.

The project is intended for educational, defensive, and authorized security research purposes. Users are responsible for ensuring that their analysis activities comply with applicable laws, regulations, and third-party service policies.

PhishLens is an evolving project. Features, detection rules, integrations, and documentation may change as development progresses. Contributions, bug reports, feature suggestions, and improvements are welcome.

This project is distributed under the MIT License. See the LICENSE file for additional information.

PhishLens is an independent open-source project and is not affiliated with, endorsed by, or associated with any of the external services or organizations mentioned in its documentation.
