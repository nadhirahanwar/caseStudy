# Case Study: Vulnerability Assessment of IIUM HURIS Using OWASP ZAP

This document presents a detailed case study of the vulnerability assessment performed on the IIUM Human Resource Information System (HURIS) using OWASP ZAP. The study outlines the tools used, the methodology followed, the vulnerabilities identified, and recommendations for mitigation.

---

## Introduction

The IIUM Human Resource Information System (HURIS) is a critical application used in the academic environment for managing HR-related tasks. This case study focuses on identifying potential security vulnerabilities using the OWASP ZAP tool, with the aim of enhancing the security posture of the application.

---

## Objectives

- To perform an automated and manual vulnerability scan on HURIS.
- To identify potential security issues that may affect confidentiality, integrity, and availability.
- To provide recommendations for mitigating the identified vulnerabilities.

---

## Tools and Environment

- **OWASP ZAP** – Open-source web application security scanning tool.
- **Browser (Firefox/Chrome)** – Configured to use OWASP ZAP as a proxy.
- **Operating System** – Windows/Linux/Mac (configuration details provided in the methodology).

---

## Methodology

### Configuration

1. **OWASP ZAP Installation**:  
   Download and install OWASP ZAP from [https://www.zaproxy.org/download/](https://www.zaproxy.org/download/).

2. **Browser Proxy Setup**:  
   Configure your browser to use `localhost` as the proxy server with port `8080`.
   
   - **Firefox**:  
     - Navigate to Settings → Network Settings → Manual Proxy Configuration.
     - Input `localhost` for HTTP Proxy and set port to `8080`.
     - Ensure "Use this proxy server for all protocols" is checked.
   
   - **Chrome**:  
     Chrome uses system proxy settings, so set the proxy in your OS’s settings accordingly.

3. **Certificate Installation**:  
   Install the ZAP root certificate in your browser to avoid HTTPS warnings:
   - Download the certificate from `http://zap`.
   - Import it into your browser under the Certificates section and trust it for identifying websites.

### Scanning Process

1. **Target URLs**:  
   The primary pages for the scan included:
   - [https://huris.iium.edu.my/](https://huris.iium.edu.my/)
   - [https://huris.iium.edu.my/online](https://huris.iium.edu.my/online)
   

2. **Automated Scanning**:  
   - Used ZAP's "Quick Start" feature to run an automated scan against the target URLs.
   - Monitored for alerts in the “Alerts” tab.

3. **Manual Exploration**:  
   - Navigated through the application manually with the proxy enabled to ensure all areas were covered.
   - This assisted in revealing any pages or parameters not captured by the automated scan.

---

## Findings

### Alert Summary

The scan identified a total of **9 alerts**, including vulnerabilities related to session management, cookie security, and missing security headers. A summary of the critical alerts is shown below:

| **Alert**                                    | **Risk Level** | **Description**                                                                 | **CWE ID**  |
|----------------------------------------------|----------------|---------------------------------------------------------------------------------|-------------|
| Absence of Anti-CSRF Tokens                  | Medium         | No Anti-CSRF tokens were found in a HTML submission form.                      | CWE-352     |
| Content Security Policy (CSP) Not Set        | Medium         | Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware.                    | CWE-693     |
| Cookie Without HttpOnly Flag                 | Low            | A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible.                           | CWE-1004    |
| Cookie Without Secure Flag                   | Low            | A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections.                            | CWE-614     |
| Cookie Without SameSite Attribute            | Low            | A cookie has been set without the SameSite attribute, which means that the cookie can be sent as a result of a 'cross-site' request. The SameSite attribute is an effective counter measure to cross-site request forgery, cross-site script inclusion, and timing attacks.                         | CWE-1275    |
| Server Leaks Version Information             | Low            | The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.               | CWE-200     |
| Strict-Transport-Security Header Not Set     | Medium         | HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.           | CWE-319     |
| Session Management Response Identified       | Informational           | The given response has been identified as containing a session management token. The 'Other Info' field contains a set of header tokens that can be used in the Header Based Session Management Method. If the request is in a context which has a Session Management Method set to "Auto-Detect" then this rule will change the session management to use the tokens identified.   | CWE-384     |
| User Agent Fuzzer                            | Informational           | Check for differences in response based on fuzzed User Agent (eg. mobile sites, access as a Search Engine Crawler). Compares the response statuscode and the hashcode of the response body with the original response.                            | N/A         |

### Detailed Findings

#### 1. Absence of Anti-CSRF Tokens
- **Risk Level**: Medium  
- **Issue**: Forms across the application lack anti-CSRF tokens, leaving authenticated sessions vulnerable to CSRF attacks.  
- **Recommendation**: Implement CSRF tokens in form submissions and validate them on the server-side.

#### 2. Missing Content Security Policy (CSP)
- **Risk Level**: Medium  
- **Issue**: Without CSP, the application is more susceptible to cross-site scripting (XSS) attacks.  
- **Recommendation**: Define and enforce a robust Content Security Policy.

#### 3. Cookie Configuration Issues
- **Risk Level**: Low  
- **Issues**:
  - Cookies missing the HttpOnly flag can be accessed via JavaScript.
  - Cookies without the Secure flag may be transmitted over insecure channels.
  - Cookies lacking the SameSite attribute can be exploited via CSRF.
- **Recommendation**: Ensure all cookies are configured with HttpOnly, Secure, and SameSite attributes appropriately.

#### 4. Information Disclosure
- **Risk Level**: Low  
- **Issue**: The web server leaks version information in the Server header.  
- **Recommendation**: Hide or modify server headers to prevent disclosing internal details.

#### 5. Strict-Transport-Security (HSTS) Absence
- **Risk Level**: Medium  
- **Issue**: Without HSTS, users may be vulnerable to protocol downgrade attacks.  
- **Recommendation**: Configure the web server with HSTS headers to enforce HTTPS.

---

## Recommendations and Mitigations

- **Enhance CSRF Protections**: Integrate anti-CSRF tokens into all forms and perform token validation on the server.
- **Implement CSP and HSTS**: Establish security headers (CSP, HSTS) to reduce the risk of XSS and MITM attacks.
- **Improve Cookie Security**: Set all cookies with the appropriate flags, including HttpOnly, Secure, and SameSite.
- **Minimize Information Disclosure**: Modify server configurations to suppress version information.
- **Regular Security Assessments**: Conduct periodic vulnerability scans and manual reviews to maintain a robust security posture.

---

## Conclusion

The use of OWASP ZAP has effectively identified several security vulnerabilities in the HURIS application. Although some alerts are low risk or informational, critical findings such as the absence of CSRF protection and lack of security headers must be promptly addressed. The remediation actions suggested in this report will help improve the overall security of the application.

---

## References

- [OWASP ZAP Documentation](https://www.zaproxy.org/getting-started/)
- [Common Weakness Enumeration (CWE)](https://cwe.mitre.org/)
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)

# Web Application Vulnerability Scan Report

**Tool Used:** OWASP ZAP  
**Date of Scan:** [YYYY-MM-DD]  
**Scanned By:** [Name/Team]  
**Target Application:** [Application Name or URL]  
**Scan Type:** [Active / Passive]  
**Scan Duration:** [Start Time – End Time]

---

## 1. Executive Summary

| Metric                         | Value            |
|-------------------------------|------------------|
| Total Issues Identified       | [Total Count]    |
| Critical Issues               | [Count]          |
| High-Risk Issues              | [Count]          |
| Medium-Risk Issues            | [Count]          |
| Low-Risk/Informational Issues | [Count]          |
| Remediation Status            | [Pending/In Progress/Complete] |

**Key Takeaway:**  
[Brief overview: e.g., "The scan identified 2 high-risk vulnerabilities that require immediate attention. No critical issues were found."]

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability          |
|------------|------------------|--------------------------------|
| Critical   | [Count]          | [e.g., Remote Code Execution]  |
| High       | [Count]          | [e.g., SQL Injection]          |
| Medium     | [Count]          | [e.g., Insecure Cookies]       |
| Low        | [Count]          | [e.g., Missing HTTP Headers]   |
| Info       | [Count]          | [e.g., Server Version Exposed] |

---

## 3. Detailed Findings

### [Vulnerability Title 1]

- **Severity:** [Critical / High / Medium / Low / Info]  
- **Description:**  
  [Short explanation of the issue]

- **Affected URLs:**  
  - [https://example.com/path1](#)
  - [https://example.com/path2](#)

- **Business Impact:**  
  [Explain potential consequence in non-technical terms.]

- **OWASP Reference:**  
  [https://owasp.org/www-project-top-ten/](#)

- **Recommendation:**  
  [Suggested fix, e.g., "Validate user inputs using allow-lists."]

- **Prevention Strategy:**  
  - Enforce input validation.
  - Use secure HTTP headers.
  - Apply regular code reviews and testing.

> **Responsible Team:** [e.g., DevOps]  
> **Target Remediation Date:** [YYYY-MM-DD]

---

(Repeat for each major vulnerability)

---

## 4. Recommendations & Next Steps

- Address **Critical** and **High** vulnerabilities **immediately**.
- Re-test application after remediation.
- Integrate secure coding standards.
- Schedule periodic scans (e.g., monthly or post-deployment).
- Consider a penetration test for in-depth analysis.

---

## Appendix (Optional)

- Scan configuration details  
- List of all scanned URLs  
- Full technical findings (for security team)

---

**Prepared by:**  
[Your Name]  
[Your Role / Department]  
[Email / Contact]  
[Date]


