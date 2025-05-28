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
| Absence of Anti-CSRF Tokens                  | Medium         | No CSRF protection implemented in forms.                                      | CWE-352     |
| Content Security Policy (CSP) Not Set        | Medium         | Missing header may lead to potential XSS vulnerabilities.                      | CWE-693     |
| Cookie Without HttpOnly Flag                 | Low            | Cookies can be accessed through client-side scripts.                           | CWE-1004    |
| Cookie Without Secure Flag                   | Low            | Cookies may be transmitted in cleartext over HTTP.                             | CWE-614     |
| Cookie Without SameSite Attribute            | Low            | Cookies are vulnerable to cross-site request forgery.                          | CWE-1275    |
| Server Leaks Version Information             | Low            | The "Server" header reveals version details of the web server.                 | CWE-200     |
| Strict-Transport-Security Header Not Set     | Medium         | Lack of HSTS header increases risk of man-in-the-middle attacks.               | CWE-319     |
| Session Management Response Identified       | Info           | Session IDs were captured, warranting review of session handling procedures.   | CWE-384     |
| User Agent Fuzzer                            | Info           | Indicates test traffic; likely a false positive.                               | N/A         |

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


