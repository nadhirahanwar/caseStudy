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
**Date of Scan:** 2025-06-21
**Scanned By:** Irdeena Zahierah Binti Zukipeli
**Target Application:** https://huris.iium.edu.my/irecruit  
**Scan Type:** Passive 
**Scan Duration:** 12:15 AM - 1:30 AM

---

## 1. Executive Summary

| Metric                         | Value            |
|-------------------------------|------------------|
| Total Issues Identified       | 15    |
| Critical Issues               | 0          |
| High-Risk Issues              | 0         |
| Medium-Risk Issues            | 5          |
| Low-Risk/Informational Issues | 10         |
| Remediation Status            | Complete |

**Key Takeaway:**  
The scan detected 15 issues, with 5 medium, 5 low and 5 informational priority alerts. The absence of CSRF tokens, missing CSP Header, insecure cookie flags, missing security headers and server information disclosure were among the most notable vulnerabilities. Immediate attention is required for CSRF mitigation and secure session handling. No critical issues were founds.

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability          |
|------------|------------------|--------------------------------|
| Critical   | 0              |   |
| High       | 0              |  |
| Medium     | 5              | Absence of Anti-CSRF Tokens, CSP Header not set, Format String Error, Missing Anti-clickjacking Header, Session ID in URL Rewrite       |
| Low        | 5              | Cookie without secure flag, Cookie without SameSite attribute, Server leaks version information via "Server" HTTP Response Header Field, Strict-Transport-Security Header not set, X-Content-Type-Options Header missing   |
| Info       | 5          | Authentication request identified, information disclosure-suspicious comments, modern web application, session management response identified, user agent fuzzer |

---

## 3. Detailed Findings

### 3.1 Absence of Anti-CSRF Tokens

- **Severity:** Medium  
- **Description:**  
  No Anti-CSRF tokens were found in a HTML submission form

- **Affected URLs:**  
  - https://huris.iium.edu.my/irecruit/login;jsessionid=678E633A71FD51531C29C2DCA137A6A4
  - https://huris.iium.edu.my/irecruit/login?login_error=t

- **Business Impact:**  
  Attackers could trick authenticated users into executing unwanted actions without their consent

- **OWASP Reference:**  
 - https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
 - https://cwe.mitre.org/data/definitions/352.html

- **Recommendation:**  
  Implement CSRF protection by including tokens in all forms and validating them on the server side

- **Prevention Strategy:**  
  - Generate unique tokens per session and include them in all POST requests.
  - Use frameworks like anti-CSRF packages such as the OWASP CSRFGuard

> **Responsible Team:** Backend Development 
> **Target Remediation Date:** [YYYY-MM-DD]

---
### 3.2 Content Security Policy (CSP) Header Not Set

- **Severity:** Medium  
- **Description:**  
  Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware.

- **Affected URLs:**  
  - https://huris.iium.edu.my/irecruit/login;jsessionid=678E633A71FD51531C29C2DCA137A6A4
  - https://huris.iium.edu.my/irecruit/login?login_error=t
  - https://huris.iium.edu.my/robots.txt
  - https://huris.iium.edu.my/sitemap.xml

- **Business Impact:**  
  ...

- **OWASP Reference:**  
 - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
 - https://www.w3.org/TR/CSP/

- **Recommendation:**  
  Ensure that web server, application server, load balancer are configured to set the Content-Security-Policy header, which help reduce XSS risk.

- **Prevention Strategy:**  
  - ............

> **Responsible Team:** Backend Development 
> **Target Remediation Date:** [YYYY-MM-DD]

---
### 3.3 Session ID in URL Rewrite

- **Severity:** Medium  
- **Description:**  
  URL rewrite is used to track user session ID. The session ID may be disclosed via cross-site referer header. In addition, the session ID might be stored in browser history or server logs.

- **Affected URLs:**  
  - https://huris.iium.edu.my/irecruit/login;jsessionid=678E633A71FD51531C29C2DCA137A6A4
  - https://huris.iium.edu.my/irecruit/resources/styles/font-awesome/css/font-awesome.min.css;jsessionid=678E633A71FD51531C29C2DCA137A6A4
    
- **Business Impact:**  
  ...

- **OWASP Reference:**  
 - https://seclists.org/webappsec/2002/q4/111

- **Recommendation:**  
  For secure content, put session ID in a cookie. To be even more secure consider using a combination of cookie and URL rewrite.

- **Prevention Strategy:**  
  - Use cookie-based session management instead of URL rewriting

> **Responsible Team:** Backend Development 
> **Target Remediation Date:** [YYYY-MM-DD]
---
### 3.4 Cookie without Secure Flag

- **Severity:** Low  
- **Description:**  
  A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections

- **Affected URLs:**  
  - https://huris.iium.edu.my/robots.txt
  - https://huris.iium.edu.my/sitemap.xml
    
- **Business Impact:**  
  ...

- **OWASP Reference:**  
 - https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html

- **Recommendation:**  
  Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such sensitive information.

- **Prevention Strategy:**  
  - ..

> **Responsible Team:** Backend Development 
> **Target Remediation Date:** [YYYY-MM-DD]
---
### 3.5 Information Disclosure - Suspicious Comments

- **Severity:** Informational  
- **Description:**  
  The response appears to contain suspicious comments which may help an attacker

- **Affected URLs:**  
  - https://huris.iium.edu.my/irecruit
  - https://huris.iium.edu.my/irecruit/js/dojo/dojo/dojo.js
  - https://huris.iium.edu.my/irecruit/js/idle.js
  - https://huris.iium.edu.my/irecruit/resources/spring/Spring-Dojo.js
    
- **Business Impact:**  
  ...

- **Recommendation:**  
 Remove all comments that return information that may help an attacker and fix any underlying problems they refer to

- **Prevention Strategy:**  
  - ..

> **Responsible Team:** Backend Development 
> **Target Remediation Date:** [YYYY-MM-DD]
---
## 4. Recommendations & Next Steps

- Apply CSRF protection on all forms using secure token validation.
- Secure cookies by enabling Secure, HttpOnly, and SameSite attributes.
- Disable URL-based session IDs and switch to secure cookies for session tracking.
- Add missing headers (CSP, HSTS, X-Frame-Options) to enhance browser-level security.
- Schedule a retest after remediation and implement regular monthly scans.

---

## Appendix (Optional)
Configuration details : 
**3.1 Absence of Anti-CSRF Tokens** 
![image](https://github.com/user-attachments/assets/3d3b338b-c27f-45f4-baa3-1760f2280b83)
**3.2 Content Security Policy (CSP) Header Not Set** 
![image](https://github.com/user-attachments/assets/9c58447c-c9d6-43cf-9201-3cf94e17399e)
**3.3 Session ID in URL Rewrite** 
![image](https://github.com/user-attachments/assets/b15b1917-04bf-4b6e-a343-8e6a0899633d)
**3.4 Cookie without Secure Flag** 
![image](https://github.com/user-attachments/assets/b20efc1c-1a1e-40ac-89df-d0757056b9ce)
**3.5 Information Disclosure - Suspicious Comments** 
![image](https://github.com/user-attachments/assets/44e56dc5-8b2c-4a55-bb48-67f2c7bc32b5)

---

**Prepared by:**  
Irdeena Zahierah  
Student Kuliyyah of Information Communication and Technology 
irdeenazahierah03@gmail.com 
21/6/2025
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------
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

