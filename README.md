
# Case Study: Vulnerability Assessment of IIUM HURIS Using OWASP ZAP
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
  - Block requests without a valid token

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
Without CSP, site is more vulnerable to Cross-Site Scripting (XSS) attacks. If a malicious script is injected, it can steal cookies, hijack sessions, or redirect users to phishing pages.

- **OWASP Reference:**  
 - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
 - https://www.w3.org/TR/CSP/

- **Recommendation:**  
  Ensure that web server, application server, load balancer are configured to set the Content-Security-Policy header, which help reduce XSS risk.

- **Prevention Strategy:**  
  - Add header `Content-Security-Policy: default-src 'self'; script-src 'self';` under middleware

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
Generate the session ID in the URL like ;usersessionid=XYZ can leak user sessions through browser history, logs, or referrer headers. An attacker who gets this ID could hijack someone’s session even without security knowledge. 

- **OWASP Reference:**  
 - https://seclists.org/webappsec/2002/q4/111

- **Recommendation:**  
  For secure content, put session ID in a cookie. To be even more secure consider using a combination of cookie and URL rewrite.

- **Prevention Strategy:**  
  - Use cookie-based session management instead of URL rewriting
  - Use secure session cookies with short expiration
  - Regenerate session ID after login or privilege changes

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
Cookies without the Secure flag may be transmitted over unencrypted (HTTP) connections. If this happens, attackers on the same network can sniff and steal session cookies

- **OWASP Reference:**  
 - https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html

- **Recommendation:**  
Set the Secure flag on all cookies so they’re only sent over HTTPS

- **Prevention Strategy:**  
  - In backend or server settings, mark all cookies as `Set-Cookie: SESSIONID=abc123; Secure; HttpOnly; SameSite=Strict` 

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
Comments in HTML or JavaScript (e.g., <!-- TODO: remove debug -->) can expose sensitive logic, admin URLs, or unfinished code to attackers. These clues might help attackers plan their next move

- **Recommendation:**  
 Remove all comments that return information that may help an attacker and fix any underlying problems they refer to

- **Prevention Strategy:**  
  - Do code reviews to check for leftover comments

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
**Date of Scan:** 2025-06-23  
**Scanned By:** HUSNA NADHIRAH BINTI KHAIRUL ANWAR  
**Target Application:** https://huris.iium.edu.my/online 
**Scan Type:** PASSIVE SCAN 
**Scan Duration:** 9:47 AM - 10:38 AM

---

## 1. Executive Summary

| Metric                         | Value            |
|-------------------------------|------------------|
| Total Issues Identified       | 9   |
| Critical Issues               | 0         |
| High-Risk Issues              | 0         |
| Medium-Risk Issues            | 2          |
| Low-Risk/Informational Issues | 7          |
| Remediation Status            | Complete |

**Key Takeaway:**  
The scan detected 9 issues, with 2 medium, 5 low and 2 informational priority alerts. The absence of CSRF tokens, CSP Header not set, insecure cookie flags, cookie without SameSite attribute, server information disclosure and Strict-Transport-Security Header not set were among the most notable vulnerabilities. Immediate attention is required for CSRF mitigation and CSP Header. No critical issues were founds.

---

## 2. Summary of Findings

| Risk Level | Number of Issues | Example Vulnerability          |
|------------|------------------|--------------------------------|
| Critical   | 0          | -  |
| High       | 0          | -         |
| Medium     | 2          | Absence of Anti-CSRF Tokens, CSP Header Not Set      |
| Low        | 5          | Cookie No HttpOnly Flag, Cookie Without Secure Flag, Cookie without SameSite Attribute, Server Lekas Version Information, Strict-Transport-Security Header Not Set  |
| Info       | 2         | Session Management Response Identified, User Agent Fuzzer |

---

## 3. Detailed Findings

### 3.1 Absence of Anti-CSRF Tokens

- **Severity:** Medium 
- **Description:**  
  No Anti-CSRF tokens were found in a HTML submission form.

- **Affected URLs:**  
  - https://huris.iium.edu.my/online

- **Business Impact:**  
  Attackers could trick authenticated users into executing unwanted actions without their consent.

- **OWASP Reference:**  
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
  - https://cwe.mitre.org/data/definitions/352.html

- **Recommendation:**  
  Implement CSRF protection by including tokens in all forms and validating them on the server side.

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
  - https://huris.iium.edu.my/online
  - https://huris.iium.edu.my/robots.txt
  - https://huris.iium.edu.my/sitemap.xml

- **Business Impact:**  
  Site is more vulnerable to attacks like XSS and data injection. This can lead to data theft, session hijacking, defacement, or malware distribution. For a university HR system, it risks exposing sensitive staff or student data, damaging reputation, and violating data protection laws.

- **OWASP Reference:**  
  - https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy
  - https://cwe.mitre.org/data/definitions/352.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  - https://www.w3.org/TR/CSP/
  - https://w3c.github.io/webappsec-csp/
  - https://web.dev/articles/csp
  - https://caniuse.com/#feat=contentsecuritypolicy
  - https://content-security-policy.com/)

- **Recommendation:**  
  Implement a strong Content Security Policy (CSP) header on all web pages to control which resources (scripts, styles, images, etc.) can be loaded by the browser.

- **Prevention Strategy:**  
  - Set CSP Headers via web server (Apache/Nginx) or in application code.
  - Avoid inline scripts and eval() to simplify CSP rules.
  - Regularly test CSP using tools like Google CSP Evaluator.
  - Combine CSP with other headers like X-XSS-Protection and X-Content-Type-Options for layered security.
  - Monitor for violations using CSP report URIs to detect and fix issues proactively.

> **Responsible Team:** Backend Development 
> **Target Remediation Date:** [YYYY-MM-DD]

---

### 3.3 Cookie No HttpOnly FLag

- **Severity:** Low
- **Description:**  
  A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible.

- **Affected URLs:**  
  - https://huris.iium.edu.my/online

- **Business Impact:**  
  Without the HttpOnly flag, cookies (especially session cookies) are exposed to client-side scripts. If an attacker exploits a Cross-Site Scripting (XSS) vulnerability, they could steal session cookies, leading to session hijacking, unauthorized access, and data breaches. This compromises user trust and may result in reputation damage and non-compliance with data protection regulations.

- **OWASP Reference:**  
  - https://owasp.org/www-community/HttpOnly

- **Recommendation:**  
  Set the HttpOnly flag on all sensitive cookies, especially session cookies, to prevent access via JavaScript.

- **Prevention Strategy:**  
  - Always set HttpOnly on authentication/session cookies.
  - Combine with other flags like Secure and SameSite for stronger protection.
  - Conduct regular security audits to check for missing cookie flags.
  - Prevent XSS attacks to further reduce the risk of cookie theft.
    
> **Responsible Team:** Backend Development 
> **Target Remediation Date:** [YYYY-MM-DD]
>
---

### 3.4 Cookie Without Secure Flag 
- **Severity:** Low
- **Description:**  
  A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections.

- **Affected URLs:**  
  - https://huris.iium.edu.my/robots.txt
  - https://huris.iium.edu.my/sitemap.xml

- **Business Impact:**  
  Cookies—especially session cookies—can be transmitted over HTTP, making them vulnerable to interception by attackers via packet sniffing or man-in-the-middle (MITM) attacks. This may lead to session hijacking, unauthorized access, and data breaches, resulting in loss of user trust, reputation damage, and potential non-compliance with data privacy regulations.

- **OWASP Reference:**  
  - https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html

- **Recommendation:**  
  Set the Secure flag on all cookies to ensure they are only transmitted over HTTPS connections.

- **Prevention Strategy:**  
  - Enforce HTTPS across the entire website using HTTP Strict Transport Security (HSTS).
  - Always set the Secure flag for all sensitive cookies.
  - Test cookies in browser developer tools to confirm flag settings.
  - Include secure cookie settings in both application and server configurations.
    
> **Responsible Team:** Backend Development 
> **Target Remediation Date:** [YYYY-MM-DD]
---

### 3.5 Server Leaks Version Information via "Server" HTTP Response Header Field
- **Severity:** Low
- **Description:**  
  The web/application server is leaking version information via the "Server" HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to..

- **Affected URLs:**  
  - https://huris.iium.edu.my/online
  - https://huris.iium.edu.my/online/
  - https://huris.iium.edu.my/robots.txt
  - https://huris.iium.edu.my/sitemap.xml

- **Business Impact:**  
  Exposing server version details increases the attack surface by helping attackers fingerprint the server and match it with known exploits. This may lead to unauthorized access, service disruption, or data compromise, especially if the server is outdated or unpatched. It also reflects a lack of security hardening, which may affect compliance audits and institutional reputation.

- **OWASP Reference:**  
  - https://httpd.apache.org/docs/current/mod/core.html#servertokens
  - https://learn.microsoft.com/en-us/previous-versions/msp-n-p/ff648552(v=pandp.10)
  - https://www.troyhunt.com/shhh-dont-let-your-response-headers/

- **Recommendation:**  
  Suppress or remove the Server header from HTTP responses to prevent disclosing version information.

- **Prevention Strategy:**  
  - Disable version disclosure in the web server configuration.
  - Use a reverse proxy (e.g., Nginx, Cloudflare) to filter and sanitize headers.
  - Regularly update and patch web server software.
  - Conduct periodic header audits using tools like curl, security scanners, or browser dev tools.
    
> **Responsible Team:** Backend Development 
> **Target Remediation Date:** [YYYY-MM-DD]

## 4. Recommendations & Next Steps

- Prioritize fixing CSRF token absence and missing CSP header.
- Add HttpOnly, Secure, and SameSite flags to all cookies.
- Remove server version from HTTP headers and enable HSTS.
- Perform a new vulnerability scan after fixes are applied.
- Apply secure development practices in all future code.
- Schedule monthly or post-update scans.
- Penetration Testing: For deeper security validation.

---

## Appendix (Optional)

**3.1 Absence of Anti-CSRF Tokens** 
![image](https://github.com/user-attachments/assets/099920a4-78cf-414b-b85f-d7426b5ac0bc)

**3.2 Content Security Policy (CSP) Header Not Set**
![image](https://github.com/user-attachments/assets/1e9fae96-8986-427e-a606-b5be6581c8ec)

**3.3 Cookie No HttpOnly FLag**
![image](https://github.com/user-attachments/assets/da22618f-f741-453d-85f7-4167c5ec03e8)

**3.4 Cookie Without Secure Flag**
![image](https://github.com/user-attachments/assets/e6dcc764-dce7-44ec-9a2e-ed302c67fca1)

**3.5 Server Leaks Version Information via "Server" HTTP Response Header Field**
![image](https://github.com/user-attachments/assets/199b4d2b-3f62-4f7b-848d-bde3c2e7f745)


---

**Prepared by:**  
Husna Nadhirah
Student Kuliyyah of Information Communication and Technology
husnanadhirahedu@gamil.com
23/6/2025

