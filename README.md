# Threat Intelligence Reports

Public threat intelligence reports and indicators of compromise (IOCs) from real-world incident investigations.

## Reports

### 2026-03-05 — WhatsApp Account Takeover via "Defisher" Phishing Kit

A phishing link distributed via Signal led to a WhatsApp account compromise through the device linking feature. The phishing site impersonated WhatsApp Web, tricking the victim into entering their phone number and then a device linking code. The attack was powered by a commercial phishing kit called "Defisher" — a Next.js application with an admin panel, WebSocket-based C2, and optional CIS country filtering.

**Key findings:**
- Phishing kit "Defisher": Next.js-based commercial tool with admin panel at `panel-my-test[.]online/auth`
- Two attack modes: QR code scanning and phone number-based device linking (phone mode used in this incident)
- WebSocket C2: phishing page communicates with backend via Socket.IO (`panel-my-test[.]online/api/socket`)
- CIS geo-filtering code present but **not active** in this campaign: source code contains `"Извините, ваш номер в зоне СНГ, ошибка"` handler, but active testing confirmed CIS numbers (RU, UA, KZ, BY) were accepted and received valid linking codes
- Infrastructure: AEZA Group (AS210644) — bulletproof hosting provider, FSB raid (Apr 2025), US OFAC sanctions (Jul 2025)
- Both domains registered 8 seconds apart (batch registration) via PDR Ltd., NS: timeweb.ru
- API endpoint exposed campaign stats: 210 views, 73 phone number inputs, campaign #8 on the server (at least 7 prior campaigns)
- Open Nginx Proxy Manager admin panel on port 81

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-03-05-whatsapp-defisher/Incident_Report_2026-03-05_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-03-05-whatsapp-defisher/Otchet_incident_WHATSAPP_DEFISHER_2026-03-05_TLP_CLEAR.pdf)

**IOCs:**

| Type | Value |
|------|-------|
| Domain | `trust-authorization[.]tech` (phishing page) |
| Domain | `panel-my-test[.]online` (C2 panel / WebSocket API) |
| IP | `147[.]45[.]43[.]133` (AEZA Group, AS210644, Frankfurt) |
| URL | `hxxps://trust-authorization[.]tech/pUsl9nuZo649dKua0HL7uG5npbYAq1bn` |
| URL | `hxxps://panel-my-test[.]online/api/socket` (WebSocket endpoint) |
| URL | `hxxps://panel-my-test[.]online/auth` (Defisher admin panel) |
| ASN | `AS210644` (AEZA-AS, bulletproof hosting) |
| Netblock | `147[.]45[.]43[.]0/24` (Aeza-Network) |
| SSH HASSH | `e42184b06d45385a906f0803d04c83da` |
| SSH Host Key SHA256 | `67e1fe70de94c56a515ae423ac6eded53e98a20cc7732114f661b372de82f934` |
| TLS Serial | `0571f6a08d8bad9c5aaad12c3a22a3012108` (trust-authorization[.]tech, LE E7) |
| TLS Serial | `06390e30192e8789eb02220f86d45db74a46` (panel-my-test[.]online, LE E8) |

**MITRE ATT&CK:** T1566.002, T1078, T1583.001, T1583.003, T1588.002, T1036.005, T1071.001, T1530

---

### 2026-03-02 — Targeted Phishing Impersonating Meta/Facebook Against a Human Rights NGO

A spear-phishing email impersonating Meta/Facebook was delivered to a Russian human rights NGO. The attackers chained legitimate services (Resend.com → Amazon SES) to achieve SPF pass, DKIM pass, and ARC pass, ensuring inbox delivery in Gmail. The phishing link led to a likely compromised legitimate British recruitment website, bypassing URL reputation filters.

**Key findings:**
- SPF, DKIM (×2), and ARC all passed — delivered to Gmail inbox, not spam
- Sending infrastructure: Resend.com email API → Amazon SES (ap-northeast-1, Tokyo) via domain registered at Sav.com (documented abuse issues)
- Phishing host: `skillbaseltd[.]co[.]uk` — confirmed domain hijacking after expiry (company in liquidation, cert evidence via crt.sh); bypasses URL reputation filters
- Broader infrastructure: cluster of 14 re-registered expired .co.uk domains on shared Cloudflare/cPanel hosting; 3 additional domains (`restorewellbeing[.]co[.]uk`, `rubyandginger[.]co[.]uk`, `senditmyway[.]co[.]uk`) have Resend+Amazon SES sending infrastructure pre-configured — staged for follow-on campaigns
- Display Name "M e t a" with spaces — evades brand-name filters matching exact string "Meta"
- Meta logo loaded directly from `facebook[.]com` — adds credibility and enables open tracking
- Targeted attack: recipient address associated with a specific organizational program, not publicly listed; email in Russian adapted to target profile

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-03-02-meta-phishing/Incident_Report_2026-03-02_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-03-02-meta-phishing/Incident_Report_2026-03-02_RU.pdf)

**IOCs:**

| Type | Value |
|------|-------|
| Email | `identity-policy@readlundy[.]com` |
| Domain | `readlundy[.]com` (sending domain, registered Aug 15, 2025) |
| Domain | `send.readlundy[.]com` (Resend SPF domain) |
| Domain | `skillbaseltd[.]co[.]uk` (phishing host) |
| URL | `hxxps://skillbaseltd[.]co[.]uk/` |
| IP | `23[.]251[.]234[.]52` (Amazon SES, ap-northeast-1, Tokyo) |
| IP | `104[.]21[.]15[.]116` (Cloudflare CDN) |
| Message-ID | `0106019caf15ae50-9ddecc03-8e54-4d63-b110-5cf354fbf092-000000@ap-northeast-1.amazonses.com` |
| Domain | `restorewellbeing[.]co[.]uk` (related infra: Resend+SES staged) |
| Domain | `rubyandginger[.]co[.]uk` (related infra: Resend+SES staged) |
| Domain | `senditmyway[.]co[.]uk` (related infra: Resend+SES staged) |

**MITRE ATT&CK:** T1583.001, T1583.006, T1584.001, T1585.002, T1566.002, T1056.003, T1656, T1036

---

### 2026-02-18 — Targeted Phishing Impersonating National Endowment for Democracy

A spear-phishing campaign impersonating the National Endowment for Democracy (NED), targeting individuals in the NGO sector with fabricated grant opportunities. The email was sent from a compromised Zambian real estate domain via Russian VPS infrastructure.

**Key findings:**
- Highly targeted: victim addressed by full name with fabricated reference to a prior NED grant application
- Sender impersonated a fictitious NED employee "Daniel Knaus" (real employee John Knaus exists)
- Infrastructure: SmartApe VPS (Moscow, DataPro datacenter) → StableServer relay → AntiSpamCloud → Gmail
- SPF/DKIM passed for the sending domain, bypassing basic email authentication
- Phantom attachment technique: email references an attached document that doesn't exist in MIME structure
- Likely multi-stage attack: initial email establishes trust, malicious payload delivered in follow-up

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-02-18-ned-phishing/Incident_Report_2026-02-18_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-02-18-ned-phishing/Incident_Report_2026-02-18_RU.pdf)

**IOCs:**

| Type | Value |
|------|-------|
| Email | `daniel.knaus@hunterspropertyzm[.]com` |
| Domain | `hunterspropertyzm[.]com` |
| IP | `188.127.227[.]111` (SmartApe VPS, Moscow) |
| Hostname | `s1277447.smartape-vps.com` |
| IP | `192.250.227[.]159` (stableserver.net relay) |
| IP | `185.201.18[.]54` (antispamcloud.com) |
| Message-ID | `177141183849.635335.*@s1277447.smartape-vps.com` |

**MITRE ATT&CK:** T1566.001, T1036.005, T1598, T1589, T1591, T1583.003, T1586.002, T1204.001, T1585

---

### 2026-02-13 — Phishing Campaign via Google Drive with Browser Fingerprinting

A phishing campaign abusing Google's legitimate infrastructure (Drive, Cloud Storage, Gmail) to deliver a browser fingerprinting payload hosted on bulletproof infrastructure (PROSPERO OOO, AS200593).

**Key findings:**
- Multi-hop delivery chain through trusted Google domains bypassing email filters
- FingerprintJS v4.2.1 + BotD for victim profiling and scanner evasion
- Advanced cloaking: automated scanners redirected to msn.com, real users fingerprinted
- Reconnaissance operation — fingerprint harvesting linked to email tracking IDs, not credential theft
- Infrastructure hosted on PROSPERO OOO (AS200593), a notorious bulletproof hosting provider labeled "BULLETPROOF" by Censys
- Same IP hosts multiple phishing campaigns: DocuSign impersonation (`docusign.notifyentryflow[.]com`) and additional domains active through late February 2026

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-02-13-google-drive-fingerprinting/Incident_Report_2026-02-13_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-02-13-google-drive-fingerprinting/Incident_Report_2026-02-13_RU.pdf)

**IOCs:**

| Type | Value |
|------|-------|
| Domain | `online.accessinformnotice[.]com` |
| Domain | `accessinformnotice[.]com` |
| Domain | `accessinformattention[.]com` |
| Domain | `docusign.notifyentryflow[.]com` (related: DocuSign impersonation, same IP) |
| Domain | `notifyentryflow[.]com` (related: parent domain) |
| Domain | `warningentrypath[.]com` (related: same IP, active Feb 26, 2026) |
| IP | `91.202.233[.]71` (PROSPERO OOO, St. Petersburg) |
| ASN | `AS200593` (PROSPERO OOO, bulletproof hosting) |
| Netblock | `91.202.233[.]0/24` |
| URL | `hxxps://online.accessinformnotice[.]com/secure/index_newest.html` |
| URL | `hxxps://online.accessinformnotice[.]com/secure/secure.php` |
| GCS | `hxxps://storage.googleapis[.]com/persontwelve/online/offer.html` |
| Google Drive | `hxxps://drive.google[.]com/file/d/18XPn0pHsygsvZcinTivBQ_I225l-xzpC` |
| Email | `neyjardespbeg2002@secure.accessinformattention[.]com` |
| Server | `Apache/2.4.41 (Ubuntu)` |
| FingerprintJS | `v4.2.1` |
| TLS Cert | `50f8484b5501e0132ef7ffc1614590845ccdc9375e53d81d2f7d7119a0387d3c` (SHA-256) |

**MITRE ATT&CK:** T1566.002, T1036.005, T1036.001, T1204.001, T1608.005, T1090, T1583.003, T1217, T1041, T1592.004, T1598

---

## Author

**Aleksei Fokin** — DevOps / Infrastructure Engineer, Warsaw, Poland

Contact: info@afokin.com

## License

All reports are published under [TLP:CLEAR](https://www.first.org/tlp/) — no restrictions on distribution.
