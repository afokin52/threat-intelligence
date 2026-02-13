# Threat Intelligence Reports

Public threat intelligence reports and indicators of compromise (IOCs) from real-world incident investigations.

## Reports

### 2026-02-13 — Phishing Campaign via Google Drive with Browser Fingerprinting

A phishing campaign abusing Google's legitimate infrastructure (Drive, Cloud Storage, Gmail) to deliver a browser fingerprinting payload hosted on bulletproof infrastructure (PROSPERO OOO, AS200593).

**Key findings:**
- Multi-hop delivery chain through trusted Google domains bypassing email filters
- FingerprintJS v4.2.1 + BotD for victim profiling and scanner evasion
- Advanced cloaking: automated scanners redirected to msn.com, real users fingerprinted
- Reconnaissance operation — fingerprint harvesting linked to email tracking IDs, not credential theft
- Infrastructure hosted on PROSPERO OOO, a notorious bulletproof hosting provider

**Documents:**
- [Incident Report (English, TLP:CLEAR)](reports/2026-02-13-google-drive-fingerprinting/Incident_Report_2026-02-13_EN.pdf)
- [Отчёт об инциденте (Russian, TLP:CLEAR)](reports/2026-02-13-google-drive-fingerprinting/Incident_Report_2026-02-13_RU.pdf)

**IOCs:**

| Type | Value |
|------|-------|
| Domain | `online.accessinformnotice.com` |
| Domain | `accessinformattention.com` |
| IP | `91.202.233.71` |
| ASN | `AS200593` (PROSPERO OOO) |
| Netblock | `91.202.233.0/24` |
| URL | `online.accessinformnotice.com/secure/index_newest.html` |
| URL | `online.accessinformnotice.com/secure/secure.php` |
| GCS | `storage.googleapis.com/persontwelve/online/offer.html` |
| Google Drive | `drive.google.com/file/d/18XPn0pHsygsvZcinTivBQ_I225l-xzpC` |
| Email | `neyjardespbeg2002@secure.accessinformattention.com` |
| Server | `Apache/2.4.41 (Ubuntu)` |
| FingerprintJS | `v4.2.1` |

**MITRE ATT&CK:** T1566.002, T1036.005, T1036.001, T1204.001, T1608.005, T1090, T1583.003, T1217, T1041, T1592.004, T1598

---

## Author

**Aleksei Fokin** — DevOps / Infrastructure Engineer, Warsaw, Poland

Contact: info@afokin.com

## License

All reports are published under [TLP:CLEAR](https://www.first.org/tlp/) — no restrictions on distribution.