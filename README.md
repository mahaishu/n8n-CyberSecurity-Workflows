# 🚀 100 n8n Cybersecurity Workflow Ideas
Automation blueprints for **Red Team & Pentest**, **Blue Team (SOC/DFIR/TI)**, **Application Security (AppSec/DevSecOps)**, and **Platform/General Security** — all using **n8n**.

> Each idea lists **Purpose**, **Integrations**, and a **Flow Outline** you can translate into n8n nodes (HTTP Request, Execute Command, IF/Switch, Function, Code, Split In Batches, Merge, Set, Move Binary Data, Wait, Cron, Webhook, Email/Slack/Teams, PostgreSQL/MongoDB/Redis, AWS, GCP, Azure, RabbitMQ, Kafka, etc.).

---

## Index

- [A. Red Team & Pentest (30)](#a-red-team--pentest-30)
- [B. Blue Team / SOC / DFIR (35)](#b-blue-team--soc--dfir-35)
- [C. Application Security / DevSecOps (25)](#c-application-security--devsecops-25)
- [D. Platform & General Security (10)](#d-platform--general-security-10)
- [E. Reference Integrations](#e-reference-integrations)
- [F. Import & Build Tips](#f-import--build-tips)
- [G. License](#g-license)

---

## A. Red Team & Pentest (30)

1) **Automated Subdomain Recon Hub**  
**Purpose:** Consolidate subdomain intel continuously.  
**Integrations:** Subfinder/Amass (Exec), DNSDB/PassiveTotal (HTTP), Shodan/Censys, Slack, PostgreSQL.  
**Flow:** Cron → Exec(Subfinder/Amass) → HTTP(DNS/Passive) → HTTP(Shodan/Censys) → Merge/Unique → DB upsert → Slack summary.

2) **Attack Surface Change Detector**  
**Purpose:** Detect new hosts/ports/services vs last run.  
**Integrations:** Nmap/Naabu/Masscan (Exec), Diff (Function), Jira/Slack.  
**Flow:** Cron → Exec(scan) → Compare with last snapshot (DB) → Create Jira issues per delta → Slack alert.

3) **Cloud Bucket Finder (S3/GCS/Azure)**  
**Purpose:** Enumerate public buckets & misconfigs.  
**Integrations:** AWS/GCP/Azure APIs, HTTP HEAD/GET, Slack, CSV export.  
**Flow:** Cron → List buckets → Check ACL/public URLs → IF public → notify Slack + write CSV to S3.

4) **Credential Spraying Orchestrator (Lab/Test Only)**  
**Purpose:** Controlled spray against lab IdP for detection tuning.  
**Integrations:** Custom IdP/API, Delay/Rate-limit, Secret store.  
**Flow:** Webhook list → Split → Wait between attempts → HTTP(Auth) → Collect results → Red/Blue joint report.

5) **GoPhish Campaign Launcher**  
**Purpose:** Spin phishing tests end-to-end.  
**Integrations:** GoPhish API, Google Sheets (targets), Slack/Email, S3 for evidence.  
**Flow:** Trigger → Fetch targets → GoPhish API(create campaign) → Poll stats → Export CSV/PDF → Send digest.

6) **Malicious Macro Build Conveyor (PoC)**  
**Purpose:** Generate PoC docs for awareness labs.  
**Integrations:** Dockerized builder, Git repo, Hashing node, VT private sandbox (optional).  
**Flow:** Webhook payload → Build (Docker) → Hash → Store to S3 → Share link + Slack.

7) **Payload Inventory & Hash Tracker**  
**Purpose:** Track artifacts, hashes, and usage.  
**Integrations:** S3, PostgreSQL, Slack.  
**Flow:** Upload webhook → Compute SHA256 → DB upsert (who/when/use) → Notify Slack.

8) **C2 Beacon Event Forwarder**  
**Purpose:** Stream C2 events to collab channels.  
**Integrations:** CS/Havoc/Sliver webhooks, Slack/Discord, TimescaleDB.  
**Flow:** Webhook(C2) → Transform → Insert DB → Slack threaded updates per host.

9) **Initial Access Monitor (Decoy Links)**  
**Purpose:** Observe clicks, IPs, User-Agents.  
**Integrations:** n8n Webhook, GeoIP, AbuseIPDB.  
**Flow:** Webhook click → Enrich(GeoIP/ASN) → IF(bad reputation) → tag IOC → Push to TI DB.

10) **Exfiltration Simulation to Cloud**  
**Purpose:** Test DLP detection.  
**Integrations:** S3/GDrive/Dropbox, Slack, Timer.  
**Flow:** Cron → Upload decoy file → Verify receipt → Notify SOC channel.

11) **AV/EDR Evasion Test Matrix Runner (Lab)**  
**Purpose:** Run known OPSEC variations against lab EDR.  
**Integrations:** Exec, Git repo of samples, Jira.  
**Flow:** Schedule → Execute cases → Collect detections → Auto-create Jira tasks for misses.

12) **TLS/Cert Recon Harvester**  
**Purpose:** Track cert issuance & SANs.  
**Integrations:** crt.sh, Censys, DB, Email.  
**Flow:** Cron → Query certs → Diff vs history → Email changes.

13) **Shadow IT Finder (App Enumeration)**  
**Purpose:** Identify unmanaged domains/apps.  
**Integrations:** SecurityTrails, Shodan, HTTP banner grabs.  
**Flow:** Fetch domains → HTTP checks → Tag suspicious → Report.

14) **Vuln Exploit Window Notifier**  
**Purpose:** Alert when a new PoC drops for in-scope CVE.  
**Integrations:** GitHub RSS, NVD, Exploit-DB, Slack.  
**Flow:** Poll feeds → Filter by CVEs seen in scans → Slack “exploit available” ping.

15) **Password Dump Honeytoken Telemetry**  
**Purpose:** Detect credential reuse events.  
**Integrations:** Canarytokens, Webhook, TI DB.  
**Flow:** Honeytoken fire → Enrich IP → Store IOC → Notify.

16) **Adversary Path Builder (ATT&CK)**  
**Purpose:** Compose ordered technique runs.  
**Integrations:** JSON (technique sets), Exec scripts, Confluence export.  
**Flow:** Select profile → Iterate techniques → Log output → Publish runbook.

17) **Browser Exploit Canary (XSS)**  
**Purpose:** Receive callbacks for injected beacons.  
**Integrations:** Webhook, Slack, urlscan.io.  
**Flow:** Host payload → When fired → Slack + store evidence.

18) **SSRF Canary Endpoint**  
**Purpose:** Detect SSRF attempts during tests.  
**Integrations:** Webhook, GeoIP, Headers parser.  
**Flow:** Receive hits → Parse metadata → Map source app → Report.

19) **Perimeter Tech Stack Mapper**  
**Purpose:** WhatWeb/Wappalyzer at scale.  
**Integrations:** Exec(whatweb) or HTTP(Wappalyzer), DB.  
**Flow:** Enumerate targets → Fingerprint → Store/Trend.

20) **Default Creds Sweep (Lab)**  
**Purpose:** Validate controls block weak creds.  
**Integrations:** HTTP basic/digest, SSH, SNMP, Slack.  
**Flow:** Parametrized list → Parallel attempts → Results table → Slack.

21) **API Fuzzing Loop (Dev/Test)**  
**Purpose:** Fuzz endpoints nightly.  
**Integrations:** ZAP/Ffuf/Katana, CI callbacks.  
**Flow:** Cron → Discover → Fuzz → Deduplicate → File Jira bugs.

22) **Email Security Bypass Lab Orchestrator**  
**Purpose:** Test mail controls (EOP/GWS).  
**Integrations:** SMTP, IMAP/Gmail API, VirusTotal.  
**Flow:** Send test set → Pull verdicts → Score bypass rate → Report.

23) **Windows Lateral Movement Lab Runner**  
**Purpose:** Practice PSRemoting/WMI/SMB.  
**Integrations:** WinRM node/SSH to jump host, Logging DB.  
**Flow:** Task list → Execute → Capture outputs → Heatmap.

24) **Phishing Landing Page Telemetry**  
**Purpose:** High-fidelity user behavior.  
**Integrations:** Webhook (form), Device fingerprint, GeoIP.  
**Flow:** Capture → Normalize → Risk scoring → Export CSV.

25) **Recon to Report (One-Click)**  
**Purpose:** Draft recon PDF from data.  
**Integrations:** DB → Markdown → PDF, Confluence.  
**Flow:** Query latest intel → Render Markdown → Convert PDF → Publish.

26) **Bluetooth/IoT Discovery (Lab)**  
**Purpose:** Detect BLE beacons, rogue IoT.  
**Integrations:** Custom sensor API, DB, Slack.  
**Flow:** Poll sensors → New MACs? → Alert + tag.

27) **WIFI Evil Twin Drill Tracker**  
**Purpose:** Simulate & log detections.  
**Integrations:** Exec(hostapd/airmon-ng), Slack, Timeline.  
**Flow:** Start/stop runs → Record detections → Timeline report.

28) **Red Team Debrief Packager**  
**Purpose:** Bundle artifacts + timelines.  
**Integrations:** S3, Zip, Confluence/Jira.  
**Flow:** Select engagement → Pull logs → Zip → Upload & link.

29) **OpSec Sanity Checker**  
**Purpose:** Check infra hygiene before ops.  
**Integrations:** DNS/WHOIS, CDN, IP rep, Cloud SG.  
**Flow:** Validate → IF leaks/misconfigs → Blocker alert.

30) **C2 Infra Expiry & Burn Plan**  
**Purpose:** Auto-retire infra on schedule.  
**Integrations:** Cloud APIs, DNS API, Slack.  
**Flow:** Daily check → If TTL reached → Destroy resources → Log.

---

## B. Blue Team / SOC / DFIR (35)

31) **Threat Intel Ingest & Normalize**  
**Purpose:** Aggregate OTX/MISP/VT/AbuseIPDB.  
**Integrations:** HTTP, CSV/JSON, PostgreSQL/Elastic.  
**Flow:** Cron → Fetch feeds → Map fields (STIX-ish) → Upsert → De-dup metrics.

32) **IOC Enrichment Micro-SOAR**  
**Purpose:** On-demand IP/URL/hash enrichment.  
**Integrations:** VirusTotal, urlscan.io, WHOIS, Shodan.  
**Flow:** Webhook IOC → Parallel enrich → Confidence score → Respond with JSON.

33) **Impossible Travel Detector**  
**Purpose:** Geo-anomalies in IdP logins.  
**Integrations:** Okta/Azure AD, GeoIP, Slack/Jira.  
**Flow:** Pull events → Sort by user → Velocity calc → Alert.

34) **OAuth App Risk Auditor**  
**Purpose:** Risky third-party OAuth grants.  
**Integrations:** Google/M365 Graph, Sheets, Slack.  
**Flow:** Pull grants → Score scopes → Notify owners.

35) **SIEM → Slack Alert Router**  
**Purpose:** Targeted, deduped alerting.  
**Integrations:** Splunk/Elastic API, Slack threads.  
**Flow:** Poll alerts → IF severity+not seen → Post thread per incident.

36) **EDR Noise Tamer**  
**Purpose:** Suppress known benigns, highlight real.  
**Integrations:** CrowdStrike/Defender API, Redis cache.  
**Flow:** Ingest → Check allowlist cache → IF new → escalate.

37) **Phishing Auto-Triage**  
**Purpose:** Classify, detonate, verdict.  
**Integrations:** Gmail/Graph, VT/AnyRun, Jira.  
**Flow:** Fetch reported → Extract URLs/attachments → Sandbox → Verdict → Ticket.

38) **Ransomware Canary Tripwire**  
**Purpose:** Early encryption detection.  
**Integrations:** SMB share watch, Slack, IR runbook link.  
**Flow:** Monitor canary changes → IF entropy spike → Page on-call.

39) **DNS Tunneling Heuristics**  
**Purpose:** Spot long, frequent queries.  
**Integrations:** DNS logs (Elastic), Function scoring.  
**Flow:** Daily job → Flag FQDNs → TI cross-check → Alert.

40) **Beaconing Periodicity Detector**  
**Purpose:** C2-like intervals.  
**Integrations:** Proxy/NetFlow, FFT periodicity (Function/Code).  
**Flow:** Pull flows → Compute periodogram → Alert candidates.

41) **URL Detonation Pipeline**  
**Purpose:** Classify links from alerts.  
**Integrations:** urlscan.io, VT, Screenshot API, S3.  
**Flow:** For each URL → Scan → Take screenshot → Store & return verdict.

42) **Abuse Mailbox Automation**  
**Purpose:** Triage employee-reported spam.  
**Integrations:** IMAP, Regex extractor, Jira.  
**Flow:** Read inbox → Extract IOCs → Enrich → Auto-close or escalate.

43) **Threat Actor Tracker**  
**Purpose:** Follow APT infra changes.  
**Integrations:** TI feeds, ASN/IP whois.  
**Flow:** Monitor named actor sets → Update watchlists → Digest.

44) **SOAR Containment Buttons**  
**Purpose:** Semi-auto block actions.  
**Integrations:** EDR isolate, FW/WAF IP block, Okta suspend.  
**Flow:** Slack action → n8n webhook → Execute API call → Confirm.

45) **Cloud Config Drift Watch**  
**Purpose:** Detect risky cloud changes.  
**Integrations:** AWS/GCP/Azure config APIs, Jira.  
**Flow:** Hourly diff → If public/privilege escalation → Ticket.

46) **S3 Public Object Sentinel**  
**Purpose:** Alert on public ACLs.  
**Integrations:** AWS S3, Slack.  
**Flow:** ListObjectsV2 → Check ACL → Alert + Fix suggestion.

47) **Exposed Secret Honeypot**  
**Purpose:** Leak detector.  
**Integrations:** Canarytokens webhook, TI DB.  
**Flow:** Receive trigger → Enrich → Block list update.

48) **Endpoint Tamper Watch**  
**Purpose:** Detect EDR kill/disable.  
**Integrations:** EDR events, Slack paging.  
**Flow:** Subscribe → IF tamper → Page & open incident.

49) **Macro Risk Scorer**  
**Purpose:** Rate Office attachments.  
**Integrations:** O365/Google, OLE parser (Function), VT.  
**Flow:** Download → Analyze → Score → Verdict email.

50) **Okta MFA Fatigue Monitor**  
**Purpose:** MFA spam pattern detection.  
**Integrations:** Okta logs, Slack/Jira.  
**Flow:** Count prompts/user window → If abnormal → Alert.

51) **Brute-Force Heatmap**  
**Purpose:** Visualize auth failures.  
**Integrations:** SIEM query, Grafana/Looker.  
**Flow:** Daily extract → Aggregate → Publish dashboard.

52) **Insider Data Egress Guard**  
**Purpose:** Sensitive files egress spikes.  
**Integrations:** DLP logs, Drive/OneDrive APIs.  
**Flow:** Pull file events → Thresholds → Escalate.

53) **Malspam Campaign Correlator**  
**Purpose:** Cluster similar emails.  
**Integrations:** IMAP, TLS certs, Sending IP.  
**Flow:** Group by features → Label clusters → Report.

54) **IR War Room Orchestrator**  
**Purpose:** Spin up channel + checklist.  
**Integrations:** Slack/Teams, Confluence, PagerDuty.  
**Flow:** Webhook incident → Create channel → Post runbook → Page roles.

55) **Asset Risk Joiner**  
**Purpose:** Merge asset CMDB + vuln + EDR.  
**Integrations:** ServiceNow, Qualys/Tenable, EDR.  
**Flow:** Nightly join → Ownership mapping → Top 10 risky assets.

56) **Threat Hunt Notebook Seeds**  
**Purpose:** Push IOCs to detections.  
**Integrations:** SAVED searches, Jupyter links.  
**Flow:** TI change → Generate hunt queries → Post to SOC channel.

57) **GeoIP Block Auto-Update**  
**Purpose:** Keep geo blocks fresh.  
**Integrations:** Firewall API, GeoIP DB.  
**Flow:** Monthly refresh → Apply policy → Verify.

58) **Password Leak Monitor**  
**Purpose:** Compromised creds watch.  
**Integrations:** HaveIBeenPwned (k-Anon), HR DB, Email.  
**Flow:** Hash search → If match → Notify user + force reset.

59) **Public Paste Scraper**  
**Purpose:** Keys/emails leaks.  
**Integrations:** Pastebin/GitHub search, Regex, Jira.  
**Flow:** Crawl → Extract → De-dupe → Tickets.

60) **SOC Daily Briefing Builder**  
**Purpose:** Morning digest.  
**Integrations:** SIEM top alerts, TI deltas, Open incidents.  
**Flow:** 07:30 Cron → Compile → Email/Slack brief.

65) **Endpoint Golden Image Drift**  
**Purpose:** Detect drift from baseline.  
**Integrations:** EDR inventory, Hash lists.  
**Flow:** Weekly compare → Deviations → Fix tasks.

62) **VPN Anomaly Detector**  
**Purpose:** Abnormal session length/volume.  
**Integrations:** VPN logs, Function.  
**Flow:** Aggregate → Z-score outliers → Alert.

63) **Shadow Admin Finder**  
**Purpose:** Hidden/high-priv accounts.  
**Integrations:** AD/Azure AD, IAM APIs.  
**Flow:** Enumerate roles → Diff vs registry → Notify.

64) **Email Auth Health (SPF/DKIM/DMARC)**  
**Purpose:** Prevent spoofing.  
**Integrations:** DNS checks, DMARC reports parse.  
**Flow:** Weekly check → Score → Action items.

65) **Webhook Abuse Sentinel**  
**Purpose:** Detect mass webhook fires.  
**Integrations:** API gateways, Rate metrics.  
**Flow:** Monitor → Threshold → Block rule.

66) **Printer/OT Device Watch**  
**Purpose:** OT anomalies.  
**Integrations:** Syslog/NetFlow, OT vendor API.  
**Flow:** Collect → Rules → Notify OT team.

67) **SSL/TLS Weak Cipher Patrol**  
**Purpose:** Find weak suites.  
**Integrations:** sslscan/sslyze, DB.  
**Flow:** Scan → Parse → Jira tasks.

---

## C. Application Security / DevSecOps (25)

68) **SAST on PR with Semgrep**  
**Purpose:** PR-time static analysis.  
**Integrations:** GitHub/GitLab, Semgrep (Docker), Jira.  
**Flow:** Webhook PR → Run Semgrep → Annotate checks → Fail/Pass → Ticket.

69) **DAST Nightly with ZAP**  
**Purpose:** Crawl/scan staging.  
**Integrations:** ZAP API, Slack, HTML report to S3.  
**Flow:** Cron → ZAP Spider+Active → Threshold → Notify.

70) **Software Composition Analysis**  
**Purpose:** Dependency vulns.  
**Integrations:** Trivy/Grype, GH Dependabot API.  
**Flow:** Build event → Scan → SBOM → Gate release.

71) **Container Image Policy Gate**  
**Purpose:** Block critical CVEs.  
**Integrations:** Trivy, Registry API, ArgoCD.  
**Flow:** Push → Scan → If critical → Block tag → Notify.

72) **IaC Misconfig Scanner**  
**Purpose:** Terraform/K8s checks.  
**Integrations:** Checkov/Terraform Cloud, Jira.  
**Flow:** PR → Scan → Inline findings → Ticket.

73) **Secrets Scanner**  
**Purpose:** Prevent key leaks.  
**Integrations:** TruffleHog/Gitleaks, Slack.  
**Flow:** Commit hook → Scan → Quarantine secrets → Rotate reminder.

74) **CICD SBOM + Provenance**  
**Purpose:** SLSA-ish attestations.  
**Integrations:** Syft, Cosign, Registry.  
**Flow:** Build → SBOM → Sign → Attach to artifact.

75) **API Contract Drift Guard**  
**Purpose:** OpenAPI drift alerts.  
**Integrations:** SwaggerHub/Postman, ZAP passive.  
**Flow:** PR → Diff OpenAPI → Raise change approvals.

76) **GraphQL Introspection Guard**  
**Purpose:** Block introspection in prod.  
**Integrations:** HTTP check, WAF rule.  
**Flow:** Daily check → If enabled → Open ticket → Push WAF fix.

77) **CSP/Headers Compliance**  
**Purpose:** Security headers baseline.  
**Integrations:** HTTP HEAD, Report-Only evaluation.  
**Flow:** Crawl → Evaluate headers → Gap report.

78) **File Upload Abuse Tests**  
**Purpose:** MIME bypass, polyglots.  
**Integrations:** ZAP/Custom scripts, S3.  
**Flow:** Test set → Upload → Analyze response → Raise bugs.

79) **SSRF Canary Test Pack**  
**Purpose:** Validate egress filters.  
**Integrations:** Canary endpoint, Logs.  
**Flow:** Send crafted URLs → Check callbacks → Report.

80) **Rate Limit & AuthZ Fuzzer**  
**Purpose:** Business logic flaws.  
**Integrations:** Ffuf/Katana, Test users.  
**Flow:** Scenario runner → Detect 429/401 gaps → Ticket.

81) **Mobile AppSec via MobSF**  
**Purpose:** APK/IPA scans.  
**Integrations:** MobSF API, Slack.  
**Flow:** Upload build → Scan → Risk grade → Gating.

82) **Dependency Auto-PR Remediator**  
**Purpose:** Auto-bump libs.  
**Integrations:** Renovate/Bot, CI checks.  
**Flow:** Nightly → Raise PRs → Tag owners → Merge if green.

83) **Static Secrets Rotation Helper**  
**Purpose:** Track key ages.  
**Integrations:** Vault/Secrets Manager, Git repos.  
**Flow:** Inventory secrets → Age calc → Reminders.

84) **App Attack Telemetry Loop**  
**Purpose:** Replay prod attacks in staging.  
**Integrations:** WAF logs, ZAP replay.  
**Flow:** Extract patterns → Generate cases → Scan staging.

85) **Compliance Pack (PCI/SOC2)**  
**Purpose:** Control checks evidence.  
**Integrations:** Cloud APIs, CI logs, Jira.  
**Flow:** Monthly pull → Evidence bundle → Confluence.

86) **Feature-Flag Abuse Tests**  
**Purpose:** Access control around flags.  
**Integrations:** FF platform API, Test scripts.  
**Flow:** Enumerate flags → Try cross-role access → Report.

87) **CORS/Redirect Weakness Finder**  
**Purpose:** Misconfig combos.  
**Integrations:** HTTP checks, Regex rules.  
**Flow:** Crawl → Test origins → Flag dangerous combos.

88) **Session Management Validations**  
**Purpose:** Cookie scope, rotation.  
**Integrations:** HTTP, ZAP scripts.  
**Flow:** Login → Action → Invalidate → Verify.

89) **CI Artifact Leakage Guard**  
**Purpose:** Private artifact exposure.  
**Integrations:** CI API, Bucket scans.  
**Flow:** Enumerate → Try fetch unauth → Ticket.

90) **Access Tokens Exposure Watch**  
**Purpose:** Public repo/token sprawl.  
**Integrations:** GH/GitLab search API, Regex.  
**Flow:** Search org → Alert → Revoke/rotate tasks.

91) **SCA License Compliance**  
**Purpose:** License policies.  
**Integrations:** FOSSology/Trivy, Jira.  
**Flow:** Analyze SBOM → Violations → Tickets.

92) **Perf & Sec Regression Join**  
**Purpose:** Correlate perf + sec.  
**Integrations:** k6/Gatling, ZAP.  
**Flow:** Run both → Correlate regressions with vulns → Gate release.

---

## D. Platform & General Security (10)

93) **Vuln Digest with Prioritization**  
**Purpose:** CVEs → asset exposure → exploitability.  
**Integrations:** NVD, EPSS/KEV, CMDB, Jira.  
**Flow:** Fetch CVEs → Join assets → Score(EPSS+KEV) → Ticket.

94) **TLS Expiry & Rotation Planner**  
**Purpose:** No surprise expirations.  
**Integrations:** crt.sh, Cert managers, Calendar.  
**Flow:** Gather expiring → Create rotation plan → Email owners.

95) **Risk Register Auto-Curator**  
**Purpose:** Keep risks current.  
**Integrations:** Jira/ServiceNow, Sheets.  
**Flow:** Weekly sync → Archive stale → Nudge owners.

96) **Backup Integrity & RPO Check**  
**Purpose:** Validate backup SLAs.  
**Integrations:** Backup API, Hashing, Slack.  
**Flow:** Verify jobs → Sample restore hash → Report.

97) **Data Classification Guardrails**  
**Purpose:** Tag data & control spread.  
**Integrations:** DLP, Drive/SharePoint APIs.  
**Flow:** Scan labels → If sensitive in public → Auto-restrict.

98) **Geo Blocklist Lifecycle**  
**Purpose:** Maintain geo policy.  
**Integrations:** GeoIP, FW APIs.  
**Flow:** Quarterly review → Update rules → Validate reachability.

99) **Security Awareness Insights**  
**Purpose:** Trend training vs incidents.  
**Integrations:** LMS, SIEM, BI tool.  
**Flow:** Join datasets → KPI report → Exec summary.

100) **Red↔Blue Exercise Loop (Purple)**  
**Purpose:** Simulate, detect, improve.  
**Integrations:** ATT&CK set, ZAP/Caldera/Atomic, SIEM/EDR.  
**Flow:** Plan techniques → Execute → Collect detections → Create engineering tasks.

---

## E. Reference Integrations

**Recon/Offensive:** Subfinder, Amass, Naabu, Nmap, Masscan, Shodan, Censys, WhatWeb/Wappalyzer, ffuf, ZAP, Katana, Metasploit, Sliver, Havoc, Cobalt Strike (events).  
**Blue/SOC:** Splunk, Elastic, CrowdStrike, Defender for Endpoint, Okta/Azure AD/Google Workspace, MISP, AlienVault OTX, VirusTotal, AbuseIPDB, urlscan.io, AnyRun/Cuckoo.  
**AppSec/DevSecOps:** Semgrep, Trivy/Grype, Checkov, MobSF, Syft/Cosign, Renovate, Dependabot, SwaggerHub/Postman.  
**Cloud/Infra:** AWS (S3, IAM, Config), GCP (Storage, IAM, SCC), Azure (Blob, Graph), Vault/Secrets Manager.  
**Collab/Ticketing:** Slack, Microsoft Teams, Jira, ServiceNow, Confluence, Gmail/Outlook.  
**Data/Storage:** PostgreSQL, TimescaleDB, Elastic, MongoDB, S3/GCS/Azure Blob, Google Sheets.  

---

## F. Import & Build Tips

- **Node choices:** Prefer **HTTP Request** for APIs, **Execute Command** for scanners, **Function/Code** for glue logic, **IF/Switch** for decisions, **Split In Batches** for lists, **Merge** for joins, **Wait** for pacing/rate-limits.  
- **Credentials:** Use n8n **Credentials** securely; never hard-code secrets in Function nodes.  
- **Idempotency:** Upsert to DB and include **de-dupe keys** (hashes, IOC values, domain).  
- **Observability:** Add **Run IDs**, **trace context**, and **metrics counters** (success/fail, new/duplicate).  
- **Safety:** Offensive workflows must run only in **authorized scope**
