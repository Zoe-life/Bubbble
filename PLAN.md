# Bubbble — Detailed Implementation Plan

## 1. Vision & Mission

**Vision:** A world where anyone — especially content creators and influencers — can click any link they receive without fear of being compromised.

**Mission:** Bubbble wraps a protective "bubble" around every link before the user visits it. If the link is malicious, the bubble self-destructs (bursts), shielding the user and generating a full audit trail. If the link is safe, the bubble gracefully degrades, delivering the user seamlessly to their destination.

---

## 2. Core Product Concept

| Scenario | Bubble Behaviour | User Experience |
|---|---|---|
| Link is **safe** | Bubble gracefully degrades | User arrives at destination normally |
| Link is **malicious** | Bubble bursts / self-destructs | User is blocked; audit report is sent |
| Link is **unknown / suspicious** | Bubble holds while scanning | User sees a "scanning" indicator |

---

## 3. Target Audience

### Primary
- Kenyan and African social-media influencers (Instagram, TikTok, X/Twitter, YouTube, Facebook)
- Content creators at risk of account-hijacking attacks delivered via DMs, comments, or emails

### Secondary
- Global influencer and creator communities
- SMEs and individuals concerned about link-based phishing
- Corporate teams receiving links in collaboration tools (Slack, Teams, WhatsApp Business)

---

## 4. Product Scope (MVP → Full Product)

### Phase 0 — Research & Design (Weeks 1–4)
- UX research interviews with 20+ Kenyan influencers
- Define threat model: phishing, session-hijacking, credential harvesting, malware downloads, redirect chains
- Design system: bubble animations (inflate → hold → burst / gracefully deflate)
- Set up project infrastructure (monorepo, CI/CD, issue tracker)

### Phase 1 — Core Engine (Weeks 5–12)
- **URL Analysis Engine** (cloud microservice)
  - Integrate Google Safe Browsing API v4
  - Integrate VirusTotal API (70+ antivirus engines + URL scanners)
  - Integrate PhishTank / OpenPhish feeds
  - WHOIS / domain-age check (newly registered domains are higher risk)
  - SSL/TLS certificate validation (missing cert → high risk)
  - Redirect-chain unwinding (follow all hops before judging final destination)
  - Content preview fetch (headless browser screenshot + basic DOM analysis)
  - Risk scoring model (0–100): combines signals from all sources
- **Threat Intelligence Database**
  - Maintain local cache of known-bad domains/IPs
  - Subscribe to MISP feeds and abuse.ch blocklists
  - Auto-refresh every 15 minutes

### Phase 2 — Browser Extension MVP (Weeks 9–16)
- Supports: Chrome, Brave, Edge (Chromium Manifest V3); Firefox (MV2 → MV3)
- Intercepts every link click before navigation
- Shows animated bubble overlay while scanning (< 2 seconds target)
- Burst animation with brief explanation for malicious links
- Graceful deflate animation for safe links (minimal friction)
- Settings panel: sensitivity level, whitelist/blacklist, notification preferences
- Works offline with cached threat lists (degraded mode)

### Phase 3 — Mobile Apps (Weeks 13–22)
- **Android** (Kotlin + Jetpack Compose) — highest priority given African market
- **iOS** (Swift + SwiftUI)
- System-level link interception via Android Intent filters and iOS Universal Links
- Share-sheet integration: user can share any suspicious link to Bubbble for analysis
- Push notifications for audit reports
- Low-data mode: defer full scanning to Wi-Fi, use lightweight local model on mobile data

### Phase 4 — Audit & Reporting System (Weeks 17–24)
- Per-user audit log stored securely (end-to-end encrypted)
- Audit report generated after every burst:
  - Link that was blocked
  - Threat category (phishing, malware, credential harvesting, etc.)
  - Origin platform (WhatsApp, Instagram DM, email, etc.)
  - Technical indicators (redirect chain, domain age, certificate issues)
  - Recommended action (e.g., "change your Instagram password if you clicked this link on another device")
- Export reports as PDF (useful for reporting attacks to authorities or platforms)
- Aggregate dashboard: weekly / monthly threat summary

### Phase 5 — Influencer-Specific Features (Weeks 21–28)
- **Account Protection Monitor:** monitor linked social accounts for signs of compromise
- **Link Quarantine Inbox:** route suspicious links received via DMs into a quarantine feed for review without opening them
- **Trusted Sender Whitelist:** auto-trust links from verified brand partners / managers
- **Collaboration with African cybersecurity agencies:** CISA Africa, KE-CIRT/CC (Kenya Computer Incident Response Team)
- **Swahili & French UI localisation** (to reach Francophone Africa)

### Phase 6 — API & Enterprise Tier (Weeks 25–32)
- Public REST API for businesses to integrate link scanning into their own apps
- Webhook support for automated threat alerts
- Multi-seat enterprise dashboard
- SLA-backed scanning (< 500 ms p95)
- SSO / SAML integration

---

## 5. Technical Architecture

```
┌─────────────────────────────────────────────────────┐
│                   CLIENT LAYER                      │
│  Browser Extension  │  Android App  │  iOS App      │
└────────────┬────────┴───────┬───────┴───────┬───────┘
             │                │               │
             └────────────────▼───────────────┘
                        BUBBBLE GATEWAY
                  (API Gateway + Auth + Rate Limit)
                              │
          ┌───────────────────┼───────────────────┐
          ▼                   ▼                   ▼
  URL ANALYSIS ENGINE   THREAT INTEL DB    AUDIT SERVICE
  (Node.js / Python)    (Redis + Postgres)  (Node.js)
          │                   │                   │
  ┌───────▼───────┐   ┌───────▼───────┐   ┌───────▼───────┐
  │ Safe Browsing │   │  Blocklist     │   │  Notification  │
  │ VirusTotal    │   │  Cache         │   │  Service       │
  │ PhishTank     │   │  (15-min TTL)  │   │  (Email/Push)  │
  │ WHOIS/SSL     │   └───────────────┘   └───────────────┘
  └───────────────┘
```

### Technology Stack

| Layer | Technology |
|---|---|
| Browser Extension | TypeScript, Manifest V3, React (popup UI) |
| Android App | Kotlin, Jetpack Compose, Retrofit |
| iOS App | Swift, SwiftUI, URLSession |
| Backend API | Node.js (Fastify) or Python (FastAPI) |
| URL Analysis | Python (aiohttp, Playwright for headless) |
| Database | PostgreSQL (user data, audits), Redis (threat cache) |
| Message Queue | RabbitMQ / AWS SQS (async scanning jobs) |
| Hosting | AWS / GCP (with Africa region nodes — AWS af-south-1 Cape Town) |
| CDN | Cloudflare (global, with African PoPs) |
| Auth | JWT + OAuth2 (social login: Google, Apple) |
| CI/CD | GitHub Actions |

---

## 6. Security Architecture

- All URL scanning happens **server-side** — the user's device never visits the link directly during analysis
- Links are analysed in a **sandboxed headless browser** (Playwright + Docker) on the server
- User audit logs are **end-to-end encrypted**; Bubbble cannot read their content
- No URLs are logged beyond what is necessary for the audit report
- GDPR and Kenya Data Protection Act (2019) compliant data handling
- Third-party API keys stored in a secrets manager (AWS Secrets Manager / HashiCorp Vault)
- Penetration testing before each major release

---

## 7. UX & Design Principles

- **Instant feedback:** scanning must feel fast (< 2 s). Progress indicator shown while bubble is "inflating"
- **Emotionally resonant animations:** the bubble concept is playful and non-threatening; burst animation is dramatic enough to be memorable
- **Minimal friction for safe links:** graceful degradation is nearly invisible
- **Clear language:** avoid technical jargon in alerts — use plain, accessible English (and Swahili)
- **Accessibility:** WCAG 2.1 AA compliance; screen-reader support
- **Mobile-first design** given African smartphone-dominant browsing patterns

---

## 8. Monetisation Strategy

| Tier | Price (KES / USD) | Features |
|---|---|---|
| Free | 0 | 50 link scans/month, basic audit reports, browser extension |
| Creator | KES 500 / $4 per month | Unlimited scans, full audit reports, link quarantine inbox |
| Pro Influencer | KES 1,500 / $11 per month | All Creator features + account monitoring, PDF exports, trusted sender manager |
| Enterprise API | Custom | REST API, SLA, multi-seat dashboard, SSO |

---

## 9. Go-to-Market Strategy

### Kenya & East Africa (Launch)
- Partner with Kenyan influencer marketing agencies (e.g., Viral Mgmt, Influencer Africa)
- Partner with KE-CIRT/CC for credibility and co-promotion
- Sponsor digital creator events (Nairobi Tech Week, Social Media Week Africa)
- Free Pro plan for top 100 Kenyan influencers (seed user programme)
- Swahili-language onboarding and support

### Pan-Africa Expansion
- Localise for Nigeria (English), Ghana (English), South Africa (English/Afrikaans), Kenya (Swahili), Francophone Africa (French)
- Partner with Africa-focused cybersecurity communities (AfricaCERT, Cyber9/12 Africa)

### Global
- Product Hunt launch
- Partnership with creator economy platforms (e.g., Gumroad, Beacons)
- App store optimisation (ASO) for keywords: "link safety", "phishing protection", "influencer security"

---

## 10. Key Risks & Mitigations

| Risk | Mitigation |
|---|---|
| False positives blocking legitimate links | Tunable sensitivity + one-click "I trust this link" override with logging |
| API rate limits / costs (VirusTotal, etc.) | Aggressive local caching; tiered API usage by subscription level |
| Slow scan times frustrating users | Async scanning with optimistic UI; lightweight local ML model for quick pre-screening |
| Limited internet connectivity in Africa | Offline mode with pre-downloaded blocklists; lightweight mobile build |
| Circumvention via URL shorteners | Unwind all redirect chains before scoring |
| Privacy concerns about sending URLs to server | Transparent privacy policy; option for on-device lite scanning |
| Regulatory: Kenya Data Protection Act | Privacy-by-design architecture; appoint a Data Protection Officer |

---

## 11. Success Metrics (KPIs)

- **Month 3:** 1,000 active users, 50 verified influencer accounts
- **Month 6:** 10,000 active users, 500 influencer accounts, < 1% false-positive rate
- **Month 12:** 50,000 active users, 5,000 influencer accounts, first enterprise customer
- **Ongoing:** Mean scan time < 1.5 s, user retention (Day 30) > 40%, NPS > 50

---

## 12. Compliance & Legal

- **Kenya Data Protection Act 2019** — register as a Data Processor, appoint DPO
- **GDPR** (for EU users) — lawful basis for processing, right to erasure
- **Terms of Service & Privacy Policy** — drafted before public launch
- **Computer Misuse and Cybercrimes Act (Kenya) 2018** — align threat reporting with national frameworks

---

## 13. Milestone Timeline Summary

| Milestone | Target |
|---|---|
| UX research & design system | Week 4 |
| Core URL analysis engine (beta) | Week 12 |
| Browser extension MVP (Chrome) | Week 16 |
| Android app MVP | Week 20 |
| iOS app MVP | Week 22 |
| Audit & reporting system | Week 24 |
| Influencer-specific features | Week 28 |
| Public API | Week 32 |
| Kenya public launch | Week 34 |
| Pan-Africa expansion | Week 44 |

---

*Last updated: March 2026*
