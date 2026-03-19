# Bubbble — Feasibility Report

## Executive Summary

Bubbble is a link-safety tool that wraps a protective "bubble" around any URL before a user visits it, detects malicious intent, and either blocks the threat (bubble bursts) or lets the user through seamlessly (bubble gracefully degrades). This report assesses the technical, operational, financial, market, regulatory, and social feasibility of building and launching Bubbble, with particular reference to the Kenyan and broader African context.

**Overall Verdict: Feasible with manageable risks.** The core technology is proven, the market gap is real and underserved, and the timing is right. Success depends on disciplined execution, strong community trust, and an Africa-first user experience that no competitor currently offers.

---

## 1. Technical Feasibility

### 1.1 Core Technology Availability

| Component | Feasibility | Notes |
|---|---|---|
| URL threat scanning | ✅ High | Google Safe Browsing, VirusTotal, PhishTank APIs exist and are well-documented |
| Browser extension | ✅ High | Manifest V3 (Chrome/Edge), Manifest V2→V3 (Firefox) are mature platforms |
| Android app | ✅ High | Android Intent filters enable system-level link interception |
| iOS app | ⚠️ Medium | iOS sandboxing limits system-level link interception; share-sheet integration is the primary mechanism |
| Redirect chain unwinding | ✅ High | Standard HTTP client with redirect following; headless browser for JS redirects |
| Headless browser sandboxing | ✅ High | Playwright + Docker for server-side sandboxed rendering |
| Audit report generation | ✅ High | Standard backend engineering; PDF export via libraries like Puppeteer or WeasyPrint |
| WhatsApp bot | ✅ High | WhatsApp Business API (Meta Cloud API) is available and well-supported |
| Real-time scanning (< 2 s) | ⚠️ Medium | Achievable with aggressive caching, async pipelines, and CDN edge nodes; requires careful engineering |
| Offline / low-bandwidth mode | ⚠️ Medium | Requires pre-downloadable blocklist bundles and a lightweight on-device ML model |

### 1.2 Infrastructure

- **Cloud hosting:** AWS af-south-1 (Cape Town, South Africa) provides a production-ready African cloud region with low latency to East Africa. GCP also has a Johannesburg region. Both are feasible.
- **Scalability:** Serverless functions (AWS Lambda) for scanning jobs allow cost-effective scaling from zero to millions of requests.
- **Reliability:** Managed database services (RDS Aurora, ElastiCache) provide 99.99% uptime SLAs.
- **Content Delivery:** Cloudflare has 13+ PoPs in Africa, ensuring fast asset delivery and DDoS protection.

### 1.3 Technical Risks

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| New attack techniques evade scanning | Medium | High | Multi-signal approach (not single API); continuous threat feed updates |
| VirusTotal / Google Safe Browsing API rate limits | Medium | Medium | Aggressive local caching; tiered API usage; fallback to local blocklists |
| iOS platform restrictions | High | Medium | Focus on share-sheet and Safari extension; monitor iOS evolution |
| Headless browser zero-days | Low | High | Run in isolated Docker containers; no network access from sandbox to production |
| Scan time > 2 seconds | Medium | Medium | Async scanning with optimistic UI; lightweight pre-screening model |

**Technical Feasibility Rating: 8/10** — All core components are buildable with existing technologies. The main engineering challenge is achieving consistently low scan latency.

---

## 2. Operational Feasibility

### 2.1 Team Requirements

To build Bubbble from MVP to public launch, the following roles are needed:

| Role | MVP Phase | Scale Phase |
|---|---|---|
| Full-Stack / Backend Engineer | 2 | 4 |
| Mobile Engineer (Android) | 1 | 2 |
| Mobile Engineer (iOS) | 1 | 2 |
| Security Engineer / Threat Intelligence Analyst | 1 | 2 |
| UI/UX Designer | 1 | 2 |
| DevOps / Cloud Engineer | 1 | 2 |
| Product Manager | 1 | 1 |
| Community Manager (Kenya-based) | 1 | 2 |

Kenya has a growing pool of software engineers (iLab Africa, Andela alumni, Strathmore University graduates), making local talent acquisition feasible. Competitive salaries in KES are significantly lower than equivalent USD salaries, reducing burn rate.

### 2.2 Partnerships Required

- **Threat intelligence:** Google Safe Browsing (free), VirusTotal (free tier + paid), PhishTank (free)
- **Payments:** Stripe (international) + M-Pesa (Daraja API, via Safaricom)
- **Cloud:** AWS Activate (startup credits available) or GCP for Startups
- **Credibility:** KE-CIRT/CC, AfricaCERT

### 2.3 Operational Risks

| Risk | Mitigation |
|---|---|
| Small founding team stretched thin | Prioritise ruthlessly; build MVP before adding features |
| Recruiting security talent in Kenya | Remote hiring; Andela / Turing talent networks |
| Third-party API dependency | Multi-provider fallback strategy; local threat cache |

**Operational Feasibility Rating: 7/10** — Buildable with a lean team. The main constraint is recruiting experienced security engineers locally.

---

## 3. Financial Feasibility

### 3.1 Estimated Development Costs (MVP — First 12 Months)

| Item | Estimated Cost (KES) | Estimated Cost (USD) |
|---|---|---|
| Engineering team (6 people × 12 months) | KES 21,600,000 | ~$167,000 |
| Design | KES 1,800,000 | ~$14,000 |
| Cloud infrastructure (AWS, Year 1) | KES 1,300,000 | ~$10,000 |
| Threat intelligence APIs (VirusTotal premium) | KES 650,000 | ~$5,000 |
| Legal (ToS, Privacy Policy, DPO registration) | KES 390,000 | ~$3,000 |
| Marketing & community (launch) | KES 1,300,000 | ~$10,000 |
| Miscellaneous / contingency (15%) | KES 4,000,000 | ~$31,000 |
| **Total Year 1** | **~KES 31,000,000** | **~$240,000** |

*Salary estimates based on Kenyan market rates for mid-senior engineers (KES 200,000–400,000/month).*

### 3.2 Funding Options

| Source | Amount | Notes |
|---|---|---|
| Bootstrapping (founder savings) | KES 0–5M | Limited but possible for a working prototype |
| Google for Startups Africa | Up to $200K in Cloud credits | Significant infra cost reduction |
| Startupbootcamp AfriTech | Mentorship + €15K cash | Kenya-relevant accelerator |
| Chandaria Innovation Centre (Strathmore) | Incubation support | Local institutional support |
| African Development Bank (seed grants) | Variable | Aligned with digital Africa agenda |
| Angel investors (Kenya tech community) | KES 5–20M | Growing angel network in Nairobi |
| Pre-seed VC (e.g., Novastar, TLcom Capital) | $200K–$1M | For traction-proven product |

### 3.3 Revenue Projections

**Conservative scenario (Year 1–3):**

| Year | Free Users | Paid Users (Creator/Pro) | MRR (USD) | ARR (USD) |
|---|---|---|---|---|
| Year 1 | 5,000 | 200 | $1,200 | $14,400 |
| Year 2 | 30,000 | 2,000 | $14,000 | $168,000 |
| Year 3 | 100,000 | 10,000 | $80,000 | $960,000 |

**Optimistic scenario (with enterprise API and partnerships):**

| Year | ARR (USD) |
|---|---|
| Year 1 | $50,000 |
| Year 2 | $400,000 |
| Year 3 | $2,000,000 |

### 3.4 Break-Even Analysis

At the Creator tier ($4/month average revenue per user), the tool reaches break-even at approximately **5,000 paid users**, assuming Year 3 operational costs of ~$240,000/year. This is achievable within 3 years given the market size.

**Financial Feasibility Rating: 6/10** — The business is financially viable but requires external funding for Year 1. Revenue at scale is clearly achievable; the challenge is surviving the early growth phase.

---

## 4. Market Feasibility

### 4.1 Market Demand Evidence

- **Influencer account hijacking is a documented, growing crisis.** High-profile cases of Nigerian, Kenyan, and South African influencers losing accounts are widely reported.
- Kenyan influencers surveyed by iLab Africa (2022) rated cybersecurity as a top-3 concern, yet fewer than 5% used any dedicated protection tool.
- The African cybersecurity market is growing at **12% CAGR** — faster than the global average.
- Mobile internet penetration in Kenya reached **44%** in 2023 (CA Kenya) and is growing rapidly.

### 4.2 Market Readiness

| Factor | Assessment |
|---|---|
| Awareness of link-based threats | Medium — growing after high-profile incidents |
| Willingness to pay for security | Low–Medium — freemium model essential |
| Smartphone penetration (Kenya) | High — 95%+ of internet access via mobile |
| App store access | High — Google Play dominant; iOS growing |
| WhatsApp penetration (Kenya) | Very High — primary communication channel |
| Trust in local tech products | Medium — preference for local solutions growing |

### 4.3 Adoption Barriers

| Barrier | Severity | Mitigation |
|---|---|---|
| Low security awareness | High | Education campaign, partner with KE-CIRT/CC |
| Reluctance to install extensions | Medium | WhatsApp bot and mobile app as primary channels |
| Price sensitivity | High | Generous free tier, KES pricing, M-Pesa |
| Trust in new/unknown product | High | KE-CIRT/CC endorsement, seed influencer programme |

**Market Feasibility Rating: 7/10** — Strong unmet need, but adoption requires significant community trust-building and education.

---

## 5. Social & Impact Feasibility

### 5.1 Social Impact

Bubbble has significant positive social impact potential:

- **Protecting livelihoods:** For Kenyan influencers, their social media account is their business. Account hijacking can mean instant loss of income, brand deals, and years of audience building.
- **Digital inclusion:** Making cybersecurity accessible and affordable for African creators — a group traditionally underserved by Western security vendors.
- **Empowerment of women creators:** Women are disproportionately targeted by malicious actors online in Africa; Bubbble provides a layer of protection accessible to all.
- **National security contribution:** Reducing successful phishing attacks contributes to Kenya's cybersecurity posture and aligns with the Kenya National Cybersecurity Strategy 2022–2027.

### 5.2 Alignment with National & Continental Goals

- **Kenya's Vision 2030:** Digital transformation and ICT as economic pillars.
- **African Union Digital Transformation Strategy 2020–2030:** Secure and resilient digital infrastructure for Africa.
- **Smart Africa Alliance:** Promotes pan-African digital economy including cybersecurity.

### 5.3 Potential for Harm (Ethical Considerations)

- **Privacy:** Sending user URLs to external scanning services must be disclosed clearly. Bubbble will adopt a privacy-first approach with minimal data retention and user consent.
- **False positives:** Incorrectly blocking legitimate links could harm businesses. The sensitivity tuning and user override mechanism mitigates this.
- **Dependency risk:** If Bubbble's service goes down, users relying on it may be unable to access links. Offline/degraded mode with local blocklists mitigates this.

**Social Feasibility Rating: 9/10** — Strong alignment with African digital development goals; clear, positive social impact.

---

## 6. Regulatory & Legal Feasibility

### 6.1 Kenya

| Regulation | Relevance | Status |
|---|---|---|
| **Data Protection Act 2019** | Governs collection/processing of personal data (URLs, user identity) | Must register as Data Processor with ODPC; appoint DPO |
| **Computer Misuse and Cybercrimes Act 2018** | Defines cyber offences; Bubbble's threat reporting aligns | Positive alignment; consult legal counsel on incident reporting obligations |
| **Communications Authority Act** | Governs digital communication services | Monitor for licensing requirements |

### 6.2 International

| Regulation | Relevance |
|---|---|
| **GDPR (EU)** | Applies to any EU users; requires lawful basis, right to erasure, data minimisation |
| **CCPA (California)** | Applies to California users; similar data rights requirements |
| **US CAN-SPAM / CASL** | Governs audit report emails; must include unsubscribe |

### 6.3 Platform Policies

- Browser extension stores (Chrome Web Store, Firefox Add-ons, Apple App Store) have review policies; Bubbble's functionality is standard and should pass review.
- WhatsApp Business API requires Meta approval; process takes 2–4 weeks but is well-established.

**Regulatory Feasibility Rating: 8/10** — Compliance is achievable with proper legal counsel and privacy-by-design architecture. Kenya's regulatory environment is supportive of cybersecurity innovation.

---

## 7. Overall Feasibility Summary

| Dimension | Score | Key Finding |
|---|---|---|
| Technical | 8/10 | All components are buildable; latency and iOS are key challenges |
| Operational | 7/10 | Lean team viable; security talent recruiting is the constraint |
| Financial | 6/10 | Requires seed funding for Year 1; path to profitability is clear |
| Market | 7/10 | Strong need; adoption barriers require education & freemium model |
| Social & Impact | 9/10 | Highly aligned with African digital development goals |
| Regulatory | 8/10 | Manageable with proper legal counsel and privacy-by-design |
| **Overall** | **7.5/10** | **Recommended to proceed** |

---

## 8. Recommendations

1. **Start with a WhatsApp bot + Android app** as the primary distribution channels for the Kenyan market, given mobile-first behavior and WhatsApp dominance.
2. **Build the browser extension in parallel** for desktop influencers who use social media on laptop/desktop.
3. **Apply for Google for Startups Africa credits immediately** to cover infrastructure costs during the pre-revenue phase.
4. **Run a seed influencer programme** — give free Pro access to 50–100 top Kenyan influencers in exchange for feedback and social proof.
5. **Register with the Office of the Data Protection Commissioner (ODPC)** as a Data Processor before public launch.
6. **Partner with KE-CIRT/CC** early for credibility and threat intelligence access.
7. **Validate the product with 20+ influencer interviews** before writing a line of code, to confirm feature prioritisation.
8. **Pursue angel funding or accelerator programmes** (Startupbootcamp AfriTech, MEST Africa) to bridge the Year 1 funding gap.

---

## 9. Conclusion

Bubbble addresses a real, growing, and underserved problem: the vulnerability of African content creators to link-based cyberattacks. No existing tool combines the Africa-first design, influencer-specific workflow, consumer-friendly UX, and affordable pricing that Bubbble plans to offer. The technical foundation is solid, the regulatory path is clear, and the social impact potential is substantial.

The primary risks — funding, adoption, and achieving consistent scan performance — are manageable with the right strategy. Bubbble is feasible and merits investment of time, talent, and capital.

**Proceed with development.**

---

*Last updated: March 2026*
