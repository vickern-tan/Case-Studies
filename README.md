# 🛡️ Cyber Attack Case Studies

Curated, research-grade write-ups of real-world cyber incidents. Each case distills what happened, how it worked (at a high level), why it mattered to the business, and how defenders can detect and respond—mapped to MITRE ATT&CK.

## 📦 What’s Inside
- Incident case studies
- MITRE ATT&CK mapping (TTPs, sub-techniques)
- Vulnerability references (CVE/CWE)
- CIA Triad & business impact summary
- Defensive guidance (detections, hardening, IR notes)
- Timelines, diagrams, and sanitized artifacts

## 🎯 Goals
- Provide a learning hub for students, analysts, DFIR practitioners, and researchers
- Showcase concise, responsible, and reproducible security analysis
- Emphasize defender value: detection logic, hypotheses, and mitigations

## 🗂 Repository Layout
/  
├─ README.md  
├─ LICENSE  
├─ .gitignore
├─ cases/  
│ └─ <CS001>/  
│ ├─ report.md # main write-up (sanitized, defender-centric)  
│ ├─ timeline.md # key dates (discovery → disclosure → patch)  
│ ├─ detections.md # hypotheses, hunting ideas, IOCs (safe)  
│ ├─ references.md # CVE/CWE, advisories, research links  
│ └─ attachments/ # images used in the case docs  
│ └─ POC-Decoded-Strings.png 
├─ index.md  
