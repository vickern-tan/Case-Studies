# 🛡️ Case Study 001 — SharePoint “ToolShell” (Sanitized)

Defender-centric write-up of suspected post-exploitation on a SharePoint/IIS host: `w3wp.exe` spawning PowerShell/CMD, attempted ASPX drop in **LAYOUTS**, and clear-text egress. No runnable PoC. Sensitive details redacted.

## 🔗 Quick Links
- **Report** → [CS001/report.md](CS001/report.md)
- **Detections (KQL + Stellar Cyber)** → [CS001/detections.md](CS001/detections.md)
- **Images** → [CS001/attachments/](CS001/attachments/)

## 📦 What’s Inside
- High-level chain, observables, ATT&CK mapping, and response ideas
- Ready-to-use **KQL** queries for MDE Advanced Hunting
- **Stellar Cyber** ATH rule sketch (builder/YAML-style)
- Sanitized IOCs to guide tuning

## 🎯 Goals
- Provide a learning hub for students, analysts, DFIR practitioners, and researchers.
- Showcase concise, responsible, and reproducible security analysis.
- Emphasize defender value: detection logic, hypotheses, and mitigations.

