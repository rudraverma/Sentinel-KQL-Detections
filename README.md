
---

![Built with KQL](https://img.shields.io/badge/Built%20with-KQL-blue?style=for-the-badge&logo=microsoft)
![MITRE ATT&CK](https://img.shields.io/badge/Mapped%20to-MITRE%20ATT%26CK-orange?style=for-the-badge&logo=mitre)
![SOC Ready](https://img.shields.io/badge/Optimized%20for-SOC%20Operations-purple?style=for-the-badge)
![Ethical Hacking](https://img.shields.io/badge/Ethical%20Hacking-Yes-green?style=for-the-badge)
![CyberHawk Consultancy](https://img.shields.io/badge/🦅-CyberHawk%20Consultancy-black?style=for-the-badge)

---

# 🧠 About This Repo

Welcome to **CyberHawk Threat Intel – Sentinel KQL Queries**, a curated collection of **Microsoft Sentinel** detection and hunting queries crafted for **real-world adversary simulation and defense**.  
This repo empowers **SOC analysts, threat hunters, and cyber defenders** to detect, investigate, and respond to modern cyber threats efficiently.

> 💬 *"They can't exploit you if you are the exploit."* — **CyberHawk Consultancy**

---

## ⚔️ Categories

| Category | Focus Area |
|-----------|-------------|
| 🩸 **Initial Access** | Phishing, malicious scripts, exploit detections |
| 🔒 **Privilege Escalation** | Token abuse, admin misuse, credential theft |
| 🕶 **Defense Evasion** | Obfuscated scripts, tampering, log deletion |
| 📡 **Command & Control** | Beaconing, DNS tunneling, persistence |
| 💣 **Exfiltration & Impact** | Ransomware, data staging, shadow copy deletion |
| 📘 **Hunting Queries** | IOC sweeps, anomaly analysis, behavioral hunting |

---

## 🧩 Example Query

```kql
// Detect potential credential dumping via LSASS access
SecurityEvent
| where EventID == 10 and ProcessName contains "lsass.exe"
| extend TargetProcess = tostring(Process)
| summarize Count = count() by Computer, TargetProcess, Account
| where Count > 5
| project TimeGenerated, Computer, Account, TargetProcess, Count
