# 🕵️‍♂️ ELHunter  
### EVTX Keyword-based Forensic Analysis Tool

---
![ELHunter_demo](https://github.com/user-attachments/assets/3720c51d-b427-4815-bede-4c3dbbe265d5)

## 🔍 Overview

**ELHunter** is a forensic-oriented CLI tool designed to hunt **keyword-based evidence**  
across **Windows Event Log (EVTX)** files in a structured and investigator-friendly manner.

The tool focuses on **readability, traceability, and evidential reporting**, making it suitable for:

- Digital forensics practice  
- Incident response analysis  
- Security investigation workflows  

> 📌 This repository provides **release binaries only**.  
> Source code is intentionally not disclosed.

---

## 👤 Author & Release

- **Author** : exyKim  
- **Version** : v1.0  
- **Release Date** : 2026-01-19  

---

## ✨ Key Features

- Analyze **single EVTX file** or **entire EVTX folders**
- Case-insensitive keyword hunting
- Real-time console output during analysis
- File-by-file evidence separation
- Structured forensic report generation (TXT)
- Automatic logging of:
  - User
  - Hostname
  - IP Address
  - Start / End Time
  - Elapsed Analysis Time

---

## ⚙️ How It Works (Logic Overview)

ELHunter operates in a **sequential, forensic-safe workflow**:

### 1️⃣ Input Selection
- User selects:
  - A single EVTX file  
  - OR a folder containing multiple EVTX files  

### 2️⃣ Keyword Definition
- One or more keywords are provided
- Matching is performed **without case sensitivity**

### 3️⃣ Event Parsing
- EVTX records are parsed sequentially
- XML event data is inspected internally
- Matching events are reported **in real time**

### 4️⃣ Evidence Structuring
- Detected events are grouped **per file**
- Each match is summarized with:
  - Event Time  
  - Event ID  
  - Key Data Field (summary)  

### 5️⃣ Forensic Report Generation
- Results are consolidated into a **single TXT report**
- Only files with detected evidence are included
- Investigator traceability is preserved

---

## ▶️ Usage

1️⃣ **Download**

Go to the Releases page and download the latest release archive.
ELHunter_v1.0.zip

2️⃣ **Extract**

Unzip the downloaded file to any directory.

3️⃣ **Run**

Open Command Prompt or PowerShell in the extracted directory
and execute the binary:

4️⃣ **Select Input Type**

<img width="737" height="810" alt="image" src="https://github.com/user-attachments/assets/af438e71-b001-4ea9-a9be-019363384360" />

5️⃣ **Enter Keywords**

6️⃣ **Review Results**

Matching events are displayed in real time

A summary is shown after the analysis completes

7️⃣ **Save Report (Optional)**

<img width="737" height="810" alt="image" src="https://github.com/user-attachments/assets/e6ac0805-931e-4c4b-8872-1fa51f3dac30" />



---
💡 **Notes**

- ELHunter is a portable CLI tool
- No installation is required
- Administrator privileges are not required
- Works with exported .evtx files

