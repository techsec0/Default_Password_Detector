# Default Password Detector 🔐

## Overview
Default Password Detector is a security-focused project designed to identify the use of default or weak passwords in systems. The goal of this project is to improve system security by detecting commonly used default credentials.

The project includes a **Java-based GUI**, a **Python detection script**, and **JSON-based credential storage**.

---

## Team Members
**This project is actively maintained by the development team. We continuously improve reliability, fix issues, and add new features based on project requirements and security best practices.**
- Yash Patel – **Project Lead & Security/Core Logic**
- Gaurav Kumavat – **Java GUI Development**
- Parth Rathod – **Core Logic & Data Handling**
- Shoaib Patel – **Database & Documentation**

---

## Project Structure
DefaultPasswordDetector/
│
├── default_pass_detector.py
├── DefaultPasswordDetector.java
├── run_gui.bat
├── credentials_db.json
├── temp_credentials.json
│
├── lib/
│ ├── gson-2.10.1.jar
│ └── javafx-sdk-24.0.2/


---

## Features
- Detects commonly used default passwords
- JavaFX-based graphical user interface
- Python-based password detection logic
- JSON files for credential storage
- Easy execution using a batch script

## Advanced fetures
- **Advanced Detection & Accuracy**
The system is designed to minimize false positives by validating detected credentials against structured datasets and contextual checks, improving the accuracy and reliability of results.

- **Automated Dependency Handling**
The project supports automatic installation and management of required libraries, ensuring smoother setup and consistent execution across environments.

- **Network & Credential Scanning Capabilities**
The tool is capable of scanning single IP addresses, IP ranges, and full subnets to identify active hosts and evaluate SSH and FTP services for default or weak password usage.
It supports automated password checks on exposed services, enabling practical assessment of common credential-based security risks in network environments.

---

## Technologies Used
- Java (JavaFX)
- Python
- JSON
- Git & GitHub

---

## Requirements
- Java JDK 17 or later
- JavaFX SDK (included in project)
- Python 3.x
- Windows OS (for `.bat` file)

---

## How to Run the Project

### 1️⃣ Run Java GUI
Double-click on run_gui or run from command prompt:
```bash
**run_gui.bat**
[The tool currently uses a Windows batch (.bat) file for controlled and secure execution of the application. This approach ensures consistent startup configuration and safe environment initialization. In future versions, the batch launcher will be replaced with a compiled executable (.exe) to improve portability, usability, and deployment security.]
=======
# Default_Password_Detector
Security tool that scan port for check default password on that !

