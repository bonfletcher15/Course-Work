# SQRhub System Overview

**SQRhub** is a web-based service that assists with malware analysis by offering the following core functionalities:

- File analysis  
- URL analysis  
- IP address, domain, or file hash analysis  

These are powered through integration with the online cybersecurity service **VirusTotal**, using a personalized API key.

---

## Main Features

Users interact with the system via **three main tabs**:

1. **File Analysis**
2. **URL Scan**
3. **Search**  
   *(Used for IP address, domain, or file hash analysis)*

Each scan or analysis is performed within its respective tab.

---

## Scan Results Display

- Results from VirusTotal (summary and details) are displayed on the **dashboard**.
- To initiate a scan, users must:
  - Input a valid value (or upload a file)
  - Click the **“Scan”** button
- The system checks its **local database**:
  - If the item already exists, it displays cached results
  - If not, it queries VirusTotal using the API

---

## Report Download

Users can **download scan reports** as `.txt` files for documentation or further analysis.

---

## API Key Configuration

- Communication with VirusTotal uses a **personalized API key**
- Users must:
  1. Have a VirusTotal account
  2. Obtain their unique API key
  3. Add it to the `config.json` file located in the initial `app` folder:
     ```json
     {
       "virustotal_api_key": "YOUR_API_KEY_HERE"
     }
     ```

---

## History Management

The system maintains a **local database** of scans, offering users:

- Viewing and accessing past scans
- Deleting individual records
- Searching through history using:
  - **Type filter**
  - **Severity filter**

---
