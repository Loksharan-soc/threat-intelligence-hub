# Threat Intelligence Hub

**Threat Intelligence Hub** is a centralized platform for collecting, analyzing, and visualizing cyber threat intelligence. It aggregates data from multiple external sources such as AbuseIPDB and VirusTotal to help security teams monitor malicious IPs, URLs, and malware indicators through a secure web interface.

---

## 🚀 Features

- **Dashboard Overview:** Real-time statistics and visualizations of threat intelligence data.
- **Malicious IPs:** Lookup and monitor suspicious IP addresses using AbuseIPDB.
- **Malware Reports:** Fetch malware and URL intelligence from VirusTotal.
- **Admin Panel:** Manage account preferences and system configurations.
- **Quick Actions:** Easily navigate to view reports, IPs, URLs, and malware indicators.
- **Modular Design:** Easily extendable to integrate more threat intelligence sources.

---

## 💪 Technologies Used

- **Backend:** Python, Flask
- **Frontend:** HTML, CSS, Jinja2 templates
- **APIs:** AbuseIPDB API, VirusTotal API
- **Database:** SQLite (or any preferred DB)
- **Version Control:** Git & GitHub

---

## 💾 Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/loksharan-soc/threat-intelligence-hub.git
   cd threat-intelligence-hub
   ```

2. Create a virtual environment and activate it:

   ```bash
   python -m venv venv
   # Windows
   venv\Scripts\activate
   # Linux/macOS
   source venv/bin/activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Set up environment variables for API keys (example using AbuseIPDB):

   ```bash
   set ABUSEIPDB_API_KEY="YOUR_API_KEY_HERE"   # Windows
   export ABUSEIPDB_API_KEY="YOUR_API_KEY_HERE"  # Linux/macOS
   ```

5. Run the Flask app:

   ```bash
   python backend/app.py
   ```

6. Open the browser at:

   ```
   http://127.0.0.1:5000
   ```

---

## ⚡ Usage

- Navigate to the **Dashboard** to view an overview of threat intelligence data.
- Click **View IPs** or **View URLs** to see detailed threat reports.
- Use the **Admin Settings** to manage your account and system preferences.
- API integrations allow fetching real-time threat intelligence for analysis.

---

## 🔒 Security Notes

- Keep your API keys secure and do not expose them publicly.
- Use HTTPS when deploying to production.
- Follow API rate limits for AbuseIPDB and VirusTotal to avoid being blocked.

---

## 📝 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Loksharan Saravanan**

- Email: [loksharan.soc@gmail.com](mailto\:loksharan.soc@gmail.com)
- GitHub: [github.com/loksharan-soc](https://github.com/loksharan-soc)
- LinkedIn: [linkedin.com/in/loksharan](https://www.linkedin.com/in/loksharan/)

