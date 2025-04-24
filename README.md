# W3Guard 🛡️
W3Guard - Web Security Scanner

W3Guard is a sophisticated web security scanner designed to assess the security of websites by performing a range of checks, from domain analysis to comprehensive network scanning. Built with modern web technologies, W3Guard integrates with multiple security databases, such as AbuseIPDB, Shodan, and VirusTotal, to provide an in-depth analysis of any URL for vulnerabilities and potential risks.

About Us - MintFire Team
MintFire is a passionate team of security enthusiasts and developers who are dedicated to creating powerful tools to enhance web security and provide insights into potential vulnerabilities.

Our Team
Avik Samanta
A web developer with a focus on security tools, Avik brings extensive experience in backend development and web application security.
LinkedIn | GitHub

Anusha Gupta
Anusha is a skilled developer with expertise in security technologies and frontend design. She is dedicated to ensuring that W3Guard provides users with an intuitive and secure scanning experience.
LinkedIn | GitHub

We work together under the name MintFire to build innovative and secure tools that help protect online environments from emerging threats.

Features
Web Security Scan: Performs a comprehensive security check of a URL, identifying vulnerabilities and possible risks.

User Authentication & Profile: Secure login system with a unique 6-digit Super Key to authenticate users.

User Credits: Each user is granted 10 credits per day, which are consumed during scans. Admins can modify user credits.

Admin Dashboard: Allows admins to view user activity, modify credits, and manage user details.

API Integrations:

AbuseIPDB: Checks IP reputation for possible malicious activity.

Shodan: Scans the domain for exposed devices and network security.

VirusTotal: Scans URLs for malware and other security threats.

Responsive Design: The application is fully responsive, using TailwindCSS for modern and clean UI components.

Dark Mode: Built with a neon green theme, featuring a visually engaging dark mode background with dynamic animations based on time of day.

Technologies Used
Frontend:

HTML, CSS, and JavaScript (Vanilla)

TailwindCSS: A utility-first CSS framework for rapid UI development.

Backend:

Flask: A lightweight Python web framework used for the backend server.

Flask-Session: Manages user sessions for login and authentication.

Database:

JSON: Stores user information, Super Key, credits, and other essential data.

APIs:

AbuseIPDB: IP reputation data to detect malicious IP addresses.

Shodan: Network and device information.

VirusTotal: Virus and malware scan data for URLs.

Installation
Prerequisites
Before installing W3Guard, ensure you have the following installed:

Python 3.7+

pip (Python package manager)

Steps
Clone the repository:

bash
Copy
Edit
git clone https://github.com/your-username/W3Guard.git
cd W3Guard
Install the required dependencies:

bash
Copy
Edit
pip install -r requirements.txt
Set up environment variables: Create a .env file in the root of the project and add your API keys:

env
Copy
Edit
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
SHODAN_API_KEY=your_shodan_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
Run the application:

bash
Copy
Edit
python app.py
The app will be accessible at http://localhost:5000.

Usage
Login:

Users need to register and verify their account with an email and a 6-digit Super Key.

Admin users can modify other users' Super Keys and credits via the admin dashboard.

Scanning:

After logging in, users can enter a URL into the input form on the homepage.

The scan will deduct 1 credit from the user’s balance.

The results will include domain info, IP reputation, network scan, security headers, and more.

Scanned results are displayed in a user-friendly format, with the option to download the full report.

Admin Panel:

Admin users can view which users are online, manage credits, and view scan statistics.

API Integrations
AbuseIPDB:

Provides details about IP reputation to help detect malicious activity.

Shodan:

Provides detailed information about open ports and devices associated with the scanned URL.

VirusTotal:

Scans the URL for malware, viruses, and other malicious content.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Contributing
We welcome contributions to enhance the functionality and improve the security of W3Guard. If you have a feature request or bug fix, please fork the repository and submit a pull request.

Steps to contribute:
Fork the repository.

Create a new branch (git checkout -b feature-name).

Commit your changes (git commit -am 'Add new feature').

Push to the branch (git push origin feature-name).

Open a pull request.

Acknowledgements
Flask: A minimal web framework that helped build the backend of this application.

TailwindCSS: A utility-first CSS framework that allowed for rapid UI design and customization.

Shodan: Provides network scans and helps identify exposed devices.

AbuseIPDB: Helps check the reputation of IPs associated with the scanned domain.

VirusTotal: Provides virus and malware scan data for enhanced security analysis.

This version places the MintFire Team and introduces you as the main contributors after the tool description, followed by your LinkedIn and GitHub links.
