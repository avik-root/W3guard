# W3Guard - Web Security Scanner

![W3Guard Logo](https://via.placeholder.com/150?text=W3Guard)

**W3Guard** is an advanced web security scanner developed to identify vulnerabilities in websites. This tool integrates with leading threat intelligence sources, such as AbuseIPDB, Shodan, and VirusTotal, to perform comprehensive security analysis of a given URL. **W3Guard** helps users detect security risks, such as malicious IPs, exposed devices, and potential malware, all through a simple and intuitive user interface.

---

## About Us - MintFire Team

**MintFire** is a dedicated team of developers and security professionals focused on building innovative tools to enhance online security. We are passionate about providing cutting-edge solutions that empower businesses and individuals to protect their web environments from emerging cyber threats.

### Our Team

- **Avik Samanta**  
  A web developer with a strong focus on backend security and modern web technologies, Avik specializes in building robust and scalable security tools.  
  [LinkedIn](https://www.linkedin.com/in/avik-samanta) | [GitHub](https://github.com/avik-root)

- **Anusha Gupta**  
  Anusha is a skilled developer with expertise in frontend design and web security. She is dedicated to creating intuitive and user-friendly experiences while maintaining high standards of security.  
  [LinkedIn]([https://www.linkedin.com/in/anusha-gupta](https://www.linkedin.com/in/anusha-gupta-735826284/)) | [GitHub](https://github.com/anushagupta11)

Together, as **MintFire**, we aim to provide innovative solutions that ensure the safety and security of online platforms.

---

## Features

- **Web Security Scan**: Detects vulnerabilities and risks on a given URL by performing a thorough security check.
- **User Authentication & Profiles**: Secure login system with a 6-digit Super Key for user verification.
- **Daily User Credits**: Each user is allotted 10 credits per day, which are deducted during scans. Admins can modify user credits.
- **Admin Dashboard**: Admin users can manage user credits, monitor user activity, and adjust settings.
- **API Integrations**:
  - **AbuseIPDB**: Retrieves IP reputation data to identify malicious activities.
  - **Shodan**: Provides insights into devices and exposed ports associated with a URL.
  - **VirusTotal**: Scans URLs for malware, viruses, and other potential threats.
- **Responsive Design**: The application adapts to all screen sizes, thanks to the use of TailwindCSS.
- **Dark Mode**: A visually striking neon green theme with a dynamic background that adjusts based on the time of day.

---

## Technologies Used

- **Frontend**:
  - HTML, CSS, and JavaScript
  - **TailwindCSS**: A utility-first CSS framework for responsive design and UI components.
- **Backend**:
  - **Flask**: A lightweight Python web framework for server-side operations.
  - **Flask-Session**: Manages user sessions for login and authentication.
- **Database**:
  - **JSON**: Stores user credentials, Super Keys, credits, and other necessary data.
- **APIs**:
  - **AbuseIPDB**: Provides IP reputation data to detect malicious activity.
  - **Shodan**: Retrieves information about devices and exposed ports.
  - **VirusTotal**: Scans URLs for malware and viruses.

---

## Installation

### Prerequisites

To run **W3Guard** locally, ensure that you have the following installed:

- Python 3.7+
- pip (Python package manager)

### Steps

1. **Clone the repository**:

```bash
git clone https://github.com/avik-root/W3Guard.git
cd W3Guard
