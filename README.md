# ISO ComplyPro

**ISO ComplyPro** is an open-source compliance tracking tool designed for ISO 27001 implementation. It helps organizations track security controls, manage evidence, and generate compliance reports.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.3.0-green.svg)](https://flask.palletsprojects.com/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

## 🌟 Features

- ✅ **Control Tracking** - Track implementation status of ISO 27001 controls
- 📎 **Evidence Management** - Upload and manage evidence documents for each control
- 👥 **Role-Based Access** - Admin, Control Owner, and Auditor roles
- 📊 **Compliance Reports** - Generate reports with visual dashboards
- 🔐 **Secure Authentication** - Password complexity, account lockout, password history
- 📝 **Audit Trail** - Complete logging of all user actions
- 💾 **Export Functionality** - Export reports to CSV format
- 🎯 **Control Selection** - Organizations can select applicable controls only

## 🚀 Quick Start

### Prerequisites
- Python 3.11 or higher
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/luilye2013-eng/iso-complypro.git
cd iso-complypro

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment configuration
cp .env.example .env

# Edit .env with your secret key (generate one)
# On Linux/Mac: python -c "import secrets; print(secrets.token_hex(32))"
# On Windows: py -c "import secrets; print(secrets.token_hex(32))"

# Run the application
python app.py
Access the application at http://127.0.0.1:5000

🔧 Configuration
Environment Variables
Variable	Description	Default
SECRET_KEY	Flask secret key for sessions	Required
DATABASE_URL	Database connection string	sqlite:///compliance.db
FLASK_DEBUG	Debug mode	False
PASSWORD_MIN_LENGTH	Minimum password length	12
MAX_LOGIN_ATTEMPTS	Failed attempts before lockout	5
👥 User Roles
Role	Permissions
Admin	Full system access, user management, control library management
Control Owner	Manage assigned controls, upload evidence, update status
Auditor	Read-only access to all controls and reports
📁 Project Structure
text
iso-complypro/
├── app.py                 # Main application
├── models.py              # Database models
├── auth.py                # Authentication utilities
├── requirements.txt       # Python dependencies
├── templates/             # HTML templates
│   ├── base.html
│   ├── login.html
│   ├── dashboard.html
│   ├── controls.html
│   └── ...
├── static/                # CSS, JS files
└── data/                  # Control library JSON files
🚢 Deployment
Deploy to Vercel
https://vercel.com/button

Push your code to GitHub

Import the repository on Vercel

Set environment variables

Deploy

Deploy to Render
https://render.com/images/deploy-to-render-button.svg

🔒 Security Features
Password complexity requirements (12+ chars, mixed case, numbers, special)

Account lockout after 5 failed attempts

Password history (prevents reuse of last 5 passwords)

Force password change on first login

Session timeout after 15 minutes

Complete audit logging

CSRF protection ready

🤝 Contributing
Contributions are welcome! Please follow these steps:

Fork the repository

Create a feature branch (git checkout -b feature/AmazingFeature)

Commit your changes (git commit -m 'Add some AmazingFeature')

Push to the branch (git push origin feature/AmazingFeature)

Open a Pull Request

📝 License
Distributed under the MIT License. See LICENSE for more information.

⚠️ Disclaimer
ISO ComplyPro is an independent open-source project. It is not affiliated with, endorsed by, or sponsored by the International Organization for Standardization (ISO). All product names, logos, and brands are property of their respective owners.

📧 Contact
Project Link: https://github.com/luilye2013-eng/iso-complypro

🙏 Acknowledgments
Flask and SQLAlchemy for the amazing framework

Bootstrap for the UI components

All contributors and testers

📊 Roadmap
Email notifications for due dates

API evidence collection (AWS, GitHub, Jira)

PDF report generation

Multi-organization support

SSO authentication (Google, Microsoft)

Automated evidence collection
