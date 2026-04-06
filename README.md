# 🌿 AyurSutra: Premium Panchakarma Management System

AyurSutra is a next-generation healthcare platform dedicated to modernizing the **Panchakarma** clinical workflow. Built by **SIH 2024 Interns**, this application bridges the gap between traditional Ayurvedic wisdom and modern clinical management with a focus on premium user experience, secure clinical records, and seamless scheduling.

---

## ✨ Key Features

- **🚀 Premium Dashboard**: Real-time stats, therapy status, and personalized health overview for both patients and specialists.
- **📅 Smart Scheduling**: Intuitive session booking with specialist selection and time-slot management.
- **🔒 Secure Health Vault**: Encrypted storage for patient history, Prakriti analysis, and clinical reports.
- **💬 Direct specialist-Patient Communication**: Seamless messaging system for personalized care coordination.
- **📊 Interactive Health Analytics**: Visual tracking of health progression and therapy adherence.
- **✨ Premium UI/UX**: Modern design system using Emerald & Slate architecture with glassmorphism and smooth animations.

---

## 🛠️ Technology Stack

- **Backend**: Python, Flask (Web Framework)
- **Database**: SQLite (SQLAlchemy ORM)
- **Frontend**: HTML5, Vanilla CSS3 (Custom Design System), Jinja2 Templating
- **Icons**: Lucide Icons
- **Typography**: Google Fonts (Inter, Outfit, Poppins)

---

## 🚀 Getting Started

Follow these steps to set up AyurSutra locally:

### 1. Prerequisites
- Python 3.9+ installed on your system.

### 2. Installation
Clone the repository and install the dependencies:
```bash
git clone https://github.com/adwaithgopinath-prog/SIH.git
cd SIH
pip install -r requirements.txt
```

### 3. Database Initialization
AyurSutra comes with a pre-configured seed script to help you get started with sample data:
```bash
python reset_db.py
```
This will recreate the database with the following test credentials:
- **Patient**: `patient1` / `password123`
- **Therapist**: `therapist1` / `password123`

### 4. Running the App
Launch the development server:
```bash
python app.py
```
Navigate to `http://127.0.0.1:5000` in your browser.

---

## 👨‍💻 Meet the Developers

This project was developed as part of an **SIH Internship Collaboration** by:

- **Adwaith Gopinath** - Full-Stack Backend Architecture
- **Saanvi Kapoor** - Lead UI/UX & Design Systems

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

*AyurSutra — Traditional Wisdom, Modernly Managed.*