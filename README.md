to activate virtual env - source venv/env/activate
to run front end  - streamlit run dashboard/enterprise_platform.py
another dashboard - streamlit run industry_dashboard.py --server.port 8501

# 🛡️ Insider Threat Detection System

![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Streamlit](https://img.shields.io/badge/Streamlit-1.28.1-FF4B4B)
![Elasticsearch](https://img.shields.io/badge/Elasticsearch-8.11-00BFB3)

**Real-time security monitoring system for detecting insider threats using machine learning and behavioral analytics with Elastic Stack integration.**

## ✨ Features

### 🔍 **Detection Capabilities**
- Real-time user behavior monitoring
- Anomaly detection using machine learning
- Rule-based threat identification
- Risk scoring algorithms

### 📊 **Visualization & Dashboard**
- Interactive Streamlit dashboard
- Real-time threat visualization
- Department-wise analytics
- Historical trend analysis

### 🔗 **Integrations**
- Elasticsearch 8.x for log storage
- Kibana for advanced analytics
- Email/SMS alerting system
- REST API for third-party integration

### 🚀 **Deployment Ready**
- Docker & Docker Compose support
- AWS EC2 deployment scripts
- Streamlit Cloud deployment
- Kubernetes ready

## 🏗️ Architecture
![alt text](image.png)


## 🚀 Quick Start

### **Option 1: Local Development (Recommended)**

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/insider-threat-detection.git
cd insider-threat-detection

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Start Elastic Stack (using Docker)
docker-compose up -d

# 6. Load sample data
python load_all_data.py

# 7. Run the dashboard
streamlit run dashboard/industry_dashboard.py

Option 2: Docker Deployment

# Using Docker Compose (includes Elasticsearch & Kibana)
docker-compose -f docker-compose.yml up -d

# Or for production setup
docker-compose -f docker-compose-aws.yml up -d

📁 Project Structure

insider-threat-detection/
├── dashboard/                 # Streamlit dashboard
│   ├── industry_dashboard.py # Main dashboard
│   ├── enhanced_dashboard.py
│   ├── enterprise_platform.py
│   ├── components/           # UI components
│   └── data/                 # Sample data
├── src/                      # Source code
│   ├── detection/           # Detection algorithms
│   ├── data_processing/     # Data pipeline
│   └── utils/              # Utilities
├── api/                     # REST API
│   └── api_server.py
├── docker/                  # Docker configurations
├── docs/                   # Documentation
├── tests/                  # Test files
├── requirements.txt        # Python dependencies
├── docker-compose.yml     # Docker Compose setup
├── Dockerfile            # Docker build file
└── README.md            # This file