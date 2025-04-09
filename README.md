# PROXMOX VNC VM Web GUI (https://zamatallica.ddns.net/)

![full_infrastructure_architecture_wSQL](https://github.com/user-attachments/assets/317eae37-cf0d-4b72-af7e-5b0e04ada3cd)
![image](https://github.com/user-attachments/assets/6b82f5b0-582a-49cb-9bd5-2299910765a9)
![image](https://github.com/user-attachments/assets/37034d96-c879-4170-81e3-0d2a200dfcba)
![image](https://github.com/user-attachments/assets/8a5b17d2-bd12-410f-ada5-0dfe320cfbac)
![image](https://github.com/user-attachments/assets/53ca2074-4f35-4bb8-ba12-fc3a24f22d35)






## 1. Project Overview
The **VM Web GUI** provides a web-based interface for accesing virtual machines on Proxmox via **Flask (Python), Node.js, and WebSockets**. It allows users to authenticate, select a VM, and open a VNC session.

## 2. System Architecture
The system consists of:
- **Flask (Python)**: Backend API for authentication and VNC ticketing.
- **Node.js WebSocket Proxy**: Relays WebSocket connections to Proxmox VNC.
- **Nginx**: Reverse proxy handling SSL termination.
- **Proxmox Server**: Manages virtual machines.
- **SQL Server**: Stores authentication logs.

## 3. Installation & Setup

### Prerequisites
- **Ubuntu 20.04+ / Windows (WSL)**
- **Python 3.8+ & Node.js 16+**
- **Proxmox API Enabled**

### Steps:
#### **Flask Backend**
```sh
cd VM_WEB_GUI
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```
#### **Node.js WebSocket Proxy**
```sh
cd VM_WEB_GUI/proxmox-proxy
npm install
node server.js
```

#### **Nginx Configuration**
Copy `nginx.conf` and restart Nginx:
```sh
sudo systemctl restart nginx
```

## 4. API Documentation

### **Flask Backend API**
| Endpoint          | Method | Description                  |
|------------------|--------|------------------------------|
| `/auth/login`    | POST   | Authenticate and return JWT  |
| `/vnc/start`     | POST   | Generate a VNC ticket       |
| `/vm/list`       | GET    | List available VMs          |

**Example Request (Login):**
```sh
curl -X POST https://your-domain.com/auth/login      -H "Content-Type: application/json"      -d '{"username": "admin", "password": "securePass"}'
```

### **Node.js WebSocket Proxy**
Handles WebSocket connections between users and Proxmox:
- **Listens on** `ws://your-domain.com:8080`
- **Forwards to** `wss://proxmox-server:5900/`

## 5. Client-Side Functionality

### **Authentication (`security.js`)**
- Handles login via `/auth/login`
- Stores JWT tokens for session management

### **VNC Connection (`index.html`)**
- Uses **noVNC** to connect to VMs.
- Fetches a **VNC ticket from Flask** and opens a WebSocket session.

## 6. SQL Server Architecture

- **ProxMox Host** (`https://192.168.1.17:8006/`)
- **Domain Controller (DC01)**:
  - Windows Server 2022, 2 vCPUs, 4GB RAM.
- **SQL Servers (SQL01 & SQL02)**
  - Windows Server 2022, 8GB RAM, 2 vCPUs.
  - SQL Always On High Availability Cluster.

## 7. Security Considerations
- **Use SSL (TLS) via Nginx.**
- **Enforce JWT authentication for API calls.**
- **Restrict WebSocket access to authenticated users.**
- **Secure SQL Server with limited permissions.**

## 8. Troubleshooting Guide

### **Issue: Cannot Connect to VNC Console**
- Ensure Proxmox API is accessible.
- Check Flask logs (`server.log`).

### **Issue: WebSocket Connection Failing**
- Confirm `server.js` is running on `ws://your-domain.com:8080`.
- Verify WebSocket forwarding in Nginx.

### **Issue: SSL Certificate Errors**
- Ensure `cert.pem` and `key.pem` are valid.

---

This document provides a **complete reference** for setting up, securing, and troubleshooting the VM Web GUI.
