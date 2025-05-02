# **File Encryption Tool**  
*A file encryption/decryption program using AES and RSA algorithms*

---

## **1. Introduction**  
This tool provides file encryption and decryption using:  
- **AES-128** (for symmetric encryption)  
- **RSA-2048** (for asymmetric key exchange)  
---

## **2. Environment**  
### **Requirements**  
- **OS**: Ubuntu 24.04 LTS (or compatible Linux distribution)  
- **Dependencies**:  
  ```bash
    # Install all dependencies on Ubuntu
    sudo apt update && sudo apt install -y \
    build-essential \
    cmake \
    libssl-dev \
    libgmp-dev  

## **3.Build**
```bash
    mkdir -p build && cd build && cmake ..  && make
```
