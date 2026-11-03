# AutoShield-EV™ — Autonomous Electric Vehicle Cybersecurity Operations Center & Threat Simulation Engine

[![UNECE: R155 / R156](https://img.shields.io/badge/UNECE-R155%20%7C%20R156-blue.svg)](#)
[![ISO: SAE 21434](https://img.shields.io/badge/Standard-ISO%2FSAE%2021434-emerald.svg)](#)
[![Functional Safety: ASIL-D](https://img.shields.io/badge/ISO%2026262-ASIL--D-red.svg)](#)
[![Autopilot: Level 3+](https://img.shields.io/badge/ADS-Level%203%2B-cyan.svg)](#)

**AutoShield-EV** is a high-fidelity, interactive cybersecurity operations center (VSOC) and real-time threat injection simulator engineered specifically for **Autonomous Electric Vehicles (Autopilot EVs)**. It bridges the gap between **autonomous perception safety**, **in-vehicle networks (CAN-FD / Automotive Ethernet)**, and **high-voltage EV battery/charging infrastructure (BMS / ISO 15118)**.

---

## 🎯 What AutoShield-EV Simulates & Protects

```
┌────────────────────────────────────────────────────────────────────────┐
│                   AUTOSHIELD-EV CYBERSECURITY SUITE                    │
├──────────────────────────┬─────────────────────────┬───────────────────┤
│ 1. Perception & ADS      │ 2. In-Vehicle Networks  │ 3. EV Powertrain  │
├──────────────────────────┼─────────────────────────┼───────────────────┤
│ • Adversarial Patch DNN  │ • AUTOSAR SecOC CMAC    │ • BMS Overvoltage │
│ • Optical Laser Blinding │ • Steering Frame Inject │ • Thermal Runaway │
│ • Phantom Braking Drop   │ • Monotonic Freshness   │ • ISO 15118 MitM  │
│ • 4D Radar Cross-Arbiter │ • Gateway Isolation     │ • Pyrotechnic Cut │
└──────────────────────────┴─────────────────────────┴───────────────────┘
```

---

## ⚡ Quickstart: Running the Application

### Option 1: One-Click Desktop Launcher
Run the batch file in the root workspace directory:
```cmd
Launch_Autopilot_EV_Cybersec.bat
```
*(Automatically launches in Microsoft Edge or Google Chrome standalone app mode).*

### Option 2: Direct In-Browser Execution
Open [`index.html`](file:///c:/Users/hp/.antigravity-ide/autopilot-ev-cybersec/index.html) or [`standalone_autoshield.html`](file:///c:/Users/hp/.antigravity-ide/autopilot-ev-cybersec/standalone_autoshield.html) directly in any modern web browser. Zero server or npm build steps required.

---

## 🛡️ Core Functional Modules

### 1. 60 FPS Autonomous Perception HUD & Cockpit
* **Real-time Road & Vehicle Rendering:** Live canvas simulation of highway lane tracking, lead vehicle distance tracking, and sensor cones.
* **Adversarial Perturbation Defense:** Visualizes sub-perceptual stickers on speed limit signs (e.g. 40 km/h misclassified as 100 km/h) and gradient entropy detection.
* **Phantom Obstacle Filtering:** Detects laser pulse reflections projected into camera optics and cross-references against 4D Imaging Radar to reject false braking events.

### 2. Red Team Attack Injector (8 Interactive Scenarios)
1. **Adversarial Optical Patch on Speed Limit Sign:** Triggers false speed limit classification.
2. **Phantom Obstacle Laser Injection:** Tests ghost obstacle phantom braking suppression.
3. **CAN-FD Steering Angle Override (0x0C4):** Attempts unauthorized ±35° lane departure.
4. **BMS Fast-Charging Overvoltage Exploit:** Simulates cell overcharge beyond 4.25V.
5. **ISO 15118 EVSE Man-in-the-Middle Attack:** Tests rogue fast-charger certificate validation.
6. **GNSS / GPS L1/L5 Coordinate Spoofing:** Shifts perceived vehicle coordinates by 120m.
7. **Rogue Telematics OTA Firmware Injection:** Tests Uptane / TUF rollback and signature protection.
8. **Ultrasonic Acoustic Jamming:** Supresses near-field 40 kHz sonar echoes.

### 3. AUTOSAR SecOC & CAN-FD Packet Sniffer
* **Live In-Vehicle Traffic Stream:** Inspects Arbitration IDs (`0x0A2`, `0x0C4`, `0x120`, `0x214`, `0x280`, `0x3F0`).
* **Cryptographic MAC Validation:** Real-time calculation and validation of CMAC-AES128 signatures and 64-bit trip freshness counters.
* **Manual Frame Injection:** Red-team debugging tool for testing bus filtering rules.

### 4. Interactive ECU Topology Map
* Visual interactive architecture of Central Gateway (CGW), Autopilot Domain (ADAS), Telematics (TCU), EPS, ESC, BMS, Inverter, and IVI.
* Dynamic animated packet flows with visual compromise and quarantine states.

### 5. High-Voltage Battery Security (BMS & V2G)
* **16-Cell Module Telemetry:** Real-time cell voltage and thermal tracking.
* **Safety Lock Status:** Hardware voltage clamping, pyrotechnic disconnect, and ECDSA P-256 attestation.
* **Plug & Charge (ISO 15118-20):** TLS 1.3 mutual authentication and contract certificate verification.

### 6. Regulatory Standards Compliance
* **UNECE WP.29 R155:** Cyber Security Management System (CSMS) & TARA.
* **UNECE WP.29 R156:** Software Update Management System (SUMS) with anti-rollback.
* **ISO 26262 / ASIL-D:** Minimal Risk Maneuver (MRM) emergency safe-stop interlock.

---

## 📁 File Structure

```
c:\Users\hp\.antigravity-ide\
├── Launch_Autopilot_EV_Cybersec.bat          # 1-Click App Launcher
└── autopilot-ev-cybersec/
    ├── index.html                           # Modern Web Dashboard
    ├── styles.css                           # Cockpit Dark Theme & Animations
    ├── app.js                               # Threat Simulation, CAN & HUD Engine
    ├── standalone_autoshield.html           # Zero-dependency single-file bundle
    └── README.md                            # Technical architecture documentation
```

