# MARTECH - Ultimate Graphical Info Gathering & Fun Tool for Termux (Non‑Root)

![Banner](https://img.shields.io/badge/MARTECH-v4.0-brightgreen) ![Termux](https://img.shields.io/badge/Termux-Compatible-blue) ![License](https://img.shields.io/badge/License-MIT-red)

**MARTECH** is an all‑in‑one terminal suite for information gathering, OSINT, network scanning, utilities, and games – designed specifically for **non‑rooted Termux** on Android. It features a sleek graphical interface, animations, and over 40 tools.

---

## 🚀 Features

### 📡 Information Gathering
- Device Info, Network Scanner, IP Geolocation, Port Scanner
- Email Breach Check (HIBP), WHOIS, Subdomain Enumeration
- DNS Brute Force, MAC Lookup, Subnet Calculator
- PhoneInfoga (phone OSINT), Sherlock (username search)
- HTTP Headers Grabber, IP Tracker, Full Recon

### 🎮 Games (10+)
- Guess Number, Rock Paper Scissors, Hangman, Tic‑Tac‑Toe
- Dice Roll, Coin Flip, Trivia Quiz, Memory Challenge
- Word Scramble, Morse Trainer

### 🛠️ Utilities
- Password Generator, QR Code Generator, Weather, Crypto Price
- Text Encoder (Base64/ROT13), URL Shortener, Hash Generator (MD5/SHA1/SHA256)
- Phone Validator, Port Knocker, Random Joke

### 📁 Reports
- Automatic saving of all results to `~/MARTECH/reports/`
- View and delete reports from the menu

### ✨ Visuals
- Matrix rain loading, glowing progress bars, typewriter effects
- Colorful banners, random hacking quotes

### 📞 Contact & Social (hidden links – opens directly)
- Telegram, WhatsApp (text only), Website, YouTube

---

## 📦 Installation

Open Termux and run:

```bash
pkg update && pkg upgrade -y
pkg install git -y
git clone https://github.com/MartechMods2/Martech_Termux_Script.git
cd Martech_Termux_Script
chmod +x martech.sh
mv martech.sh $PREFIX/bin/martech
