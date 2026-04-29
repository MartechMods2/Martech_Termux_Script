# MARTSCRIPT - Info Gathering & Fun Tool for Termux (Non‑Root)

![Banner](https://img.shields.io/badge/MARTECH-v1.0-brightgreen) ![Termux](https://img.shields.io/badge/Termux-Compatible-blue) ![License](https://img.shields.io/badge/License-MIT-red)

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


## 🖥️ Usage

After installation, simply run martech. You will see an interactive menu with 40 options. Navigate using numbers and press Enter.

All outputs are automatically saved as reports in ~/MARTECH/reports/ with timestamps.

---

## 💰 Donations

If you find MARTECH useful and would like to support continued development, you can donate via:

· PayPal: [your-paypal-email-or-link]
· Bitcoin (BTC): [your-btc-address]

Your support is greatly appreciated! 🙏

---

## ⚠️ Legal Disclaimer

This tool is provided for educational purposes and authorized security testing only.
You must have explicit permission to scan or gather information about any target. Unauthorized access or use against systems you do not own is illegal and punishable by law. The author assumes no liability for any misuse or damage caused by this tool.

By using MARTECH, you agree to use it responsibly and within the bounds of the law.

---

## 📸 Screenshots

(Add your own screenshots here)

---

## 🤝 Contributing

Feel free to fork the repository, add new features, and submit pull requests. For major changes, please open an issue first.

---

## 📄 License

MIT

---

## 🌟 Support

If you like MARTECH, give it a ⭐ on GitHub!

For issues, open an issue in the repository.

---

Created by Martech – Ethical hacking for everyone 🔒

## 📦 Installation

Open Termux and run:

```bash
pkg update && pkg upgrade -y
pkg install git -y
git clone https://github.com/MartechMods2/Martech_Termux_Script.git
cd Martech_Termux_Script
chmod +x martech.sh
mv martech.sh $PREFIX/bin/martech

#Or If you wanna do some ip lookup

pkg update && pkg upgrade 
pkg install python termux-api python3
pip install requests colorama tabulate
git clone https://github.com/MartechMods2/Martech_Termux_Script.git
cd Martech_Termux_Script
python3 MarIntel.py
