#!/data/data/com.termux/files/usr/bin/bash
# MARTECH - Ultimate Working Script (No jq, No Broken APIs)
# Created by Martech

set -euo pipefail

# Colors
RED='\033[1;91m'
GREEN='\033[1;92m'
YELLOW='\033[1;93m'
BLUE='\033[1;94m'
MAGENTA='\033[1;95m'
CYAN='\033[1;96m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

REPORT_DIR="$HOME/MARTECH/reports"
mkdir -p "$REPORT_DIR"

# Helper: safe curl with timeout
get_url() {
    curl -s --max-time 10 "$1" 2>/dev/null || echo ""
}

save_report() {
    local section="$1"
    local content="$2"
    local ts=$(date +"%Y%m%d_%H%M%S")
    local file="$REPORT_DIR/martech_${section}_${ts}.txt"
    {
        echo "========================================"
        echo "MARTECH REPORT - $section"
        echo "Generated: $(date)"
        echo "========================================"
        echo "$content"
    } > "$file"
    echo -e "${GREEN}✓ Saved: $file${RESET}"
}

show_banner() {
    clear
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    ${RED}███╗   ███╗ █████╗ ██████╗ ████████╗███████╗ ██████╗██╗  ██╗${CYAN}║${RESET}"
    echo "║                    ${RED}████╗ ████║██╔══██╗██╔══██╗╚══██╔══╝██╔════╝██╔════╝██║  ██║${CYAN}║${RESET}"
    echo "║                    ${RED}██╔████╔██║███████║██████╔╝   ██║   █████╗  ██║     ███████║${CYAN}║${RESET}"
    echo "║                    ${RED}██║╚██╔╝██║██╔══██║██╔══██╗   ██║   ██╔══╝  ██║     ██╔══██║${CYAN}║${RESET}"
    echo "║                    ${RED}██║ ╚═╝ ██║██║  ██║██║  ██║   ██║   ███████╗╚██████╗██║  ██║${CYAN}║${RESET}"
    echo "║                    ${RED}╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝${CYAN}║${RESET}"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
    echo -e "${YELLOW}${BOLD}                   Welcome to my world of hacking${RESET}"
    echo -e "${RED}${BOLD}                 Use this tool responsibly${RESET}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${GREEN}Date:${RESET} $(date '+%Y-%m-%d %H:%M:%S')   ${GREEN}Device:${RESET} $(getprop ro.product.model 2>/dev/null || echo "Unknown")"
    echo -e "${DIM}                          Created by Martech${RESET}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════════════════════════${RESET}"
}

random_quote() {
    local quotes=(
        "${CYAN}\"The quieter you become, the more you can hear.\"${RESET}"
        "${RED}🔓 Hack the planet! 🔓${RESET}"
        "${GREEN}☁️ There is no cloud — just someone else's computer. ☁️${RESET}"
        "${MAGENTA}⚡ Stay curious. Stay dangerous. ⚡${RESET}"
        "${YELLOW}🧠 Knowledge is the ultimate weapon. 🧠${RESET}"
        "${BLUE}🌐 Every password is just a delay. 🌐${RESET}"
    )
    echo -e "${quotes[$((RANDOM % ${#quotes[@]}))]}"
}

# =============================== WORKING FEATURES ===============================

device_info() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== DEVICE INFO ===${RESET}\n"
    local info=""
    info+="Model: $(getprop ro.product.model 2>/dev/null || echo 'N/A')\n"
    info+="Android: $(getprop ro.build.version.release 2>/dev/null || echo 'N/A')\n"
    info+="Kernel: $(uname -r)\n"
    local bat=$(termux-battery-status 2>/dev/null | grep -o '"percentage":[0-9]*' | cut -d: -f2)
    info+="Battery: ${bat:-N/A}%\n"
    info+="Storage: $(df -h /data | awk 'NR==2 {print $2" total, "$3" used, "$4" free"}')\n"
    info+="RAM: $(free -h | awk 'NR==2 {print $2" total, "$3" used, "$4" free"}')\n"
    info+="Local IP: $(ip -4 addr show wlan0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo 'N/A')\n"
    info+="Public IP: $(get_url "https://ifconfig.me" || echo 'N/A')"
    echo -e "$info" | fold -s -w 70
    save_report "DeviceInfo" "$info"
}

ip_geolocation() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== IP GEOLOCATION ===${RESET}"
    read -p "Enter IP or domain: " target
    local data=$(get_url "http://ipinfo.io/$target")
    if [[ -z "$data" ]]; then
        echo -e "${RED}Failed to fetch data. Check your internet.${RESET}"
        return
    fi
    echo "$data" | grep -E '"ip"|"city"|"region"|"country"|"org"' | sed 's/[",]//g'
    save_report "GeoIP" "$data"
}

port_scanner() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== PORT SCANNER ===${RESET}"
    read -p "Target IP: " target
    read -p "Port range (e.g., 1-100): " ports
    local start=$(echo "$ports" | cut -d- -f1)
    local end=$(echo "$ports" | cut -d- -f2)
    echo -e "${YELLOW}Scanning...${RESET}"
    for port in $(seq "$start" "$end"); do
        timeout 1 bash -c "echo >/dev/tcp/$target/$port" 2>/dev/null && echo -e "${GREEN}Port $port open${RESET}"
    done | tee /tmp/ports.txt
    save_report "PortScan" "$(cat /tmp/ports.txt 2>/dev/null || echo 'No open ports found')"
}

email_breach() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== EMAIL BREACH CHECK ===${RESET}"
    read -p "Email: " email
    local resp=$(get_url "https://haveibeenpwned.com/api/v3/breachedaccount/$email")
    if [[ -z "$resp" ]]; then
        echo -e "${GREEN}No breaches found for $email${RESET}"
        save_report "EmailBreach" "No breaches found"
    else
        echo "$resp" | grep -o '"Name":"[^"]*"' | cut -d'"' -f4 | head -5
        save_report "EmailBreach" "$resp"
    fi
}

whois_lookup() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== WHOIS ===${RESET}"
    read -p "Domain: " domain
    whois "$domain" | head -30 | tee /tmp/whois.txt
    save_report "WHOIS" "$(cat /tmp/whois.txt)"
}

dns_brute() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== DNS BRUTE (common subdomains) ===${RESET}"
    read -p "Domain: " domain
    for sub in www mail ftp admin blog shop api dev test vpn; do
        local ip=$(dig +short "$sub.$domain" | head -1)
        if [[ -n "$ip" ]]; then
            echo -e "${GREEN}$sub.$domain -> $ip${RESET}"
        fi
    done
}

mac_lookup() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== MAC LOOKUP ===${RESET}"
    read -p "MAC address: " mac
    local vendor=$(get_url "https://api.macvendors.com/$mac")
    if [[ -z "$vendor" || "$vendor" == *"Not Found"* ]]; then
        echo -e "${RED}Vendor not found${RESET}"
    else
        echo -e "${GREEN}Vendor: $vendor${RESET}"
        save_report "MACLookup" "$vendor"
    fi
}

http_headers() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== HTTP HEADERS ===${RESET}"
    read -p "URL (include http://): " url
    curl -I -s "$url" | head -15 | tee /tmp/headers.txt
    save_report "HTTPHeaders" "$(cat /tmp/headers.txt)"
}

ip_tracker() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== IP TRACKER ===${RESET}"
    read -p "IP address: " ip
    local data=$(get_url "http://ipinfo.io/$ip")
    echo "$data" | grep -E '"ip"|"city"|"region"|"country"|"org"' | sed 's/[",]//g'
    save_report "IPTracker" "$data"
}

password_gen() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== PASSWORD GENERATOR ===${RESET}"
    read -p "Length (default 16): " len
    len=${len:-16}
    local pass=$(tr -dc 'A-Za-z0-9!@#$%^&*()_+' </dev/urandom | head -c "$len")
    echo -e "${GREEN}$pass${RESET}"
    save_report "Password" "$pass"
}

weather() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== WEATHER ===${RESET}"
    read -p "City name: " city
    curl -s "wttr.in/$city?0T" | head -n 7
}

crypto_price() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== CRYPTO PRICE ===${RESET}"
    read -p "Symbol (BTC, ETH, etc): " sym
    sym=$(echo "$sym" | tr '[:upper:]' '[:lower:]')
    local price=$(get_url "https://api.coingecko.com/api/v3/simple/price?ids=$sym&vs_currencies=usd" | grep -o '"usd":[0-9.]*' | cut -d: -f2)
    if [[ -z "$price" ]]; then
        echo -e "${RED}Symbol not found${RESET}"
    else
        echo -e "${GREEN}${sym^^} price: \$$price USD${RESET}"
    fi
}

text_encoder() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== TEXT ENCODER ===${RESET}"
    echo "1) Base64 Encode  2) Base64 Decode  3) ROT13"
    read -p "Choice: " opt
    read -p "Text: " text
    case $opt in
        1) echo -e "${GREEN}$(echo -n "$text" | base64)${RESET}" ;;
        2) echo -e "${GREEN}$(echo -n "$text" | base64 -d 2>/dev/null || echo 'Invalid base64')${RESET}" ;;
        3) echo -e "${GREEN}$(echo "$text" | tr 'A-Za-z' 'N-ZA-Mn-za-m')${RESET}" ;;
        *) echo -e "${RED}Invalid${RESET}" ;;
    esac
}

url_shortener() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== URL SHORTENER ===${RESET}"
    read -p "Long URL: " url
    local short=$(get_url "https://tinyurl.com/api-create.php?url=$url")
    if [[ -z "$short" ]]; then
        echo -e "${RED}Failed to shorten${RESET}"
    else
        echo -e "${GREEN}Short URL: $short${RESET}"
    fi
}

hash_gen() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== HASH GENERATOR ===${RESET}"
    read -p "Text: " text
    echo -e "MD5:    $(echo -n "$text" | md5sum | cut -d' ' -f1)"
    echo -e "SHA1:   $(echo -n "$text" | sha1sum | cut -d' ' -f1)"
    echo -e "SHA256: $(echo -n "$text" | sha256sum | cut -d' ' -f1)"
}

phone_validator() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== PHONE VALIDATOR ===${RESET}"
    read -p "Phone number (+countrycode): " num
    local data=$(get_url "http://apilayer.net/api/validate?access_key=demo&number=$num")
    local valid=$(echo "$data" | grep -o '"valid":true' | head -1)
    if [[ -n "$valid" ]]; then
        echo -e "${GREEN}Valid phone number${RESET}"
        local country=$(echo "$data" | grep -o '"country_name":"[^"]*"' | cut -d'"' -f4)
        echo "Country: $country"
    else
        echo -e "${RED}Invalid or unsupported number${RESET}"
    fi
}

port_knocker() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== PORT KNOCKER ===${RESET}"
    read -p "Target IP: " target
    read -p "Ports (comma separated): " ports
    IFS=',' read -ra PORTS <<< "$ports"
    for port in "${PORTS[@]}"; do
        echo -e "${YELLOW}Knocking on $port...${RESET}"
        nc -zv -w 1 "$target" "$port" 2>&1 | grep -v 'refused' || echo "Port $port may be filtered"
    done
    echo -e "${GREEN}Done.${RESET}"
}

random_joke() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== RANDOM JOKE ===${RESET}"
    local joke=$(get_url "https://official-joke-api.appspot.com/random_joke")
    local setup=$(echo "$joke" | grep -o '"setup":"[^"]*"' | cut -d'"' -f4)
    local punchline=$(echo "$joke" | grep -o '"punchline":"[^"]*"' | cut -d'"' -f4)
    if [[ -n "$setup" && -n "$punchline" ]]; then
        echo -e "${CYAN}$setup${RESET}"
        echo -e "${GREEN}$punchline${RESET}"
    else
        echo -e "${RED}Could not fetch joke${RESET}"
    fi
}

# =============================== GAMES ===============================
guess_number() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== GUESS NUMBER ===${RESET}"
    local secret=$((RANDOM % 100 + 1))
    local guess tries=0
    while true; do
        read -p "Guess (1-100): " guess
        ((tries++))
        if [[ $guess -lt $secret ]]; then echo -e "${YELLOW}Too low${RESET}"
        elif [[ $guess -gt $secret ]]; then echo -e "${YELLOW}Too high${RESET}"
        else echo -e "${GREEN}Correct in $tries tries!${RESET}"; break; fi
    done
}

rock_paper_scissors() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== ROCK PAPER SCISSORS ===${RESET}"
    local choices=("Rock" "Paper" "Scissors")
    while true; do
        echo -e "${CYAN}1) Rock  2) Paper  3) Scissors  4) Quit${RESET}"
        read -p "Choice: " player
        [[ $player == 4 ]] && break
        [[ ! $player =~ ^[1-3]$ ]] && { echo -e "${RED}Invalid${RESET}"; continue; }
        local comp=$((RANDOM % 3 + 1))
        echo -e "${BLUE}You: ${choices[$player-1]}  |  ${RED}Computer: ${choices[$comp-1]}${RESET}"
        if [[ $player -eq $comp ]]; then echo -e "${YELLOW}Tie${RESET}"
        elif [[ ($player -eq 1 && $comp -eq 3) || ($player -eq 2 && $comp -eq 1) || ($player -eq 3 && $comp -eq 2) ]]; then
            echo -e "${GREEN}You win!${RESET}"
        else echo -e "${RED}Computer wins${RESET}"; fi
    done
}

hangman() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== HANGMAN ===${RESET}"
    local words=("linux" "termux" "hacker" "python" "matrix")
    local word=${words[$RANDOM % ${#words[@]}]}
    local guessed="" attempts=6
    while [[ $attempts -gt 0 ]]; do
        local display=""
        for ((i=0; i<${#word}; i++)); do
            local c="${word:$i:1}"
            [[ "$guessed" == *"$c"* ]] && display+="$c" || display+="_"
        done
        echo -e "${CYAN}Word: $display   Attempts left: $attempts${RESET}"
        [[ "$display" == "$word" ]] && { echo -e "${GREEN}You won! Word: $word${RESET}"; return; }
        read -p "Guess letter: " g
        [[ ${#g} -ne 1 ]] && { echo -e "${RED}One letter${RESET}"; continue; }
        [[ "$guessed" == *"$g"* ]] && { echo -e "${YELLOW}Already guessed${RESET}"; continue; }
        guessed+="$g"
        [[ "$word" != *"$g"* ]] && ((attempts--)) && echo -e "${RED}Wrong!${RESET}"
    done
    echo -e "${RED}Game over! Word: $word${RESET}"
}

tictactoe() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== TIC TAC TOE vs Computer ===${RESET}"
    local b=(1 2 3 4 5 6 7 8 9)
    local player="X" comp="O" moves=0
    draw() {
        echo -e "\n ${b[0]} | ${b[1]} | ${b[2]} "
        echo "---|---|---"
        echo " ${b[3]} | ${b[4]} | ${b[5]} "
        echo "---|---|---"
        echo " ${b[6]} | ${b[7]} | ${b[8]} \n"
    }
    win() {
        local s=$1
        for w in "0 1 2" "3 4 5" "6 7 8" "0 3 6" "1 4 7" "2 5 8" "0 4 8" "2 4 6"; do
            local a b c
            read -r a b c <<< "$w"
            [[ ${b[$a]} == "$s" && ${b[$b]} == "$s" && ${b[$c]} == "$s" ]] && return 0
        done
        return 1
    }
    while true; do
        draw
        if [[ $moves -ge 9 ]]; then echo -e "${YELLOW}Tie!${RESET}"; break; fi
        while true; do
            read -p "Your move (1-9): " m
            if [[ $m =~ ^[1-9]$ ]] && [[ ${b[$((m-1))]} =~ ^[0-9]$ ]]; then
                b[$((m-1))]=$player
                ((moves++))
                break
            else echo -e "${RED}Invalid${RESET}"; fi
        done
        win "$player" && { draw; echo -e "${GREEN}You win!${RESET}"; break; }
        if [[ $moves -ge 9 ]]; then draw; echo -e "${YELLOW}Tie!${RESET}"; break; fi
        echo -e "${CYAN}Computer thinking...${RESET}"
        sleep 1
        local cm
        while true; do
            cm=$((RANDOM % 9))
            [[ ${b[$cm]} =~ ^[0-9]$ ]] && { b[$cm]=$comp; ((moves++)); break; }
        done
        win "$comp" && { draw; echo -e "${RED}Computer wins!${RESET}"; break; }
    done
}

dice() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== DICE ROLL ===${RESET}"
    read -p "Press Enter to roll..."
    echo -e "${GREEN}You rolled $((RANDOM % 6 + 1))${RESET}"
}

coinflip() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== COIN FLIP ===${RESET}"
    [[ $((RANDOM % 2)) -eq 0 ]] && echo -e "${YELLOW}Heads${RESET}" || echo -e "${YELLOW}Tails${RESET}"
}

trivia() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== TRIVIA ===${RESET}"
    local q="What is the capital of France?|Paris|London|Berlin|Madrid"
    IFS='|' read -r text correct w1 w2 w3 <<< "$q"
    echo -e "${CYAN}$text${RESET}"
    echo "1) $correct   2) $w1   3) $w2   4) $w3"
    read -p "Answer (1-4): " ans
    [[ $ans -eq 1 ]] && echo -e "${GREEN}Correct!${RESET}" || echo -e "${RED}Wrong! Answer: $correct${RESET}"
}

memory() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== MEMORY CHALLENGE ===${RESET}"
    local seq=""
    for i in {1..4}; do
        seq+="$((RANDOM % 10))"
        echo -e "${CYAN}Memorize: $seq${RESET}"
        sleep 2
        clear; show_banner
        read -p "Enter sequence: " guess
        [[ "$guess" != "$seq" ]] && { echo -e "${RED}Wrong! It was $seq${RESET}"; return; }
        echo -e "${GREEN}Correct! Next...${RESET}"
    done
    echo -e "${GREEN}You passed!${RESET}"
}

wordscramble() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== WORD SCRAMBLE ===${RESET}"
    local word="termux"
    local scrambled=$(echo "$word" | fold -w1 | shuf | tr -d '\n')
    echo -e "${CYAN}Unscramble: $scrambled${RESET}"
    read -p "Answer: " guess
    [[ "$guess" == "$word" ]] && echo -e "${GREEN}Correct!${RESET}" || echo -e "${RED}Wrong! It was $word${RESET}"
}

morse() {
    show_banner
    echo -e "${MAGENTA}${BOLD}=== MORSE TRAINER ===${RESET}"
    echo -e "${CYAN}What is Morse code for 'A'?${RESET}"
    read -p "Answer: " guess
    [[ "$guess" == ".-" ]] && echo -e "${GREEN}Correct!${RESET}" || echo -e "${RED}Wrong! It is .-${RESET}"
}

# =============================== CONTACT & REPORTS ===============================
show_contact() {
    show_banner
    echo -e "${MAGENTA}${BOLD}══════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${GLOW}                 📱 CONTACT & SOCIAL MEDIA${RESET}"
    echo -e "${MAGENTA}${BOLD}══════════════════════════════════════════════════════════════════${RESET}"
    echo -e "${CYAN}1) Open Telegram${RESET}"
    echo -e "${CYAN}2) Open WhatsApp (text only)${RESET}"
    echo -e "${CYAN}3) Open Website${RESET}"
    echo -e "${CYAN}4) Open YouTube Channel${RESET}"
    echo -e "${CYAN}5) Back to Main Menu${RESET}"
    echo -e "${MAGENTA}${BOLD}══════════════════════════════════════════════════════════════════${RESET}"
    read -p "👉 Choose [1-5]: " contact_choice
    case $contact_choice in
        1) termux-open "https://t.me/martechmods" 2>/dev/null || echo "Install termux-open" ;;
        2) termux-open "https://wa.me/2348140893169" 2>/dev/null || echo "Install termux-open" ;;
        3) termux-open "https://martechmods2.github.io/MartChat/ModHive.html" 2>/dev/null || echo "Install termux-open" ;;
        4) termux-open "https://youtube.com/@martechmods" 2>/dev/null || echo "Install termux-open" ;;
        5) return ;;
        *) echo -e "${RED}Invalid${RESET}" ;;
    esac
    read -p "Press Enter..."
}

view_reports() {
    if [[ -z "$(ls -A "$REPORT_DIR" 2>/dev/null)" ]]; then
        echo -e "${YELLOW}No reports found.${RESET}"
        return
    fi
    echo -e "${CYAN}Reports:${RESET}"
    select r in "$REPORT_DIR"/*; do
        [[ -n "$r" ]] && less -R "$r" && break
    done
}

delete_reports() {
    echo -e "${RED}Delete all reports? (y/N)${RESET}"
    read -r confirm
    [[ "$confirm" =~ ^[Yy]$ ]] && rm -rf "$REPORT_DIR"/* && echo -e "${GREEN}Deleted.${RESET}"
}

# =============================== MAIN MENU ===============================
main_menu() {
    while true; do
        show_banner
        random_quote
        echo -e "\n${GREEN}${BOLD}MARTECH MENU:${RESET}"
        echo -e "${GREEN}1)${RESET} Device Info           ${GREEN}12)${RESET} HTTP Headers"
        echo -e "${GREEN}2)${RESET} IP Geolocation        ${GREEN}13)${RESET} IP Tracker"
        echo -e "${GREEN}3)${RESET} Port Scanner          ${GREEN}14)${RESET} Password Generator"
        echo -e "${GREEN}4)${RESET} Email Breach Check    ${GREEN}15)${RESET} Weather"
        echo -e "${GREEN}5)${RESET} WHOIS Lookup          ${GREEN}16)${RESET} Crypto Price"
        echo -e "${GREEN}6)${RESET} DNS Brute             ${GREEN}17)${RESET} Text Encoder"
        echo -e "${GREEN}7)${RESET} MAC Lookup            ${GREEN}18)${RESET} URL Shortener"
        echo -e "${GREEN}8)${RESET} Phone Validator       ${GREEN}19)${RESET} Hash Generator"
        echo -e "${GREEN}9)${RESET} Port Knocker          ${GREEN}20)${RESET} Random Joke"
        echo -e "${GREEN}10)${RESET} Games Menu           ${GREEN}21)${RESET} Contact Menu"
        echo -e "${GREEN}11)${RESET} View Reports          ${GREEN}22)${RESET} Delete Reports"
        echo -e "${RED}23)${RESET} Exit"
        echo ""
        read -p "Choice (1-23): " choice

        case $choice in
            1) device_info ;;
            2) ip_geolocation ;;
            3) port_scanner ;;
            4) email_breach ;;
            5) whois_lookup ;;
            6) dns_brute ;;
            7) mac_lookup ;;
            8) phone_validator ;;
            9) port_knocker ;;
            10) 
                echo -e "${CYAN}1) Guess Number  2) RPS  3) Hangman  4) TicTacToe  5) Dice  6) Coin Flip  7) Trivia  8) Memory  9) Scramble  10) Morse${RESET}"
                read -p "Game: " g
                case $g in
                    1) guess_number ;;
                    2) rock_paper_scissors ;;
                    3) hangman ;;
                    4) tictactoe ;;
                    5) dice ;;
                    6) coinflip ;;
                    7) trivia ;;
                    8) memory ;;
                    9) wordscramble ;;
                    10) morse ;;
                    *) echo -e "${RED}Invalid${RESET}" ;;
                esac
                ;;
            11) view_reports ;;
            12) http_headers ;;
            13) ip_tracker ;;
            14) password_gen ;;
            15) weather ;;
            16) crypto_price ;;
            17) text_encoder ;;
            18) url_shortener ;;
            19) hash_gen ;;
            20) random_joke ;;
            21) show_contact ;;
            22) delete_reports ;;
            23) echo -e "${GREEN}Goodbye! Use responsibly.${RESET}"; exit 0 ;;
            *) echo -e "${RED}Invalid choice${RESET}" ;;
        esac
        echo ""
        read -p "Press Enter to continue..."
    done
}

# =============================== START ===============================
trap 'echo -e "\n${RED}Interrupted. Exiting...${RESET}"; exit 0' INT

if [[ "$#" -eq 1 && ( "$1" == "-h" || "$1" == "--help" ) ]]; then
    show_help
fi

# First run warning
if [[ ! -f "$HOME/.martech_warning_shown" ]]; then
    clear
    echo -e "${RED}${BOLD}⚠️  LEGAL DISCLAIMER ⚠️${RESET}"
    echo -e "${YELLOW}This tool is for educational and authorized security testing only.${RESET}"
    echo -e "${YELLOW}Unauthorized use against systems you do not own is illegal.${RESET}"
    echo -e "${YELLOW}The author assumes no liability for misuse.${RESET}"
    echo -e "${GREEN}Type 'accept' to continue: ${RESET}"
    read -r agreement
    if [[ "$agreement" != "accept" ]]; then
        echo -e "${RED}Exiting.${RESET}"
        exit 0
    fi
    touch "$HOME/.martech_warning_shown"
fi

# Install essential packages silently (ignore errors)
pkg install -y curl netcat-openbsd whois bc &>/dev/null || true

main_menu
