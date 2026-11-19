YHN - The Guardian v0.0.1 -- Advanced Protection System - Anti-debug     

build:
apt update && apt install -y libssl-dev
gcc -Wall -Wextra -O2 yhn.c -o yhn_guardian -lcrypto
./yhn_guardian
