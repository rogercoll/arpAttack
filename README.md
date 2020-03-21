#ARP ATTACK

## Requisits for compilation

sudo apt-get install libpcap-dev

## Install

go build -o main main.go


## Run

./main dos --i wlan0 --victim 192.168.1.70 --fakeAddr 192.168.1.1
