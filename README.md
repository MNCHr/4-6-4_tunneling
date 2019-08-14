# Coarse tunneling
## About 4-6-4_tunneling
- [eth][v4] <-O-> [eth][v6][v4] <-O-> [eth][v4]

## Execution
1. create veth0~4 with veth_setup.sh of behavior_model/tools repository
  ```
  sudo ./veth_setup.sh
  ```
2. compile
  ```
  $ p4c-bm2-ss 
  ```

n. use hdr.ipv4.ttl and hdr.ipv6.hopLimit as indicator of operation of each switch
  ```
  $ sudo simple_switch -i 1@veth2 -i 2@veth0 test.json --device-id 0 --thrift-port 9090 --log-console > P4_1.txt
  $ sudo simple_switch -i 1@veth3 -i 2@veth4 test.json --device-id 1 --thrift-port 9091 --log-console > P4_2.txt
  $ tail -f P4_1.txt | grep -e hdr.ipv4.ttl -A 10 -B 40 -e hdr.ipv6.hopLimit -A 11 -B 50
  $ sudo ./send.py
  ```
