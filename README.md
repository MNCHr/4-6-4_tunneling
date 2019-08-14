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

