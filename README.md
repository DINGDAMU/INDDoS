Citation
--------
```
@article{ding2021innetwork,
  title={In-Network Volumetric DDoS Victim Identification Using Programmable Commodity Switches},
  author={Ding, Damu and Savi, Marco and Pederzolli, Federico and Mauro, Campanella and Siracusa, Domenico},
  journal={IEEE Transactions on Network and Service Management},
  year={2021},
  publisher={IEEE}
}
```
INDDoS has been implemented in two different testbeds:
* Bmv2 (available in the folder INDDoS.p4app)
* Tofino (available in folder INDDoS\_TNA)

#Bmv2
Installation
------------

1. Install [docker](https://docs.docker.com/engine/installation/) if you don't
   already have it.

2. Clone the repository to local 

    ```
    git clone https://github.com/DINGDAMU/INDDoS.git  
    ```

3. ```
    cd INDDoS
   ```

4. If you want, put the `p4app` script somewhere in your path. For example:

    ```
    cp p4app /usr/local/bin
    ```

Execute the program
--------------

1.  ```
    ./p4app run INDDoS.p4app 
    ```
    After this step you'll see the terminal of **mininet**
2. Forwarding some packets in **mininet**

   ```
    pingall
    pingall
   ```
or 
   ```
    h1 ping h2 -c 12 -i 0.1
   ```

It is also possible to test the code by using **scapy**
An example can be found in INDDoS.p4app/send.py and INDDoS.p4app/receive.py


3. Enter INDDoS.p4app folder
   ```
    cd INDDoS.p4app 
   ```
4. Check the result by reading the register
   ```
    ./read_registers1.sh
    ./read_registers2.sh
    ./read_registers3.sh
   ```
 
 In registers `occSlots 1-3` there are the resulsted number of 1s.

# Tofino
The P4 code has been installed and tested in Edgecore Wedge-100BF-32X switch equipped with Barefoot Tofino 3.3 Tbps ASIC using SDE 9.1.1. 

