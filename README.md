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

INDDoS
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


