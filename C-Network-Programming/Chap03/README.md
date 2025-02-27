Prerequisites
- Install libssh library
    ```shell
      sudo apt update && sudo apt upgrade
      sudo apt-get install libssh-dev 
    ```

Run the code 

4.1. Simple SSH Connection:

- Run the following command to compile the code:
    ```shell
      gcc -o ssh_client ssh_client.c -lssh
    ```
    
- Run the following command to execute the code:
    ```shell
      ./ssh_client
    ```

4.3. Secure File Transfer:

- Run the following command to run the code for ssh_file_transfer:
    ```shell
        ./ssh_file_transfer <mode> <localfile> <remotefile> <password> 
    
        example:
          ./ssh_file_transfer upload localfile.txt /home/chienpham/remotefile.txt password  
    ```

4.4. Port forwarding with SSH Tunnel:

- Run the following command to run the code for ssh_tunnel:
    ```shell
        ./ssh_tunnel <localport> <remoteport> <remotehost> <username> <password> 
        ./ssh_tunnel <remotehost> <username> <password> 
        example:
          ./ssh_tunnel 8080 80 localhost chienpham password
   ```

Check the result
- Run the following command to check the result:
    ```    shell
              http://<localhost>:<localport> 
   ```

example: http://localhost:9000 it loads the web page from the remote server<192.168.255.150>:80
        