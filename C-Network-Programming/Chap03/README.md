Prerequisites
- Install libssh library
    ```shell
      sudo apt update && sudo apt upgrade
      sudo apt-get install libssh-dev 
    ```

- Run the following command to compile the code:
    ```shell
      gcc -o ssh_client ssh_client.c -lssh
    ```
    
- Run the following command to execute the code:
    ```shell
      ./ssh_client
    ```
  
- Run the following command to run the code for ssh_file_transfer:
    ```shell
        ./ssh_file_transfer <mode> <localfile> <remotefile> <password> 
    
        example:
          ./ssh_file_transfer upload localfile.txt /home/chienpham/remotefile.txt password  
    ```