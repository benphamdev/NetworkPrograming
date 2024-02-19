/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package Server;

import java.net.ServerSocket;
import java.net.Socket;

/**
 *
 * @author benpham
 */
public class Server {

    public static void main(String[] args) {
        try {
            // tao server socket va lang nghe

            int port = 6666;
            ServerSocket serverSocket = new ServerSocket(port);

            // chap nhan ket noi tu 1 client
            while (true) {
                Socket clientSocket = serverSocket.accept();
                MProcess mProcess = new MProcess(clientSocket);
                mProcess.start();
            }

            // bat dau trao doi thong tin
//            //ngat ket noi
//            clientSocket.close();
//            serverSocket.close();
        } catch (Exception e) {
        }
    }
}
