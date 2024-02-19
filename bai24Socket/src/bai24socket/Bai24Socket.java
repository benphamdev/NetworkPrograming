/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package bai24socket;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;

/**
 *
 * @author benpham
 */
public class Bai24Socket {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) throws UnknownHostException {
        String hostName = InetAddress.getLocalHost().getHostName();
        checkPort("https://www.facebook.com/");
    }

    public static void checkPort(String urlString) {
        int startPort = 1, endPort = 65535; // Maximum port number
        System.out.println("Scanning ports on host: " + urlString);

        for (int port = startPort; port <= endPort; port++) {
            try (Socket socket = new Socket()) {
                socket.connect(new InetSocketAddress(urlString, port), 1000); // Timeout set to 1 second
                System.out.println("Port " + port + " is open");
            } catch (IOException e) {
//                 Connection refused or timeout
//                System.out.println("Port " + port + " is closed"); // Optionally print closed ports
            }

//            try {
//                Socket socket = new Socket(urlString, port);
////                socket.connect(new InetSocketAddress(hostName, port), 1000);
//                System.out.println("Port : " + port + " is open");
//            } catch (Exception e) {
////                e.printStackTrace();
//            }
        }

        System.out.println("Port scan completed");
    }
}
