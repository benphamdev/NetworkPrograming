/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai26chatroomclient;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Scanner;

/**
 *
 * @author benpham
 */
public class ChatClient {

    private static final int PORT = 6666;
    private String URL = "";

    public void startClient() {
        try {
            URL = InetAddress.getLocalHost().getHostName();
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            Socket socket = new Socket(URL, PORT);
            System.out.println("Connected to server");

            // lien tuc doc du lieu tu sever
            ClientListener clientListener = new ClientListener(socket);
            new Thread(clientListener).start();

            // lien tuc doc du lieu tu scanner
            OutputStream outputStream = socket.getOutputStream();
            Scanner sc = new Scanner(System.in);
            while (true) {
                String message = sc.nextLine();
                outputStream.write(message.getBytes());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
