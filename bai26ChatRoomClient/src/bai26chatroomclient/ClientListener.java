/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai26chatroomclient;

import java.io.InputStream;
import java.net.Socket;

/**
 *
 * @author benpham
 */
public class ClientListener implements Runnable {

    private Socket socket;
    private InputStream inputStream;

    public ClientListener(Socket socket) {
        this.socket = socket;
        try {
            this.inputStream = socket.getInputStream();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        try {
            byte[] bytes = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(bytes)) != -1) {
                String message = new String(bytes, 0, bytesRead);
                System.out.println(message);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
