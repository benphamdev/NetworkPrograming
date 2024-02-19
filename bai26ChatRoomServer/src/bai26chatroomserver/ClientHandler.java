/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai26chatroomserver;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

/**
 *
 * @author benpham
 */
public class ClientHandler implements Runnable {

    private Socket socket;
    private String id;
    private InputStream inputStream;
    private OutputStream outputStream;
    private ChatServer chatServer;

    public ClientHandler(Socket socket, String id, ChatServer chatServer) {
        this.socket = socket;
        this.id = id;
        this.chatServer = chatServer;

        try {
            this.inputStream = socket.getInputStream();
            this.outputStream = socket.getOutputStream();
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
                this.chatServer.broadcastMessage(this.id, message);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendMessage(String message) {
        try {
            outputStream.write(message.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getId() {
        return id;
    }

}
