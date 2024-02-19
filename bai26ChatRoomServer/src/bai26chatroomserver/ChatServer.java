/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai26chatroomserver;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author benpham
 */
public class ChatServer {

    private static int PORT = 6666;
    private List<ClientHandler> clientHandlers = new ArrayList<>();

    public void startServer() {
        try {
            // webserver
            ServerSocket serverSocket = new ServerSocket(PORT);
            System.out.println("Server startd listening on port : " + PORT);

            while (true) {
                Socket clientSocket = serverSocket.accept();
                System.out.println("New client connected : " + clientSocket.getInetAddress().getHostAddress());

                ClientHandler clientHandler
                        = new ClientHandler(clientSocket, System.currentTimeMillis() + " ", this);
                clientHandlers.add(clientHandler);
                new Thread(clientHandler).start();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void broadcastMessage(String id, String message) {
        for (ClientHandler clientHandler : clientHandlers) {
            if (!clientHandler.getId().equals(id)) {
                clientHandler.sendMessage(id + " : " + message);
            }
        }
    }
}
