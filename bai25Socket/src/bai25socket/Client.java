/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai25socket;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Scanner;

/**
 *
 * @author benpham
 */
public class Client {

    public static void main(String[] args) {
        Scanner sc = new Scanner(System.in);

        try {
            // ket noi den server
            int port = 6666;
            Socket clientSocket = new Socket(InetAddress.getLocalHost().getHostName(), port);

            // xu li sau
            DataInputStream in = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
            DataOutputStream pw = new DataOutputStream(clientSocket.getOutputStream());
            String msg = "";

            while (true) {
                // gui tin nhan
                System.out.print("Client : ");
                msg = sc.nextLine();
                pw.writeUTF(msg);
                pw.flush();

                // nhan tin
                System.out.println("Server : " + in.readUTF());
            }
        } catch (Exception e) {
            System.out.println("khong the ket noi");
        }
    }
}
