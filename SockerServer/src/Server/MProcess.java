/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package Server;

import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.util.Scanner;

/**
 *
 * @author benpham
 */
public class MProcess extends Thread {

    private Socket socket;

    public MProcess(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        Scanner sc = new Scanner(System.in);
        try {
            // xu li sau
            DataInputStream in = new DataInputStream(new BufferedInputStream(socket.getInputStream()));
            DataOutputStream pw = new DataOutputStream(socket.getOutputStream());
            String msg = "";

            while (true) {
                // nhan tin
                msg = in.readUTF();
                System.out.println("Client : " + msg);

                // gui tin nhan
                System.out.print("Server : ");
                msg = sc.nextLine();
                pw.writeUTF(msg);
                pw.flush();
            }

        } catch (Exception ex) {

        }

    }
}
