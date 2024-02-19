/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package bai27_remote_server;

import javax.imageio.ImageIO;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

/**
 * @author benpham
 */
public class Bai27_Remote_Server {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        try {
            ServerSocket serverSocket = new ServerSocket(6666);
            while (true) {
                Socket socket = serverSocket.accept();

                System.out.println("Client connnected: "
                        + socket.getInetAddress()
                                .getHostName());

                Thread thread = new Thread(
                        () -> handleClientRequest(socket)
                );
                thread.start();
            }
        } catch (Exception e) {
        }
    }

    public static void handleClientRequest(Socket socket) {
        try {
            while (true) {
                BufferedReader br = new BufferedReader(
                        new InputStreamReader(socket.getInputStream()));

                PrintWriter pw = new PrintWriter(socket.getOutputStream());

                String request = br.readLine();
                System.out.println(request);

                if (request.equals("shutdown")) {
                    // su  dung runtime
                    String[] cmd = {"/bin/sh",
                            "-c", "shutdown -P +30"};
                    Runtime.getRuntime()
                           .exec(cmd);
                    pw.println("may tinh dang tat ....");
                    pw.flush();
                } else if (request.equals("restart")) {
                    String[] cmd1 = {"reboot"};
                    Runtime.getRuntime()
                           .exec(cmd1);
                    pw.println("may tinh dang khoi dong lai ");
                    pw.flush();

                } else if (request.equals("cancel")) {
                    String[] cmd = {"/bin/sh",
                            "-c", "shutdown -c"};
                    Runtime.getRuntime()
                           .exec(cmd);
                    pw.println("may tinh da huy tat ");
                    pw.flush();
                } else if (request.equals("screen")) {
                    BufferedImage capture = new Robot()
                            .createScreenCapture(new Rectangle(Toolkit.getDefaultToolkit()
                                                                      .getScreenSize()));

                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    ImageIO.write(capture, "png", baos);
                    byte[] imageBytes = baos.toByteArray();
                    baos.close();

                    pw.println(imageBytes.length);
                    pw.flush();
                    socket.getOutputStream()
                          .write(imageBytes);
                } else if (request.equals("download")) {

                }
            }

        } catch (Exception e) {
            System.out.println("loi");
            e.printStackTrace();
        }
    }
}
