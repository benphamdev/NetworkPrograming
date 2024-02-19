/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package bai27_remote_client;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

/**
 * @author benpham
 */
public class Bai27_Remote_Client {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        try {
            Socket socket = new Socket(
                    InetAddress.getLocalHost().getHostName(), 6666);

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));

            PrintWriter pw = new PrintWriter(socket.getOutputStream());

            Scanner sc = new Scanner(System.in);

            boolean exit = false;
            while (!exit) {
                System.out.println("1. shutdown");
                System.out.println("2. restart");
                System.out.println("3. cancel shutdown");
                System.out.println("4. screen shot");
                System.out.println("5. Dowload");
                System.out.println("6. Upload");
                int choice = sc.nextInt();
                sc.nextLine();
                switch (choice) {
                    case 1:
                        pw.println("shutdown");
                        pw.flush();
                        System.out.println(br.readLine());
                        break;
                    case 2:
                        pw.println("restart");
                        pw.flush();
                        System.out.println(br.readLine());
                        break;
                    case 3:
                        pw.println("cancel");
                        pw.flush();
                        System.out.println(br.readLine());
                        break;
                    case 4:
                        pw.println("screen");
                        pw.flush();

                        int len = Integer.parseInt(br.readLine());
                        byte[] imageBytes = new byte[len];
                        int byteRead = socket.getInputStream().read(imageBytes);
                        if (byteRead > 0) {
                            System.out.println("nhap ten anh : ");
                            String fileName = sc.nextLine();
                            Path imgPath = Paths.get(fileName + ".png");
                            Files.write(imgPath, imageBytes);
                            System.out.println("done");
                        }
                        break;
                    case 5:
                        pw.println("download");
                        pw.flush();
                        
                    default:
                        throw new AssertionError();
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
