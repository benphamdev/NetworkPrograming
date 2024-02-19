/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package bai22inetaddress;

import java.net.InetAddress;

/**
 *
 * @author benpham
 */
public class Bai22InetAddress {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here

        try {
            String domain = "www.google.com";
            InetAddress address = InetAddress.getByName(domain);

            System.out.println("Ten mien " + domain);
            System.out.println("dia chi ip : " + address.getHostAddress());

            InetAddress localhost = InetAddress.getLocalHost();
            System.out.println("dia chi ip cua localhost : " + localhost.getHostAddress());
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

}
