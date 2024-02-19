/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai22inetaddress;

import java.net.URI;
import java.net.URL;
import javax.net.ssl.HttpsURLConnection;

/**
 *
 * @author benpham
 */
public class UrlExample2 {

    public static void main(String[] args) {
        String[] websites = {
            "https://titv.nv",
            "https://google.com",
            "https://nvexpress.net"
        };

        for (String wString : websites) {
            checkWebsite(wString);
        }
    }

    public static void checkWebsite(String urlString) {
        try {
            URL url = new URI(urlString).toURL();
            HttpsURLConnection connection = (HttpsURLConnection) url.openConnection();

            // http code :  200, 401, 403, 500, 404
            int respone = connection.getResponseCode();

            if (respone == 200) {
                System.out.println(urlString + " trang web hoat dong");
            } else {
                System.out.println("khong hoat dong " + respone);
            }

        } catch (Exception e) {
            System.out.println(urlString + " khong the ket noi ");
        }
    }
}
