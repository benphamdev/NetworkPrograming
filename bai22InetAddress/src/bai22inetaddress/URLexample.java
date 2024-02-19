/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai22inetaddress;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URI;
import java.net.URL;

public class URLexample {

    public static void main(String[] args) {
        try {
            String urlString = "https://www.facebook.com/";
            URL url = new URI(urlString).toURL();

            // doc du lieu
            InputStreamReader inputStreamReader = new InputStreamReader(url.openStream());
            BufferedReader br = new BufferedReader(inputStreamReader);
            String line = "";

            while ((line = br.readLine()) != null) {
                System.out.println(line);
            }

            br.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
