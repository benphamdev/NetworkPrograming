/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package bai18thread;

/**
 *
 * @author benpham
 */
public class Bai18Thread {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here
        System.out.println("Main");

        Thread th = new TaskA();
        th.start();

        for (int i = 0; i < 999; i++) {
            System.out.println("main : " + i);
        }

        Thread th1 = new Thread(new TaskB());
        th1.start();
        System.out.println("Finish");
    }

}
