/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Main.java to edit this template
 */
package bai20synchronized;

/**
 *
 * @author benpham
 */
public class Bai20synchronized {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        // TODO code application logic here

        Counter counter = new Counter();
        Thread thr = new Thread(() -> {
            for (int i = 0; i < 1000; i++) {
                counter.increament();
            }
        });

        Thread thr1 = new Thread(() -> {
            for (int i = 0; i < 2000; i++) {
                counter.increament();
            }
        });

        thr.start();;

        thr1.start();
        try {
            thr.join();
            thr1.join();
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        System.out.println(counter.getCnt());
    }

}
