/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai18thread;

/**
 *
 * @author benpham
 */
public class TaskA extends Thread {

    @Override
    public void run() {
        super.run(); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/OverriddenMethodBody
        for (int i = 0; i < 10000; i++) {
            System.out.println("Task A : " + i);
        }
    }

}
