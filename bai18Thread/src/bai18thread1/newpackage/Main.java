/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai18thread1.newpackage;

/**
 *
 * @author benpham
 */
public class Main {

    public static void main(String[] args) {
        Buffer buffer = new Buffer(50);
        Customer c = new Customer(1, buffer);
        Customer c1 = new Customer(12, buffer);
        Customer c2 = new Customer(123, buffer);
        Customer c3 = new Customer(1234, buffer);
        Customer c4 = new Customer(12345, buffer);
        Customer c5 = new Customer(12345, buffer);
        Customer c6 = new Customer(12453, buffer);
        Customer c7 = new Customer(12343, buffer);
        Producer producer1 = new Producer(334, buffer);
        Producer producer2 = new Producer(33, buffer);
        Producer producer3 = new Producer(323, buffer);
        Producer producer4 = new Producer(33, buffer);
        Producer producer5 = new Producer(3233, buffer);
        Producer producer6 = new Producer(33433, buffer);

        // bat dau san xuat
        producer1.start();
        producer2.start();
        producer3.start();
        producer4.start();
        producer5.start();
        producer6.start();
        // bat dau mua
        c.start();
        c1.start();
        c2.start();
        c3.start();
        c4.start();
        c5.start();
        c6.start();
        c7.start();
    }
}
