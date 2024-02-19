/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai18thread1.newpackage;

import java.util.ArrayList;

/**
 *
 * @author benpham
 */
public class Buffer {

    private int capacity;
    private ArrayList<Integer> products;

    public Buffer(int capacity) {
        this.capacity = capacity;
        products = new ArrayList<>();
    }

    public void addProduct(int product, int producerId) {
        System.out.println("-------------------------------");
        System.out.println("producer " + producerId + " add " + product);

        products.add(product);
        System.out.println("So luong ton kho " + products.size());
    }

    public void removeProduct(int customerId) {
        System.out.println("Customer " + customerId + " bought " + products.get(0));
        products.remove(0);
    }

    public int getCapacity() {
        return this.capacity;
    }

    public int getSize() {
        return this.products.size();
    }

}
