/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.bai21managelibthread;

/**
 *
 * @author benpham
 */
public class Student extends Thread {

    private Library lib;
    private String title, id;

    public Student(Library lib, String title, String id) {
        this.lib = lib;
        this.title = title;
        this.id = id;
    }

    @Override
    public void run() {
        try {
            for (int i = 0; i < 5; i++) {
                if (lib.borrowBook(id, title)) {
                    sleep((long) Math.random());
                    lib.returnBook(id, title);
                    sleep(2000);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
