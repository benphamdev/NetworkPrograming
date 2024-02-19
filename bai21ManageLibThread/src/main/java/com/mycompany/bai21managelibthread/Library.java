/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.bai21managelibthread;

import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author benpham
 */
public class Library {

    private List<Book> books;

    public Library() {
        books = new ArrayList<>();
    }

    public synchronized void addBook(Book book) {
        books.add(book);
        System.out.println(" da them quyen sach " + book.getTitle());
    }

    public synchronized boolean borrowBook(String id, String title) {
        for (Book book : books) {
            if (book.getTitle().equals(title) && book.isAvailable()) {
                book.setAvailable(false);
                System.out.println("mssv " + id + " Da cho muon sach " + title);
                return true;
            }
        }
        System.out.println("mssv " + id + " khong the cho muon sach " + title);
        return false;
    }

    public synchronized boolean returnBook(String id, String title) {
        for (Book book : books) {
            if (book.getTitle().equals(title) && !book.isAvailable()) {
                book.setAvailable(true);
                System.out.println("mssv " + id + " Da tra sach " + title);
                return true;
            }
        }
        System.out.println("mssv " + id + " khong the tra sach " + title);
        return false;
    }

    public void displayBooks() {
        for (Book book : books) {
            System.out.println(book);
        }
    }
}
