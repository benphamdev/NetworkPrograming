/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */
package com.mycompany.bai21managelibthread;

/**
 *
 * @author benpham
 */
public class Bai21ManageLibThread {

    public static void main(String[] args) {
        Library library = new Library();
        library.addBook(new Book("java", "chien"));
        library.addBook(new Book("javascript", "chien1"));
        library.addBook(new Book("go", "chien2"));
        library.addBook(new Book("c++", "chien3"));
        library.addBook(new Book("c", "chien4"));
        library.addBook(new Book("python", "chien5"));
        library.addBook(new Book("c#", "chien6"));

        library.displayBooks();

//        library.borrowBook("java");
//        library.borrowBook("java");
//        library.borrowBook("go");
//        library.returnBook("java");
//        library.returnBook("java");
        Student s = new Student(library, "java", "1");
        Student s1 = new Student(library, "java", "2");
        Student s2 = new Student(library, "java", "3");
        Student s3 = new Student(library, "java", "4");
        s.start();
        s1.start();
        s2.start();
        s3.start();

    }
}
