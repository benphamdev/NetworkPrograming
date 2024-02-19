/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai20synchronized;

/**
 *
 * @author benpham
 */
public class Counter {

    // đồng bộ : tại một thời điểm , chỉ có 1 thread được tương tác với giá trị
    private int cnt;

//    synchronized : đồng bộ, tại 1 thời điểm chỉ có 1 thread gọi
    public synchronized void increament() {
        this.cnt++;
    }

    public int getCnt() {
        return cnt;
    }
}
