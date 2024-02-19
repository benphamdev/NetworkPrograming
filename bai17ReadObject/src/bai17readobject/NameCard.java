/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package bai17readobject;

import java.io.Serializable;

/**
 *
 * @author benpham
 */
public class NameCard implements Serializable {

    private String fullName, address, phoneNum, email, image;

    public NameCard(String fullName, String address, String phoneNum, String email, String image) {
        this.fullName = fullName;
        this.address = address;
        this.phoneNum = phoneNum;
        this.email = email;
        this.image = image;
    }

    public NameCard() {

    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getAddress() {
        return address;
    }

    public void setAddress(String address) {
        this.address = address;
    }

    public String getPhoneNum() {
        return phoneNum;
    }

    public void setPhoneNum(String phoneNum) {
        this.phoneNum = phoneNum;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getImage() {
        return image;
    }

    public void setImage(String image) {
        this.image = image;
    }

    @Override
    public String toString() {
        return "NameCard{" + "fullName=" + fullName + ", address=" + address + ", phoneNum=" + phoneNum + ", email=" + email + ", image=" + image + '}';
    }

}
