/*
 * JASON HOWARTH
 * SDEV325 6380
 * 16 JULY 2017
 * HOMEWORK 5: Vulnerable to CWE-759 (Use of a One-Way Hash without a Salt)
 * File: SDEV325_HW5_CWE759_Vulnerable.java
 */
package sdev325_hw5_cwe759_vulnerable;

import java.util.*;
import java.security.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class SDEV325_HW5_CWE759_Vulnerable {
           
    public static void main(String[] args) {

        Scanner input = new Scanner(System.in);

        //Tell user to create a username
        System.out.print("Create an account. Enter a username: ");
        //Store username
        String inputUsername = input.next();

        //Tell user to create a password
        System.out.print("\nEnter a password: ");
        //Store password
        String inputPassword = input.next();

        //CWE-759 VULNERABILITY: Uses one-way hash without a Salt for Password
        MessageDigest md;
        try {
            //Use SHA algorithm for hashing
            md = MessageDigest.getInstance("SHA");
            
            //Get inputPassword bytes
            md.update(inputPassword.getBytes());
            
            //Hashes inputPassword bytes using SHA algorithm - DOES NOT ADD SALT (CWE-759 VULNERABILITY)
            byte byteData[] = md.digest();

            //Convert hashed inputPassword bytes to hexadecimal
            StringBuffer hexString = new StringBuffer();
            for (int i=0;i<byteData.length;i++) {
                hexString.append(Integer.toHexString(0xFF & byteData[i]));
            }

            //Store both the username and hashed password
            String storedUsername = inputUsername;
            String storedPassword = hexString.toString();

            //Print Username and Hashed Password
            System.out.print("\nYour Username is " + storedUsername + " and ");
            System.out.print("your hashed password in hex is " + storedPassword + ".\n");

        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SDEV325_HW5_CWE759_Vulnerable.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}
