package com.zeroone.libicc;

public class Main {

  public static void main(String[] args) {
    String lib = System.getenv("lib");
    System.out.println("lib >>>>>>>>>"+lib);
    System.load(lib);
  }
}
