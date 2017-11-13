#!/bin/bash

javac GmSSL.java
java -Djava.library.path=../ GmSSL
