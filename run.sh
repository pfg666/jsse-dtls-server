#!/bin/bash
javac -d bin/ -sourcepath src/ src/example/Main.java
java -cp bin/ example.Main $@
