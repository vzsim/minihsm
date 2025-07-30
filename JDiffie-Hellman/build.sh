#!/bin/sh

javac --class-path ./libs/bcprov-jdk18on-1.81.jar --source-path ./src -d ./bin ./src/ru/dh/Main.java
java  --class-path ./libs/bcprov-jdk18on-1.81.jar:./bin ru.dh.Main