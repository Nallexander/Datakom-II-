#!/bin/bash
touch output1.txt
for i in `seq 1 20`;
do
    python Task3.py
done

grep -A 1 "1.0.0.1 --> 2.1.0.2" output1.txt | grep -v -- "--" > output_2.1.0.2
grep -A 1 "1.0.0.1 --> 2.2.1.2" output1.txt | grep -v -- "--" > output_2.2.1.2
grep -A 1 "1.0.0.1 --> 2.3.3.2" output1.txt | grep -v -- "--" > output_2.3.3.2
grep -A 1 "1.0.0.1 --> 1.1.0.2" output1.txt | grep -v -- "--" > output_1.1.0.2
grep -A 1 "1.0.0.1 --> 2.3.1.2" output1.txt | grep -v -- "--" > output_2.3.1.2

