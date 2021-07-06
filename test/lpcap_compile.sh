#!/bin/bash

echo "input filename(no extension): "
read name

gcc -o $name.out $name.c -lpcap

