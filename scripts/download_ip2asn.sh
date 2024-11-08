#!/bin/bash

cd "$(dirname "$0")"
cd ..

echo "Download ip2asn-v4 and ip2asn-v6 files..."
echo "=====START"
wget https://iptoasn.com/data/ip2asn-v4.tsv.gz -O ./data/ip2asn-v4.tsv.gz
wget https://iptoasn.com/data/ip2asn-v6.tsv.gz -O ./data/ip2asn-v6.tsv.gz

echo "=====FINISH"

echo "Uncompress ip2asn-v4 and ip2asn-v6 files..."

gunzip ./data/ip2asn-v4.tsv.gz
gunzip ./data/ip2asn-v6.tsv.gz

echo "Completed ip2asn files are in 'data' directory!"