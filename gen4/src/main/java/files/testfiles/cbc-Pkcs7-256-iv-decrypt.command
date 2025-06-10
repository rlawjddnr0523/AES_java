#!/bin/bash

cd "$(dirname "$0")"

chmod +x cbc-Pkcs7-256-iv-decrypt.command

if ! command -v java &> /dev/null; then
    echo "❌ Java가 설치되어 있지 않습니다. https://www.oracle.com/kr/java/technologies/downloads/ 에서 설치해주세요!"
    read -p "Enter를 누르시면 창이 닫힙니다."
    exit 1
fi

java -jar AES-java-0.2b.jar --decrypt --keysize 256 --mode cbc --padding pkcs7padding \
--infile cipher.txt \
--outfile result.txt \
--keypath Sec_key.txt \
--initialvector initialVector.txt

echo ""
read -p "Enter를 누르시면 창이 닫힙니다."
exit 1
