#!/bin/bash

# set vars
id="$1"
domain="$2"
path="$(pwd)"
target="$path/target/$id"
lists="$path/lists"
timestamp="$(date +%s)"
scan="$target/scans/$id-$timestamp"
patterns="$scan/patterns"

# kalo target ga eksis
mkdir -p $target
touch $target/root.txt
echo $domain | anew $target/root.txt
if [ ! -d "$target" ]; then
	echo "path ga ada"
	exit 1
fi
echo "$domain" | anew root-lists.txt
mkdir -p "$scan"
cd "$scan"

## mulai nyeken ##
echo "Mulai scan target:"
cat "$target/root.txt"
cp -v "$target/root.txt" "$scan/root.txt"


# update resolvers
echo "update resolvers dan wordlists"
mkdir -p "$lists"
# Download resolvers-trusted.txt, jika gagal maka coba lagi hingga berhasil atau terjadi error yang lain
while ! wget -O $lists/resolvers-trusted.txt https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt; do
    echo "Gagal mengunduh resolvers-trusted.txt, mencoba lagi dalam 10 detik..."
    sleep 10
done
# Download resolvers.txt, jika gagal maka coba lagi hingga berhasil atau terjadi error yang lain
while ! wget -O $lists/resolvers.txt https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt; do
    echo "Gagal mengunduh resolvers.txt, mencoba lagi dalam 10 detik..."
    sleep 10
done
# Download wordlists.txt, jika gagal maka coba lagi hingga berhasil atau terjadi error yang lain
while ! wget -O $lists/wordlists.txt https://raw.githubusercontent.com/trickest/wordlists/main/inventory/subdomains.txt; do
    echo "Gagal mengunduh wordlists.txt, mencoba lagi dalam 10 detik..."
    sleep 10
done

# perform scan
echo "Mencari subdomains"
cat $scan/root.txt | haktrails subdomains | anew subs.txt | wc -l
cat $scan/root.txt | subfinder | anew subs.txt | wc -l
cat $scan/root.txt | shuffledns -w $lists/wordlists.txt -r $lists/resolvers.txt | anew subs.txt | wc -l

echo "Resolve subdomains yang ditemukan"
puredns resolve "$scan/subs.txt" -r "$lists/resolvers.txt" -w "$scan/resolved.txt" | wc -l
dnsx -l "$scan/resolved.txt" -json -o "$scan/dns.json" | jq -r '.a?[]?' | anew "$scan/ips.txt" | wc -l

echo "Memindai port & menemukan server HTTP"
nmap -T4 -iL "$scan/ips.txt" --top-ports 3000 -n --open -oX "$scan/nmap.xml"
tew -x "$scan/nmap.xml" -dnsx "$scan/dns.json" -vhost -o "$scan/hostport.txt" | httpx -sr -srd "$scan/responses" -json -o "$scan/http.json"
cat "$scan/http.json" | jq -r '.url' | sed -e 's/:80$//g' -e 's/:443$//g' | anew "$scan/http.txt"

echo "crawling ges"
gospider -S "$scan/http.txt" -q | anew "$scan/gospider_crawl.txt"
cat $scan/http.txt | gau | anew "$scan/gau_crawl.txt"
cat "$scan/gospider_crawl.txt" "$scan/gau_crawl.txt" | anew "$scan/crawl.txt"


echo "Javascript scrapping"
cat "$scan/crawl.txt" | grep '\.js' | httpx -sr -srd js | anew "$scan/crawl.txt"

echo "Cari pattern bug"
mkdir -p "$patterns"

echo "XSS"
gf xss | anew "$patterns/xss.txt"

echo "Sqli"
gf sqli | anew "$patterns/sqli.txt"

echo "RCE"
gf rce | anew "$patterns/rce.txt"

echo "SSRF"
gf ssrf | anew "$patterns/ssrf.txt"

echo "IDOR"
gf idor | anew "$patterns/idor.txt"

echo "Redirect"
gf redirect | anew "$patterns/redirect.txt"

echo "XXE"
gf xxe | anew "$patterns/xxe.txt"



# hitung waktu
akhir=$(date +%s)
detik="$(expr $akhir - $timestamp)"
waktu=""

if [[ "$detik" gt 59 ]]
then
	menit=$(expr $detik / 60)
	waktu="$menit menit"
else
	waktu="$detik detik"
fi
echo "scan $id dalam waktu $waktu"
