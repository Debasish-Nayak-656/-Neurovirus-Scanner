/*
    NeuroVirus YARA Rules — Network Threat Indicators
*/

rule C2_Communication_Patterns
{
    meta:
        description = "Detects common C2 (Command & Control) communication patterns"
        severity = "critical"
        category = "C2"

    strings:
        $b1 = "beacon" nocase
        $b2 = "checkin" nocase
        $b3 = "heartbeat" nocase
        $ua1 = "Mozilla/4.0 (compatible; MSIE 6.0)" // common malware UA
        $ua2 = "curl/7.29" // hardcoded curl versions
        $p1 = "/gate.php"
        $p2 = "/panel.php"
        $p3 = "/c2/"
        $p4 = "/cmd?"
        $p5 = "/upload.php"
        $cobalt = "cdn.bootcss.com/bootstrap"
        $empire = "launcher.bat"

    condition:
        2 of ($b*) or 1 of ($p*) or any of ($ua*) or $cobalt or $empire
}


rule DNS_Tunneling_Indicators
{
    meta:
        description = "Detects DNS tunneling indicators"
        severity = "high"
        category = "NETWORK"

    strings:
        $dns1 = "dnscat" nocase
        $dns2 = "iodine" nocase
        $dns3 = "dns2tcp" nocase
        $dns4 = "TXT" fullword
        $long_sub = /[a-z0-9]{40,}\.[a-z]{2,6}/

    condition:
        any of ($dns*) or $long_sub
}


rule Tor_Hidden_Service
{
    meta:
        description = "Detects references to Tor hidden services"
        severity = "high"
        category = "NETWORK"

    strings:
        $onion = ".onion" nocase
        $tor1 = "torproject.org" nocase
        $tor2 = "SOCKS5" nocase
        $tor3 = "127.0.0.1:9050"
        $tor4 = "127.0.0.1:9150"

    condition:
        any of them
}


rule Data_Exfiltration_Patterns
{
    meta:
        description = "Detects data exfiltration behaviour"
        severity = "critical"
        category = "EXFILTRATION"

    strings:
        $ftp1 = "ftp://" nocase
        $ftp2 = "FtpPutFile" nocase
        $smtp1 = "smtp://" nocase
        $smtp2 = "SmtpClient" nocase
        $paste1 = "pastebin.com/api" nocase
        $paste2 = "transfer.sh" nocase
        $cloud1 = "api.dropbox.com" nocase
        $cloud2 = "storage.googleapis.com" nocase
        $doc1 = "Documents" fullword
        $doc2 = "password" nocase
        $doc3 = "credentials" nocase

    condition:
        (1 of ($ftp*) or 1 of ($smtp*) or 1 of ($paste*) or 1 of ($cloud*)) and
        1 of ($doc*)
}
