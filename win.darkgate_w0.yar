rule win_darkgate_w0 {
    meta:
        author = "RussianPanda"
        description = "Detects DarkGate" 
        date = "2023-09-17"
        source="https://www.esentire.com/blog/from-darkgate-to-danabot"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkgate"
        malpedia_rule_date = "20230917"
        malpedia_hash = ""
        malpedia_version = "20231204"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $s1 = "hanydesk"
        $s2 = "darkgate.com"
        $s3 = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+="
        $s4 = {80 e3 30 81 e3 ff 00 00 00 c1 eb 04}
        $s5 = {80 e3 3c 81 e3 ff 00 00 00 c1 eb 02} 
        $s6 = {80 e1 03 c1 e1 06}
    condition:
        all of ($s*) 
        and uint16(0) == 0x5A4D
    }
