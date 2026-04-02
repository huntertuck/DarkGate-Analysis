rule win_darkgate_w1 {
    meta:
        author = "enzok"
        description = "DarkGate Payload"
        cape_type = "DarkGate Payload"
        source="https://github.com/kevoreilly/CAPEv2/blob/8689f9f05dec4500d7becd03e9939444f3be3a8f/data/yara/CAPE/DarkGate.yar"
        malpedia_reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.darkgate"
        malpedia_rule_date = "20230917"
        malpedia_hash = ""
        malpedia_version = "20231204"
        malpedia_sharing = "TLP:WHITE"
    strings:
        $part1 = {8B 55 ?? 8A 4D ?? 80 E1 3F C1 E1 02 8A 5D ?? 80 E3 30 81 E3 FF [3] C1 EB 04 02 CB 88 4C 10 FF FF 45 ?? 80 7D ?? 40}
        $part2 = {8B 55 ?? 8A 4D ?? 80 E1 0F C1 E1 04 8A 5D ?? 80 E3 3C 81 E3 FF [3] C1 EB 02 02 CB 88 4C 10 FF FF 45 ?? 80 7D ?? 40}
        $part3 = {8B 55 ?? 8A 4D ?? 80 E1 03 C1 E1 06 8A 5D ?? 80 E3 3F 02 CB 88 4C 10 FF FF 45}
        $alphabet = "zLAxuU0kQKf3sWE7ePRO2imyg9GSpVoYC6rhlX48ZHnvjJDBNFtMd1I5acwbqT+="
    condition:
        ($alphabet) and any of ($part*)
}
