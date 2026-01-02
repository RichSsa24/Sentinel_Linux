/*
    YARA Rules for Linux Security Monitor
    Detects suspicious scripts and potentially malicious content
*/

rule Reverse_Shell_Bash
{
    meta:
        description = "Detects bash reverse shell patterns"
        severity = "critical"
        author = "Ricardo Solís"
        date = "2024-01-01"
        mitre_attack = "T1059.004"

    strings:
        $s1 = "/dev/tcp/" ascii
        $s2 = "bash -i" ascii
        $s3 = "exec 5<>/dev/tcp" ascii
        $s4 = "0>&1" ascii
        $s5 = "2>&1" ascii

    condition:
        ($s1 and ($s4 or $s5)) or $s2 or $s3
}

rule Reverse_Shell_Netcat
{
    meta:
        description = "Detects netcat reverse shell patterns"
        severity = "critical"
        author = "Ricardo Solís"
        date = "2024-01-01"
        mitre_attack = "T1059"

    strings:
        $nc1 = "nc -e /bin/sh" ascii nocase
        $nc2 = "nc -e /bin/bash" ascii nocase
        $nc3 = "ncat -e /bin/sh" ascii nocase
        $nc4 = "netcat -e" ascii nocase
        $nc5 = "nc -c /bin/sh" ascii nocase

    condition:
        any of them
}

rule Reverse_Shell_Python
{
    meta:
        description = "Detects Python reverse shell patterns"
        severity = "critical"
        author = "Ricardo Solís"
        date = "2024-01-01"
        mitre_attack = "T1059.006"

    strings:
        $py1 = "socket.socket" ascii
        $py2 = "subprocess.call" ascii
        $py3 = "os.dup2" ascii
        $py4 = "/bin/sh" ascii
        $py5 = "pty.spawn" ascii

    condition:
        ($py1 and $py2 and $py4) or ($py1 and $py3) or $py5
}

rule Encoded_Command
{
    meta:
        description = "Detects base64 encoded command execution"
        severity = "high"
        author = "Ricardo Solís"
        date = "2024-01-01"
        mitre_attack = "T1027"

    strings:
        $b64_1 = "base64 -d" ascii
        $b64_2 = "base64 --decode" ascii
        $b64_3 = "echo" ascii
        $pipe = "|" ascii
        $bash = "bash" ascii
        $sh = "/bin/sh" ascii

    condition:
        ($b64_1 or $b64_2) and $pipe and ($bash or $sh)
}

rule Persistence_Cron
{
    meta:
        description = "Detects potential cron-based persistence"
        severity = "medium"
        author = "Ricardo Solís"
        date = "2024-01-01"
        mitre_attack = "T1053.003"

    strings:
        $cron1 = "/etc/crontab" ascii
        $cron2 = "/etc/cron.d" ascii
        $cron3 = "crontab -" ascii
        $wget = "wget" ascii
        $curl = "curl" ascii

    condition:
        any of ($cron*) and ($wget or $curl)
}

rule Credential_Access_Shadow
{
    meta:
        description = "Detects attempts to access shadow file"
        severity = "critical"
        author = "Ricardo Solís"
        date = "2024-01-01"
        mitre_attack = "T1003.008"

    strings:
        $shadow = "/etc/shadow" ascii
        $cat = "cat " ascii
        $read = "read" ascii
        $unshadow = "unshadow" ascii

    condition:
        $shadow and ($cat or $unshadow)
}

rule Suspicious_Download_Execute
{
    meta:
        description = "Detects download and execute patterns"
        severity = "high"
        author = "Ricardo Solís"
        date = "2024-01-01"
        mitre_attack = "T1105"

    strings:
        $wget_sh = "wget" ascii
        $curl_sh = "curl" ascii
        $pipe_sh = "| sh" ascii
        $pipe_bash = "| bash" ascii
        $exec = "| /bin/sh" ascii

    condition:
        ($wget_sh or $curl_sh) and ($pipe_sh or $pipe_bash or $exec)
}

rule SSH_Key_Theft
{
    meta:
        description = "Detects SSH key access patterns"
        severity = "high"
        author = "Ricardo Solís"
        date = "2024-01-01"
        mitre_attack = "T1552.004"

    strings:
        $ssh1 = ".ssh/id_rsa" ascii
        $ssh2 = ".ssh/id_dsa" ascii
        $ssh3 = ".ssh/id_ecdsa" ascii
        $ssh4 = ".ssh/id_ed25519" ascii
        $cat = "cat " ascii
        $scp = "scp " ascii
        $cp = "cp " ascii

    condition:
        any of ($ssh*) and ($cat or $scp or $cp)
}



