rule Linux_Server_God_Mode_Rule {
   meta:
      description = "Detects a wide range of threats specific to Linux servers including rootkits, trojans, and exploitation methods"
      author = "Jonathan Provost"
      reference = "Internal Research - Comprehensive Linux Server Security"
      date = "2023-12-28"
      score = 70

   strings:
      // Rootkits
      $ = "LD_PRELOAD=" ascii wide nocase                              /* LD_PRELOAD rootkit indicator */
      $ = "/etc/ld.so.preload" ascii wide                             /* Common file used by rootkits */

      // Common Exploitation Methods
      $ = "wget http" ascii wide nocase                               /* Common download command */
      $ = "curl -O" ascii wide nocase                                 /* File download via curl */
      $ = "chmod +x" ascii wide nocase                                /* Making a file executable */
      $ = "base64 -d" ascii wide nocase                               /* Base64 decoding, common in obfuscated payloads */
      $ = "mkfifo" ascii wide                                          /* Named pipe creation, often used in reverse shells */

      // Specific Malware and Trojans
      $ = "nmap -sS" ascii wide nocase                                /* Nmap stealth scan, common in reconnaissance */
      $ = "/bin/bash -i" ascii wide nocase                            /* Bash reverse shell */
      $ = "nc -lvp" ascii wide                                        /* Netcat listener, common in backdoors */
      $ = "python -m SimpleHTTPServer" ascii wide                     /* Python HTTP server, used for file hosting */

      // System Tampering
      $ = "rm -rf /" ascii wide nocase                                /* Destructive command, system tampering */
      $ = "iptables -F" ascii wide nocase                             /* Flushing iptables, potential security disabling */
      $ = "useradd" ascii wide                                        /* User creation, potential unauthorized access */
      $ = "passwd root" ascii wide nocase                             /* Changing root password */
      
      // Suspicious Activity
      $ = "ssh-keygen" ascii wide nocase                              /* SSH key generation, potential unauthorized access */
      $ = "crontab -e" ascii wide nocase                              /* Editing cron jobs, potential for persistence */
      $ = ".ssh/authorized_keys" ascii wide                           /* SSH authorized_keys file, common target for adding unauthorized access */

   condition:
      3 of them
}
