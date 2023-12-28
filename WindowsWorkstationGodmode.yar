rule Windows_Workstation_God_Mode_Rule {
   meta:
      description = "Detects various threats commonly targeting Windows workstations, including trojans, phishing tools, and ransomware"
      author = "Jonathan Provost"
      reference = "Internal Research - Comprehensive Windows Workstation Security"
      date = "2023-12-28"
      score = 70

   strings:
      // Ransomware Indicators
      $ = "WannaCry" ascii wide nocase                             /* Ransomware indicator */
      $ = "Ryuk" ascii wide nocase                                 /* Ransomware indicator */
      $ = ".onion" ascii wide nocase                               /* Tor address, often used in ransomware notes */

      // Phishing and Trojan Indicators
      $ = "powershell -ExecutionPolicy Bypass" ascii wide         /* PowerShell execution bypass */
      $ = "cmd.exe /c" ascii wide                                  /* Command execution */
      $ = "keylogger" ascii wide nocase                            /* Keylogger indicator */

      // Common Malware Persistence Mechanisms
      $ = "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide  /* Registry key for autorun */
      $ = "C:\\Users\\" wide nocase /.*\\.exe/                     /* Executable in user directory */

      // Workstation Application Indicators
      $ = "outlook.exe" ascii wide                                 /* Email client, often targeted by phishing attacks */
      $ = "chrome.exe" ascii wide                                  /* Web browser, common target for browser hijackers */

   condition:
      3 of them
}
