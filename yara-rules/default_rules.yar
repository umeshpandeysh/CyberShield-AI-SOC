rule Phishing_Suspicious_Keywords {
    meta:
        description = "Detects common phishing keywords in emails"
        author = "CyberShield SOC"
    strings:
        $s1 = "verify your account" nocase
        $s2 = "update your password" nocase
        $s3 = "urgent security action" nocase
        $s4 = "click here to reset" nocase
        $s5 = "unusual sign-in activity" nocase
        $s6 = "immediate action required" nocase
    condition:
        any of them
}
