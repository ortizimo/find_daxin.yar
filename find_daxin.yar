
/* 
	NOTE: According to a BleepingComputer report: "Daxin is one of the most advanced backdoors ever deployed from Chinese hackers (APT SLUG)
	aka Owlproxy targeting hardened corporate networks that have advanced threat detection capabilities. It uses hijacked TCP connections 
	for a high degree of stealth in communications and helps establish a legitimate traffic to remain undetected. This opens an encrypted 
	communication channel through TCP tunnels." 
*/

rule find_daxin
{					
	meta:
		author = "Saulo 'Sal' Ortiz, Sr. Cyber Forensics Analyst, ATG"
    description = "Searches for Daxin Advanced Backdoor"
		date = "2022-03-08"
		version = "1.0"
		in_the_wild = "True"

	strings:
		$a1 = "ipfltdrvs.sys" nocase private
		$a2 = "ndislan.sys" nocase private
		$a3 = "ndislan_win2008_x64.sys" nocase private
		$a4 = "ntbios.sys" nocase private
		$a5 = "patrol.sys" nocase private
		$a6 = "performanceaudit.sys" nocase private
		$a7 = "print64.sys" nocase private
		$a8 = "printsrv64.sys" nocase private
		$a9 = "prv64.sys" nocase private
		$a10 = "sqlwriter.sys" nocase private
		$a11 = "srt.sys" nocase private
		$a12 = "srt64.sys" nocase private
		$a13 = "syswant.sys" nocase private
		$a14 = "usbmrti.sys" nocase private
		$a15 = "vncwantd.sys" nocase private
		$a16 = "wantd.sys" nocase private
		$a17 = "win2k8.sys" nocase private
		$a18 = "wmipd.sys" nocase private
		$a19 = "[CSIDL_SYSTEM]\drivers\pagefile.sys" nocase ascii private 
		$a20 = "[CSIDL_SYSTEM]\spool\drivers\ntds.sys" nocase ascii private
		
	condition:
		any of ($a*)
}
