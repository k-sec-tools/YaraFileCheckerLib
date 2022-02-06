import "pe"
import "hash"
import "math"

rule susp_string : score_70{
    strings:
        $s1 = " /v /c " nocase
        $s2 = " bypass " nocase
        $s3 = " hidden " nocase
        $s4 = "-noexit" nocase
        $s5 = "-nolog" nocase
        $s6 = "-noni" nocase
        $s7 = "-nop" nocase
        $s8 = "-windowstyle" nocase
        $s9 = ".decode(" nocase
        $s10 = ".downloadfile(" nocase
        $s11 = ".downloadstring(" nocase
        $s12 = ".invoke(" nocase
        $s13 = ".open(\"get\"" nocase
        $s14 = ".open(\"post\"" nocase
        $s15 = ".readtoend()" nocase
        $s16 = ".regread" nocase
        $s17 = ".responsetext." nocase
        $s18 = ".send(" nocase
        $s19 = ".split('" nocase
        $s20 = ".wmi(" nocase
        $s21 = "<script" nocase
        $s22 = "activexobject" nocase
        $s23 = "adodb.connection" nocase
        $s24 = "adodb.stream" nocase
        $s25 = "application/x-www-form-urlencoded" nocase
        $s26 = "bypass" nocase
        $s27 = "cmd /c" nocase
        $s28 = "cmd.exe" nocase
        $s29 = "cmd=" nocase
        $s30 = "convertto-securestring" nocase
        $s31 = "cscript" nocase
        $s32 = "ddeauto" nocase
        $s33 = "decodestring" nocase
        $s34 = "decompress" nocase
        $s35 = "document.write(" nocase
        $s36 = "document_close-->" nocase
        $s37 = "document_open" nocase
        $s38 = "download(" nocase
        $s39 = "downloadfile(" nocase
        $s40 = "eval(" nocase
        $s41 = "eventvwr.exe" nocase
        $s42 = "exename32=" nocase
        $s43 = "exename64=" nocase
        $s44 = "frombase64string" nocase
        $s45 = "get-itemproperty" nocase
        $s46 = "getalphabetsymbol" nocase
        $s47 = "getobject(" nocase
        $s48 = "gp '" nocase
        $s49 = "hta:application" nocase
        $s50 = "invoke" nocase
        $s51 = "invoke-ex" nocase
        $s52 = "invoke-item" nocase
        $s53 = "io.compression.compressionmode" nocase
        $s54 = "io.memorystream" nocase
        $s55 = "io.streamreader" nocase
        $s56 = "javascript:application" nocase
        $s57 = "join(" nocase
        $s58 = "js:application" nocase
        $s59 = "jscript.encode" nocase
        $s60 = "microsoft.xmlhttp" nocase
        $s61 = "ms-excel:ofe|u|" nocase
        $s62 = "ms-powerpoint:ofe|u|" nocase
        $s63 = "ms-word:ofe|u|" nocase
        $s64 = "msxml2.freethreadeddomdocument" nocase
        $s65 = "net.webclient" nocase
        $s66 = "os.system(" nocase
        $s67 = "powershell" nocase
        $s68 = "program cannot be run" nocase
        $s69 = "program must be run" nocase
        $s70 = "randomize" nocase
        $s71 = "reg add" nocase
        $s72 = "replace(" nocase
        $s73 = "requestedExecutionLevel" nocase
        $s74 = "requestedPrivileges" nocase
        $s75 = "runhtmlapplication" nocase
        $s76 = "scripting.filesystemobject" nocase
        $s77 = "securestringtoglobalallocunicode" nocase
        $s78 = "send(" nocase
        $s79 = "shell (" nocase
        $s80 = "shell =" nocase
        $s81 = "shell" nocase
        $s82 = "shell(" nocase
        $s83 = "shell.application  " nocase
        $s84 = "shell=" nocase
        $s85 = "shellexecute(" nocase
        $s86 = "shellopenmacro" nocase
        $s87 = "start-process" nocase
        $s88 = "string.fromcharcode" nocase
        $s89 = "system.io.compression.deflatestream" nocase
        $s90 = "system.net.webclient" nocase
        $s91 = "target=\"\\\\" nocase
        $s92 = "webclient" nocase
        $s93 = "win32_process" nocase
        $s94 = "windowstate='minimize'" nocase
        $s95 = "wmiobject" nocase
        $s96 = "word.application" nocase
        $s97 = "wscript.exe" nocase
        $s98 = "wscript.shell" nocase
        $s99 = "wscript.sleep" nocase
        $s100 = "[runtime.interopservices.marshal]" nocase
        $s101 = "[system.net.servicepointmanager]" nocase
        $s102 = "start-sleep" nocase
        $s103 = "on error resume next" nocase
        $s104 = "stdole" nocase
        $s105 = "32 -s " nocase
        

		$e1 = /heading \d{1,} hidden/ nocase
    condition:
    2 of ($s*) and not any of ($e*)
}

rule evil_html: HTML score_40 {
    strings:
        $tag = "<html>" fullword nocase
		$s1 = "document.write" fullword nocase
		$s2 = "unescape" fullword nocase
		$s3 = "getelementbyid" fullword nocase
		$s4 = ".substring" fullword nocase
		$s5 = "http_referrer" fullword nocase
		$s6 = "copy(" fullword nocase
		$s7 = "getenv" fullword nocase
		$s8 = "fopen" fullword nocase
		$s9 = "fwrite" fullword nocase
    condition:
        $tag and 2 of ($s*)
}

private rule MSI: executable score_80 {
   strings:
      $r1 = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }
   condition:
      uint16(0) == 0xCFD0 and $r1
}

rule executable : executable score_80 {
strings:
    $magic1 = { 4d 5a } // MZ
    $magic2 = {46 75 6E 63 74 69 6F 6E} //vbs
    $magic3 = {72 65 67 66} //reg
    $magic4 = {FF 4B 45 59 42 20 20 20} //sys
    $magic5 = {FF FE 3C 00 3F 00 78 00 6D 00 6C} //job
    $magic6 = {43 57 53} //swf
    $magic7 = {5A 57 53} //swf
    $magic8 = {46 57 53} //swf
    $magic9 = {40 65 63 68} //BATCH
    $magic10 = {40 45 43 48} //BATCH
    $magic11 = {43 57 53} //CWS
    $magic12 = {5A 57 53} //ZWS
    $magic13 = {46 57 53} //FWS (Flash)
    $magic14 = {7F 45} //ELF
    $magic15 = {23 21} //Script
    $magic16 = {FF FE} //Windows Registry File
    $magic17 = {4F 6E 20 45 72 72 6F 72 20 52 65 73 75 6D 65} //VBS
condition:
    for any of ($magic*) :($ at 0)
}