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
		$s11 = "account update" fullword nocase
		$s12 = "password" fullword nocase
		$s13 = "sign on" fullword nocase
    condition:
        $tag and 2 of ($s*)
}

rule possible_exploit : PDF score_50{
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        weight = 3
        
    strings:
        $magic = { 25 50 44 46 }
        
        $attrib0 = /\/JavaScript /
        $attrib3 = /\/ASCIIHexDecode/
        $attrib4 = /\/ASCII85Decode/

        $action0 = /\/Action/
        $action1 = "Array"
        $shell = "A"
        $cond0 = "unescape"
        $cond1 = "String.fromCharCode"
        
        $nop = "%u9090%u9090"
    condition:
        $magic at 0 and (2 of ($attrib*)) or ($action0 and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule FlashNewfunction: PDF score_50 {
   meta:  
      ref = "CVE-2010-1297"
      hide = true
      impact = 5 
      ref = "http://blog.xanda.org/tag/jsunpack/"
   strings:
      $unescape = "unescape" fullword nocase
      $shellcode = /%u[A-Fa-f0-9]{4}/
      $shellcode5 = /(%u[A-Fa-f0-9]{4}){5}/
      $cve20101297 = /\/Subtype ?\/Flash/
   condition:
      ($unescape and $shellcode and $cve20101297) or ($shellcode5 and $cve20101297)
}


rule shellcode_blob_metadata : PDF score_50{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
                weight = 4
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic at 0 and 1 of ($reg*)
}

rule suspicious_js : PDF {
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        weight = 3
        
    strings:
        $magic = { 25 50 44 46 }
        
        $attrib0 = /\/OpenAction /
        $attrib1 = /\/JavaScript /

        $js0 = "eval"
        $js1 = "Array"
        $js2 = "String.fromCharCode"
        
    condition:
        $magic at 0 and all of ($attrib*) and 2 of ($js*)
}

rule suspicious_launch_action : PDF score_50{
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        weight = 2
        
    strings:
        $magic = { 25 50 44 46 }
        
        $attrib0 = /\/Launch/
        $attrib1 = /\/URL /
        $attrib2 = /\/Action/
        $attrib3 = /\/F /

    condition:
        $magic at 0 and 3 of ($attrib*)
}

rule suspicious_embed : PDF score_50{
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        ref = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
        weight = 2
        
    strings:
        $magic = { 25 50 44 46 }
        
        $meth0 = /\/Launch/
        $meth1 = /\/GoTo(E|R)/ //means go to embedded or remote
        $attrib0 = /\/URL /
        $attrib1 = /\/Action/
        $attrib2 = /\/Filespec/
        
    condition:
        $magic at 0 and 1 of ($meth*) and 2 of ($attrib*)
}

rule suspicious_obfuscation : PDF score_50{
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        weight = 2
        
    strings:
        $magic = { 25 50 44 46 }
        $reg = /\/\w#[a-zA-Z0-9]{2}#[a-zA-Z0-9]{2}/
        
    condition:
        $magic at 0 and #reg > 5
}

rule invalid_XObject_js : PDF score_50{
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        description = "XObject's require v1.4+"
        ref = "https://blogs.adobe.com/ReferenceXObjects/"
        version = "0.1"
        weight = 2
        
    strings:
        $magic = { 25 50 44 46 }
        $ver = /%PDF-1\.[4-9]/
        
        $attrib0 = /\/XObject/
        $attrib1 = /\/JavaScript/
        
    condition:
        $magic at 0 and not $ver and all of ($attrib*)
}


rule js_splitting : PDF score_50{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "These are commonly used to split up JS code"
                weight = 2
                
        strings:
                $magic = { 25 50 44 46 }
                $js = /\/JavaScript/
                $s0 = "getAnnots"
                $s1 = "getPageNumWords"
                $s2 = "getPageNthWord"
                $s3 = "this.info"
                                
        condition:
                $magic at 0 and $js and 1 of ($s*)
}

rule header_evasion : PDF score_50{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                description = "3.4.1, 'File Header' of Appendix H states that ' Acrobat viewers require only that the header appear somewhere within the first 1024 bytes of the file.'  Therefore, if you see this trigger then any other rule looking to match the magic at 0 won't be applicable"
                ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
                version = "0.1"
                weight = 3

        strings:
                $magic = { 25 50 44 46 }
        condition:
                $magic in (5..1024) and #magic == 1
}

rule BlackHole_v2 : PDF score_50 {
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        ref = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
        weight = 3
        
    strings:
        $magic = { 25 50 44 46 }
        $content = "Index[5 1 7 1 9 4 23 4 50"
        
    condition:
        $magic at 0 and $content
}


rule XDP_embedded_PDF : PDF score_50{
    meta:
        author = "Glenn Edwards (@hiddenillusion)"
        version = "0.1"
        ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
        weight = 1        

    strings:
        $s1 = "<pdf xmlns="
        $s2 = "<chunk>"
        $s3 = "</pdf>"
        $header0 = "%PDF"
        $header1 = "JVBERi0"

    condition:
        all of ($s*) and 1 of ($header*)
}

rule multiple_filtering : PDF score_50 {
meta: 
author = "Glenn Edwards (@hiddenillusion)"
version = "0.2"
weight = 3

    strings:
            $magic = { 25 50 44 46 }
            $attrib = /\/Filter.*(\/ASCIIHexDecode\W+|\/LZWDecode\W+|\/ASCII85Decode\W+|\/FlateDecode\W+|\/RunLengthDecode){2}/ 
            // left out: /CCITTFaxDecode, JBIG2Decode, DCTDecode, JPXDecode, Crypt

    condition: 
            $magic in (0..1024) and $attrib
}
rule PDF_Document_with_Embedded_IQY_File : score_60 {
    meta:
        Author = "InQuest Labs"
        Description = "This signature detects IQY files embedded within PDF documents which use a JavaScript OpenAction object to run the IQY."
        Reference = "https://blog.inquest.net"  
  
    strings:
        $pdf_magic = "%PDF"
        $efile = /<<\/JavaScript [^\x3e]+\/EmbeddedFile/        
        $fspec = /<<\/Type\/Filespec\/F\(\w+\.iqy\)\/UF\(\w+\.iqy\)/
        $openaction = /OpenAction<<\/S\/JavaScript\/JS\(/
        
        /*
          <</Type/Filespec/F(10082016.iqy)/UF(10082016.iqy)/EF<</F 1 0 R/UF 1 0 R>>/Desc(10082016.iqy)>> 
          ...
          <</Names[(10082016.iqy) 2 0 R]>>
          ...
          <</JavaScript 9 0 R/EmbeddedFiles 10 0 R>>
          ...
          OpenAction<</S/JavaScript/JS(
        */
        
        /*
            obj 1.9
             Type: /EmbeddedFile
             Referencing:
             Contains stream
              <<
                /Length 51
                /Type /EmbeddedFile
                /Filter /FlateDecode
                /Params
                  <<
                    /ModDate "(D:20180810145018+03'00')"
                    /Size 45
                  >>
              >>
             WEB
            1
            http://i86h.com/data1.dat
            2
            3
            4
            5
        */
   
   condition:
      $pdf_magic in (0..60)  and all of them
}


rule NTLM_Credential_Theft_via_PDF :  score_100{
    meta:
        Author      = "InQuest Labs"
        URL         = "https://github.com/InQuest/yara-rules"
        Description = "This signature detects Adobe PDF files that reference a remote UNC object for the purpose of leaking NTLM hashes."

    strings:
        // we have three regexes here so that we catch all possible orderings but still meet the requirement of all three parts.
        $badness1 = /\s*\/AA\s*<<\s*\/[OC]\s*<<((\s*\/\D\s*\[[^\]]+\])(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])(\s*\/\D\s*\[[^\]]+\]))\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)/ nocase
        $badness2 = /\s*\/AA\s*<<\s*\/[OC]\s*<<\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)((\s*\/\D\s*\[[^\]]+\])(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])(\s*\/\D\s*\[[^\]]+\]))/ nocase
        $badness3 = /\s*\/AA\s*<<\s*\/[OC]\s*<<((\s*\/\D\s*\[[^\]]+\])\s*\/F\s*\((\\\\\\\\[a-z0-9]+\.[^\\]+\\\\[a-z0-9]+|https?:\/\/[^\)]+)\)(\s*\/S\s*\/GoTo[ER])|(\s*\/S\s*\/GoTo[ER])\s*\/F\s*\(\\\\\\\\[a-z0-9]+.[^\\]+\\\\[a-z0-9]+\)(\s*\/\D\s*\[[^\]]+\]))/ nocase

    condition:
        for any i in (0..1024) : (uint32be(i) == 0x25504446) and any of ($badness*)
}

rule Docm_in_PDF : score_50 {
   meta:
      description = "Detects an embedded DOCM in PDF combined with OpenAction"
      license = "https://creativecommons.org/licenses/by-nc/4.0/"
      author = "Florian Roth"
      reference = "Internal Research"
      date = "2017-05-15"
   strings:
      $a1 = /<<\/Names\[\([\w]{1,12}.docm\)/ ascii
      $a2 = "OpenAction" ascii fullword
      $a3 = "JavaScript" ascii fullword
   condition:
      uint32(0) == 0x46445025 and all of them
}
