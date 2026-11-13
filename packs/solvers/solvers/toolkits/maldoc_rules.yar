/*
  YARA rules for common document droppers (backlog row 87, solvers/toolkits/maldoc.py).
  Static triage hints only: a hit says where to look, it is never an answer. The toolkit scans
  the file's own bytes and, appended after a NUL gap, what it decoded from them (macro source,
  decoded strings, PDF streams, RTF object data), so a rule can match text that is compressed
  in the file itself.
*/

rule maldoc_ole_container
{
    strings:
        $ole = { D0 CF 11 E0 A1 B1 1A E1 }
    condition:
        $ole at 0
}

rule maldoc_vba_autoexec
{
    strings:
        $a1 = "AutoOpen" nocase
        $a2 = "Auto_Open" nocase
        $a3 = "Document_Open" nocase
        $a4 = "Workbook_Open" nocase
        $a5 = "AutoExec" nocase
        $a6 = "AutoClose" nocase
        $a7 = "Document_Close" nocase
        $v = "Attribute VB_Name" nocase
    condition:
        $v and any of ($a*)
}

rule maldoc_vba_shell_exec
{
    strings:
        $v = "Attribute VB_Name" nocase
        $s1 = "WScript.Shell" nocase
        $s2 = "Shell(" nocase
        $s3 = "ShellExecute" nocase
        $s4 = "CreateObject" nocase
        $s5 = "GetObject" nocase
        $s6 = "ExecuteExcel4Macro" nocase
        $s7 = "MacScript" nocase
        $s8 = /\bShell[ \t]+[A-Za-z"]/ nocase
    condition:
        $v and any of ($s*)
}

rule maldoc_vba_download
{
    strings:
        $v = "Attribute VB_Name" nocase
        $d1 = "URLDownloadToFile" nocase
        $d2 = "MSXML2.XMLHTTP" nocase
        $d3 = "WinHttp.WinHttpRequest" nocase
        $d4 = "Microsoft.XMLHTTP" nocase
        $d5 = "ADODB.Stream" nocase
        $d6 = "MSXML2.ServerXMLHTTP" nocase
    condition:
        $v and any of ($d*)
}

rule maldoc_vba_string_obfuscation
{
    strings:
        $v = "Attribute VB_Name" nocase
        $c = /Chr[W$]?\(\s*[0-9&Hh]+\s*\)\s*[&+]\s*Chr[W$]?\(/ nocase
        $r = "StrReverse(" nocase
    condition:
        $v and ($c or $r)
}

rule maldoc_powershell_encoded
{
    strings:
        $p = "powershell" nocase ascii wide
        $e1 = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{20,}/ nocase ascii wide
        $e2 = "FromBase64String" nocase ascii wide
        $e3 = "-nop" nocase ascii wide
        $e4 = "-w hidden" nocase ascii wide
        $e5 = "-windowstyle hidden" nocase ascii wide
        $e6 = "DownloadString" nocase ascii wide
        $e7 = "IEX" ascii wide fullword
    condition:
        $p and any of ($e*)
}

rule maldoc_lolbin_launch
{
    strings:
        $l1 = "mshta" nocase ascii wide
        $l2 = "regsvr32" nocase ascii wide
        $l3 = "rundll32" nocase ascii wide
        $l4 = "certutil" nocase ascii wide
        $l5 = "bitsadmin" nocase ascii wide
        $l6 = "wscript" nocase ascii wide
        $l7 = "cscript" nocase ascii wide
        $l8 = "cmd.exe" nocase ascii wide
        $l9 = "cmd /c" nocase ascii wide
        $l10 = "msiexec" nocase ascii wide
        $l11 = "curl " nocase ascii wide
    condition:
        any of them
}

rule maldoc_xlm_macro
{
    strings:
        $x1 = "xl/macrosheets/" ascii
        $x2 = "Auto_Open" nocase ascii wide
        $x3 = "=EXEC(" nocase ascii wide
        $x4 = "=CALL(" nocase ascii wide
        $x5 = "=REGISTER(" nocase ascii wide
        $x6 = "=HALT()" nocase ascii wide
        $x7 = "=FORMULA(" nocase ascii wide
    condition:
        $x1 or 2 of ($x2, $x3, $x4, $x5, $x6, $x7)
}

rule maldoc_ooxml_remote_template
{
    strings:
        $t = "attachedTemplate" ascii
        $e = "TargetMode=\"External\"" ascii
    condition:
        $t and $e
}

rule maldoc_dde_field
{
    strings:
        $d1 = "DDEAUTO" ascii wide
        $d2 = /DDE\s+"?[A-Za-z]:\\/ ascii wide
        $d3 = "=cmd|" nocase ascii wide
        $d4 = "=MSEXCEL|" nocase ascii wide
    condition:
        any of them
}

rule maldoc_rtf_object
{
    strings:
        $r = "{\\rt" ascii
        $o1 = "\\objdata" ascii
        $o2 = "\\objupdate" ascii
        $o3 = "\\objemb" ascii
    condition:
        $r at 0 and any of ($o*)
}

rule maldoc_rtf_equation_editor
{
    strings:
        $r = "{\\rt" ascii
        $e1 = "Equation.3" nocase ascii wide
        $e2 = "4571756174696f6e2e33" nocase ascii
        $e3 = "Equation Native" ascii wide
        $e4 = "Equation.2" nocase ascii wide
    condition:
        $r at 0 and any of ($e*)
}

rule maldoc_ole_package
{
    strings:
        $p1 = "\x01Ole10Native" wide
        $p2 = "Package" ascii fullword
        $p3 = "5061636b61676500" nocase ascii
    condition:
        $p1 or (uint32(0) == 0x74725c7b and ($p2 or $p3))
}

rule maldoc_pdf_javascript
{
    strings:
        $pdf = "%PDF-" ascii
        $j1 = "/JavaScript" ascii
        $j2 = "/JS" ascii
    condition:
        $pdf in (0..1024) and any of ($j*)
}

rule maldoc_pdf_auto_action
{
    strings:
        $pdf = "%PDF-" ascii
        $a1 = "/OpenAction" ascii
        $a2 = "/AA" ascii
        $a3 = "/Launch" ascii
    condition:
        $pdf in (0..1024) and any of ($a*)
}

rule maldoc_pdf_embedded_file
{
    strings:
        $pdf = "%PDF-" ascii
        $e = "/EmbeddedFile" ascii
    condition:
        $pdf in (0..1024) and $e
}

rule maldoc_onenote_embedded_file
{
    strings:
        $one = { E4 52 5C 7B 8C D8 A7 4D AE B1 53 78 D0 29 96 D3 }
        $fdso = { E7 16 E3 BD 65 26 11 45 A4 C4 8D 4D 0B 7A 9E AC }
    condition:
        $one at 0 and $fdso
}

rule maldoc_lnk_shortcut
{
    strings:
        $h = { 4C 00 00 00 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46 }
    condition:
        $h at 0
}

rule maldoc_lnk_script_host
{
    strings:
        $h = { 4C 00 00 00 01 14 02 00 }
        $s1 = "powershell" nocase ascii wide
        $s2 = "cmd.exe" nocase ascii wide
        $s3 = "mshta" nocase ascii wide
        $s4 = "wscript" nocase ascii wide
        $s5 = "rundll32" nocase ascii wide
        $s6 = "/c " ascii wide
    condition:
        $h at 0 and any of ($s*)
}

rule maldoc_iso9660_image
{
    strings:
        $cd = "CD001" ascii
    condition:
        $cd at 32769
}

rule maldoc_vhd_image
{
    strings:
        $c = "conectix" ascii
    condition:
        $c at 0 or $c at (filesize - 512)
}

rule maldoc_hta_application
{
    strings:
        $h = "<hta:application" nocase ascii wide
        $s = "<script" nocase ascii wide
    condition:
        $h and $s
}

rule maldoc_wsf_job
{
    strings:
        $j = "<job" nocase ascii wide
        $s = "<script" nocase ascii wide
        $l = "language=" nocase ascii wide
    condition:
        all of them
}

rule maldoc_html_smuggling
{
    strings:
        $b1 = "msSaveOrOpenBlob" ascii
        $b2 = "createObjectURL" ascii
        $b3 = "new Blob(" ascii
        $a = "atob(" ascii
        $d = ".download" ascii
    condition:
        2 of ($b*) or (any of ($b*) and $a and $d)
}

rule maldoc_activemime
{
    strings:
        $a = "ActiveMime" ascii
        $b = "QWN0aXZlTWltZQ" ascii
    condition:
        any of them
}
