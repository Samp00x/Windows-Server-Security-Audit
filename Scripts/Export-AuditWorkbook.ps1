# Minimal Open XML writer for the runtime report. Requires only .NET on Windows PowerShell 5.1.
function Export-AuditWorkbook {
    [CmdletBinding()]
    param([object[]]$Rows, [string[]]$Columns, [object[]]$Notes, [string]$Path)
    # Preserve owner edits and avoid leaving an old workbook presented as a new export.
    if (Test-Path -LiteralPath $Path -PathType Leaf) {
        $parent = (Resolve-Path -LiteralPath (Split-Path -Parent $Path)).Path
        $history = Join-Path $parent ('History/workbook-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $history -Force -ErrorAction Stop | Out-Null
        Move-Item -LiteralPath $Path -Destination (Join-Path $history (Split-Path -Leaf $Path)) -ErrorAction Stop
    }
    Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
    if ($Rows.Count -gt 1048575) { throw 'Excel row limit exceeded. Full review is retained in CSV.' }
    $tempPath = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    $archive = $null
    function Write-ZipText {
        param($Zip, [string]$Name, [string]$Text)
        $entry = $Zip.CreateEntry($Name)
        $writer = [System.IO.StreamWriter]::new($entry.Open(), [System.Text.UTF8Encoding]::new($false))
        try { $writer.Write($Text) } finally { $writer.Dispose() }
    }
    function ConvertTo-ColumnName {
        param([int]$Number)
        $name = ''
        while ($Number -gt 0) {
            $Number--; $name = [char](65 + ($Number % 26)) + $name
            $Number = [math]::Floor($Number / 26)
        }
        $name
    }
    function New-SheetXml {
        param([object[]]$Data, [string[]]$Headers, [bool]$Review)
        $xml = [System.Text.StringBuilder]::new()
        [void]$xml.Append('<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>')
        for ($c = 1; $c -le $Headers.Count; $c++) {
            $width = 26
            if ($Headers[$c-1] -in @('DirectAdministrativeGroups','IndirectPaths','Notes','Value')) { $width = 65 }
            if ($Headers[$c-1] -eq 'SID') { $width = 47 }
            [void]$xml.Append("<col min=`"$c`" max=`"$c`" width=`"$width`" customWidth=`"1`"/>")
        }
        [void]$xml.Append('</cols><sheetData>')
        for ($r = 0; $r -le $Data.Count; $r++) {
            $rowNumber = $r + 1
            $height = 32
            if ($r -gt 0) {
                $lineCount = 1
                foreach ($header in $Headers) {
                    $charactersPerLine = 23
                    if ($header -in @('DirectAdministrativeGroups','IndirectPaths','Notes','Value')) { $charactersPerLine = 60 }
                    if ($header -eq 'SID') { $charactersPerLine = 43 }
                    $lines = 0
                    foreach ($line in ([string]$Data[$r-1].$header -split "`n")) {
                        $lines += [math]::Max(1, [math]::Ceiling($line.Length / $charactersPerLine))
                    }
                    $lineCount = [math]::Max($lineCount, $lines)
                }
                $height = [math]::Min(409, [math]::Max(32, 16 * $lineCount + 8))
            }
            [void]$xml.Append("<row r=`"$rowNumber`" ht=`"$height`" customHeight=`"1`">")
            for ($c = 0; $c -lt $Headers.Count; $c++) {
                $value = $Headers[$c]
                $style = 1
                if ($r -gt 0) {
                    $value = $Data[$r-1].($Headers[$c]); $style = 2
                    if ($Review -and $Headers[$c] -in @('OwnerDecision','Notes')) { $style = 3 }
                }
                $reference = (ConvertTo-ColumnName ($c + 1)) + $rowNumber
                if ($value -is [datetime]) {
                    $number = $value.ToOADate().ToString('R', [cultureinfo]::InvariantCulture)
                    [void]$xml.Append("<c r=`"$reference`" s=`"4`"><v>$number</v></c>")
                }
                else {
                    $text = [string]$value
                    if ($text.Length -gt 32767) { throw "Excel cell limit exceeded at $reference. Full review is retained in CSV; no truncated workbook will be published." }
                    $text = [System.Security.SecurityElement]::Escape([System.Xml.XmlConvert]::VerifyXmlChars($text))
                    [void]$xml.Append("<c r=`"$reference`" s=`"$style`" t=`"inlineStr`"><is><t xml:space=`"preserve`">$text</t></is></c>")
                }
            }
            [void]$xml.Append('</row>')
        }
        $lastColumn = ConvertTo-ColumnName $Headers.Count
        $lastRow = $Data.Count + 1
        [void]$xml.Append("</sheetData><autoFilter ref=`"A1:$lastColumn$lastRow`"/></worksheet>")
        $xml.ToString()
    }
    try {
        $archive = [System.IO.Compression.ZipFile]::Open($tempPath, [System.IO.Compression.ZipArchiveMode]::Create)
        Write-ZipText $archive '[Content_Types].xml' '<?xml version="1.0" encoding="utf-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>'
        Write-ZipText $archive '_rels/.rels' '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>'
        Write-ZipText $archive 'xl/workbook.xml' '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Review" sheetId="1" r:id="rId1"/><sheet name="Collection" sheetId="2" r:id="rId2"/></sheets></workbook>'
        Write-ZipText $archive 'xl/_rels/workbook.xml.rels' '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>'
        Write-ZipText $archive 'xl/styles.xml' '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><numFmts count="1"><numFmt numFmtId="164" formatCode="yyyy-mm-dd hh:mm:ss"/></numFmts><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="4"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF17365D"/></patternFill></fill><fill><patternFill patternType="solid"><fgColor rgb="FFFFF2CC"/></patternFill></fill></fills><borders count="1"><border/></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="5"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="0" fontId="0" fillId="3" borderId="0" xfId="0" applyAlignment="1"><alignment wrapText="1" vertical="top"/></xf><xf numFmtId="164" fontId="0" fillId="0" borderId="0" xfId="0" applyNumberFormat="1" applyAlignment="1"><alignment vertical="top"/></xf></cellXfs><cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles></styleSheet>'
        Write-ZipText $archive 'xl/worksheets/sheet1.xml' (New-SheetXml -Data $Rows -Headers $Columns -Review $true)
        Write-ZipText $archive 'xl/worksheets/sheet2.xml' (New-SheetXml -Data $Notes -Headers @('Field','Value') -Review $false)
        $archive.Dispose(); $archive = $null
        Move-Item -LiteralPath $tempPath -Destination $Path -Force -ErrorAction Stop
    }
    finally {
        if ($archive) { $archive.Dispose() }
        if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath }
    }
}
