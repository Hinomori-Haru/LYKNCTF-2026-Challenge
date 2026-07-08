#requires -RunAsAdministrator

[CmdletBinding()]
param(
  [string]$Root    = $PSScriptRoot,
  [string]$WorkVhd = '',
  [string]$OutVhd  = '',
  [int]   $SizeMB  = 100,
  [string]$Letter  = 'X'
)
$ErrorActionPreference = 'Stop'
if (-not $Root)    { $Root = (Get-Location).Path }
if (-not $WorkVhd) { $WorkVhd = Join-Path $Root 'ctf.vhd' }
if (-not $OutVhd)  { $OutVhd  = Join-Path $Root 'infected.vhd' }
$X = "${Letter}:"

function Info($m){ Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)  { Write-Host "[OK] $m" -ForegroundColor Green }

function With-Vhd([scriptblock]$body){
  $fs=[IO.File]::Open($WorkVhd,'Open','ReadWrite')
  try { & $body $fs } finally { $fs.Close() }
}

function RB($fs,[int64]$o,[int]$n){ $b=[byte[]]::new($n); $fs.Position=$o; [void]$fs.Read($b,0,$n); $b }
function WB($fs,[int64]$o,[byte[]]$b){ $fs.Position=$o; $fs.Write($b,0,$b.Length) }
function FindBytes([byte[]]$h,[byte[]]$n,[int]$s=0){
  for($i=$s;$i -le $h.Length-$n.Length;$i++){ $m=$true
    for($j=0;$j -lt $n.Length;$j++){ if($h[$i+$j]-ne$n[$j]){$m=$false;break} }
    if($m){return $i} } ; return -1 }

function RecHasData([byte[]]$r){
  $a=[BitConverter]::ToUInt16($r,0x14)
  while($a+8 -le $r.Length){
    $t=[BitConverter]::ToUInt32($r,$a); if($t -eq 0xFFFFFFFF){break}
    $len=[BitConverter]::ToUInt32($r,$a+4); if($len -le 0 -or ($a+$len) -gt $r.Length){break}
    if($t -eq 0x80){return $true}
    $a+=$len }
  return $false }

function ApplyFixup([byte[]]$r){
  $usaOff=[BitConverter]::ToUInt16($r,0x04); $usaCnt=[BitConverter]::ToUInt16($r,0x06)
  if($usaOff -lt 0x2A -or ($usaOff+$usaCnt*2) -gt $r.Length){ return $r }
  for($i=1;$i -lt $usaCnt;$i++){
    $se=$i*512-2; if(($se+2) -gt $r.Length){break}
    $r[$se]=$r[$usaOff+$i*2]; $r[$se+1]=$r[$usaOff+$i*2+1] }
  return $r }

function DataRunStats([byte[]]$r){
  $a=[BitConverter]::ToUInt16($r,0x14)
  while($a+4 -le $r.Length){
    $t=[BitConverter]::ToUInt32($r,$a); if($t -eq 0xFFFFFFFF){break}
    $len=[BitConverter]::ToUInt32($r,$a+4); if($len -le 0 -or ($a+$len) -gt $r.Length){break}
    if($t -eq 0x80 -and $r[$a+9] -eq 0 -and $r[$a+8] -eq 1){
      $lastVCN=[BitConverter]::ToUInt64($r,$a+0x18)
      $runOff =[BitConverter]::ToUInt16($r,$a+0x20)
      $p=$a+$runOff; [int64]$sum=0
      while($p -lt ($a+$len) -and $r[$p] -ne 0){
        $h=$r[$p]; $p++; $ls=$h -band 0xF; $os=$h -shr 4
        [int64]$cnt=0; for($i=0;$i -lt $ls;$i++){ $cnt += [int64]$r[$p] * [int64][math]::Pow(256,$i); $p++ }
        $p += $os; $sum += $cnt }
      return [pscustomobject]@{ Sum=$sum; LastVCN=[int64]$lastVCN }
    }
    $a+=$len }
  return $null }

Info "Cleaning up old VHD..."
try { Dismount-VHD $WorkVhd -EA SilentlyContinue } catch {}
Remove-Item $WorkVhd,$OutVhd -EA SilentlyContinue

Info "Creating fixed VHD ${SizeMB}MB: $WorkVhd"
New-VHD -Path $WorkVhd -SizeBytes ($SizeMB*1MB) -Fixed | Out-Null
$disk = Mount-VHD -Path $WorkVhd -Passthru | Get-Disk
Initialize-Disk -Number $disk.Number -PartitionStyle GPT | Out-Null
$part = New-Partition -DiskNumber $disk.Number -UseMaximumSize -DriveLetter $Letter
Format-Volume -DriveLetter $Letter -FileSystem NTFS -NewFileSystemLabel 'DATA' -Confirm:$false -Force | Out-Null
Ok "Volume ${X} ready"
Dismount-VHD -Path $WorkVhd

Info "Reading volume serial (on-disk) from VHD..."
$serialHex = $null; $partStart = 0; $backupVBR = 0
With-Vhd {
  param($fs)
  $pe = RB $fs (2*512) 128
  $firstLBA = [BitConverter]::ToUInt64($pe,0x20); $lastLBA = [BitConverter]::ToUInt64($pe,0x28)
  $script:partStart = [int64]$firstLBA*512
  $script:backupVBR = $script:partStart + [int64]($lastLBA-$firstLBA)*512
  $vbr = RB $fs $script:partStart 512
  $ser = $vbr[0x48..0x4F]
  $script:serialHex = ($ser | ForEach-Object { $_.ToString('X2') }) -join ''
}
Ok "Serial on-disk = $serialHex  (partStart=0x$('{0:X}' -f $partStart))"

Info "Generating flag UUID + part4 (gen_flag.js)..."
Push-Location $Root
node gen_flag.js
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "gen_flag.js failed" }
Pop-Location
$script:P = Get-Content (Join-Path $Root 'pieces.json') -Raw | ConvertFrom-Json
Ok ("flag = " + $script:P.flag)

Info "Building flag.zip (ZipCrypto, password = AES key Phase 3)..."
Push-Location $Root
node make_zip.js $serialHex
if ($LASTEXITCODE -ne 0) { Pop-Location; throw "make_zip.js failed" }
Pop-Location
$srcZip = Join-Path $Root 'flag.zip'

Info "Remounting and building directory tree..."
Mount-VHD -Path $WorkVhd | Out-Null
Get-ChildItem $X\ -Force -EA SilentlyContinue |
  Where-Object { $_.Name -notin '$RECYCLE.BIN','System Volume Information' } |
  Remove-Item -Recurse -Force -EA SilentlyContinue

$dirs = @(
  "$X\Users\victim\Documents\Backup","$X\Users\victim\Downloads","$X\Users\victim\Desktop",
  "$X\Users\victim\AppData\Roaming","$X\Windows\System32","$X\ProgramData\Logs")
$dirs | ForEach-Object { New-Item -ItemType Directory -Path $_ -Force | Out-Null }
"meeting notes 2026..." | Out-File "$X\Users\victim\Documents\notes.txt"
"todo: pay invoice"     | Out-File "$X\Users\victim\Desktop\todo.txt"
[IO.File]::WriteAllBytes("$X\Windows\System32\drv.sys",[byte[]]::new(20KB))
[IO.File]::WriteAllBytes("$X\ProgramData\Logs\app.log",[byte[]]::new(12KB))

Info "Forcing fragmentation: filling disk and carving holes..."
$buf=[byte[]]::new(64KB); $i=0
try { while ($true) { [IO.File]::WriteAllBytes("$X\Windows\System32\f$i.tmp",$buf); $i++ } } catch {}
$max=$i-1
Ok "filled $i files (~$([int]($i*64/1024))MB)"
0..$max | Where-Object { $_ % 2 -eq 0 } | ForEach-Object { Remove-Item "$X\Windows\System32\f$_.tmp" -EA SilentlyContinue }

$dst = "$X\Users\victim\Documents\Backup\flag.zip"
Copy-Item $srcZip $dst
Write-VolumeCache -DriveLetter $Letter -EA SilentlyContinue
Info "Checking fragmentation (requires >=2 fragments):"
$contig = Get-Command contig.exe -EA SilentlyContinue
if ($contig) { & contig.exe -a -nobanner $dst } else { Write-Warning "contig.exe not found -> skipping fragmentation verify" }

0..$max | Where-Object { $_ % 2 -eq 1 } | ForEach-Object { Remove-Item "$X\Windows\System32\f$_.tmp" -EA SilentlyContinue }
Write-VolumeCache -DriveLetter $Letter -EA SilentlyContinue
Dismount-VHD -Path $WorkVhd
Ok "Disk ready, flag.zip LIVE and fragmented"

Info "Placing 3 flag pieces..."
With-Vhd {
  param($fs)
  $pe = RB $fs (2*512) 128
  $firstLBA = [BitConverter]::ToUInt64($pe,0x20); $lastLBA = [BitConverter]::ToUInt64($pe,0x28)
  $pStart = [int64]$firstLBA*512
  $bVBR   = $pStart + [int64]($lastLBA-$firstLBA)*512
  $vbr = RB $fs $pStart 512
  $bps=[BitConverter]::ToUInt16($vbr,0x0B); $spc=$vbr[0x0D]; $mftLCN=[BitConverter]::ToUInt64($vbr,0x30)
  $mftByte = $pStart + [int64]$mftLCN*$spc*$bps

  $mft = RB $fs $mftByte (512*1024)
  $needle = [Text.Encoding]::Unicode.GetBytes("flag.zip")
  $recAbs = -1
  for($off=0; ($off+1024) -le $mft.Length; $off+=1024){
    if(-not ($mft[$off] -eq 0x46 -and $mft[$off+1] -eq 0x49 -and $mft[$off+2] -eq 0x4C -and $mft[$off+3] -eq 0x45)){ continue }
    $rec0 = [byte[]]($mft[$off..($off+1023)])
    if((FindBytes $rec0 $needle) -lt 0){ continue }
    if(-not (RecHasData $rec0)){ continue }
    $recAbs = $mftByte + $off; break }
  if ($recAbs -lt 0) { throw "flag.zip DATA record NOT FOUND" }
  Write-Host ("    recAbs=0x{0:X}  backupVBR=0x{1:X}" -f $recAbs,$bVBR)

  $recFx = ApplyFixup ([byte[]]($rec0.Clone()))
  $rs = DataRunStats $recFx
  if ($rs) {
    Write-Host ("    runlist (after fixup): sum={0} cluster, lastVCN+1={1}" -f $rs.Sum,($rs.LastVCN+1))
    if ($rs.Sum -ne ($rs.LastVCN+1)) {
      throw ("RUNLIST ERROR: runlist maps {0} clusters but lastVCN+1={1} (diff {2}). " -f $rs.Sum,($rs.LastVCN+1),(($rs.LastVCN+1)-$rs.Sum)) +
            "Corrupt record -> DO NOT SHIP."
    }
  }

  $name=[byte[]]::new(72)
  $m1=[Text.Encoding]::Unicode.GetBytes($script:P.p1enc)
  if ($m1.Length -gt 72) { throw "p1enc too long for GPT name (72 bytes)" }
  [Array]::Copy($m1,$name,$m1.Length)
  WB $fs 0x438 $name

  $ser = $vbr[0x48..0x4F]
  $m2 = [Text.Encoding]::ASCII.GetBytes($script:P.p2m)
  for($k=0;$k -lt $m2.Length;$k++){ $m2[$k] = $m2[$k] -bxor $ser[$k % 8] }
  WB $fs ($bVBR+0x80) $m2

  $m3 = [Text.Encoding]::ASCII.GetBytes($script:P.p3m)
  $rec = RB $fs $recAbs 1024
  $mk = FindBytes $rec ([byte[]]@(0xFF,0xFF,0xFF,0xFF)) 0x30
  if ($mk -lt 0 -or ($mk+8+$m3.Length) -ge 1024) { throw "could not find safe slack" }
  WB $fs ($recAbs+$mk+8) $m3
}
Ok "3 pieces placed (piece 4 is in flag.zip live, fragmented)"

Copy-Item $WorkVhd $OutVhd -Force
Info "Encrypting infected.vhd with: C++ encryptor"
$exe = Join-Path $Root 'encryptor_cpp\encryptor.exe'
if (-not (Test-Path $exe)) { throw "Not built $exe. Build it first." }
& $exe $OutVhd; $rc=$LASTEXITCODE

if ($rc -ne 0) { throw "encryptor failed" }
Ok "infected.vhd has been encrypted"
