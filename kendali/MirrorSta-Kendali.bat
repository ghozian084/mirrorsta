<# : bagian batch - klik dua kali file ini untuk menjalankan
@echo off
title MirrorSta Kendali
powershell -NoProfile -ExecutionPolicy Bypass -Command "iex (Get-Content -LiteralPath '%~f0' -Raw)"
echo.
pause
exit /b
#>

# =====================================================================
#  MirrorSta Kendali (Windows)
#  Program kecil yang membiarkan penerima MirrorSta (mis. IFP layar sentuh)
#  menggerakkan & mengklik mouse di komputer ini.
#
#  - Hanya mendengarkan di 127.0.0.1 (komputer ini sendiri), port 47811.
#  - Hanya menerima koneksi dari halaman MirrorSta resmi (cek header Origin).
#  - Halaman MirrorSta yang meneruskan sentuhan dari penerima, dan hanya
#    selama Anda mencentang "Izinkan kendali" saat berbagi layar.
#  - Tutup jendela ini untuk menghentikan kendali kapan saja.
# =====================================================================

$Port = 47811
$AllowedOrigins = @('https://ghozian084.github.io')

Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class MsInput {
    [DllImport("user32.dll")]
    public static extern void mouse_event(uint flags, int dx, int dy, int data, UIntPtr extra);
}
"@

# MOUSEEVENTF_*: koordinat ABSOLUTE 0..65535 memetakan ke layar utama, tidak terpengaruh skala DPI
$MOVE = 0x0001; $LDOWN = 0x0002; $LUP = 0x0004; $RDOWN = 0x0008; $RUP = 0x0010
$WHEEL = 0x0800; $ABSOLUTE = 0x8000
$Inv = [Globalization.CultureInfo]::InvariantCulture

function Read-Exact($stream, [int]$n) {
    $buf = New-Object byte[] $n
    $off = 0
    while ($off -lt $n) {
        $r = $stream.Read($buf, $off, $n - $off)
        if ($r -le 0) { throw 'koneksi ditutup' }
        $off += $r
    }
    return ,$buf
}

function Send-Text($stream, [string]$text) {
    $data = [Text.Encoding]::UTF8.GetBytes($text)   # pesan pendek (< 126 byte)
    $frame = [byte[]](@(0x81, $data.Length) + $data)
    $stream.Write($frame, 0, $frame.Length)
}

function Invoke-Input([string]$msg) {
    # format: "<op> <x> <y> [arg]"  - op: m=gerak, d=tekan, u=lepas, w=gulir; x,y = 0..1
    $p = $msg.Split(' ')
    if ($p.Length -lt 3) { return }
    $x = [Math]::Min(1, [Math]::Max(0, [double]::Parse($p[1], $Inv)))
    $y = [Math]::Min(1, [Math]::Max(0, [double]::Parse($p[2], $Inv)))
    $ax = [int]($x * 65535); $ay = [int]($y * 65535)
    [MsInput]::mouse_event($MOVE -bor $ABSOLUTE, $ax, $ay, 0, [UIntPtr]::Zero)
    $arg = if ($p.Length -gt 3) { $p[3] } else { '0' }
    switch ($p[0]) {
        'd' { $f = if ($arg -eq '2') { $RDOWN } else { $LDOWN }; [MsInput]::mouse_event($f, 0, 0, 0, [UIntPtr]::Zero) }
        'u' { $f = if ($arg -eq '2') { $RUP } else { $LUP }; [MsInput]::mouse_event($f, 0, 0, 0, [UIntPtr]::Zero) }
        'w' {
            # deltaY browser: positif = gulir ke bawah; Windows: positif = ke atas
            $d = [int][Math]::Max(-1200, [Math]::Min(1200, -[double]::Parse($arg, $Inv)))
            if ($d -ne 0) { [MsInput]::mouse_event($WHEEL, 0, 0, $d, [UIntPtr]::Zero) }
        }
    }
}

function Serve-Client($client) {
    $stream = $client.GetStream()
    # --- jabat tangan WebSocket ---
    $req = New-Object Text.StringBuilder
    while (-not $req.ToString().EndsWith("`r`n`r`n")) {
        $b = $stream.ReadByte()
        if ($b -lt 0 -or $req.Length -gt 8192) { return }
        [void]$req.Append([char]$b)
    }
    $headers = @{}
    foreach ($line in $req.ToString().Split("`r`n", [StringSplitOptions]::RemoveEmptyEntries) | Select-Object -Skip 1) {
        $i = $line.IndexOf(':')
        if ($i -gt 0) { $headers[$line.Substring(0, $i).Trim().ToLower()] = $line.Substring($i + 1).Trim() }
    }
    $origin = $headers['origin']
    if (-not $headers['sec-websocket-key'] -or ($AllowedOrigins -notcontains $origin)) {
        $deny = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 403 Forbidden`r`nContent-Length: 0`r`n`r`n")
        $stream.Write($deny, 0, $deny.Length)
        Write-Host "Koneksi ditolak dari: $origin"
        return
    }
    $sha = [Security.Cryptography.SHA1]::Create()
    $accept = [Convert]::ToBase64String($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($headers['sec-websocket-key'] + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')))
    $resp = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 101 Switching Protocols`r`nUpgrade: websocket`r`nConnection: Upgrade`r`nSec-WebSocket-Accept: $accept`r`n`r`n")
    $stream.Write($resp, 0, $resp.Length)
    Send-Text $stream 'ok MirrorSta-Kendali 1'
    Write-Host 'Halaman MirrorSta tersambung. Kendali siap.'

    # --- baca frame WebSocket ---
    while ($true) {
        $h = Read-Exact $stream 2
        $op = $h[0] -band 0x0F
        $len = [int64]($h[1] -band 0x7F)
        if ($len -eq 126) { $e = Read-Exact $stream 2; $len = ([int64]$e[0] -shl 8) -bor $e[1] }
        elseif ($len -eq 127) { $e = Read-Exact $stream 8; $len = 0; foreach ($x in $e) { $len = ($len -shl 8) -bor $x } }
        if ($len -gt 65536) { return }
        $mask = if ($h[1] -band 0x80) { Read-Exact $stream 4 } else { $null }
        $data = if ($len -gt 0) { Read-Exact $stream ([int]$len) } else { New-Object byte[] 0 }
        if ($mask) { for ($i = 0; $i -lt $data.Length; $i++) { $data[$i] = $data[$i] -bxor $mask[$i % 4] } }
        switch ($op) {
            8 { return }                                                     # close
            9 { $pong = [byte[]](@(0x8A, $data.Length) + $data); $stream.Write($pong, 0, $pong.Length) }  # ping
            1 { try { Invoke-Input ([Text.Encoding]::UTF8.GetString($data)) } catch { } }
        }
    }
}

$listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $Port)
try { $listener.Start() } catch {
    Write-Host "Port $Port sedang dipakai. Mungkin MirrorSta Kendali sudah berjalan di jendela lain."
    return
}
Write-Host '================================================'
Write-Host ' MirrorSta Kendali berjalan.'
Write-Host ' Biarkan jendela ini terbuka selama berbagi layar.'
Write-Host ' Tutup jendela ini untuk menghentikan kendali.'
Write-Host '================================================'
while ($true) {
    $client = $listener.AcceptTcpClient()
    try { Serve-Client $client } catch { } finally {
        $client.Close()
        Write-Host 'Halaman MirrorSta terputus.'
    }
}
