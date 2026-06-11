<?php
/**
 * Standalone Joomla/PHP backdoor scanner — single file, no dependencies.
 *
 * PURPOSE: Detect the backdoor families found on nccthailand.com (April 2025
 * compromise) plus common PHP webshell patterns, on shared hosting where you
 * usually only have FTP/web access and no SSH.
 *
 * USAGE (web):
 *   1. Edit $PASSWORD below to a long random value.
 *   2. Upload this file anywhere inside the site (e.g. webroot).
 *   3. Open https://yoursite/scan-backdoor.php?key=YOUR_PASSWORD
 *   4. Click "เริ่มสแกน", watch progress bar, read the report.
 *   5. DELETE THIS FILE when done.
 *
 * USAGE (CLI / SSH):
 *   php scan-backdoor.php /path/to/webroot
 *
 * This script is READ-ONLY: it walks files and matches patterns. It never
 * executes, decodes-and-runs, or modifies anything it finds.
 *
 * @version 1.0.0
 */

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------
$VERSION  = '1.0.0';
$PASSWORD = 'Colorpack@Secure';   // required for web access

$IS_CLI = (PHP_SAPI === 'cli');

// Scan root: CLI arg, else directory of this script.
if ($IS_CLI) {
    $ROOT = isset($argv[1]) ? rtrim($argv[1], '/') : getcwd();
} else {
    $ROOT = __DIR__;
}

// Only read files with these extensions (plus we always check .zip presence).
$EXT = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'pht', 'inc', 'htaccess'];

// Read at most this many bytes per file (webshells fit easily; keeps it fast).
$MAX_READ = 512 * 1024;

// Directories where a .php file is itself suspicious (uploads / assets / cache).
$UPLOAD_DIRS = ['/images/', '/media/', '/cache/', '/tmp/', '/files/', '/logs/', '/assets/'];

// Skip these directory names entirely (huge + low-risk vendor trees).
$SKIP_DIRS = ['.git', '.svn', 'node_modules'];

// Known-bad MD5s (exact-match = confirmed).
$BAD_MD5 = [
    '08bd2f0ce6ed34305c95dbcbc02363f0' => 'eval(php://input) backdoor (api.php)',
    'd77869a7921ff2805219c46b9c773671' => 'md5-cookie auth eval-shell (babimild incident)',
    '3a97c88412481d5907127c4bad475ca4' => 'Tiny File Manager zip:// loader (index.php)',
    'f12f4e959025d3fcffc5a0aff6438f64' => 'Tiny File Manager payload (index.zip)',
    '4cc322f9ef465c320fb3eeaf02620c48' => 'Tiny File Manager payload (index.zip)',
    'df6e1a6e15fdf201ab8dec4b52f13061' => 'Tiny File Manager payload (index.zip)',
    'dc664ad407ee7833a22c23bffbfaa580' => 'Tiny File Manager payload (index.zip)',
    'b79f7dd760034cea6c2bdb630680176e' => 'Tiny File Manager payload (index.zip)',
    'ee9ca512c40000688eecad28351cf220' => 'Tiny File Manager payload (index.zip)',
    '615872191651d7bbe397ba5857b0d386' => 'Tiny File Manager payload (index.zip)',
    '4411686fefa17de35547eaf8e56ea621' => 'Tiny File Manager payload (index.zip)',
    'c27b29cf74a80d593a5e1383c884c57d' => 'Tiny File Manager payload (index.zip)',
    'c75d0cbcda23cdc0c88d903ecf8dfad8' => 'Tiny File Manager payload (index.zip)',
];

// ---------------------------------------------------------------------------
// AUTH (web only)
// ---------------------------------------------------------------------------
if (!$IS_CLI) {
    $given = isset($_GET['key']) ? (string) $_GET['key'] : '';
    if ($PASSWORD === 'CHANGE_ME_to_a_long_random_string' || !hash_equals($PASSWORD, $given)) {
        header('HTTP/1.1 403 Forbidden');
        header('Content-Type: text/plain; charset=utf-8');
        echo "403 Forbidden.\n";
        echo "Set \$PASSWORD in this file and call ?key=YOUR_PASSWORD\n";
        exit;
    }

    $hKey  = htmlspecialchars($given, ENT_QUOTES, 'UTF-8');
    $hRoot = htmlspecialchars($ROOT, ENT_QUOTES, 'UTF-8');

    // LANDING PAGE — shown when scan not yet requested
    if (empty($_POST['scan']) && empty($_GET['scan'])) {
        header('Content-Type: text/html; charset=utf-8');
        echo <<<HTML
<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Colorpack Backdoor Scan V1.0</title>
<style>
 body{font:15px/1.6 -apple-system,"Segoe UI","Sarabun",Tahoma,sans-serif;margin:0;padding:2rem 1.5rem;max-width:600px;margin-inline:auto;color:#1a1a1a}
 h1{font-size:1.5rem;margin:0 0 .3rem}
 .meta{color:#555;font-size:.9rem;margin-bottom:1.5rem}
 .btn{display:inline-block;background:#c0392b;color:#fff;border:none;border-radius:8px;padding:.75rem 2.5rem;font-size:1.05rem;font-weight:700;cursor:pointer;letter-spacing:.02em;transition:background .15s}
 .btn:hover{background:#a93226}
 .warn{background:#fff8e1;border:1px solid #e3c97a;padding:.8rem 1rem;border-radius:8px;margin:1.5rem 0;color:#7a5b00;font-size:.88rem;line-height:1.5}
 #overlay{display:none;position:fixed;inset:0;background:rgba(255,255,255,.95);flex-direction:column;align-items:center;justify-content:center;z-index:999;gap:1.2rem}
 #overlay.show{display:flex}
 .spinner{width:48px;height:48px;border:5px solid #e0e0e0;border-top-color:#2563eb;border-radius:50%;animation:spin .8s linear infinite}
 @keyframes spin{to{transform:rotate(360deg)}}
 .spin-msg{font-size:1rem;color:#555;text-align:center;line-height:1.7}
</style></head><body>
<div id="overlay">
 <div class="spinner"></div>
 <div class="spin-msg">กำลังสแกน กรุณารอ...<br><small style="color:#aaa">อาจใช้เวลา 10–60 วินาที</small></div>
</div>
<h1>Colorpack Backdoor Scan V1.0</h1>
<div class="meta">Root: <code>{$hRoot}</code></div>
<div class="warn">
 <strong>หมายเหตุ:</strong> scanner นี้ดูเฉพาะไฟล์ — ยังต้องดู database (admin แปลกปลอม), access log, cron job ด้วย<br>
 <strong>ลบไฟล์ scanner นี้ออกจาก server ทันทีหลังใช้เสร็จ</strong>
</div>
<form method="post" action="?key={$hKey}" id="scanForm">
 <input type="hidden" name="scan" value="1">
 <button type="submit" class="btn" id="startBtn">เริ่มสแกน</button>
</form>
<script>
document.getElementById('scanForm').addEventListener('submit', function(e) {
 e.preventDefault();
 var overlay = document.getElementById('overlay');
 var btn = document.getElementById('startBtn');
 overlay.classList.add('show');
 btn.disabled = true;
 var form = this;
 requestAnimationFrame(function(){
  requestAnimationFrame(function(){ form.submit(); });
 });
});
</script>
<footer style="margin-top:3rem;padding-top:1rem;border-top:1px solid #eee;color:#bbb;font-size:.78rem">
 จัดทำโดย ทีมงาน บริษัท คัลเลอร์แพค ครีเอชั่น จำกัด ·
 <a href="https://colorpack.co.th/" target="_blank" rel="noopener" style="color:#bbb">colorpack.co.th</a>
 · v{$VERSION}
</footer>
</body></html>
HTML;
        exit;
    }

    @set_time_limit(300);

    // STREAMING SETUP — flush output as scan progresses
    if (function_exists('apache_setenv')) @apache_setenv('no-gzip', '1');
    @ini_set('zlib.output_compression', '0');
    @ini_set('output_buffering', 'off');
    while (ob_get_level() > 0) ob_end_clean();
    ob_implicit_flush(true);
    header('Content-Type: text/html; charset=utf-8');
    header('X-Accel-Buffering: no');
    header('X-Accel-Buffering: no');
    header('Cache-Control: no-cache, no-store');
    header('X-Content-Type-Options: nosniff');

    // Output HTML head + progress bar immediately (before any scan work)
    echo <<<HTML
<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Colorpack Backdoor Scan V1.0</title>
<style>
 body{font:15px/1.6 -apple-system,"Segoe UI","Noto Sans Thai","Noto Sans",Tahoma,sans-serif;margin:0;padding:1.5rem;max-width:1000px;margin-inline:auto;color:#1a1a1a}
 h1{font-size:1.5rem;margin:0 0 .3rem}
 .meta{color:#555;font-size:.9rem;margin-bottom:1rem}
 .sum{display:flex;gap:.6rem;flex-wrap:wrap;margin:1rem 0}
 .sum span{padding:.4rem .8rem;border-radius:6px;font-weight:700}
 table{border-collapse:collapse;width:100%;font-size:.88rem}
 th,td{border:1px solid #ddd;padding:.45rem .6rem;text-align:left;vertical-align:top}
 th{background:#f0f0f0}
 code{font-family:Menlo,Consolas,monospace;font-size:.85rem;word-break:break-all}
 .tag{font-weight:700;border-radius:4px;padding:.1em .5em;color:#fff;font-size:.78rem;white-space:nowrap}
 .clean{background:#e6f4ea;color:#1a6b32;border:1px solid #9bcca9;padding:1rem;border-radius:8px}
 .warn{background:#fff8e1;border:1px solid #e3c97a;padding:.8rem 1rem;border-radius:8px;margin:1rem 0;color:#7a5b00}
 #prog-wrap{margin:1.2rem 0 1.5rem}
 #prog-track{background:#e0e0e0;border-radius:6px;height:20px;width:100%;overflow:hidden;position:relative}
 #prog-bar{background:#2563eb;height:20px;position:absolute;width:35%;animation:slide 1.6s ease-in-out infinite alternate}
 @keyframes slide{0%{left:-35%}100%{left:100%}}
 #prog-label{font-size:.88rem;color:#555;margin-top:.4rem}
 @keyframes blink{0%,100%{opacity:1}50%{opacity:.35}}
 #prog-label.waiting{animation:blink 1.2s ease-in-out infinite}
 .tabs{display:flex;gap:0;margin:1rem 0 0;border-bottom:2px solid #ddd;flex-wrap:wrap}
 .tab{background:#f7f7f7;border:1px solid #ddd;border-bottom:none;padding:.45rem 1.1rem;cursor:pointer;font-size:.88rem;font-weight:600;margin-bottom:-2px;border-radius:4px 4px 0 0;color:#777;transition:color .15s}
 .tab.tc{color:#a93226}.tab.tc.active{background:#fff;border-color:#c0392b;border-bottom-color:#fff;color:#c0392b}
 .tab.th{color:#7a4800}.tab.th.active{background:#fff;border-color:#9a5b00;border-bottom-color:#fff;color:#9a5b00}
 .tab.tm{color:#555}.tab.tm.active{background:#fff;border-color:#888;border-bottom-color:#fff;color:#333}
 .tab .bdg{display:inline-block;min-width:1.5em;text-align:center;border-radius:10px;padding:.05em .45em;font-size:.72rem;margin-left:.3rem;color:#fff}
 .tab.tc .bdg{background:#c0392b}.tab.th .bdg{background:#9a5b00}.tab.tm .bdg{background:#888}
 .tab-panel{display:none}.tab-panel.on{display:block}
 #todo-sum{font-size:.82rem;color:#555;margin:.6rem 0 .8rem;padding:.4rem .7rem;background:#f7f7f7;border-radius:6px;display:inline-block}
 .act-btn{border:1px solid #ccc;background:#fff;border-radius:4px;padding:.2rem .55rem;font-size:.73rem;cursor:pointer;white-space:nowrap;margin:.1rem .1rem 0 0;transition:background .1s,color .1s}
 .act-btn:hover{background:#f0f0f0}
 tr.done{opacity:.45}tr.done td{text-decoration:line-through}
 tr.done .del-btn{background:#1a6b32;border-color:#1a6b32;color:#fff}
 tr.fp{opacity:.45}
 tr.fp .fp-btn{background:#555;border-color:#555;color:#fff}
 .act-td{width:140px;white-space:nowrap}
 @media(max-width:640px){
  table{font-size:.78rem}
  th:first-child,td:first-child{display:none}
  .act-td{width:auto}
  .act-btn{padding:.15rem .3rem;font-size:.68rem}
 }
</style>
<script>
function updateProg(n,total){
 var pct=total>0?Math.round(n/total*100):0;
 var lbl=document.getElementById('prog-label');
 lbl.className='';
 lbl.textContent='กำลังสแกน... '+n.toLocaleString('th')+' / '+total.toLocaleString('th')+' ไฟล์ ('+pct+'%)';
 document.getElementById('prog-bar').style.width=pct+'%';
}
function doneProg(n,t){
 document.getElementById('prog-bar').style.width='100%';
 document.getElementById('prog-label').textContent='สแกนเสร็จ — '+n.toLocaleString('th')+' ไฟล์ ใช้เวลา '+t+'s';
 setTimeout(function(){
  var w=document.getElementById('prog-wrap');
  if(w)w.style.display='none';
 },1500);
}
function showTab(id,el){
 document.querySelectorAll('.tab-panel').forEach(function(p){p.classList.remove('on');});
 document.querySelectorAll('.tab').forEach(function(t){t.classList.remove('active');});
 document.getElementById('tp-'+id).classList.add('on');
 el.classList.add('active');
}
function markRow(btn,cls){
 var tr=btn.closest('tr');
 if(tr.classList.contains(cls)){tr.classList.remove(cls);}
 else{tr.classList.remove('done','fp');tr.classList.add(cls);}
 refreshTodo();
}
function refreshTodo(){
 var all=document.querySelectorAll('tbody tr').length;
 var done=document.querySelectorAll('tr.done').length;
 var fp=document.querySelectorAll('tr.fp').length;
 var el=document.getElementById('todo-sum');
 if(el) el.textContent='รอดำเนินการ '+(all-done-fp)+' · ลบแล้ว '+done+' · ไม่อันตราย '+fp+' / รวม '+all;
}
</script>
</head><body>
<h1>Colorpack Backdoor Scan V1.0</h1>
<div class="meta">Root: <code>{$hRoot}</code></div>
<div id="prog-wrap">
 <div id="prog-track"><div id="prog-bar"></div></div>
 <div id="prog-label" class="waiting">กำลังเตรียมสแกน...</div>
</div>
HTML;
    // Pad to 8 KB — forces browser to flush internal buffer and start rendering
    echo str_repeat(' ', 8192) . "\n";
    @ob_flush(); flush();
}

// ---------------------------------------------------------------------------
// DETECTION RULES
// Each rule: severity (CRITICAL|HIGH|MEDIUM|LOW), label, and a callback that
// receives ($content) and returns true on match.
// ---------------------------------------------------------------------------
function rx($content, $pattern) { return (bool) preg_match($pattern, $content); }

function fileEntropy($s) {
    $len = strlen($s);
    if ($len < 200) return 0.0;
    $freq = array_count_values(str_split($s));
    $e = 0.0;
    foreach ($freq as $c) { $p = $c / $len; $e -= $p * log($p, 2); }
    return round($e, 2);
}

$RULES = [
    // --- CRITICAL: near-certain backdoor signatures ---
    ['CRITICAL', 'zip:// / phar:// stream-wrapper include loader',
        function($c) { return rx($c, '~\b(include|require)(_once)?\s*\(?\s*[\'"](zip|phar|compress\.zlib)://~i'); }],

    ['CRITICAL', 'eval()/assert() on php://input',
        function($c) { return rx($c, '~(eval|assert)\s*\(.{0,80}php://input~is')
               || rx($c, '~file_get_contents\s*\(\s*[\'"]php://input[\'"]\s*\).{0,80}(eval|assert)~is'); }],

    ['CRITICAL', 'eval() of decoded data (base64/gzinflate/gzuncompress/rot13)',
        function($c) { return rx($c, '~(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|str_rot13|strrev|gzdecode|convert_uudecode)\s*\(~i'); }],

    ['CRITICAL', 'eval()/system() directly on user input',
        function($c) { return rx($c, '~(eval|assert|system|passthru|shell_exec|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)\b~i'); }],

    ['CRITICAL', 'goto flow-flattening obfuscation (webshell)',
        function($c) { return preg_match_all('~\bgoto\s+[A-Za-z0-9_]+\s*;~', $c) >= 15
               && rx($c, '~[A-Za-z0-9_]+:\s*goto~'); }],

    ['CRITICAL', 'dynamic call from user input  $_GET[x]()',
        function($c) { return rx($c, '~\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(~'); }],

    ['CRITICAL', 'strrev-encoded function name (anti-detection obfuscation)',
        function($c) { return rx($c, '~strrev\s*\(\s*[\'"](?:edoced|46esab|etalfnizg|metsys|lave|tressa|pmetbus)[\'"]~i'); }],

    ['CRITICAL', 'Unicode/binary variable names (non-ASCII obfuscation)',
        function($c) { return substr_count($c, "\xef\xbf\xbd") >= 50
               || (bool) preg_match('/\$[\x80-\xff]{3,}/', $c)
               || (strlen($c) > 200 && preg_match_all('/[\xe0-\xef][\x80-\xbf]{2}/', $c) * 3 > strlen($c) * 0.45); }],

    ['CRITICAL', 'openssl_decrypt with user-supplied key (AES-encrypted shell)',
        function($c) { return rx($c, '~openssl_decrypt\s*\(.{0,300}\$_(REQUEST|GET|POST|COOKIE)~is'); }],

    // --- HIGH: strong indicators, verify before deleting ---
    ['HIGH', 'preg_replace with /e (code execution) modifier',
        function($c) { return rx($c, '~preg_replace\s*\(\s*[\'"][^\'"]*/[a-zA-Z]*e[a-zA-Z]*[\'"]~'); }],

    ['HIGH', 'create_function (often used to hide eval)',
        function($c) { return rx($c, '~\bcreate_function\s*\(~i'); }],

    ['HIGH', 'long hex-encoded string run (obfuscation)',
        function($c) { return rx($c, '~(\\\\x[0-9a-fA-F]{2}){16,}~'); }],

    ['HIGH', 'base64 blob piped into eval/assert/create_function',
        function($c) { return rx($c, '~(eval|assert|create_function)\s*\(.{0,40}base64_decode~is'); }],

    ['HIGH', 'known webshell name signature',
        function($c) { return rx($c, '~\b(c99shell|r57shell|wso\s*shell|b374k|IndoXploit|AnonymousFox|alfa\s*team|p0wny|FilesMan|MARIJUANA|GeneXus)\b~i'); }],

    ['HIGH', 'Tiny File Manager payload string',
        function($c) { return rx($c, '~Tiny\s*File\s*Manager~i'); }],

    ['HIGH', '@session_start + @set_time_limit(0) (file-manager webshell pattern)',
        function($c) { return rx($c, '~@session_start\s*\(\s*\)~i') && rx($c, '~@set_time_limit\s*\(\s*0\s*\)~i'); }],

    ['HIGH', 'data:image URI as payload carrier (obfuscated eval payload)',
        function($c) { return rx($c, '~data:image/[a-zA-Z]+;[A-Za-z0-9+/]{500,}~') && rx($c, '~preg_match~i'); }],

    ['HIGH', 'variable assigned shell function then called (indirect execution)',
        function($c) {
            if (!preg_match('~\$([a-zA-Z_]\w*)\s*=\s*["\'](?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)["\']~i', $c, $m)) return false;
            return (bool) preg_match('~\$' . preg_quote($m[1], '~') . '\s*\(~', $c);
        }],

    ['HIGH', 'hex string assigned to variable then called (obfuscated function name)',
        function($c) {
            if (!preg_match('~\$([a-zA-Z_]\w*)\s*=\s*["\'](\\\\x[0-9a-fA-F]{2}){4,}["\']~', $c, $m)) return false;
            return (bool) preg_match('~\$' . preg_quote($m[1], '~') . '\s*\(~', $c);
        }],

    ['HIGH', 'chmod 0777 on written file (post-drop permission escalation)',
        function($c) { return rx($c, '~chmod\s*\(\s*["\']?0?777\b~i')
               && rx($c, '~(file_put_contents|move_uploaded_file|fwrite|fputs)\s*\(~i'); }],

    // --- MEDIUM: worth a look ---
    ['MEDIUM', 'char-built dangerous function name (chr().chr()...)',
        function($c) { return rx($c, '~(chr\s*\(\s*\d+\s*\)\s*\.\s*){4,}~i'); }],

    ['MEDIUM', 'remote fetch + write to disk (dropper)',
        function($c) { return rx($c, '~(curl_exec|file_get_contents)\s*\(.{0,120}https?://~is')
               && rx($c, '~(fwrite|file_put_contents|fputs)\s*\(~i'); }],

    ['MEDIUM', 'error_reporting(0) next to eval/decoder',
        function($c) { return rx($c, '~@?error_reporting\s*\(\s*0\s*\)~i')
               && rx($c, '~(eval|base64_decode|gzinflate|str_rot13|php://input)~i'); }],

    ['MEDIUM', 'high Shannon entropy >7.2 bits/byte (encrypted/packed payload)',
        function($c) { return strlen($c) > 2000 && fileEntropy($c) > 7.2; }],
];

// ---------------------------------------------------------------------------
// OUTPUT HELPERS
// ---------------------------------------------------------------------------
function out_fatal($msg) {
    global $IS_CLI;
    if ($IS_CLI) { fwrite(STDERR, "FATAL: $msg\n"); }
    else { header('Content-Type: text/plain; charset=utf-8'); echo "FATAL: $msg\n"; }
    exit(2);
}

// ---------------------------------------------------------------------------
// ITERATOR FACTORY — reused for pre-count and main scan
// ---------------------------------------------------------------------------
$makeIt = function () use ($ROOT, $SKIP_DIRS) {
    return new RecursiveIteratorIterator(
        new RecursiveCallbackFilterIterator(
            new RecursiveDirectoryIterator($ROOT, FilesystemIterator::SKIP_DOTS),
            function ($cur) use ($SKIP_DIRS) {
                if ($cur->isDir()) {
                    return !in_array($cur->getFilename(), $SKIP_DIRS, true);
                }
                return true;
            }
        ),
        RecursiveIteratorIterator::LEAVES_ONLY
    );
};

if (!is_dir($ROOT)) out_fatal("Not a directory: $ROOT");

// ---------------------------------------------------------------------------
// PRE-COUNT (web only) — quick pass to get total for progress bar percentage
// ---------------------------------------------------------------------------
$totalFiles = 0;
if (!$IS_CLI) {
    try {
        foreach ($makeIt() as $file) {
            if (!$file->isFile()) continue;
            $lc  = strtolower($file->getFilename());
            $ext = strtolower($file->getExtension());
            if ($lc === 'index.zip'
                || preg_match('~^adman\.\d+\.txt$~i', $lc)
                || in_array($ext, $EXT, true)
                || $lc === '.htaccess') {
                $totalFiles++;
            }
        }
    } catch (Throwable $e) {
        out_fatal("Cannot read root: $ROOT — " . $e->getMessage());
    }
    echo '<script>updateProg(0,' . $totalFiles . ');</script>';
    flush();
}

// ---------------------------------------------------------------------------
// SCAN
// ---------------------------------------------------------------------------
$findings = [];      // each: [severity, label, path, extra]
$scanned  = 0;
$started  = microtime(true);
$sevRank  = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2, 'LOW' => 3];
$selfReal = realpath(__FILE__);

try {
    $it = $makeIt();
} catch (Throwable $e) {
    out_fatal("Cannot read root: $ROOT — " . $e->getMessage());
}

foreach ($it as $file) {
    if (!$file->isFile()) continue;
    $path = $file->getPathname();
    if (realpath($path) === $selfReal) continue;   // never flag ourselves
    $lc   = strtolower($file->getFilename());
    $ext  = strtolower($file->getExtension());
    $relU = str_replace('\\', '/', str_replace($ROOT, '', $path));

    // Rule: AdmaNi hit-counter file — proves an AdmaNi shell was/is active here.
    if (preg_match('~^adman\.\d+\.txt$~i', $lc)) {
        $val = trim(@file_get_contents($path));
        $findings[] = ['HIGH', 'AdmaNi shell hit-counter file (active shell indicator)', $relU,
            "value=$val — AdmaNi (Iranian/Turkish) shell toolkit marker"];
        continue;
    }

    // Rule: stray index.zip = zip:// loader payload.
    if ($ext === 'zip' && $lc === 'index.zip') {
        $md5 = @md5_file($path);
        $why = isset($BAD_MD5[$md5]) ? $BAD_MD5[$md5] : 'index.zip beside index.php = zip:// loader payload';
        $findings[] = ['CRITICAL', 'Suspicious index.zip payload', $relU, "md5=$md5 — $why"];
        continue;
    }

    // Rule: double PHP extension (.php.jpg, .php.gif) — Apache/nginx misconfiguration exploit.
    if (preg_match('~\.php\d?\.(jpg|jpeg|gif|png|ico|bmp|svg|txt|html|htm)$~i', $lc)) {
        $findings[] = ['HIGH', 'double extension (PHP evasion technique)', $relU,
            'hides PHP behind .' . strtoupper($ext) . ' — exploits server extension-handling misconfiguration'];
    }

    // Rule: PHP opening tag inside image/media file (polyglot shell).
    if (in_array($ext, ['jpg','jpeg','gif','png','ico','bmp','svg','webp'], true)) {
        $head = @file_get_contents($path, false, null, 0, 1024);
        if ($head !== false && preg_match('~<\?(php|=)~i', $head)) {
            $findings[] = ['CRITICAL', 'PHP code embedded in image file (polyglot shell)', $relU,
                'PHP opening tag found inside .' . strtoupper($ext) . ' — classic upload bypass technique'];
        }
        continue;   // don't run PHP content rules on image files
    }

    $isCode = in_array($ext, $EXT, true) || $lc === '.htaccess';
    if (!$isCode) continue;

    $scanned++;

    // Web: push progress update every 100 files
    if (!$IS_CLI && $scanned % 100 === 0) {
        echo '<script>updateProg(' . $scanned . ',' . $totalFiles . ');</script>';
        flush();
    }

    $content = @file_get_contents($path, false, null, 0, $MAX_READ);
    if ($content === false) continue;

    // Exact known-bad hash.
    $md5 = md5($content);
    if (isset($BAD_MD5[$md5])) {
        $findings[] = ['CRITICAL', 'Known backdoor (exact MD5 match)', $relU, $BAD_MD5[$md5] . " — md5=$md5"];
        continue;
    }

    // Skip the LOCATION rule for framework-generated cache files
    // (Joomla / RSFirewall: "<md5>-cache-<name>-<md5>.php"). Content rules below
    // still run on them, so a webshell hiding under a cache-like name is caught.
    $isCacheFile = (bool) preg_match('~-cache-.*\.php$~i', $relU)
                && (bool) preg_match('~[a-f0-9]{32}~i', $relU);

    // PHP file sitting in a TOP-LEVEL upload/asset dir = suspicious by location.
    // Anchor to webroot ($relU starts with the dir) so component trees that
    // merely contain "cache"/"media" in their name (e.g. com_cache) don't match.
    if (!$isCacheFile && in_array($ext, ['php','phtml','php3','php4','php5','pht'], true)) {
        foreach ($UPLOAD_DIRS as $d) {
            if (strpos($relU, $d) === 0) {
                $isStub = (strlen($content) <= 60 && rx($content, '~_JEXEC|no direct access~i'));
                if (!$isStub) {
                    $findings[] = ['HIGH', 'PHP file in upload/asset directory', $relU, 'unexpected executable in data dir'];
                }
                break;
            }
        }
    }

    // Pattern rules.
    foreach ($RULES as [$sev, $label, $cb]) {
        if ($cb($content)) {
            $findings[] = [$sev, $label, $relU, ''];
        }
    }
}

usort($findings, function ($a, $b) use ($sevRank) {
    $r = $sevRank[$a[0]] <=> $sevRank[$b[0]];
    return $r !== 0 ? $r : strcmp($a[2], $b[2]);
});

$elapsed = round(microtime(true) - $started, 2);
$counts  = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
foreach ($findings as $f) $counts[$f[0]]++;

// ---------------------------------------------------------------------------
// OUTPUT
// ---------------------------------------------------------------------------
if ($IS_CLI) {
    echo "Backdoor scan — root: $ROOT\n";
    echo "Files read: $scanned   Time: {$elapsed}s\n";
    echo "CRITICAL {$counts['CRITICAL']}  HIGH {$counts['HIGH']}  MEDIUM {$counts['MEDIUM']}\n";
    echo str_repeat('-', 70) . "\n";
    if (!$findings) {
        echo "No file findings. (Still review DB, logs, cron — files only.)\n";
    }
    foreach ($findings as [$sev, $label, $path, $extra]) {
        $mt = @filemtime($ROOT . $path);
        $mtStr = $mt ? date('Y-m-d', $mt) : '?';
        printf("[%-8s] %s  [mtime:%s]\n           %s%s\n", $sev, $path, $mtStr, $label, $extra ? "  ($extra)" : '');
    }
    exit($counts['CRITICAL'] > 0 ? 1 : 0);
}

// Web: signal scan complete, then render results
echo '<script>doneProg(' . $scanned . ',' . $elapsed . ');</script>' . "\n";
flush();

$h        = function($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); };
$sevColor = ['CRITICAL'=>'#8a1c12','HIGH'=>'#9a5b00','MEDIUM'=>'#555','LOW'=>'#777'];
$sevBg    = ['CRITICAL'=>'#fdecea','HIGH'=>'#fff3da','MEDIUM'=>'#f3f3f3','LOW'=>'#f7f7f7'];
?>
<div class="meta">Files read: <?=$scanned?> · Time: <?=$elapsed?>s</div>
<div class="sum">
 <span style="background:#fdecea;color:#8a1c12">CRITICAL <?=$counts['CRITICAL']?></span>
 <span style="background:#fff3da;color:#9a5b00">HIGH <?=$counts['HIGH']?></span>
 <span style="background:#f3f3f3;color:#555">MEDIUM <?=$counts['MEDIUM']?></span>
</div>
<div class="warn"><strong>หมายเหตุ:</strong> scanner นี้ดูเฉพาะไฟล์ — ยังต้องดู database (admin แปลกปลอม), access log, cron job ด้วย และ <strong>ลบไฟล์ scanner นี้</strong> หลังใช้เสร็จ</div>
<?php if (!$findings): ?>
 <div class="clean">ไม่พบ pattern backdoor ในไฟล์ แต่ยืนยันสะอาด 100% ไม่ได้จาก scan ไฟล์อย่างเดียว — ดู DB + log ต่อ</div>
<?php else:
  $byLv = ['CRITICAL'=>[], 'HIGH'=>[], 'MEDIUM'=>[]];
  foreach ($findings as $f) $byLv[$f[0]][] = $f;
  $first = 'CRITICAL';
  foreach (['CRITICAL','HIGH','MEDIUM'] as $s) { if ($byLv[$s]) { $first=$s; break; } }
  $tabCls = ['CRITICAL'=>'tc','HIGH'=>'th','MEDIUM'=>'tm'];
?>
<div id="todo-sum">รอดำเนินการ <?=count($findings)?> · ลบแล้ว 0 · ไม่อันตราย 0 / รวม <?=count($findings)?></div>
<div class="tabs">
<?php foreach (['CRITICAL','HIGH','MEDIUM'] as $s): if (!$byLv[$s]) continue; ?>
 <button class="tab <?=$tabCls[$s]?><?=$s===$first?' active':''?>" onclick="showTab('<?=$s?>',this)">
  <?=$s?> <span class="bdg"><?=count($byLv[$s])?></span>
 </button>
<?php endforeach; ?>
</div>
<?php foreach (['CRITICAL','HIGH','MEDIUM'] as $s): if (!$byLv[$s]) continue; ?>
<div id="tp-<?=$s?>" class="tab-panel<?=$s===$first?' on':''?>">
 <table><thead><tr><th>mtime</th><th>Path</th><th>Reason</th><th class="act-td">Action</th></tr></thead><tbody>
 <?php foreach ($byLv[$s] as [$sev,$label,$path,$extra]):
   $mt = @filemtime($ROOT . $path);
   $mtStr = $mt ? date('Y-m-d', $mt) : '—';
   $mtColor = ($mt && (time()-$mt) < 30*86400) ? 'color:#c0392b;font-weight:700' : 'color:#888';
 ?>
  <tr style="background:<?=$sevBg[$sev]?>">
   <td style="white-space:nowrap;font-size:.82rem;<?=$mtColor?>"><?=$mtStr?></td>
   <td><code><?=$h($path)?></code></td>
   <td><?=$h($label)?><?php if($extra):?><br><small><code><?=$h($extra)?></code></small><?php endif;?></td>
   <td class="act-td">
    <button class="act-btn del-btn" onclick="markRow(this,'done')">✓ ลบแล้ว</button>
    <button class="act-btn fp-btn"  onclick="markRow(this,'fp')">⊘ ไม่อันตราย</button>
   </td>
  </tr>
 <?php endforeach; ?>
 </tbody></table>
</div>
<?php endforeach; ?>
<?php endif; ?>
<p style="color:#777;font-size:.82rem;margin-top:2rem">CRITICAL = near-certain backdoor, ลบได้หลังยืนยัน path · HIGH/MEDIUM = ดู context ก่อนลบ (อาจ false positive ใน plugin บางตัว)</p>
<footer style="margin-top:3rem;padding-top:1rem;border-top:1px solid #eee;color:#bbb;font-size:.78rem">
 จัดทำโดย ทีมงาน บริษัท คัลเลอร์แพค ครีเอชั่น จำกัด ·
 <a href="https://colorpack.co.th/" target="_blank" rel="noopener" style="color:#bbb">colorpack.co.th</a>
 · v<?=$VERSION?>
</footer>
</body></html>
