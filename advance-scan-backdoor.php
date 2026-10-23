<?php
/**
 * Colorpack Advanced Backdoor Scanner — single file, no dependencies.
 *
 * PURPOSE: Detect backdoor families + provide in-browser delete/edit actions
 * for flagged and Joomla-structure files. Built for shared hosting with only
 * FTP/web access and no SSH.
 *
 * USAGE (web):
 *   1. Edit $PASSWORD below to a long random value.
 *   2. Upload this file anywhere inside the site (e.g. webroot).
 *   3. Open https://yoursite/advance-scan-backdoor.php(sign in with the password)
 *   4. Click "เริ่มสแกน", use delete/edit buttons on findings.
 *   5. DELETE THIS FILE when done.
 *
 * WRITE FEATURES (ENABLE_WRITE = true):
 *   - Delete: CRITICAL/HIGH files — CSRF token + typing filename + anti-bot delay.
 *   - Edit: all findings — in-browser code editor with auto .bak backup.
 *
 * CHANGES in 2.0:
 *   - Security: session login (no password in URL), rate limit, HTTPS/IP/expiry options, audit log,
 *     edit/delete limited to scanned files, quarantined backups, CSRF key per session, XSS fixes.
 *   - Detection: PHP->shell, reverse shells, disable_functions bypass, droppers, cloaking/SEO spam,
 *     JS skimmers/miners, web file managers (capability heuristic + default credentials), head+tail scan.
 *   - Server audit: PHP/php.ini hardening, permissions, exposed backup/secret files.
 *   - UI: new light theme, risk score, one row per file, global search, code viewer/editor popup with
 *     suspicious-line highlighting, results survive Back/refresh (auto-rescan when files change).
 *
 * 2.0.1: fixes 504 Gateway Time-out behind nginx (time-boxed cache stats, no silent pre-count pass,
 *         keep-alive output while scanning, resumable cache clearing, scan finishes + caches even if
 *         the proxy drops the connection - open ?view=last).
 *
 * @version 2.0.1
 */

// ---------------------------------------------------------------------------
// CONFIG
// ---------------------------------------------------------------------------
$VERSION      = '2.0.1';
$PASSWORD     = 'CHANGE_ME_to_a_long_random_string';   // required for web access — set a unique long random value per site
$ALLOW_IPS     = [];                  // e.g. ['203.0.113.5'] — empty = any IP
$REQUIRE_HTTPS = true;                // refuse plain HTTP (set false only for local testing)
$EXPIRES       = '';                  // e.g. '2026-12-31 23:59' — scanner disables itself after this time
$ENABLE_WRITE = true;                 // set false to disable delete/edit actions

$IS_CLI = (PHP_SAPI === 'cli');

// Scan root: CLI arg, else directory of this script.
if ($IS_CLI) {
    $ROOT = isset($argv[1]) ? rtrim($argv[1], '/') : getcwd();
} else {
    $ROOT = __DIR__;
}

function bd_css() {
    return <<<'CSSEOF'
/* ===== v2.0 theme · © Colorpack Creation Co., Ltd. ===== */
:root{color-scheme:light;--bg:#F4F1EA;--panel:#FFFFFF;--panel2:#EFEBE1;--line:#D8D3C7;--line2:#B8B2A3;--ink:#1B1F24;--mute:#4A525C;--acc:#0B7A6B;--acc-ink:#FFFFFF;--acc-soft:rgba(11,122,107,.10);--crit:#B42318;--crit-ink:#FFFFFF;--crit-t:#B42318;--warn:#9A5B00;--code:#0B6B5E;--grid:rgba(27,31,36,.035);--hover:#F8F5EE;--bad-bg:#FBEDEA;--warn-bg:#FDF3E4;--ok-bg:#EEF6F1;--warn-t:#5C3000;--c-bg:#B42318;--c-fg:#FFFFFF;--c-bd:#B42318;--h-bg:#FDE7C8;--h-fg:#5C3000;--h-bd:#E7C99A;--glow:none;--btn-glow:none;--bdg:#6B7280;--modal-bg:rgba(27,31,36,.55)}
html{background:var(--bg)}
body{font-family:"IBM Plex Sans Thai","Noto Sans Thai","Sarabun",system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);background-image:linear-gradient(var(--grid) 1px,transparent 1px),linear-gradient(90deg,var(--grid) 1px,transparent 1px);background-size:44px 44px;color:var(--ink);max-width:1280px;padding:0 2rem 2rem;line-height:1.65}
a{color:var(--acc)}a:hover{opacity:.8}
button:focus-visible,input:focus-visible,textarea:focus-visible,a:focus-visible{outline:3px solid var(--acc);outline-offset:2px}
::selection{background:var(--acc-soft)}
.topbar{display:flex;flex-wrap:wrap;align-items:center;gap:1rem;margin:0 -2rem 1.8rem;padding:.9rem 2rem;background:#12171D;border-bottom:1px solid #1F2A36;color:#E6EDF3;position:sticky;top:0;z-index:50}
.topbar .brand{display:flex;align-items:center;gap:.7rem;font-weight:700;font-size:1.05rem;letter-spacing:.4px;line-height:1.2}
.topbar .brand svg{filter:drop-shadow(0 0 6px rgba(45,226,192,.6));flex:none}
.topbar .brand small{display:block;font-size:.62rem;letter-spacing:.16em;color:#8B98A8;font-weight:500}
.topbar .ver{font-size:.7rem;font-weight:500;padding:.1rem .55rem;border:1px solid #2A3745;border-radius:99px;color:#8B98A8;font-family:Menlo,Consolas,monospace}
.topbar .root{font-family:Menlo,Consolas,monospace;font-size:.78rem;color:#8B98A8;word-break:break-all}
.topbar .sp{margin-left:auto;display:flex;gap:.5rem;flex-wrap:wrap}
.topbar a,.topbar button{min-height:44px;box-sizing:border-box;display:inline-flex;align-items:center;background:transparent;color:#E6EDF3;border:1px solid #2A3745;border-radius:8px;padding:0 .95rem;font-size:.85rem;text-decoration:none;cursor:pointer;font-family:inherit;transition:border-color .15s,color .15s}
.topbar a:hover,.topbar button:hover{border-color:#2DE2C0;color:#2DE2C0;opacity:1}
.topbar a.out{color:#FF8A8C;border-color:#5A2A2C}
h1{font-size:2rem;line-height:1.3;font-weight:700;margin:0 0 .5rem;color:var(--ink)}
.meta{color:var(--mute)}
code{font-family:"IBM Plex Mono",Menlo,Consolas,monospace;color:var(--code)}
.warn{background:var(--warn-bg);border:1px solid var(--h-bd);color:var(--warn-t);border-radius:10px}
.warn strong{color:inherit}
.btn{background:var(--acc);color:var(--acc-ink);border-radius:10px;min-height:48px;box-shadow:var(--btn-glow)}
.btn:hover{background:var(--acc);opacity:.88}
.cache-box{background:var(--panel);border:1px solid var(--line);border-radius:12px;color:var(--ink)}
.clr-btn,.sel-filter-btn{background:transparent;color:var(--acc);border:1px solid var(--acc);border-radius:8px;min-height:36px}
.clr-btn:hover,.sel-filter-btn:hover{background:var(--acc-soft)}
#overlay{background:var(--bg);opacity:.97}.spin-msg{color:var(--mute)}
.spinner{border-color:var(--line);border-top-color:var(--acc)}
.sum{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.8rem;margin:1.2rem 0 1.6rem}
.sum span{display:flex;flex-direction:column;border-radius:14px;padding:1rem 1.2rem;font-weight:600;font-size:.8rem;letter-spacing:.04em;border:1px solid var(--line);background:var(--panel);color:var(--mute)}
.sum span b{font-size:2.5rem;line-height:1.1;font-weight:700;margin-top:.15rem;color:var(--ink)}
.sum span.sc-c{background:var(--c-bg);border-color:var(--c-bd);color:var(--c-fg);box-shadow:var(--glow)}.sum span.sc-c b{color:var(--c-fg)}
.sum span.sc-h{background:var(--h-bg);border-color:var(--h-bd);color:var(--h-fg)}.sum span.sc-h b{color:var(--h-fg)}
.hero{display:flex;flex-wrap:wrap;gap:1.6rem;align-items:center;margin:.4rem 0 1.2rem}
.gauge{position:relative;width:150px;height:150px;flex:none}
.gauge svg{display:block}.gauge .trk{stroke:var(--line)}
.gauge .gv{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge .gv b{font-size:2.3rem;line-height:1;font-weight:700}
.gauge .gv small{font-size:.62rem;letter-spacing:.16em;color:var(--mute);margin-top:.25rem}
.hero .tx{flex:1 1 300px;min-width:0}
.hero .tx .eyebrow{font-size:.74rem;font-weight:600;letter-spacing:.16em}
.rk-hi{--rk:var(--crit)}.rk-mid{--rk:var(--warn)}.rk-lo{--rk:var(--acc)}
.tabs{border-bottom:0;gap:.5rem;margin:1.2rem 0 .8rem}
.tab{margin:0;min-height:44px;border:1px solid var(--line2)!important;border-radius:99px;background:var(--panel);color:var(--ink)!important;padding:.4rem 1.1rem;font-size:.9rem}
.tab.active{background:var(--ink)!important;color:var(--bg)!important;border-color:var(--ink)!important}
.tab .bdg{background:var(--bdg)!important;color:#fff}.tab.active .bdg{background:var(--bg)!important;color:var(--ink)}
.tab.tc .bdg{background:var(--crit)!important;color:var(--crit-ink)}
#todo-sum{background:transparent;padding:0;color:var(--mute);font-size:.88rem}
.tab-panel table{background:var(--panel);border:1px solid var(--line);border-radius:12px;border-collapse:separate;border-spacing:0;overflow:hidden;color:var(--ink)}
.tab-panel th{background:var(--panel2);border:0;border-bottom:1px solid var(--line);font-size:.72rem;letter-spacing:.1em;text-transform:uppercase;color:var(--mute)}
.tab-panel td{border:0;border-bottom:1px solid var(--line);padding:.8rem .7rem}
.tab-panel tr:last-child td{border-bottom:0}
.tab-panel tbody tr{background:var(--panel)!important;transition:background .12s}
.tab-panel tbody tr:hover{background:var(--hover)!important}
tr.sev-CRITICAL td:first-child{box-shadow:inset 4px 0 0 var(--crit)}
tr.sev-HIGH td:first-child{box-shadow:inset 4px 0 0 #E0A85C}
tr.sev-MEDIUM td:first-child{box-shadow:inset 4px 0 0 var(--line2)}
.tab-panel td[style*="color:#888"]{color:var(--mute)!important}
.tab-panel td[style*="c0392b"]{color:var(--crit-t)!important}
.act-btn{min-height:32px;border-radius:8px;border-color:var(--line2);background:transparent;color:var(--ink)}
.act-btn:hover{background:var(--hover)}
.act-btn.danger-btn{background:var(--crit);color:var(--crit-ink);border-color:transparent;box-shadow:none}
.act-btn.edit-btn{background:transparent;color:var(--acc);border:1px solid var(--acc);box-shadow:none}
.act-btn.view-btn{background:transparent;color:var(--ink);border:1px solid var(--line2)}
.danger-btn:hover,.edit-btn:hover{transform:none;opacity:.9}
tr.done .del-btn{background:#1A6B32;border-color:#1A6B32;color:#fff}
tr.fp .fp-btn{background:#6B7280;border-color:#6B7280;color:#fff}
.bulk-bar{background:var(--warn-bg);border-color:var(--h-bd);border-radius:10px;color:var(--warn-t)}
.bulk-del-btn{background:var(--crit);color:var(--crit-ink);border-radius:8px}
.filter-inp{min-height:36px;border:1px solid var(--line2);border-radius:8px;background:var(--panel);color:var(--ink)}
.filter-inp:focus{border-color:var(--acc)}
.filter-count{color:var(--mute)}
.clean{background:var(--ok-bg);border:1px solid var(--acc);color:var(--ink);border-radius:12px}
.modal-bg{background:var(--modal-bg)}
.del-modal{background:var(--panel);border:1px solid var(--line2);border-radius:16px;color:var(--ink)}
.del-modal h2{color:var(--crit-t)}.del-modal .del-sub,.del-label{color:var(--mute)}.del-label strong{color:var(--ink)}
.del-fname{background:var(--bad-bg);border-color:var(--crit);color:var(--crit-t)}
.confirm-input{background:var(--bg);color:var(--ink);border-color:var(--line2)}
.confirm-input.ok{background:var(--ok-bg);border-color:var(--acc)}
.del-btn-confirm{background:var(--crit);color:var(--crit-ink)}
.del-btn-cancel{border-color:var(--line2);color:var(--mute)}.del-btn-cancel:hover{background:var(--hover)}
#prog-track{border-radius:99px;background:var(--line)}#prog-bar{background:var(--acc);border-radius:99px}
#prog-label{color:var(--mute)}
details.sv{background:var(--panel)!important;border:1px solid var(--line)!important;color:var(--ink);border-radius:12px;padding:.8rem 1.1rem;margin:1rem 0}
details.sv summary{list-style:none;cursor:pointer;font-weight:700;min-height:32px}details.sv summary::-webkit-details-marker{display:none}details.sv summary::before{content:'▸ ';color:var(--acc)}details[open].sv summary::before{content:'▾ '}
details.sv table{width:100%;border-collapse:separate;border-spacing:0 3px;margin-top:.6rem;font-size:.86rem;border:0}
details.sv td{border:0!important;padding:.55rem .7rem!important;background:transparent}
.sv-FAIL td{background:var(--bad-bg)!important}.sv-WARN td{background:var(--warn-bg)!important}
.sv-FAIL .lv{color:var(--crit-t)}.sv-WARN .lv{color:var(--warn)}
.sv .nf{color:var(--crit-t)}.sv .nw{color:var(--warn)}.sv .okc{margin-top:.6rem;font-size:.82rem;color:var(--acc)}
.sv .dd{color:var(--mute);word-break:break-all}
.rsn{display:flex;gap:.5rem;align-items:flex-start;padding:.1rem 0}
.rsn .dot{flex:none;width:.6rem;height:.6rem;border-radius:50%;margin-top:.5em;background:var(--line2)}
.dot-CRITICAL{background:var(--crit)!important}.dot-HIGH{background:#E0A85C!important}.dot-MEDIUM{background:var(--line2)!important}
.rsn-n{margin-top:.25rem;font-size:.72rem;color:var(--mute)}
.cp-footer{margin-top:3rem;padding:1.6rem 0 1rem;border-top:1px solid var(--line);display:flex;flex-wrap:wrap;gap:1.2rem;align-items:center;color:var(--mute);font-size:.82rem;line-height:1.7}
.cp-footer .mark{display:flex;align-items:center;gap:.9rem}
.cp-footer .logo{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#2DE2C0,#1F5FBF);display:flex;align-items:center;justify-content:center;font-weight:700;font-size:1.3rem;color:#0A0E13;flex:none}
.cp-footer .co{color:var(--ink);font-weight:700;font-size:.95rem}
.cp-footer .co-en{font-size:.68rem;letter-spacing:.14em}
.cp-footer .cr{margin-left:auto;text-align:right}
/* login + audit pages */
body.lg{display:grid;place-items:center;min-height:100vh;max-width:none;padding:1.5rem}
.lg main{width:min(92vw,400px)}
.lg .card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:1.4rem}
.lg label{display:block;font-size:.82rem;font-weight:600;margin-bottom:.4rem}
.lg input{width:100%;box-sizing:border-box;min-height:48px;padding:0 .9rem;border-radius:8px;border:1px solid var(--line2);background:var(--bg);color:var(--ink);font-size:1rem}
.lg .go{margin-top:1rem;width:100%;min-height:48px;border:0;border-radius:8px;background:var(--acc);color:var(--acc-ink);font-weight:700;font-size:1rem;cursor:pointer;box-shadow:var(--btn-glow)}
.lg .err{color:var(--crit-t);margin:0 0 1rem;font-size:.9rem}
.lg .note{margin-top:1rem;font-size:.78rem;line-height:1.7;color:var(--mute)}
.lg .cpr{margin-top:1.4rem;padding-top:1rem;border-top:1px solid var(--line);font-size:.76rem;line-height:1.7;color:var(--mute);text-align:center}
body.au{max-width:1100px;padding:2rem}
.au .tw{overflow-x:auto}.au table{border-collapse:collapse;width:100%;font-size:.86rem;background:var(--panel);border:1px solid var(--line)}
.au th{background:var(--panel2);text-align:left;color:var(--mute);padding:.5rem}.au td{padding:.45rem;border-top:1px solid var(--line);vertical-align:top;word-break:break-all}
.au tr.bad td{background:var(--bad-bg)}
@media(max-width:640px){body{padding:0 1rem 1.5rem}.topbar{margin:0 -1rem 1.4rem;padding:.8rem 1rem}h1{font-size:1.5rem}.cp-footer .cr{margin-left:0;text-align:left}}
@media print{.topbar{display:none!important}html,body{background:#fff!important;background-image:none!important;color:#000!important}.cp-footer{color:#444}}
CSSEOF;
}

function bd_js() {
    return '';
}

/**
 * Risk score 0-100 from per-FILE counts. Tiered with diminishing returns, so a pile of
 * low-severity notes can never look like a confirmed backdoor:
 *   any CRITICAL file  -> 60..100   (more criticals / highs push it up, with diminishing effect)
 *   else any HIGH file -> 30..59
 *   only MEDIUM files  ->  1..24
 *   nothing            ->  0
 */
function bd_risk($c, $h, $m) {
    if ($c > 0) {
        $s = 60 + 25 * (1 - pow(0.80, $c - 1)) + 10 * (1 - pow(0.90, $h)) + 5 * (1 - pow(0.95, $m));
        return (int) min(100, round($s));
    }
    if ($h > 0) {
        $s = 30 + 22 * (1 - pow(0.88, $h - 1)) + 7 * (1 - pow(0.95, $m));
        return (int) min(59, round($s));
    }
    if ($m > 0) return (int) max(1, round(24 * (1 - pow(0.95, $m))));
    return 0;
}
function bd_risk_label($r) {
    if ($r <= 0)  return 'ปลอดภัย';
    if ($r < 25)  return 'ต่ำ';
    if ($r < 60)  return 'ปานกลาง';
    if ($r < 85)  return 'สูง';
    return 'วิกฤต';
}

/**
 * Last-scan cache: results are kept server-side (protected dir) so the results page survives
 * Back / refresh / visiting the editor and returning: GET ?view=last re-renders them without rescanning.
 */
function scanCacheFile() { global $ROOT; return $ROOT . '/_backdoor_scan_backups/scan_last.json.php'; }
function scanCacheLoad() {
    $f = scanCacheFile();
    if (!is_file($f)) return null;
    $raw = (string) @file_get_contents($f);
    $d = json_decode(substr($raw, (int) strpos($raw, "\n") + 1), true);
    return (is_array($d) && isset($d['findings'])) ? $d : null;
}
function scanCacheSave($d) {
    global $ROOT;
    $dir = $ROOT . '/_backdoor_scan_backups';
    if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
    if (!is_file($dir . '/.htaccess')) { @file_put_contents($dir . '/.htaccess', "Require all denied\nOrder allow,deny\nDeny from all\n"); }
    if (!is_file($dir . '/index.html')) { @file_put_contents($dir . '/index.html', ''); }
    @file_put_contents(scanCacheFile(), '<?php http_response_code(404); exit; ?>' . "\n" . json_encode($d, JSON_UNESCAPED_UNICODE), LOCK_EX);
    @chmod(scanCacheFile(), 0600);
}
/** Files (scan-relevant extensions) added/changed/moved in after $since — catches stale cached results. */
function changedSince($ROOT, $since, $EXT, $SKIP_DIRS, $limit = 20, $budget = 8.0) {
    $out = []; $t0 = microtime(true);
    try {
        $it = new RecursiveIteratorIterator(new RecursiveCallbackFilterIterator(
            new RecursiveDirectoryIterator($ROOT, FilesystemIterator::SKIP_DOTS),
            function ($cur) use ($SKIP_DIRS) { return !($cur->isDir() && in_array($cur->getFilename(), $SKIP_DIRS, true)); }
        ), RecursiveIteratorIterator::LEAVES_ONLY);
        foreach ($it as $f) {
            if (microtime(true) - $t0 > $budget) break;   // never stall the page; a later scan will catch the rest
            if (!$f->isFile()) continue;
            $lc = strtolower($f->getFilename());
            if (!(in_array(strtolower($f->getExtension()), $EXT, true) || $lc === '.htaccess' || $lc === '.user.ini' || $lc === 'index.zip')) continue;
            // ctime also changes on mv / unzip, which keep the old mtime
            if (max($f->getMTime(), $f->getCTime()) >= $since) {
                $out[] = substr($f->getPathname(), strlen($ROOT));
                if (count($out) >= $limit) break;
            }
        }
    } catch (Throwable $e) { }
    return $out;
}
function scanCacheDrop($rel) {
    $d = scanCacheLoad();
    if (!$d) return;
    $d['findings'] = array_values(array_filter($d['findings'], function ($f) use ($rel) { return $f[2] !== $rel; }));
    scanCacheSave($d);
}

/**
 * Locate the lines that make each detection rule fire, so the viewer/editor can highlight them.
 * Rules are opaque callbacks over the whole file, so: (1) try single lines, (2) widen to small
 * line windows, (3) fall back to "whole file". Time-boxed so huge files cannot stall the page.
 */
function bd_marks($raw) {
    $out = ['lines' => [], 'whole' => []];
    if ($raw === '' || strlen($raw) > 1048576) return $out;
    $lines = explode("\n", $raw);
    $n = count($lines);
    $t0 = microtime(true);
    $rank = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2, 'LOW' => 3];
    $best = [];   // line (1-based) => [sev, label]
    $add = function ($ln, $sev, $label) use (&$best, $rank) {
        if (!isset($best[$ln]) || $rank[$sev] < $rank[$best[$ln][0]]) $best[$ln] = [$sev, $label];
    };
    foreach (bd_rules() as [$sev, $label, $cb]) {
        if (microtime(true) - $t0 > 3.0) break;
        $GLOBALS['RX_ERR'] = false;
        if (!$cb($raw)) continue;
        $found = false;
        $hits = 0; $extra = 0;
        for ($i = 0; $i < $n; $i++) {
            if (trim($lines[$i]) === '') continue;
            if ($cb($lines[$i])) {
                $found = true;
                if ($hits < 6) { $add($i + 1, $sev, $label); $hits++; } else { $extra++; }
            }
            if (microtime(true) - $t0 > 3.0) break;
        }
        if ($extra > 0) $out['whole'][] = [$sev, $label . ' (+' . $extra . ' บรรทัดที่เหมือนกัน ไม่ได้ไฮไลต์)'];
        if (!$found) {
            foreach ([2, 3, 4, 6, 10, 20] as $w) {
                for ($i = 0; $i + $w <= $n; $i++) {
                    if ($cb(implode("\n", array_slice($lines, $i, $w)))) {
                        for ($k = $i; $k < $i + $w; $k++) { if (trim($lines[$k]) !== '') $add($k + 1, $sev, $label); }
                        $found = true; break;
                    }
                    if (microtime(true) - $t0 > 3.0) break 2;
                }
                if ($found) break;
            }
        }
        if (!$found) $out['whole'][] = [$sev, $label];
    }
    ksort($best);
    foreach ($best as $ln => [$sv, $lb]) $out['lines'][] = ['l' => $ln, 's' => $sv, 'r' => $lb];
    return $out;
}

/**
 * Audit trail: every login, scan and file action is appended (JSON lines) to a log in the
 * protected backups dir, so use of this scanner can be reviewed after the fact.
 */
function auditLog($event, $detail = '') {
    global $ROOT;
    $dir = $ROOT . '/_backdoor_scan_backups';
    if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
    if (!is_file($dir . '/.htaccess')) { @file_put_contents($dir . '/.htaccess', "Require all denied\nOrder allow,deny\nDeny from all\n"); }
    if (!is_file($dir . '/index.html')) { @file_put_contents($dir . '/index.html', ''); }
    $f = $dir . '/audit.log.php';   // .php + exit header: unreadable over HTTP even without .htaccess (nginx)
    if (is_file($f) && filesize($f) > 1048576) { @rename($f, $f . '.1.php'); }
    if (!is_file($f)) { @file_put_contents($f, '<?php http_response_code(404); exit; ?>' . "\n"); }
    $row = json_encode([
        't'  => gmdate('c'),
        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'cli',
        'ua' => substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 120),
        'ev' => $event,
        'd'  => substr((string)$detail, 0, 300),
    ], JSON_UNESCAPED_UNICODE);
    @file_put_contents($f, $row . "\n", FILE_APPEND | LOCK_EX);
    @chmod($f, 0600);
}

// Only read files with these extensions (plus we always check .zip presence).
$EXT = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'pht', 'inc', 'htaccess'];

// Read at most this many bytes per file (webshells fit easily; keeps it fast).
$MAX_READ = 512 * 1024;

// Directories where a .php file is itself suspicious (uploads / assets / cache).
$UPLOAD_DIRS = ['/images/', '/media/', '/cache/', '/tmp/', '/files/', '/logs/', '/assets/'];

// Skip these directory names entirely (huge + low-risk vendor trees).
$SKIP_DIRS = ['.git', '.svn', 'node_modules', '_backdoor_scan_backups'];

// Known-bad MD5s (exact-match = confirmed).
$BAD_MD5 = [
    '08bd2f0ce6ed34305c95dbcbc02363f0' => 'eval(php://input) backdoor (api.php)',
    'd77869a7921ff2805219c46b9c773671' => 'md5-cookie auth eval-shell (known incident)',
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
    // Security headers on every response
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('Referrer-Policy: no-referrer');
    header('Cache-Control: no-store');
    header("Content-Security-Policy: frame-ancestors 'none'");
    $deny = function ($code, $msg) { http_response_code($code); header('Content-Type: text/plain; charset=utf-8'); echo $msg . "\n"; exit; };

    if ($PASSWORD === 'CHANGE_ME_to_a_long_random_string' || strlen($PASSWORD) < 12) {
        $deny(403, "403 Forbidden.\nSet a unique \$PASSWORD (12+ chars) in this file first.");
    }
    if ($EXPIRES !== '' && time() > strtotime($EXPIRES)) { $deny(410, '410 Expired.'); }
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
          || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    if ($REQUIRE_HTTPS && !$https) { $deny(403, '403 HTTPS required.'); }
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if ($ALLOW_IPS && !in_array($ip, $ALLOW_IPS, true)) { $deny(403, '403 Forbidden.'); }

    session_name('bdscan');
    session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => $https, 'httponly' => true, 'samesite' => 'Strict']);
    session_start();

    // Brute-force limiter: 5 failures / 15 min per IP
    $rlFile = sys_get_temp_dir() . '/bdscan_rl_' . md5($ip . __FILE__);
    $rl = is_file($rlFile) ? json_decode((string)@file_get_contents($rlFile), true) : [];
    $rl = is_array($rl) ? array_filter($rl, function ($t) { return $t > time() - 900; }) : [];

    if (isset($_GET['logout'])) { auditLog('logout'); $_SESSION = []; session_destroy(); header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?')); exit; }

    if (empty($_SESSION['auth'])) {
        $err = '';
        // Password from POST form, or from ?key= (one-shot: logs in, then redirects to a clean URL)
        $tryPw = null;
        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && isset($_POST['_login'])) { $tryPw = (string) $_POST['_login']; }
        elseif (isset($_GET['key'])) { $tryPw = (string) $_GET['key']; }
        if ($tryPw !== null) {
            if (count($rl) >= 5) { auditLog('login_blocked', 'rate limit'); $deny(429, '429 Too many attempts. Try again in 15 minutes.'); }
            if (hash_equals($PASSWORD, $tryPw)) {
                session_regenerate_id(true);
                auditLog('login_ok');
                $_SESSION['auth'] = true;
                $_SESSION['csk']  = bin2hex(random_bytes(32));
                @unlink($rlFile);
                header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?')); exit;   // strips ?key= from the address bar
            }
            $rl[] = time();
            auditLog('login_fail', 'attempt ' . count($rl));
            @file_put_contents($rlFile, json_encode(array_values($rl)), LOCK_EX);
            $err = 'รหัสผ่านไม่ถูกต้อง';
        }
        header('Content-Type: text/html; charset=utf-8');
        echo '<!doctype html><html lang="th" ><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Sign in · Backdoor Scan</title><style>' . bd_css() . '</style>' . bd_js() . '</head>'
           . '<body class="lg"><main>'
           . '<svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="var(--acc)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg>'
           . '<h1 style="margin:.8rem 0 .2rem;font-size:1.7rem;letter-spacing:.04em">BACKDOOR SCAN</h1><p class="meta" style="margin:0 0 1.4rem;font-size:.9rem">เข้าสู่ระบบเพื่อสแกนและจัดการไฟล์น่าสงสัย</p>'
           . '<form method="post" class="card">'
           . ($err ? '<p role="alert" class="err">' . $err . '</p>' : '')
           . '<label for="pw">รหัสผ่าน</label><input id="pw" type="password" name="_login" autofocus autocomplete="current-password">'
           . '<button class="go">เข้าสู่ระบบ</button></form>'
           . '<div class="note">● ล็อกอินได้ 5 ครั้งต่อ 15 นาทีต่อ IP<br>● ทุกการใช้งานบันทึกใน audit log</div>'
           . '<div class="cpr">© ' . date('Y') . ' บริษัท คัลเลอร์แพค ครีเอชั่น จำกัด สงวนลิขสิทธิ์<br><a href="https://colorpack.co.th/" target="_blank" rel="noopener">colorpack.co.th</a></div></main>';
        exit;
    }
    session_write_close();   // release session lock; csrf key stays readable

    // Audit log viewer (?audit=1)
    if (isset($_GET['audit'])) {
        $rows = [];
        $af = $ROOT . '/_backdoor_scan_backups/audit.log.php';
        if (is_file($af)) { $all = file($af, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES); array_shift($all); $rows = array_slice(array_reverse($all), 0, 300); }
        header('Content-Type: text/html; charset=utf-8');
        $e = function ($v) { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); };
        echo '<!doctype html><html lang="th" ><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Audit log · Backdoor Scan</title><style>' . bd_css() . '</style>' . bd_js() . '</head><body class="au">'
           . '<h1>ประวัติการใช้งาน (audit log)</h1><p class="meta"><a href="' . $e(strtok($_SERVER['REQUEST_URI'], '?')) . '">← กลับ</a> · ล่าสุด 300 รายการ · login_fail / login_blocked / denied จำนวนมาก หรือ IP แปลกปลอม = มีคนพยายามเข้า</p>'
           . '<div class="tw"><table><tr><th>เวลา (UTC)</th><th>IP</th><th>เหตุการณ์</th><th>รายละเอียด</th><th>User-Agent</th></tr>';
        foreach ($rows as $line) {
            $r = json_decode($line, true); if (!is_array($r)) continue;
            $bad = strpos($r['ev'], 'fail') !== false || strpos($r['ev'], 'block') !== false || strpos($r['ev'], 'denied') !== false;
            echo '<tr' . ($bad ? ' class="bad"' : '') . '><td style="white-space:nowrap">' . $e($r['t'])
               . '</td><td>' . $e($r['ip']) . '</td><td><b>' . $e($r['ev']) . '</b></td><td style="word-break:break-all">' . $e($r['d'])
               . '</td><td style="color:#8B98A8;font-size:.78rem">' . $e($r['ua']) . '</td></tr>';
        }
        echo '</table></div>' . ($rows ? '' : '<p>ยังไม่มีบันทึก</p>')
           . '<div class="cp-footer"><div class="cr" style="margin-left:0;text-align:left">© ' . date('Y') . ' บริษัท คัลเลอร์แพค ครีเอชั่น จำกัด สงวนลิขสิทธิ์ · <a href="https://colorpack.co.th/" target="_blank" rel="noopener">colorpack.co.th</a></div></div>';
        exit;
    }
    $given = '';
    $hKey  = '';
    $hRoot = htmlspecialchars($ROOT, ENT_QUOTES, 'UTF-8');
    $DESIGN_CSS = bd_css();
    $DESIGN_JS  = bd_js();
    $DESIGN_FOOTER = '<div class="cp-footer"><div class="mark"><div class="logo">C</div><div><div class="co">บริษัท คัลเลอร์แพค ครีเอชั่น จำกัด</div><div class="co-en">COLORPACK CREATION CO., LTD.</div></div></div>'
        . '<div class="cr"><div>© ' . date('Y') . ' บริษัท คัลเลอร์แพค ครีเอชั่น จำกัด สงวนลิขสิทธิ์</div>'
        . '<div><a href="https://colorpack.co.th/" target="_blank" rel="noopener">colorpack.co.th</a> · Backdoor Scan v' . htmlspecialchars($VERSION, ENT_QUOTES, 'UTF-8') . '</div></div></div>';
    $DESIGN_LOGO = '<svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#F4B183" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6l8-3z"/><path d="M9 12l2 2 4-4"/></svg>';

    // CSRF helpers — HMAC keyed on PASSWORD, valid for current or previous 5-min window
    function csrfToken($action, $path) {
        
        return hash_hmac('sha256', $action . '|' . $path . '|' . floor(time() / 300), $_SESSION['csk']);
    }
    /**
 * Safe backup: stores a neutralised copy (".quarantine" suffix, random dir name,
 * deny-all .htaccess + index.html) so a backed-up backdoor can never be executed
 * or read over HTTP. Returns false on failure so callers abort the destructive step.
 */
function backupFile($ROOT, $realFile, $rel) {
    $root = $ROOT . DIRECTORY_SEPARATOR . '_backdoor_scan_backups';
    if (!is_dir($root)) { if (!@mkdir($root, 0700, true)) return false; }
    if (!is_file($root . '/.htaccess')) {
        @file_put_contents($root . '/.htaccess', "Require all denied\nOrder allow,deny\nDeny from all\n");
    }
    if (!is_file($root . '/index.html')) { @file_put_contents($root . '/index.html', ''); }
    static $run = null;
    if ($run === null) { $run = gmdate('Ymd-His') . '-' . bin2hex(random_bytes(6)); }
    $rel  = str_replace(['..', "\0"], '', $rel);
    $dest = $root . DIRECTORY_SEPARATOR . $run . $rel . '.quarantine';
    if (!@mkdir(dirname($dest), 0700, true) && !is_dir(dirname($dest))) return false;
    if (!@copy($realFile, $dest)) return false;
    @chmod($dest, 0600);
    return true;
}

function guardRoot($ROOT) {
    $root = $ROOT . DIRECTORY_SEPARATOR . '_backdoor_scan_backups';
    if (!is_dir($root)) { @mkdir($root, 0700, true); }
    if (!is_file($root . '/.htaccess')) {
        @file_put_contents($root . '/.htaccess', "Require all denied\nOrder allow,deny\nDeny from all\n");
    }
    if (!is_file($root . '/index.html')) { @file_put_contents($root . '/index.html', ''); }
    return $root;
}
// Only paths reported by the last scan may be read / edited / deleted.
function allowedPath($ROOT, $rel) {
    $f = $ROOT . '/_backdoor_scan_backups/allow.json.php';
    $raw = is_file($f) ? (string)@file_get_contents($f) : '';
    $list = $raw !== '' ? json_decode(substr($raw, strpos($raw, "\n") + 1), true) : null;
    if (!is_array($list) || !isset($list[$rel])) return false;
    $real = realpath($ROOT . $rel);
    $base = strtolower(basename((string)$real));
    if (!$real || $real === realpath(__FILE__)) return false;                 // never the scanner itself
    if ($base === 'configuration.php' && dirname($real) === realpath($ROOT)) return false;
    if (strpos($real, realpath($ROOT) . '/_backdoor_scan_backups') === 0) return false;
    return true;
}

    function csrfValid($action, $path, $token) {
        if (hash_equals(csrfToken($action, $path), $token)) return true;
        
        return hash_equals(
            hash_hmac('sha256', $action . '|' . $path . '|' . (floor(time() / 300) - 1), $_SESSION['csk']),
            $token
        );
    }

    // WRITE ACTIONS — delete_file / get_file / save_file
    if ($ENABLE_WRITE && !empty($_POST['_action'])) {
        header('Content-Type: application/json; charset=utf-8');
        $act  = (string) ($_POST['_action']  ?? '');
        $frel = (string) ($_POST['_path']    ?? '');
        $tok  = (string) ($_POST['_token']   ?? '');
        if ($act === 'bulk_delete') {
            @set_time_limit(0);            // no timeout for large deletes
            @ini_set('memory_limit', '512M');
            $bPaths  = json_decode((string)($_POST['_paths']  ?? '[]'), true);
            $bTokens = json_decode((string)($_POST['_tokens'] ?? '[]'), true);
            if (!is_array($bPaths) || count($bPaths) === 0) {
                echo json_encode(['ok' => false, 'err' => 'No paths']); exit;
            }
            if (count($bPaths) > 10000) {  // per-request cap (client sends in batches)
                echo json_encode(['ok' => false, 'err' => 'Too many in one batch (max 10000)']); exit;
            }
            $bRealRoot = realpath($ROOT);
            $bSep      = DIRECTORY_SEPARATOR;
            $bDeleted  = 0; $bErrors = [];
            $bBackup   = $ROOT . $bSep . '_backdoor_scan_backups';
            foreach ($bPaths as $bi => $bRel) {
                $bRel = (string)$bRel;
                $bTok = isset($bTokens[$bi]) ? (string)$bTokens[$bi] : '';
                if (!csrfValid('delete_file', $bRel, $bTok)) {
                    $bErrors[] = $bRel . ' (token)'; continue;
                }
                if (!allowedPath($ROOT, $bRel)) { auditLog('denied', 'bulk_delete not in scan: ' . $bRel); $bErrors[] = $bRel . ' (not a scan result)'; continue; }
                $bReal = realpath($ROOT . $bRel);
                if (!$bReal || !$bRealRoot || strpos($bReal, $bRealRoot . $bSep) !== 0) {
                    $bErrors[] = $bRel . ' (path)'; continue;
                }
                if (!backupFile($ROOT, $bReal, $bRel)) {
                    $bErrors[] = $bRel . ' (backup failed — not deleted)'; continue;
                }
                if (@unlink($bReal)) { $bDeleted++; scanCacheDrop($bRel); auditLog('delete_file', $bRel . ' (bulk)'); }
                else { $bErrors[] = $bRel . ' (permission)'; }
            }
            echo json_encode(['ok' => true, 'deleted' => $bDeleted, 'errors' => $bErrors]); exit;
        }
        if (!csrfValid($act, $frel, $tok)) {
            auditLog('denied', 'csrf ' . $act . ' ' . $frel);
            echo json_encode(['ok' => false, 'err' => 'Token invalid / expired']); exit;
        }
        if ($act === 'clear_cache') {
            auditLog('clear_cache');
            $cPaths = ['/cache', '/tmp', '/administrator/cache'];
            $deleted = 0; $errors = 0; $found = []; $more = false; $cT0 = microtime(true);
            foreach ($cPaths as $cd) {
                $dir = $ROOT . $cd;
                $rd = realpath($dir);
                $rr = realpath($ROOT);
                // never follow a symlinked cache dir out of the site root
                if (is_link($dir) || !$rd || !$rr || strpos($rd, $rr . DIRECTORY_SEPARATOR) !== 0) continue;
                $found[] = $cd;
                try {
                    $it = new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS),
                        RecursiveIteratorIterator::CHILD_FIRST
                    );
                    foreach ($it as $f) {
                        if ($f->isFile() && !$f->isLink() && $f->getFilename() !== 'index.html') {
                            @unlink($f->getPathname()) ? $deleted++ : $errors++;
                        }
                        if ((($deleted + $errors) & 255) === 0 && microtime(true) - $cT0 > 20) { $more = true; break 2; }   // stay under proxy time-outs; client calls again
                    }
                } catch (Throwable $e) { $errors++; }
            }
            echo json_encode(['ok' => true, 'deleted' => $deleted, 'errors' => $errors, 'dirs' => $found, 'more' => $more]); exit;
        }
        if (!allowedPath($ROOT, $frel)) {
            auditLog('denied', $act . ' not in scan: ' . $frel);
            echo json_encode(['ok' => false, 'err' => 'Path not in last scan results']); exit;
        }
        $realRoot = realpath($ROOT);
        $realFile = realpath($ROOT . $frel);
        $sep = DIRECTORY_SEPARATOR;
        if (!$realFile || !$realRoot || strpos($realFile, $realRoot . $sep) !== 0) {
            echo json_encode(['ok' => false, 'err' => 'Path outside root']); exit;
        }
        if ($act === 'delete_file') {
            $confirm = (string) ($_POST['_confirm'] ?? '');
            if ($confirm !== basename($realFile)) {
                echo json_encode(['ok' => false, 'err' => 'ยืนยันชื่อไฟล์ไม่ถูกต้อง']); exit;
            }
            // Backup before delete
            if (!backupFile($ROOT, $realFile, $frel)) {
                echo json_encode(['ok' => false, 'err' => 'สำรองไฟล์ไม่สำเร็จ — ยกเลิกการลบ']); exit;
            }
            $okDel = @unlink($realFile);
            auditLog($okDel ? 'delete_file' : 'delete_failed', $frel);
            if ($okDel) scanCacheDrop($frel);
            echo json_encode($okDel
                ? ['ok' => true]
                : ['ok' => false, 'err' => 'ลบไม่ได้ — เช็ก permission']); exit;
        }
        if ($act === 'get_file') {
            auditLog('get_file', $frel);
            $raw = @file_get_contents($realFile);
            echo json_encode($raw === false
                ? ['ok' => false, 'err' => 'อ่านไฟล์ไม่ได้']
                : ['ok' => true, 'content' => $raw, 'size' => strlen($raw), 'marks' => bd_marks($raw)]); exit;
        }
        if ($act === 'save_file') {
            $content = (string) ($_POST['_content'] ?? '');
            if (strlen($content) > 2 * 1024 * 1024) {
                echo json_encode(['ok' => false, 'err' => 'ไฟล์ใหญ่เกิน 2MB']); exit;
            }
            if (!backupFile($ROOT, $realFile, $frel)) {
                echo json_encode(['ok' => false, 'err' => 'สำรองไฟล์ไม่สำเร็จ — ยกเลิกการบันทึก']); exit;
            }
            $r = file_put_contents($realFile, $content, LOCK_EX);
            auditLog($r !== false ? 'save_file' : 'save_failed', $frel . ' (' . strlen($content) . ' B)');
            echo json_encode($r !== false
                ? ['ok' => true, 'marks' => bd_marks($content)]
                : ['ok' => false, 'err' => 'บันทึกไม่ได้ — เช็ก permission']); exit;
        }
        echo json_encode(['ok' => false, 'err' => 'Unknown action']); exit;
    }

    // LANDING PAGE — shown when scan not yet requested
    $lastScan = scanCacheLoad();
    $lastScanId = $lastScan['time'] ?? 0;
    $viewLast = isset($_GET['view']) && $_GET['view'] === 'last' && $lastScan;
    $staleFiles = [];
    if ($viewLast) {
        $staleFiles = changedSince($ROOT, (int)($lastScan['time'] ?? 0), $EXT, $SKIP_DIRS);
        if ($staleFiles) { $viewLast = false; $_POST['scan'] = '1'; auditLog('rescan_auto', count($staleFiles) . ' new/changed files since last scan'); }
    }
    if (empty($_POST['scan']) && empty($_GET['scan']) && !$viewLast) {
        $hLast = $lastScan ? '<a class="btn" style="background:transparent;color:var(--acc);border:1px solid var(--acc);box-shadow:none;margin-left:.6rem;text-decoration:none;display:inline-flex;align-items:center" href="?view=last">ดูผลสแกนล่าสุด · ' . htmlspecialchars(date('d/m/Y H:i', (int)($lastScan['time'] ?? 0)), ENT_QUOTES, 'UTF-8') . '</a>' : '';
        // Pre-compute cache stats
        $cDirList = ['/cache', '/tmp', '/administrator/cache'];
        // Time-boxed (2.5 s): cache/tmp can hold 100k+ files; a slow count here caused 504 gateway time-outs.
        $cCount = 0; $cSize = 0; $cFound = []; $cCut = false; $cT0 = microtime(true);
        foreach ($cDirList as $cd) {
            $dir = $ROOT . $cd;
            if (!is_dir($dir)) continue;
            $cFound[] = $cd;
            try {
                foreach (new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
                ) as $f) {
                    if ($f->isFile() && $f->getFilename() !== 'index.html') {
                        $cCount++;
                        $cSize += $f->getSize();
                    }
                    if (($cCount & 255) === 0 && microtime(true) - $cT0 > 2.5) { $cCut = true; break 2; }
                }
            } catch (Throwable $e) {}
        }
        $hCacheInfo = $cCount > 0
            ? ($cCut ? 'มากกว่า ' : '') . number_format($cCount) . ' ไฟล์ (' . ($cSize >= 1048576
                ? round($cSize / 1048576, 1) . ' MB'
                : round($cSize / 1024, 1) . ' KB') . ')'
            : '(ไม่พบโฟลเดอร์ cache/tmp)';
        $hClearToken  = csrfToken('clear_cache', '__cache__');
        $hClearShow   = $cCount > 0 ? '' : 'style="display:none"';
        header('Content-Type: text/html; charset=utf-8');
        echo <<<HTML
<!doctype html><html lang="th"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Colorpack Advanced Backdoor Scan V2.0.1</title>
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
 .cache-box{background:#f0f4ff;border:1px solid #c5d5f5;border-radius:8px;padding:.7rem 1rem;margin:1.5rem 0;display:flex;align-items:center;gap:.8rem;flex-wrap:wrap;font-size:.9rem}
 .clr-btn{background:#2563eb;color:#fff;border:none;border-radius:6px;padding:.35rem .9rem;font-size:.85rem;font-weight:600;cursor:pointer;transition:background .15s}
 .clr-btn:hover{background:#1a4db8}
 .clr-btn:disabled{opacity:.5;cursor:not-allowed}
{$DESIGN_CSS}
 body{max-width:720px}
</style>{$DESIGN_JS}</head><body>
<div class="topbar"><div class="brand">{$DESIGN_LOGO}<div>BACKDOOR SCAN<small>COLORPACK SECURITY</small></div><span class="ver">v{$VERSION}</span></div>
 <div class="sp"><a href="?audit=1">ประวัติ</a><a class="out" href="?logout=1">ออกจากระบบ</a></div></div>
<div id="overlay">
 <div class="spinner"></div>
 <div class="spin-msg">กำลังสแกน กรุณารอ...<br><small style="color:#aaa">อาจใช้เวลา 10–60 วินาที</small></div>
</div>
<h1>สแกนหา backdoor</h1>
<div class="meta">Root: <code>{$hRoot}</code></div>
<div class="warn">
 <strong>หมายเหตุ:</strong> scanner นี้ดูเฉพาะไฟล์ — ยังต้องดู database (admin แปลกปลอม), access log, cron job ด้วย<br>
 <strong>ลบไฟล์ scanner นี้ออกจาก server ทันทีหลังใช้เสร็จ</strong>
</div>
<form method="post" action="" id="scanForm">
 <input type="hidden" name="scan" value="1">
 <button type="submit" class="btn" id="startBtn">เริ่มสแกน</button>{$hLast}
</form>
<div id="cache-section" class="cache-box" {$hClearShow}>
 <span><strong>Cache / Tmp:</strong> <span id="cache-info">{$hCacheInfo}</span></span>
 <button class="clr-btn" id="clr-btn" onclick="clearCache()">ล้าง Cache</button>
</div>
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
function clearCache(){
 var btn=document.getElementById('clr-btn');
 btn.disabled=true; btn.textContent='กำลังล้าง...';
 var fd=new FormData();
 fd.append('_action','clear_cache');
 fd.append('_path','__cache__');
 fd.append('_token','{$hClearToken}');
 var total=0;
 function step(){
  var f2=new FormData();
  f2.append('_action','clear_cache');f2.append('_path','__cache__');f2.append('_token','{$hClearToken}');
  fetch('',{method:'POST',body:f2})
   .then(function(r){return r.json();})
   .then(function(d){
    if(!d.ok){btn.disabled=false;btn.textContent='ล้าง Cache';alert('Error: '+d.err);return;}
    total+=d.deleted;
    document.getElementById('cache-info').textContent='ล้างแล้ว '+total.toLocaleString()+' ไฟล์'+(d.more?' ... กำลังล้างต่อ':'');
    if(d.more){btn.textContent='กำลังล้าง... '+total.toLocaleString();step();return;}
    btn.textContent='✓ ล้างสำเร็จ';
    var s=document.getElementById('cache-section');
    s.style.background='#e6f4ea'; s.style.borderColor='#9bcca9';
   })
   .catch(function(){btn.disabled=false;btn.textContent='ล้าง Cache';alert('Connection error');});
 }
 step();
}
</script>
{$DESIGN_FOOTER}
</body></html>
HTML;
        exit;
    }

    $isFetch    = !empty($_POST['_fetch']);
    $hProgStyle = $isFetch ? ' style="display:none"' : '';
    @set_time_limit(900);
    ignore_user_abort(true);   // finish + cache the scan even if the proxy cuts the connection (open ?view=last afterwards)

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
<title>Colorpack Advanced Backdoor Scan V2.0.1</title>
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
 /* ── Advanced: danger & edit buttons ── */
 .danger-btn{background:linear-gradient(135deg,#c0392b,#7b241c);color:#fff;border:none;border-radius:5px;padding:.22rem .6rem;font-size:.72rem;font-weight:700;cursor:pointer;white-space:nowrap;transition:transform .12s,box-shadow .12s;box-shadow:0 2px 4px rgba(192,57,43,.3)}
 .danger-btn:hover{transform:translateY(-1px);box-shadow:0 4px 10px rgba(192,57,43,.45)}
 .danger-btn:active{transform:translateY(0)}
 .edit-btn{background:linear-gradient(135deg,#2563eb,#1a4db8);color:#fff;border:none;border-radius:5px;padding:.22rem .6rem;font-size:.72rem;font-weight:700;cursor:pointer;white-space:nowrap;transition:transform .12s,box-shadow .12s;box-shadow:0 2px 4px rgba(37,99,235,.3)}
 .edit-btn:hover{transform:translateY(-1px);box-shadow:0 4px 10px rgba(37,99,235,.45)}
 .edit-btn:active{transform:translateY(0)}
 /* ── Modal backdrop ── */
 .modal-bg{display:none;position:fixed;inset:0;background:rgba(0,0,0,.65);z-index:1000;align-items:center;justify-content:center;backdrop-filter:blur(5px);-webkit-backdrop-filter:blur(5px)}
 .modal-bg.open{display:flex}
 /* ── Delete confirm modal ── */
 .del-modal{background:#fff;border-radius:16px;padding:2rem 1.8rem;max-width:460px;width:92%;box-shadow:0 24px 64px rgba(0,0,0,.35);animation:popIn .18s cubic-bezier(.34,1.56,.64,1)}
 @keyframes popIn{from{opacity:0;transform:scale(.9)}to{opacity:1;transform:scale(1)}}
 .del-modal-icon{font-size:2.2rem;text-align:center;margin-bottom:.5rem}
 .del-modal h2{color:#c0392b;margin:0 0 .3rem;font-size:1.15rem;text-align:center}
 .del-modal .del-sub{color:#777;font-size:.83rem;text-align:center;margin-bottom:1rem}
 .del-fname{font-family:Menlo,Consolas,monospace;font-size:.8rem;background:#fdecea;border:1px solid #f5b7b1;padding:.45rem .75rem;border-radius:8px;word-break:break-all;margin:.6rem 0 1rem;color:#7b241c}
 .del-label{font-size:.83rem;color:#555;margin-bottom:.35rem}
 .del-label strong{color:#1a1a1a}
 .confirm-input{width:100%;box-sizing:border-box;border:2px solid #ddd;border-radius:8px;padding:.5rem .75rem;font-size:.88rem;font-family:Menlo,Consolas,monospace;outline:none;transition:border-color .2s,background .2s}
 .confirm-input:focus{border-color:#aaa}
 .confirm-input.ok{border-color:#27ae60;background:#f0faf3}
 .confirm-input.bad{border-color:#c0392b;animation:shake .28s}
 @keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-6px)}60%{transform:translateX(6px)}}
 .del-countdown{font-size:.78rem;color:#e67e22;font-weight:600;min-height:1.1rem;margin:.45rem 0 0;text-align:center}
 .del-btn-confirm{display:block;width:100%;padding:.65rem;margin-top:.8rem;background:linear-gradient(135deg,#c0392b,#7b241c);color:#fff;border:none;border-radius:10px;font-size:.95rem;font-weight:700;cursor:pointer;transition:opacity .2s,transform .1s;letter-spacing:.02em}
 .del-btn-confirm:not(:disabled):hover{transform:translateY(-1px)}
 .del-btn-confirm:disabled{opacity:.38;cursor:not-allowed}
 .del-btn-cancel{display:block;width:100%;padding:.45rem;margin-top:.5rem;background:none;border:1px solid #ddd;border-radius:10px;cursor:pointer;color:#777;font-size:.88rem;transition:background .15s}
 .del-btn-cancel:hover{background:#f5f5f5}
 /* ── Editor modal ── */
 .editor-bg{display:none;position:fixed;inset:0;background:rgba(27,31,36,.6);z-index:1000;align-items:center;justify-content:center;padding:4vh 3vw;box-sizing:border-box;backdrop-filter:blur(3px);-webkit-backdrop-filter:blur(3px)}
 .editor-bg.open{display:flex}
 .editor-win{width:min(1100px,100%);height:100%;max-height:88vh;background:#1e1e1e;border-radius:14px;overflow:hidden;display:flex;flex-direction:column;box-shadow:0 24px 64px rgba(0,0,0,.45);animation:popIn .18s cubic-bezier(.34,1.56,.64,1)}
 .editor-header{background:#2d2d2d;color:#ccc;padding:.55rem 1rem;display:flex;align-items:center;gap:.75rem;font-size:.82rem;border-bottom:1px solid #3c3c3c;flex-shrink:0}
 .editor-title{color:#569cd6;font-weight:700;font-size:.85rem;white-space:nowrap}
 .editor-efile{font-family:Menlo,Consolas,monospace;color:#4ec9b0;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.78rem}
 .editor-badge{background:#264f78;color:#9cdcfe;border-radius:4px;padding:.1em .5em;font-size:.7rem;font-weight:600}
 .editor-hbtn{background:rgba(255,255,255,.1);color:#ccc;border:1px solid rgba(255,255,255,.15);border-radius:5px;padding:.25rem .65rem;cursor:pointer;font-size:.78rem;transition:background .15s}
 .editor-hbtn:hover{background:rgba(255,255,255,.2)}
 .editor-body{flex:1;display:flex;overflow:hidden;position:relative;background:#1e1e1e}
 .editor-hl{position:absolute;top:0;bottom:0;left:3.4rem;right:0;overflow:hidden;pointer-events:none;font-size:.8rem}
 .editor-hl>div{position:absolute;left:0;right:0;top:0}
 .hl-bar{position:absolute;left:0;right:0;height:1.55em;border-left:3px solid #FF4D4F;background:rgba(255,77,79,.22)}
 .hl-bar.HIGH{border-color:#FFB020;background:rgba(255,176,32,.20)}
 .hl-bar.MEDIUM{border-color:#9CDCFE;background:rgba(156,220,254,.14)}
 .editor-nums b.mk{color:#FF6B6D}.editor-nums b.mk.HIGH{color:#FFB020}.editor-nums b.mk.MEDIUM{color:#9CDCFE}
 .editor-marks{background:#2a1c1c;border-bottom:1px solid #3c2a2a;color:#ffd0d0;font-size:.78rem;padding:.4rem .9rem;display:none;gap:.5rem;flex-wrap:wrap;align-items:center;flex-shrink:0}
 .editor-marks.on{display:flex}
 .editor-marks button{background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.18);color:#ffe7e7;border-radius:6px;padding:.15rem .55rem;font-size:.74rem;cursor:pointer;font-family:inherit}
 .editor-marks button:hover{background:rgba(255,255,255,.18)}
 .editor-marks .sv-c{color:#FF8A8C}.editor-marks .sv-h{color:#FFC76B}.editor-marks .sv-m{color:#9CDCFE}
 .editor-nums{background:#1e1e1e;color:#4a4a4a;font-family:Menlo,Consolas,monospace;font-size:.8rem;line-height:1.55;padding:.75rem .5rem .75rem .75rem;text-align:right;user-select:none;overflow:hidden;min-width:2.8rem;border-right:1px solid #2d2d2d}
 .editor-ta{flex:1;background:transparent;position:relative;z-index:1;white-space:pre;overflow:auto;color:#d4d4d4;font-family:Menlo,Consolas,monospace;font-size:.8rem;line-height:1.55;border:none;resize:none;padding:.75rem .9rem;outline:none;tab-size:2;-moz-tab-size:2;overflow-y:auto}
 .editor-ta::selection{background:#264f78}
 .editor-footer{background:#007acc;color:#fff;padding:.4rem 1rem;display:flex;align-items:center;gap:.8rem;font-size:.78rem;flex-shrink:0;border-top:1px solid #005fa3}
 .editor-info{flex:1;opacity:.82}
 .editor-bak{background:rgba(255,255,255,.15);border-radius:3px;padding:.1em .5em;font-size:.72rem}
 .editor-save{background:#fff;color:#007acc;border:none;border-radius:5px;padding:.3rem 1rem;font-weight:700;cursor:pointer;font-size:.8rem;transition:background .15s,transform .1s}
 .editor-save:hover{background:#e8f0fe;transform:translateY(-1px)}
 .editor-save:disabled{opacity:.5;cursor:not-allowed;transform:none}
 /* ── Toast notification ── */
 .toast{position:fixed;bottom:1.6rem;right:1.6rem;padding:.7rem 1.2rem;border-radius:10px;font-size:.87rem;font-weight:600;color:#fff;z-index:2000;opacity:0;transform:translateY(10px);transition:opacity .22s,transform .22s;pointer-events:none;max-width:320px;box-shadow:0 8px 24px rgba(0,0,0,.25)}
 .toast.show{opacity:1;transform:translateY(0)}
 .toast.success{background:linear-gradient(135deg,#27ae60,#1e8449)}
 .toast.error{background:linear-gradient(135deg,#c0392b,#922b21)}
 .toast.info{background:linear-gradient(135deg,#2563eb,#1a4db8)}
 @media print{
  #prog-wrap,.warn,footer,.act-btn,.danger-btn,.edit-btn,.tabs,.modal-bg,.editor-bg,.toast{display:none!important}
  .tab-panel{display:block!important}
  body{padding:.5rem;max-width:100%}
  tr{page-break-inside:avoid;break-inside:avoid}
 }
 /* ── Bulk delete bar ── */
 .bulk-bar{display:none;align-items:center;gap:.7rem;padding:.5rem .9rem;background:#fff3da;border:1px solid #e3c97a;border-radius:8px;margin:.4rem 0 .5rem;font-size:.84rem;flex-wrap:wrap}
 .bulk-bar.has-sel{display:flex}
 .bulk-del-btn{background:linear-gradient(135deg,#c0392b,#7b241c);color:#fff;border:none;border-radius:6px;padding:.28rem .85rem;font-size:.8rem;font-weight:700;cursor:pointer;white-space:nowrap}
 .bulk-del-btn:disabled{opacity:.45;cursor:not-allowed}
 .cb-col{width:28px;text-align:center;padding:.35rem .3rem}
 input.row-cb,input.hd-cb{cursor:pointer;width:14px;height:14px}
 .filter-bar{display:flex;gap:.5rem;align-items:center;margin:.5rem 0 .4rem;flex-wrap:wrap}
 .filter-inp{flex:1;min-width:140px;border:1px solid #ccc;border-radius:6px;padding:.3rem .6rem;font-size:.83rem;outline:none}
 .filter-inp:focus{border-color:#2563eb}
 .sel-filter-btn{background:#2563eb;color:#fff;border:none;border-radius:6px;padding:.3rem .75rem;font-size:.8rem;font-weight:700;cursor:pointer;white-space:nowrap}
 .sel-filter-btn:hover{background:#1a4db8}
 .filter-count{font-size:.78rem;color:#888}
 tr.f-hide{display:none}
{$DESIGN_CSS}
</style>{$DESIGN_JS}
<script>
function updateProg(n,total){
 var lbl=document.getElementById('prog-label');
 lbl.className='';
 var pb=document.getElementById('prog-bar');
 if(total>0){
  var pct=Math.min(99,Math.round(n/total*100));
  lbl.textContent='กำลังสแกน... '+n.toLocaleString('th')+' / ~'+total.toLocaleString('th')+' ไฟล์ ('+pct+'%)';
  pb.style.animation='none';pb.style.left='0';pb.style.width=pct+'%';
 }else{
  lbl.textContent='กำลังสแกน... '+n.toLocaleString('th')+' ไฟล์';
 }
}
function doneProg(n,t){
 var pb=document.getElementById('prog-bar');pb.style.animation='none';pb.style.left='0';pb.style.width='100%';
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
 refreshTodo();saveMarks();
}
function saveMarks(){
 try{var m={};document.querySelectorAll('tbody tr[data-path]').forEach(function(r){
  var c=r.classList.contains('done')?'done':(r.classList.contains('fp')?'fp':'');
  if(c)m[r.getAttribute('data-path')]=c;});
  localStorage.setItem('bdscan_marks_'+(window.SCAN_ID||''),JSON.stringify(m));}catch(e){}
}
function restoreMarks(){
 try{var m=JSON.parse(localStorage.getItem('bdscan_marks_'+(window.SCAN_ID||''))||'{}');
  document.querySelectorAll('tbody tr[data-path]').forEach(function(r){
   var c=m[r.getAttribute('data-path')];if(c)r.classList.add(c);});
  refreshTodo();}catch(e){}
}
function refreshTodo(){
 var all=document.querySelectorAll('tbody tr').length;
 var done=document.querySelectorAll('tr.done').length;
 var fp=document.querySelectorAll('tr.fp').length;
 var el=document.getElementById('todo-sum');
 if(el) el.textContent='รอดำเนินการ '+(all-done-fp)+' · ลบแล้ว '+done+' · ไม่อันตราย '+fp+' / รวม '+all;
}
/* ── Advanced: toast ── */
function toast(msg,type){
 var t=document.getElementById('adv-toast');
 t.className='toast '+type;
 t.textContent=msg;
 void t.offsetWidth;
 t.classList.add('show');
 clearTimeout(t._tm);
 t._tm=setTimeout(function(){t.classList.remove('show');},3200);
}
/* ── Delete modal ── */
var _delD={};
function openDelete(path,token){
 _delD={path:path,token:token};
 document.getElementById('del-fname-box').textContent=path;
 var base=path.split('/').pop();
 document.getElementById('del-expected').textContent=base;
 var inp=document.getElementById('del-input');
 inp.value=''; inp.className='confirm-input';
 var btn=document.getElementById('del-confirm-btn');
 btn.disabled=true; btn.textContent='ยืนยันลบไฟล์';
 document.getElementById('del-modal-bg').classList.add('open');
 var secs=3,cd=document.getElementById('del-countdown');
 cd.textContent='⏳ กรุณารอ '+secs+' วินาที...';
 var tm=setInterval(function(){
  secs--;
  if(secs<=0){clearInterval(tm);cd.textContent='';checkDelInput();}
  else cd.textContent='⏳ กรุณารอ '+secs+' วินาที...';
 },1000);
 inp.focus();
}
function closeDelete(){document.getElementById('del-modal-bg').classList.remove('open');}
function checkDelInput(){
 var expected=document.getElementById('del-expected').textContent;
 var val=document.getElementById('del-input').value;
 var cd=document.getElementById('del-countdown');
 var btn=document.getElementById('del-confirm-btn');
 if(cd.textContent){btn.disabled=true;return;}
 var ok=val===expected;
 document.getElementById('del-input').className='confirm-input'+(val?(ok?' ok':' bad'):'');
 btn.disabled=!ok;
}
function confirmDelete(){
 var btn=document.getElementById('del-confirm-btn');
 btn.disabled=true; btn.textContent='กำลังลบ...';
 var fd=new FormData();
 fd.append('_action','delete_file');
 fd.append('_path',_delD.path);
 fd.append('_token',_delD.token);
 fd.append('_confirm',document.getElementById('del-input').value);
 fetch(location.href,{method:'POST',body:fd})
  .then(function(r){return r.json();})
  .then(function(d){
   if(d.ok){
    closeDelete();
    document.querySelectorAll('tr[data-path="'+_delD.path.replace(/"/g,'\\"')+'"]').forEach(function(r){
     r.style.transition='opacity .35s,transform .35s';
     r.style.opacity='0';r.style.transform='translateX(30px)';
     setTimeout(function(){r.remove();refreshTodo();},380);
    });
    toast('ลบไฟล์สำเร็จ ✓','success');
   }else{
    toast('ผิดพลาด: '+d.err,'error');
    btn.disabled=false;btn.textContent='ยืนยันลบไฟล์';
   }
  })
  .catch(function(){toast('Connection error','error');btn.disabled=false;btn.textContent='ยืนยันลบไฟล์';});
}
/* ── Editor modal ── */
var _editD={};
function openEditor(path,getToken,saveToken,ro){
 _editD={path:path,saveToken:saveToken,dirty:false,ro:!!ro};
 document.getElementById('editor-efile').textContent=path;
 var ta=document.getElementById('editor-ta');
 ta.value=''; _marks={lines:[],whole:[]}; applyMarks(null); updateEditorNums(1); updateEditorInfo(0,0);
 document.getElementById('editor-bg').classList.add('open');
 document.getElementById('editor-save-btn').disabled=false;
 document.getElementById('editor-save-btn').style.display=ro?'none':'';
 document.getElementById('editor-bak').style.display=ro?'none':'';
 ta.readOnly=!!ro;
 document.getElementById('editor-title').textContent=ro?'👁 ดู code (อ่านอย่างเดียว)':'✏ แก้ไข code';
 var fd=new FormData();
 fd.append('_action','get_file');fd.append('_path',path);fd.append('_token',getToken);
 fetch(location.href,{method:'POST',body:fd})
  .then(function(r){return r.json();})
  .then(function(d){
   if(d.ok){ta.value=d.content;_editD.dirty=false;_marks=d.marks||{lines:[],whole:[]};updateEditorNums(d.content.split('\\n').length);updateEditorInfo(d.content.split('\\n').length,d.content.length);applyMarks(d.marks);}
   else{ta.value='// Error: '+d.err;}
  })
  .catch(function(){ta.value='// Connection error';});
}
function closeEditor(force){
 if(!force&&_editD.dirty&&!confirm('มีการแก้ไขที่ยังไม่บันทึก — ปิดโดยไม่บันทึก?'))return;
 _editD.dirty=false;
 document.getElementById('editor-bg').classList.remove('open');
}
var _marks={lines:[],whole:[]};
function updateEditorNums(lines){
 var n=document.getElementById('editor-nums');
 var mk={};(_marks.lines||[]).forEach(function(m){mk[m.l]=m.s;});
 var h='';for(var i=1;i<=lines;i++)h+=mk[i]?'<b class="mk '+mk[i]+'">'+i+'</b><br>':i+'<br>';
 n.innerHTML=h||'1<br>';
}
function applyMarks(m){
 _marks=m||{lines:[],whole:[]};
 var hl=document.getElementById('editor-hl-in');hl.innerHTML='';
 (_marks.lines||[]).forEach(function(x){
  var d=document.createElement('div');d.className='hl-bar '+x.s;
  d.style.top='calc(.75rem + '+(x.l-1)+' * 1.55em)';hl.appendChild(d);
 });
 var bar=document.getElementById('editor-marks');bar.innerHTML='';
 var any=(_marks.lines||[]).length||(_marks.whole||[]).length;
 bar.classList.toggle('on',!!any);
 if(any){
  var t=document.createElement('span');t.textContent='⚠ ตำแหน่งน่าสงสัย:';bar.appendChild(t);
  var cls={CRITICAL:'sv-c',HIGH:'sv-h',MEDIUM:'sv-m'};
  (_marks.lines||[]).slice(0,40).forEach(function(x){
   var b=document.createElement('button');b.type='button';
   b.innerHTML='<span class="'+(cls[x.s]||'')+'">●</span> บรรทัด '+x.l;
   b.title=x.s+' — '+x.r;b.onclick=function(){jumpToLine(x.l);};bar.appendChild(b);
  });
  if((_marks.lines||[]).length>40){var more=document.createElement('span');more.textContent='… อีก '+((_marks.lines.length)-40)+' บรรทัด';bar.appendChild(more);}
  (_marks.whole||[]).forEach(function(w){var s=document.createElement('span');s.textContent='· ทั้งไฟล์: '+w[1];bar.appendChild(s);});
 }
 syncEditorScroll();
}
function jumpToLine(l){
 var ta=document.getElementById('editor-ta');
 var lh=parseFloat(getComputedStyle(ta).lineHeight)||20;
 ta.scrollTop=Math.max(0,(l-1)*lh-ta.clientHeight/3);
 syncEditorScroll();
 var pos=0,ls=ta.value.split('\\n');for(var i=0;i<l-1&&i<ls.length;i++)pos+=ls[i].length+1;
 ta.focus();try{ta.setSelectionRange(pos,pos+(ls[l-1]||'').length);}catch(e){}
}
function updateEditorInfo(lines,chars){
 document.getElementById('editor-info').textContent=lines+' บรรทัด · '+chars.toLocaleString()+' ตัวอักษร';
}
function onEditorInput(){
 _editD.dirty=true;
 var ta=document.getElementById('editor-ta');
 var lines=ta.value.split('\\n');
 updateEditorNums(lines.length);
 updateEditorInfo(lines.length,ta.value.length);
}
function syncEditorScroll(){
 var ta=document.getElementById('editor-ta');
 document.getElementById('editor-nums').scrollTop=ta.scrollTop;
 var hl=document.getElementById('editor-hl-in');if(hl)hl.style.transform='translate('+(-ta.scrollLeft)+'px,'+(-ta.scrollTop)+'px)';
}
function saveFile(){
 if(_editD.ro)return;
 var btn=document.getElementById('editor-save-btn');
 btn.disabled=true;btn.textContent='กำลังบันทึก...';
 var fd=new FormData();
 fd.append('_action','save_file');fd.append('_path',_editD.path);
 fd.append('_token',_editD.saveToken);fd.append('_content',document.getElementById('editor-ta').value);
 fetch(location.href,{method:'POST',body:fd})
  .then(function(r){return r.json();})
  .then(function(d){
   btn.disabled=false;btn.textContent='💾 บันทึก';
   if(d.ok){_editD.dirty=false;if(d.marks){applyMarks(d.marks);updateEditorNums(document.getElementById('editor-ta').value.split('\\n').length);}toast('บันทึกสำเร็จ — สำรองไฟล์ไว้แล้ว ✓','success');}
   else{toast('ผิดพลาด: '+d.err,'error');}
  })
  .catch(function(){btn.disabled=false;btn.textContent='💾 บันทึก';toast('Connection error','error');});
}
/* ── Rescan ── */
function doRescan(){
 var f=document.createElement('form');
 f.method='POST';f.action=location.href;
 var i=document.createElement('input');i.type='hidden';i.name='scan';i.value='1';
 f.appendChild(i);document.body.appendChild(f);f.submit();
}
/* ── Filter rows ── */
function clearFilter(tab){
 var inp=document.getElementById('filter-inp-'+tab);
 if(inp){inp.value='';filterRows(tab,'');}
}
function filterRows(tab,q){
 q=q.toLowerCase().trim();
 var rows=document.querySelectorAll('#tp-'+tab+' tbody tr');
 var shown=0;
 rows.forEach(function(tr){
  var path=(tr.dataset.path||'').toLowerCase();
  var reason=(tr.querySelector('td:nth-child(4)')||{}).textContent||'';
  var match=!q||path.indexOf(q)>=0||reason.toLowerCase().indexOf(q)>=0;
  tr.classList.toggle('f-hide',!match);
  if(match)shown++;
 });
 var el=document.getElementById('filter-count-'+tab);
 if(el)el.textContent=q?'แสดง '+shown+' รายการ':'';
}
function globalFilter(q){
 q=q.toLowerCase().trim();
 var counts={},total=0;
 document.querySelectorAll('.tab-panel').forEach(function(panel){
  var tab=panel.id.replace('tp-',''),n=0;
  panel.querySelectorAll('tbody tr').forEach(function(tr){
   var path=(tr.dataset.path||'').toLowerCase();
   var reason=((tr.querySelector('td:nth-child(4)')||{}).textContent||'').toLowerCase();
   var ok=!q||path.indexOf(q)>=0||reason.indexOf(q)>=0;
   tr.classList.toggle('f-hide',!ok);
   if(ok)n++;
  });
  counts[tab]=n;total+=n;
 });
 document.querySelectorAll('.tab').forEach(function(t){
  var m=(t.getAttribute('onclick')||'').match(/showTab\('([A-Z]+)'/);
  var b=t.querySelector('.bdg');
  if(m&&b){b.textContent=q?counts[m[1]]:b.getAttribute('data-n');}
 });
 var el=document.getElementById('g-filter-count');
 if(el)el.textContent=q?('พบ '+total+' รายการ'):'';
 if(q){ // jump to the first tab that has a match
  var act=document.querySelector('.tab.active'),am=act&&(act.getAttribute('onclick')||'').match(/showTab\('([A-Z]+)'/);
  if(!am||!counts[am[1]]){
   var jumped=false;
   document.querySelectorAll('.tab').forEach(function(t){
    var m=(t.getAttribute('onclick')||'').match(/showTab\('([A-Z]+)'/);
    if(!jumped&&m&&counts[m[1]]){jumped=true;t.click();}
   });
  }
 }
}
function selectAll(tab){
 var rows=document.querySelectorAll('#tp-'+tab+' tbody tr');
 if(!_bulkSel[tab])_bulkSel[tab]={};
 rows.forEach(function(tr){
  var cb=tr.querySelector('.row-cb');
  if(cb){cb.checked=true;_bulkSel[tab][cb.dataset.path]=cb.dataset.dtok;}
 });
 syncBulkBar(tab);
}
function selectFiltered(tab){
 var rows=document.querySelectorAll('#tp-'+tab+' tbody tr:not(.f-hide)');
 if(!_bulkSel[tab])_bulkSel[tab]={};
 var added=0;
 rows.forEach(function(tr){
  var cb=tr.querySelector('.row-cb');
  if(cb&&!cb.checked){cb.checked=true;_bulkSel[tab][cb.dataset.path]=cb.dataset.dtok;added++;}
 });
 syncBulkBar(tab);
 if(!added){var all=document.querySelectorAll('#tp-'+tab+' tbody tr:not(.f-hide) .row-cb');alert('เลือกแล้ว '+all.length+' รายการ (ครบแล้ว)');}
}
/* ── Bulk delete ── */
var _bulkSel={};
function onRowCheck(cb){
 var tab=cb.dataset.tab,path=cb.dataset.path;
 if(!_bulkSel[tab])_bulkSel[tab]={};
 if(cb.checked)_bulkSel[tab][path]=cb.dataset.dtok;
 else delete _bulkSel[tab][path];
 syncBulkBar(tab);
}
function toggleAllRows(hdCb,tab){
 document.querySelectorAll('.row-cb[data-tab="'+tab+'"]').forEach(function(cb){
  cb.checked=hdCb.checked;
  if(!_bulkSel[tab])_bulkSel[tab]={};
  if(cb.checked)_bulkSel[tab][cb.dataset.path]=cb.dataset.dtok;
  else delete _bulkSel[tab][cb.dataset.path];
 });
 syncBulkBar(tab);
}
function syncBulkBar(tab){
 var sel=_bulkSel[tab]?Object.keys(_bulkSel[tab]):[];
 var bar=document.getElementById('bulk-bar-'+tab);
 var btn=document.getElementById('bulk-del-btn-'+tab);
 if(!bar)return;
 if(sel.length){bar.classList.add('has-sel');btn.textContent='🗑 ลบที่เลือก ('+sel.length+' ไฟล์)';btn.disabled=false;}
 else{bar.classList.remove('has-sel');}
}
var BULK_BATCH=1000;   // files per request — avoids POST-size / timeout limits
function doBulkDelete(tab){
 var sel=_bulkSel[tab]?Object.keys(_bulkSel[tab]):[];
 if(!sel.length)return;
 if(!confirm('ยืนยันลบ '+sel.length+' ไฟล์? — backup ไว้ใน _backdoor_scan_backups'))return;
 var btn=document.getElementById('bulk-del-btn-'+tab);
 btn.disabled=true;
 // split into batches so any number of files can be deleted
 var batches=[];
 for(var i=0;i<sel.length;i+=BULK_BATCH)batches.push(sel.slice(i,i+BULK_BATCH));
 var totalDeleted=0,allFailed=[],done=0,total=sel.length;
 function removeRow(p){
  document.querySelectorAll('tr[data-path="'+p+'"]').forEach(function(tr){
   tr.style.transition='opacity .3s,transform .3s';
   tr.style.opacity='0';tr.style.transform='translateX(20px)';
   setTimeout(function(){tr.remove();refreshTodo();},320);
  });
 }
 function finish(){
  _bulkSel[tab]={};
  var hd=document.querySelector('.hd-cb[data-tab="'+tab+'"]');
  if(hd)hd.checked=false;
  syncBulkBar(tab);
  toast('ลบ '+totalDeleted+' ไฟล์สำเร็จ'+(allFailed.length?' ('+allFailed.length+' ผิดพลาด)':'')+' ✓',allFailed.length?'info':'success');
  setTimeout(function(){if(confirm('ลบสำเร็จ — สแกนใหม่เลยไหม?'))doRescan();},600);
 }
 function runBatch(idx){
  if(idx>=batches.length){finish();return;}
  var group=batches[idx];
  var tokens=group.map(function(p){return _bulkSel[tab][p]||'';});
  btn.textContent='กำลังลบ... '+done+'/'+total;
  var fd=new FormData();
  fd.append('_action','bulk_delete');
  fd.append('_path','__bulk__');
  fd.append('_token','__bulk__');
  fd.append('_paths',JSON.stringify(group));
  fd.append('_tokens',JSON.stringify(tokens));
  fetch(location.href,{method:'POST',body:fd})
   .then(function(r){return r.json();})
   .then(function(d){
    if(d.ok){
     var failed=d.errors||[];
     allFailed=allFailed.concat(failed);
     totalDeleted+=(d.deleted||0);
     group.forEach(function(p){
      if(failed.some(function(e){return e.indexOf(p)===0;}))return;
      removeRow(p);
     });
     done+=group.length;
     runBatch(idx+1);
    }else{
     toast('ผิดพลาด: '+d.err,'error');
     btn.disabled=false;btn.textContent='🗑 ลบที่เลือก ('+sel.length+' ไฟล์)';
    }
   })
   .catch(function(){toast('Connection error','error');btn.disabled=false;btn.textContent='🗑 ลบที่เลือก ('+sel.length+' ไฟล์)';});
 }
 runBatch(0);
}
document.addEventListener('keydown',function(e){
 if((e.ctrlKey||e.metaKey)&&e.key==='s'&&document.getElementById('editor-bg').classList.contains('open')){
  e.preventDefault();saveFile();
 }
 if(e.key==='Escape'){
  if(document.getElementById('del-modal-bg').classList.contains('open'))closeDelete();
  else if(document.getElementById('editor-bg').classList.contains('open'))closeEditor();
 }
});
</script>
</head><body>
<div class="topbar"><div class="brand">{$DESIGN_LOGO}<div>BACKDOOR SCAN<small>COLORPACK SECURITY</small></div><span class="ver">v{$VERSION}</span></div>
 <div class="root">{$hRoot}</div>
 <div class="sp"><button onclick="doRescan()">🔄 สแกนใหม่</button><button onclick="window.print()">ส่งออก PDF</button><a href="?audit=1">ประวัติ</a><a class="out" href="?logout=1">ออกจากระบบ</a></div></div>
<div id="prog-wrap"{$hProgStyle}>
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
/**
 * Server hardening audit — inspects the PHP runtime that is actually serving this request
 * (web SAPI = real production config; CLI results may differ from FPM/Apache).
 * Returns [[level FAIL|WARN|OK, title, detail, fix], ...]
 */
function serverAudit($ROOT) {
    $o = [];
    $add = function ($lvl, $t, $d, $fix = '') use (&$o) { $o[] = [$lvl, $t, $d, $fix]; };
    $ini = function ($k) { return trim((string) ini_get($k)); };
    $on  = function ($k) use ($ini) { return in_array(strtolower($ini($k)), ['1', 'on', 'true', 'yes'], true); };

    // PHP version / EOL
    if (PHP_VERSION_ID < 80200)      $add('FAIL', 'PHP version end-of-life', 'PHP ' . PHP_VERSION . ' no longer gets security fixes', 'Upgrade to PHP 8.3+');
    elseif (PHP_VERSION_ID < 80300)  $add('WARN', 'PHP version near end-of-life', 'PHP ' . PHP_VERSION . ' — security-only support ends Dec 2026', 'Plan upgrade to PHP 8.3+');
    else                             $add('OK', 'PHP version', PHP_VERSION);
    $add(PHP_SAPI === 'cli' ? 'WARN' : 'OK', 'SAPI', PHP_SAPI . (PHP_SAPI === 'cli' ? ' — CLI php.ini can differ from the web server; run this from the browser for real results' : ''));

    // Dangerous functions
    $danger = ['exec', 'system', 'shell_exec', 'passthru', 'popen', 'proc_open', 'pcntl_exec', 'dl', 'symlink', 'putenv'];
    $dis = array_map('trim', explode(',', $ini('disable_functions')));
    $open = array_values(array_filter($danger, function ($f) use ($dis) { return !in_array($f, $dis, true) && function_exists($f); }));
    if (count($open) >= 6) $add('FAIL', 'disable_functions is empty/weak', 'Shell-exec functions callable: ' . implode(', ', $open), 'disable_functions = exec,system,shell_exec,passthru,popen,proc_open,pcntl_exec,dl,symlink (only if the site does not need them)');
    elseif ($open)         $add('WARN', 'Some dangerous functions enabled', implode(', ', $open), 'Add them to disable_functions if unused');
    else                   $add('OK', 'disable_functions', 'dangerous functions disabled');

    if ($on('allow_url_include')) $add('FAIL', 'allow_url_include=On', 'Remote file inclusion possible', 'allow_url_include = Off');
    else                          $add('OK', 'allow_url_include', 'Off');
    if ($on('allow_url_fopen'))   $add('WARN', 'allow_url_fopen=On', 'Lets droppers fetch remote payloads with file_get_contents', 'allow_url_fopen = Off if the site does not need it');
    if ($on('display_errors'))    $add('FAIL', 'display_errors=On', 'Leaks paths/queries to visitors', 'display_errors = Off; log_errors = On');
    else                          $add('OK', 'display_errors', 'Off');
    if ($on('expose_php'))        $add('WARN', 'expose_php=On', 'X-Powered-By reveals the PHP version', 'expose_php = Off');
    if ($ini('open_basedir') === '') $add('WARN', 'open_basedir not set', 'A shell in one site can read other sites on the account', 'open_basedir = /path/to/site:/tmp');
    else                             $add('OK', 'open_basedir', $ini('open_basedir'));
    if ($on('enable_dl'))         $add('WARN', 'enable_dl=On', 'dl() can load extensions at runtime', 'enable_dl = Off');
    if ($ini('auto_prepend_file') !== '' || $ini('auto_append_file') !== '')
        $add('FAIL', 'auto_prepend/append_file is set', 'prepend=' . $ini('auto_prepend_file') . ' append=' . $ini('auto_append_file') . ' — classic persistence trick', 'Verify it is yours; check php.ini, .user.ini, .htaccess');
    if (!$on('session.cookie_httponly')) $add('WARN', 'session.cookie_httponly off', 'Session cookie readable by JavaScript (XSS → session theft)', 'session.cookie_httponly = 1');
    if (!$on('session.use_strict_mode')) $add('WARN', 'session.use_strict_mode off', 'Session fixation easier', 'session.use_strict_mode = 1');
    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    if ($https && !$on('session.cookie_secure')) $add('WARN', 'session.cookie_secure off', 'Cookie may be sent over HTTP', 'session.cookie_secure = 1');
    if ($on('cgi.fix_pathinfo') && stripos((string)($_SERVER['SERVER_SOFTWARE'] ?? ''), 'nginx') !== false)
        $add('WARN', 'cgi.fix_pathinfo=1 on nginx', 'Image-with-PHP uploads can execute (image.jpg/x.php)', 'cgi.fix_pathinfo = 0');

    // Filesystem
    foreach (['configuration.php', 'wp-config.php', '.env'] as $cf) {
        $f = $ROOT . '/' . $cf;
        if (is_file($f)) {
            $perm = @fileperms($f) & 0777;
            if ($perm & 0022) $add('FAIL', $cf . ' is group/world-writable', sprintf('mode %04o', $perm), 'chmod 0640 (or 0600)');
            elseif ($perm & 0004) $add('WARN', $cf . ' is world-readable', sprintf('mode %04o', $perm), 'chmod 0640');
            else $add('OK', $cf . ' permissions', sprintf('mode %04o', $perm));
        }
    }
    $ww = [];
    foreach (@scandir($ROOT) ?: [] as $e) {
        if ($e === '.' || $e === '..') continue;
        $p = $ROOT . '/' . $e;
        if (is_dir($p) && !is_link($p) && ((@fileperms($p) & 0777) === 0777)) $ww[] = $e;
    }
    if ($ww) $add('FAIL', 'World-writable (0777) top-level directories', implode(', ', array_slice($ww, 0, 8)), 'chmod 0755 on directories; 0644 on files');
    $exposed = [];
    foreach (['.env', '.git/config', '.svn/entries', 'phpinfo.php', 'info.php', 'test.php', 'adminer.php', 'configuration.php.bak', 'configuration.php~', 'wp-config.php.bak', 'backup.sql', 'dump.sql', 'database.sql', 'backup.zip', 'site.zip', 'public_html.zip'] as $x) {
        if (file_exists($ROOT . '/' . $x)) $exposed[] = $x;
    }
    foreach (@glob($ROOT . '/*.{sql,bak,old,orig,tar.gz,tgz}', GLOB_BRACE) ?: [] as $x) { $exposed[] = basename($x); }
    $exposed = array_values(array_unique($exposed));
    if ($exposed) $add('FAIL', 'Sensitive/backup files reachable in webroot', implode(', ', array_slice($exposed, 0, 10)), 'Move outside webroot or delete; block via server config');
    else          $add('OK', 'No obvious backup/secret files in webroot', '');
    return $o;
}

function serverAuditHtml($items) {
    $e = function ($v) { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); };
    $nf = $nw = $nok = 0; foreach ($items as $i) { if ($i[0] === 'FAIL') $nf++; elseif ($i[0] === 'WARN') $nw++; else $nok++; }
    $h = '<details class="sv"' . ($nf ? ' open' : '') . '><summary>ความปลอดภัยของ PHP / Server — <span class="nf">' . $nf . ' ต้องแก้</span> · <span class="nw">' . $nw . ' ควรปรับ</span></summary><table>';
    foreach ($items as [$l, $t, $d, $fix]) {
        if ($l === 'OK') continue;
        $h .= '<tr class="sv-' . $l . '"><td class="lv" style="width:64px;font-weight:700">' . $l . '</td><td><b>' . $e($t) . '</b>'
            . ($d !== '' ? '<br><span class="dd">' . $e($d) . '</span>' : '')
            . ($fix !== '' ? '<br><code style="font-size:.8rem">' . $e($fix) . '</code>' : '') . '</td></tr>';
    }
    return $h . '</table><div class="okc">✓ ผ่าน ' . $nok . ' รายการ</div></details>';
}

function rx($content, $pattern) {
    $r = preg_match($pattern, $content);
    if ($r === false) { $GLOBALS['RX_ERR'] = true; }   // backtrack/JIT limit: not a clean "no match"
    return (bool) $r;
}

function fileEntropy($s) {
    $len = strlen($s);
    if ($len < 200) return 0.0;
    $freq = count_chars($s, 1);
    $e = 0.0;
    foreach ($freq as $c) { $p = $c / $len; $e -= $p * log($p, 2); }
    return round($e, 2);
}

function bd_rules() {
    return [
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

    // --- v1.1 additions (config-file persistence, callback shells, nested decoders) ---
    ['CRITICAL', '.htaccess/.user.ini auto_prepend/append_file (persistence)',
        function($c) { return rx($c, '~(php_value\s+)?auto_(prepend|append)_file\s*[= ]\s*\S+~i'); }],

    ['CRITICAL', 'AddHandler/AddType maps non-PHP extension to PHP (hidden shell in images/txt)',
        function($c) { return rx($c, '~(AddHandler|AddType|SetHandler)\s+\S*(php|httpd-php)\S*\s+\.?(jpe?g|png|gif|ico|txt|css|js|svg|webp)~i'); }],

    ['CRITICAL', 'nested decoders inside eval/assert (multi-layer dropper)',
        function($c) { return rx($c, '~(eval|assert)\s*\((?:\s*\w+\s*\()*?\s*(gzinflate|gzuncompress|base64_decode|str_rot13|htmlspecialchars_decode|urldecode|rawurldecode|hex2bin)\s*\(~is'); }],

    ['HIGH', 'eval of variable function result  eval($x(...))',
        function($c) { return rx($c, '~\beval\s*\(\s*\$\w+\s*\(~'); }],

    ['HIGH', 'callback function fed with request data (array_map/usort/call_user_func...)',
        function($c) { return rx($c, '~\b(array_map|array_filter|array_walk|usort|uasort|uksort|call_user_func(_array)?|register_shutdown_function|iterator_apply)\s*\([^;]{0,100}\$_(GET|POST|REQUEST|COOKIE)~is'); }],

    ['HIGH', 'include/require of request-controlled path',
        function($c) { return rx($c, '~\b(include|require)(_once)?\s*\(?\s*[^;]{0,60}\$_(GET|POST|REQUEST|COOKIE)\b~i'); }],

    ['HIGH', 'variable-variable call fed with request data  $$x($_REQUEST...)',
        function($c) { return rx($c, '~\$\{?\$\w+\}?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)~'); }],

    ['MEDIUM', 'hex2bin/pack("H*") decoding (string obfuscation)',
        function($c) { return rx($c, '~\bhex2bin\s*\(\s*[\'"][0-9a-f]{16,}|pack\s*\(\s*[\'"]H\*[\'"]~i'); }],

    // --- v1.3: dual-use web file managers / admin tools (not malicious code, but a full takeover tool) ---
    ['CRITICAL', 'Tiny File Manager DEFAULT password hash (admin@123 / user@123) — anyone can log in',
        function($c) { return rx($c, '~\$2y\$10\$/K\.hjNr84lLNDt8fTXjoI\.DBp6Pp|\$2y\$10\$Fg6Dz8oH9fPoZ2jJan5tZuv6Z4Kp~'); }],

    ['CRITICAL', 'file manager with default/weak credentials hard-coded (fm_admin, admin:admin ...)',
        function($c) { return rx($c, '~[\'"]fm_admin[\'"]\s*=>\s*[\'"]fm_admin[\'"]~i')
               || rx($c, '~\$(auth_users|users|accounts)\s*=\s*array\s*\(\s*[\'"](admin|root|user|test)[\'"]\s*=>\s*[\'"](admin|root|password|123456|1234|pass|test)[\'"]~i'); }],

    ['CRITICAL', 'web file manager tool (read/write/delete/upload/chmod over the whole site — commonly dropped by attackers)',
        function($c) {
            if (rx($c, '~alexantr/filemanager|PHP File Manager|\bFM_EMBED\b|Tiny\s*File\s*Manager|Web\s*File\s*Manager|\bFileManager\s+by\b|\bfilesman\b|\bPHPFileManager\b~i')) return true;
            // generic heuristic: capability groups typical of a full-site admin tool
            $groups = [
                'list'   => '~\b(scandir|glob|opendir|readdir|RecursiveDirectoryIterator|FilesystemIterator)\b~',
                'read'   => '~\b(readfile|fpassthru|file_get_contents|highlight_file|show_source)\b|Content-Disposition~i',
                'write'  => '~\b(file_put_contents|fwrite|fputs)\b~',
                'delete' => '~\b(unlink|rmdir)\b~',
                'move'   => '~\b(rename|copy)\s*\(~',
                'perm'   => '~\b(chmod|touch|chown)\s*\(~',
                'upload' => '~\bmove_uploaded_file\b|\$_FILES~',
                'archive'=> '~\b(ZipArchive|PharData|gzopen|gzcompress)\b|\.(tar|zip)\b~i',
                'remote' => '~\b(curl_exec|curl_init)\b|file_get_contents\s*\(\s*\$\w+~',
            ];
            $g = 0; foreach ($groups as $re) { if (preg_match($re, $c)) $g++; }
            $login = rx($c, '~(\$auth_users|password_verify|password_hash|hash_equals|\$_SESSION\s*\[[^\]]*(auth|login|user)|md5\s*\(\s*\$_(POST|GET|REQUEST))~i')
                  || rx($c, '~[\'"](login|password|passwd|pass)[\'"]\s*(=>|\])~i');
            $ui    = rx($c, '~<form\b[^>]*>|<table\b|<!doctype html~i');
            return $g >= 7 && preg_match($groups['upload'], $c) && preg_match($groups['write'], $c)
                && preg_match($groups['delete'], $c) && ($login || $ui);
        }],

    // --- v1.2: PHP→shell, reverse shells, disable_functions bypass, droppers, spam/skimmers ---
    ['CRITICAL', 'request value stored in a variable then passed to a shell function',
        function($c) { return rx($c, '~\$(\w+)\s*=\s*\$_(GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*;.{0,300}?\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*\$\1\b~is'); }],

    ['CRITICAL', 'backtick shell execution with request data',
        function($c) {
            // only a backtick expression in statement position (echo/=/return/( ...), never SQL identifiers inside strings
            if (!preg_match_all('~(?:\b(?:echo|print|return)\s+|[=(,.;{]\s*)`([^`\n]{0,200}\$_(?:GET|POST|REQUEST|COOKIE)[^`\n]{0,200})`~', $c, $m)) return false;
            foreach ($m[1] as $cmd) {
                if (!preg_match('~\b(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|FROM|TABLE|DATABASE|INTO|WHERE|VALUES|SET|JOIN|ORDER|GROUP|LIMIT|UNIQUE|PRIMARY|ENGINE|CHARSET)\b~i', $cmd)) return true;
            }
            return false;
        }],

    ['CRITICAL', 'reverse shell (socket + process execution / known one-liners)',
        function($c) { return rx($c, '~\b(fsockopen|stream_socket_client|socket_connect|pfsockopen)\s*\(.{0,400}\b(exec|shell_exec|system|proc_open|popen|passthru)\s*\(~is')
               || rx($c, '~bash\s+-i\s*>&?\s*/dev/tcp/~i')
               || rx($c, '~/bin/(ba)?sh\s+-i\b|\bnc(at)?\s+(-e|-c)\s|python\d*\s+-c\s*[\'"]import\s+socket|perl\s+-e\s*[\'"]use\s+Socket~i'); }],

    ['CRITICAL', 'putenv LD_PRELOAD / mail() disable_functions bypass',
        function($c) { return rx($c, '~putenv\s*\(\s*[\'"](LD_PRELOAD|LD_LIBRARY_PATH|PHP_INI_SCAN_DIR)~i')
               || rx($c, '~imap_open\s*\(.{0,200}-oProxyCommand~is'); }],

    ['CRITICAL', 'move_uploaded_file to a request-controlled path (arbitrary upload shell)',
        function($c) { return rx($c, '~move_uploaded_file\s*\([^;]{0,200}\$_(GET|POST|REQUEST|COOKIE)~is'); }],

    ['HIGH', 'attempt to change disable_functions / load extensions at runtime',
        function($c) { return rx($c, '~ini_(set|restore)\s*\(\s*[\'"](disable_functions|open_basedir|safe_mode)~i')
               || rx($c, '~\bdl\s*\(\s*[\'"][^\'"]+\.so~i') || rx($c, '~\bFFI::cdef\s*\(|new\s+FFI\s*\(~'); }],

    ['HIGH', 'writes request data to a request-chosen file (dropper)',
        function($c) { return rx($c, '~(file_put_contents|fwrite|fputs)\s*\([^;]{0,100}\$_(GET|POST|REQUEST|COOKIE)[^;]{0,200}\$_(GET|POST|REQUEST|COOKIE)~is'); }],

    ['HIGH', 'remote payload download and write/execute (dropper)',
        function($c) { return rx($c, '~(file_put_contents|fwrite|copy)\s*\([^;]{0,120}(file_get_contents|curl_exec)\s*\(\s*[\'"]?https?://~is')
               || rx($c, '~\b(wget|curl)\s+[^;\'"\n]{0,120}https?://[^;\'"\n]{0,200}(\|\s*(ba)?sh|-O\s+\S+\.(php|sh)|&&\s*chmod)~i'); }],

    ['HIGH', 'symlink to system path (cross-account read attack)',
        function($c) { return rx($c, '~\bsymlink\s*\(\s*[\'"]/(etc|home|var|usr)/~i'); }],

    ['HIGH', 'search-engine cloaking (serves different content to Googlebot) / SEO spam',
        function($c) { return rx($c, '~HTTP_USER_AGENT.{0,160}(googlebot|bingbot|yandex|baiduspider|slurp)~is')
               && rx($c, '~(file_get_contents|curl_exec|include|require|header\s*\(\s*[\'"]Location)~i'); }],

    ['HIGH', 'conditional redirect for visitors from search engines (.htaccess / PHP)',
        function($c) { return rx($c, '~RewriteCond\s+%\{HTTP_(REFERER|USER_AGENT)\}[^\n]{0,120}(google|bing|yahoo|baidu|yandex|bot)[^\n]*\n\s*RewriteRule[^\n]*https?://~i')
               || rx($c, '~HTTP_REFERER.{0,120}(google|bing|yahoo).{0,200}header\s*\(\s*[\'"]Location~is'); }],

    ['HIGH', 'JavaScript obfuscation injected in page (eval/atob/unescape/fromCharCode)',
        function($c) { return rx($c, '~document\.write\s*\(\s*unescape\s*\(~i')
               || rx($c, '~\beval\s*\(\s*(atob|unescape|String\.fromCharCode)\s*\(~i'); }],

    ['HIGH', 'cryptominer script',
        function($c) { return rx($c, '~\b(coinhive|cryptonight|coinimp|minero\.cc|webminepool|authedmine|crypto-loot)\b~i'); }],

    ['HIGH', 'credential/card harvesting: mails or stores POSTed password/card fields',
        function($c) { return rx($c, '~(mail|file_put_contents|fwrite)\s*\([^;]{0,200}\$_POST\s*\[[^\]]*(pass|pwd|card|cvv|ccnum)~is'); }],

    ['MEDIUM', 'hidden links block (SEO spam injection)',
        function($c) { return rx($c, '~<(div|span|ul)[^>]+style\s*=\s*[\'"][^\'"]*(display\s*:\s*none|left\s*:\s*-\d{3,}|text-indent\s*:\s*-\d{3,})[^\'"]*[\'"][^>]*>\s*(<a\s|<ul|<li)~i'); }],

    ['MEDIUM', 'external script from suspicious TLD',
        function($c) { return rx($c, '~<script[^>]+src\s*=\s*[\'"](https?:)?//[^\'"/]+\.(ru|xyz|top|tk|click|pw|gq|cf|ml)/[^\'"]*\.js~i'); }],

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

    ['CRITICAL', 'Tiny File Manager payload string',
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
}
$RULES = bd_rules();

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
$findings = []; $scanned = 0; $started = microtime(true);
$sevRank  = ['CRITICAL' => 0, 'HIGH' => 1, 'MEDIUM' => 2, 'LOW' => 3];
if (!empty($viewLast)) {
    $findings = $lastScan['findings']; $scanned = (int)($lastScan['scanned'] ?? 0);
} else {
if (!$IS_CLI) {
    // No silent pre-count pass (it doubled the walk and sent nothing for minutes -> 504 behind nginx).
    // Progress uses the previous scan's file count as an estimate; 0 = indeterminate bar.
    $totalFiles = (int)($lastScan['scanned'] ?? 0);
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

$lastPing = microtime(true);
foreach ($it as $file) {
    if (!$file->isFile()) continue;
    // keep-alive: send a byte every few seconds so proxies (nginx fastcgi_read_timeout) never see a silent connection
    if (!$IS_CLI && microtime(true) - $lastPing > 3) { echo '<script>updateProg(' . $scanned . ',' . $totalFiles . ');</script>'; flush(); $lastPing = microtime(true); }
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

    // Rule: .htaccess outside webroot — Joomla only needs one in root.
    if ($lc === '.htaccess' && $relU !== '/.htaccess') {
        $findings[] = ['HIGH', '.htaccess in subdirectory (Joomla: root only)', $relU,
            'Joomla normally has .htaccess only in root — subdirectory .htaccess can redirect, block security, or serve malicious content'];
    }

    // Rule: double PHP extension (.php.jpg, .php.gif) — Apache/nginx misconfiguration exploit.
    if (preg_match('~\.php\d?\.(jpg|jpeg|gif|png|ico|bmp|svg|txt|html|htm)$~i', $lc)) {
        $findings[] = ['HIGH', 'double extension (PHP evasion technique)', $relU,
            'hides PHP behind .' . strtoupper($ext) . ' — exploits server extension-handling misconfiguration'];
    }

    // Rule: another copy of this scanner left on the server (leaked tool / forgotten upload).
    if (preg_match('~(scan-backdoor|advance-scan)[^/]*\.php$~i', $lc) && realpath($path) !== realpath(__FILE__)) {
        $findings[] = ['HIGH', 'Scanner copy left on server — delete it (the tool is public; its password may be known)', $relU, ''];
    }

    // Rule: well-known webshell / file-manager file names.
    if (preg_match('~^(file-?manager|filemanager\d*|filesman|fm|shell|wso\d*|c99\d*|r57|b374k|alfa|uploader?|up|cmd|mini|xl|tinyfilemanager|wp-?filemanager|wp-?file-?manager)\.(php\d?|phtml|pht)$~i', $lc)
        // skip genuine CMS-extension parts (guarded by _JEXEC / ABSPATH and living in MVC folders)
        && !(preg_match('~/(controllers?|models?|views?|helpers?|tables|classes|src|libraries|vendor|admin|site)/~i', $relU)
             && preg_match('~_JEXEC|\bABSPATH\b|defined\s*\(\s*[\'"]WPINC~', $content))) {
        $findings[] = ['HIGH', 'file name typical of a web shell / file manager', $relU, 'verify this is a file you installed'];
    }
    if (preg_match('~^(adminer(-[\d.]+)?|phpmyadmin|pma|dbadmin)\.php$~i', $lc)) {
        $findings[] = ['MEDIUM', 'database admin tool in webroot (remove after use / restrict by IP)', $relU, ''];
    }

    // Rule: hash/hex-named PHP file (random dropper names, e.g. eb290968a00d.php, 35defc640dindex.php).
    if (in_array($ext, ['php','phtml','pht','php5','php7'], true)
        && preg_match('~^[a-f0-9]{8,32}(index)?\.[a-z0-9]+$~', $lc)
        && !preg_match('~-cache-~', $lc)) {
        $findings[] = ['MEDIUM', 'random hex-named PHP file (typical dropper name)', $relU, ''];
    }

    // Rule: WordPress-style paths — PHP in uploads, unexpected mu-plugins, wp-* look-alikes on non-WP sites.
    if (preg_match('~^/wp-content/uploads/.*\.(php\d?|phtml|pht)$~i', $relU)) {
        $findings[] = ['CRITICAL', 'PHP file inside WordPress uploads (should never execute here)', $relU, ''];
    }
    if (preg_match('~^/wp-content/mu-plugins/[^/]+\.php$~i', $relU)) {
        $findings[] = ['MEDIUM', 'WordPress mu-plugin (auto-loaded, common persistence spot) — verify it is yours', $relU, ''];
    }
    if (!is_file($ROOT . '/wp-config.php') && preg_match('~^/(wp-[a-z0-9_-]+\.php|wp-content/|wp-includes/)~i', $relU)) {
        $findings[] = ['HIGH', 'WordPress-looking file on a non-WordPress site (look-alike shell)', $relU, ''];
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

    $isCode = in_array($ext, $EXT, true) || $lc === '.htaccess' || $lc === '.user.ini';
    if (!$isCode) continue;

    $scanned++;

    // Web: push progress update every 100 files
    if (!$IS_CLI && $scanned % 100 === 0) {
        echo '<script>updateProg(' . $scanned . ',' . $totalFiles . ');</script>';
        flush();
    }

    $content = @file_get_contents($path, false, null, 0, $MAX_READ);
    if ($content === false) continue;

    $GLOBALS['RX_ERR'] = false;
    $fsize = @filesize($path);

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

    // Payload appended after >512KB of padding: also scan the last 64KB.
    if ($fsize !== false && $fsize > $MAX_READ) {
        $tail = @file_get_contents($path, false, null, max($MAX_READ, $fsize - 65536), 65536);
        if ($tail !== false) { $content .= "\n" . $tail; }
        $findings[] = ['MEDIUM', 'Oversized code file (>512KB) — head+tail scanned only', $relU, round($fsize / 1024) . ' KB'];
    }

    // Pattern rules.
    foreach ($RULES as [$sev, $label, $cb]) {
        if ($cb($content)) {
            $findings[] = [$sev, $label, $relU, ''];
        }
    }
    if (!empty($GLOBALS['RX_ERR'])) {
        $findings[] = ['MEDIUM', 'Scan incomplete (regex limit hit) — review manually', $relU, preg_last_error_msg()];
    }
}

}   // end fresh-scan block

usort($findings, function ($a, $b) use ($sevRank) {
    $r = $sevRank[$a[0]] <=> $sevRank[$b[0]];
    return $r !== 0 ? $r : strcmp($a[2], $b[2]);
});

$elapsed = !empty($viewLast) ? (float)($lastScan['elapsed'] ?? 0) : round(microtime(true) - $started, 2);
$counts  = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
foreach ($findings as $f) $counts[$f[0]]++;
if (!$IS_CLI && empty($viewLast)) {
    $lastScanId = time();
    scanCacheSave(['time' => $lastScanId, 'scanned' => $scanned, 'elapsed' => $elapsed, 'findings' => $findings]);
}
if (!$IS_CLI && $ENABLE_WRITE && empty($viewLast)) {
    $allow = [];
    foreach ($findings as $f) $allow[$f[2]] = 1;
    $gr = guardRoot($ROOT);
    @file_put_contents($gr . '/allow.json.php', '<?php http_response_code(404); exit; ?>' . "\n" . json_encode($allow), LOCK_EX);
    @chmod($gr . '/allow.json.php', 0600);
}

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
    echo "\n== PHP / server hardening (" . PHP_SAPI . ") ==\n";
    foreach (serverAudit($ROOT) as [$l, $t, $d, $fix]) {
        if ($l === 'OK') continue;
        printf("[%-4s] %s%s%s\n", $l, $t, $d !== '' ? " — $d" : '', $fix !== '' ? "\n       fix: $fix" : '');
    }
    exit($counts['CRITICAL'] > 0 ? 1 : 0);
}

// Web: signal scan complete, then render results
auditLog(!empty($viewLast) ? 'view_last' : 'scan', $scanned . ' files, ' . count($findings) . ' findings, CRIT ' . $counts['CRITICAL'] . ' HIGH ' . $counts['HIGH']);
echo '<script>doneProg(' . $scanned . ',' . $elapsed . ');</script>' . "\n";
if ($staleFiles) { echo '<div class="warn" style="margin-top:1rem"><strong>สแกนใหม่อัตโนมัติ:</strong> พบไฟล์ใหม่/ที่เปลี่ยนแปลงหลังการสแกนครั้งก่อน ' . count($staleFiles) . (count($staleFiles) >= 20 ? '+' : '') . ' ไฟล์ (เช่น <code>' . htmlspecialchars((string)$staleFiles[0], ENT_QUOTES, 'UTF-8') . '</code>)</div>'; }
flush();

// One row per FILE: merge every rule that fired on the same path (highest severity decides the tab).
$grouped = [];
foreach ($findings as [$sv, $lb, $pt, $ex]) {
    if (!isset($grouped[$pt])) $grouped[$pt] = [$sv, [], $pt, ''];
    $grouped[$pt][1][] = [$sv, $lb, $ex];
    if ($sevRank[$sv] < $sevRank[$grouped[$pt][0]]) $grouped[$pt][0] = $sv;
}
foreach ($grouped as &$g) {
    usort($g[1], function ($a, $b) use ($sevRank) { return $sevRank[$a[0]] <=> $sevRank[$b[0]]; });
}
unset($g);
$findings = array_values($grouped);
usort($findings, function ($a, $b) use ($sevRank) {
    $r = $sevRank[$a[0]] <=> $sevRank[$b[0]];
    return $r !== 0 ? $r : strcmp($a[2], $b[2]);
});
$counts = ['CRITICAL'=>0,'HIGH'=>0,'MEDIUM'=>0,'LOW'=>0];
foreach ($findings as $f) $counts[$f[0]]++;

$h        = function($s) { return htmlspecialchars((string)$s, ENT_QUOTES, 'UTF-8'); };
$sevColor = ['CRITICAL'=>'#8a1c12','HIGH'=>'#9a5b00','MEDIUM'=>'#555','LOW'=>'#777'];
$sevBg    = ['CRITICAL'=>'transparent','HIGH'=>'transparent','MEDIUM'=>'transparent','LOW'=>'transparent'];
?>
<div class="meta">Files read: <?=$scanned?> · Time: <?=$elapsed?>s</div>
<?php
 $risk = bd_risk($counts['CRITICAL'], $counts['HIGH'], $counts['MEDIUM']);
 $riskLbl = bd_risk_label($risk);
 $ring = round(326.7*(1-$risk/100),1);
 $rk   = $risk>=60 ? 'rk-hi' : ($risk>=25 ? 'rk-mid' : 'rk-lo');   // red / amber / green
 $nTot = count($findings);
?>
<div class="hero <?=$rk?>">
 <div class="gauge" role="img" aria-label="Risk score <?=$risk?> / 100 (<?=$riskLbl?>)">
  <svg width="150" height="150" viewBox="0 0 120 120" aria-hidden="true"><circle class="trk" cx="60" cy="60" r="52" fill="none" stroke-width="9"/><circle cx="60" cy="60" r="52" fill="none" stroke-width="9" stroke-linecap="round" stroke-dasharray="326.7" style="stroke:var(--rk);stroke-dashoffset:<?=$ring?>;transform:rotate(-90deg);transform-origin:60px 60px"/></svg>
  <div class="gv"><b style="color:var(--rk)"><?=$risk?></b><small>RISK SCORE</small><small style="margin-top:.15rem;font-weight:700;letter-spacing:.04em;color:var(--rk)"><?=$riskLbl?></small></div>
 </div>
 <div class="tx">
  <div class="eyebrow" style="color:var(--rk)">● <?=$nTot ? 'พบภัยคุกคามที่ต้องจัดการ' : 'ไม่พบ pattern น่าสงสัย'?></div>
  <h1 style="margin:.4rem 0 .4rem"><?=$nTot?> ไฟล์น่าสงสัย</h1>
  <div class="meta" style="max-width:560px;font-size:.9rem">ไฟล์ที่ลบหรือแก้ไขจะถูกสำรองเป็น .quarantine ในโฟลเดอร์ที่เปิดจากเว็บไม่ได้ ทำได้เฉพาะไฟล์ที่ผลสแกนนี้รายงาน และทุกการกระทำบันทึกใน audit log</div>
 </div>
</div>
<div class="sum">
 <span class="sc-c">วิกฤต · CRITICAL <b><?=$counts['CRITICAL']?></b></span>
 <span class="sc-h">สูง · HIGH <b><?=$counts['HIGH']?></b></span>
 <span>กลาง · MEDIUM <b><?=$counts['MEDIUM']?></b></span>
</div>
<div class="warn"><strong>หมายเหตุ:</strong> scanner นี้ดูเฉพาะไฟล์ — ยังต้องดู database (admin แปลกปลอม), access log, cron job ด้วย และ <strong>ลบไฟล์ scanner นี้</strong> หลังใช้เสร็จ</div>
<?=serverAuditHtml(serverAudit($ROOT))?>
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
<div class="filter-bar" style="margin-top:1rem">
 <input type="text" class="filter-inp" id="g-filter" placeholder="🔍 ค้นหาทุกระดับ เช่น filemanager, shell, .htaccess" oninput="globalFilter(this.value)" aria-label="ค้นหาในทุกแท็บ">
 <span class="filter-count" id="g-filter-count"></span>
</div>
<div class="tabs">
<?php foreach (['CRITICAL','HIGH','MEDIUM'] as $s): if (!$byLv[$s]) continue; ?>
 <button class="tab <?=$tabCls[$s]?><?=$s===$first?' active':''?>" onclick="showTab('<?=$s?>',this)">
  <?=$s?> <span class="bdg" data-n="<?=count($byLv[$s])?>"><?=count($byLv[$s])?></span>
 </button>
<?php endforeach; ?>
</div>
<?php foreach (['CRITICAL','HIGH','MEDIUM'] as $s): if (!$byLv[$s]) continue; ?>
<div id="tp-<?=$s?>" class="tab-panel<?=$s===$first?' on':''?>">
<div class="filter-bar">
 <input type="text" class="filter-inp" placeholder="กรอง path เช่น .htaccess, admin.php" oninput="filterRows('<?=$s?>',this.value)" id="filter-inp-<?=$s?>">
 <button class="sel-filter-btn" onclick="selectFiltered('<?=$s?>')">เลือกที่กรอง</button>
 <button class="sel-filter-btn" style="background:#888" onclick="clearFilter('<?=$s?>')">✕ ล้างตัวกรอง</button>
 <button class="sel-filter-btn" style="background:#27ae60" onclick="selectAll('<?=$s?>')">เลือกทั้งหมด <?=count($byLv[$s])?> ไฟล์</button>
 <span class="filter-count" id="filter-count-<?=$s?>"></span>
</div>
<div class="bulk-bar" id="bulk-bar-<?=$s?>">
 <strong id="bulk-del-btn-<?=$s?>-label"></strong>
 <button class="bulk-del-btn" id="bulk-del-btn-<?=$s?>" disabled onclick="doBulkDelete('<?=$s?>')">🗑 ลบที่เลือก</button>
 <span style="color:#7a5b00;font-size:.78rem">สำรองใน _backdoor_scan_backups ก่อนลบ</span>
</div>
 <table><thead><tr><th class="cb-col"><input type="checkbox" class="hd-cb" data-tab="<?=$s?>" onchange="toggleAllRows(this,'<?=$s?>')"></th><th>mtime</th><th>Path</th><th>Reason</th><th class="act-td">Action</th></tr></thead><tbody>
 <?php foreach ($byLv[$s] as [$sev,$label,$path,$extra]):
   $mt = @filemtime($ROOT . $path);
   $mtStr = $mt ? date('Y-m-d', $mt) : '—';
   $mtColor = ($mt && (time()-$mt) < 30*86400) ? 'color:#c0392b;font-weight:700' : 'color:#888';
 ?>
  <?php
   $dTok = $ENABLE_WRITE ? csrfToken('delete_file', $path) : '';
   $gTok = $ENABLE_WRITE ? csrfToken('get_file',    $path) : '';
   $sTok = $ENABLE_WRITE ? csrfToken('save_file',   $path) : '';
  ?>
  <tr class="sev-<?=$sev?>" style="background:<?=$sevBg[$sev]?>" data-path="<?=$h($path)?>" data-dtok="<?=($ENABLE_WRITE&&in_array($sev,['CRITICAL','HIGH'],true))?$h($dTok):''?>">
   <td class="cb-col"><?php if($ENABLE_WRITE&&in_array($sev,['CRITICAL','HIGH'],true)):?><input type="checkbox" class="row-cb" data-tab="<?=$s?>" data-path="<?=$h($path)?>" data-dtok="<?=$h($dTok)?>" onchange="onRowCheck(this)"><?php endif;?></td>
   <td style="white-space:nowrap;font-size:.82rem;<?=$mtColor?>"><?=$mtStr?></td>
   <td><code><?=$h($path)?></code></td>
   <td class="rsn-td"><?php foreach ($label as [$rs,$rl,$rx]): ?><div class="rsn"><span class="dot dot-<?=$rs?>" title="<?=$rs?>"></span><span><?=$h($rl)?><?php if($rx):?> <small><code><?=$h($rx)?></code></small><?php endif;?></span></div><?php endforeach; ?><?php if (count($label) > 1): ?><div class="rsn-n"><?=count($label)?> เหตุผลที่ตรง</div><?php endif; ?></td>
   <td class="act-td">
    <?php if($ENABLE_WRITE && in_array($sev,['CRITICAL','HIGH'],true)): ?>
    <button class="act-btn danger-btn" onclick='openDelete(<?=json_encode($path, JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_TAG|JSON_HEX_AMP)?>,<?=json_encode($dTok, JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_TAG|JSON_HEX_AMP)?>)'>🗑 ลบไฟล์</button>
    <?php endif; ?>
    <?php if($ENABLE_WRITE): ?>
    <button class="act-btn edit-btn" onclick='openEditor(<?=json_encode($path, JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_TAG|JSON_HEX_AMP)?>,<?=json_encode($gTok, JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_TAG|JSON_HEX_AMP)?>,<?=json_encode($sTok, JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_TAG|JSON_HEX_AMP)?>)'>✏ แก้ไข</button>
    <button class="act-btn view-btn" onclick='openEditor(<?=json_encode($path, JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_TAG|JSON_HEX_AMP)?>,<?=json_encode($gTok, JSON_HEX_APOS|JSON_HEX_QUOT|JSON_HEX_TAG|JSON_HEX_AMP)?>,"",true)'>👁 ดู code</button>
    <?php endif; ?>
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
<?=$DESIGN_FOOTER?>
<!-- ── Delete Confirm Modal ── -->
<div id="del-modal-bg" class="modal-bg" onclick="if(event.target===this)closeDelete()">
 <div class="del-modal">
  <div class="del-modal-icon">⚠️</div>
  <h2>ยืนยันลบไฟล์</h2>
  <div class="del-sub">ไฟล์จะถูกลบออกจาก server อย่างถาวร ไม่สามารถกู้คืนได้</div>
  <div id="del-fname-box" class="del-fname"></div>
  <div class="del-label">พิมพ์ชื่อไฟล์ <strong><span id="del-expected"></span></strong> เพื่อยืนยัน:</div>
  <input type="text" id="del-input" class="confirm-input" autocomplete="off" spellcheck="false"
   oninput="checkDelInput()" onpaste="setTimeout(checkDelInput,10)" placeholder="พิมพ์ชื่อไฟล์ที่นี่...">
  <div id="del-countdown" class="del-countdown"></div>
  <button id="del-confirm-btn" class="del-btn-confirm" onclick="confirmDelete()" disabled>ยืนยันลบไฟล์</button>
  <button class="del-btn-cancel" onclick="closeDelete()">ยกเลิก</button>
 </div>
</div>
<!-- ── Code Editor Modal ── -->
<div id="editor-bg" class="editor-bg" onclick="if(event.target===this)closeEditor()">
 <div class="editor-win" role="dialog" aria-modal="true" aria-label="Code editor">
 <div class="editor-header">
  <span id="editor-title" class="editor-title">✏ แก้ไข code</span>
  <span id="editor-efile" class="editor-efile"></span>
  <span class="editor-badge">PHP</span>
  <button class="editor-hbtn" onclick="closeEditor()">✕ ปิด</button>
 </div>
 <div id="editor-marks" class="editor-marks" role="status"></div>
 <div class="editor-body">
  <div id="editor-nums" class="editor-nums">1<br></div>
  <div class="editor-hl" aria-hidden="true"><div id="editor-hl-in"></div></div>
  <textarea id="editor-ta" class="editor-ta" wrap="off" spellcheck="false" autocomplete="off"
   oninput="onEditorInput()" onscroll="syncEditorScroll()"></textarea>
 </div>
 <div class="editor-footer">
  <span id="editor-info" class="editor-info">—</span>
  <span id="editor-bak" class="editor-bak">💾 สำรองไฟล์ก่อนบันทึกอัตโนมัติ</span>
  <button id="editor-save-btn" class="editor-save" onclick="saveFile()">💾 บันทึก</button>
 </div>
 </div>
</div>
<script>window.SCAN_ID='<?=(int)($lastScanId ?? 0)?>';restoreMarks();try{history.replaceState(null,'',location.pathname+'?view=last');}catch(e){}</script>
<!-- ── Toast ── -->
<div id="adv-toast" class="toast"></div>
</body></html>
