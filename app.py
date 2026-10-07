from flask import Flask, request, jsonify, render_template_string
from model import PhishingDetector
import ipaddress
import socket
import time
import requests
from urllib.parse import urlparse, parse_qsl
import re

app = Flask(__name__)

detector = PhishingDetector()


HTML = r"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">

<title>PhishGuard | AI URL Threat Intelligence</title>

<style>
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

:root {
    --bg: #050912;
    --panel: #0b1220;
    --panel2: #101a2c;
    --border: rgba(95, 180, 255, .16);
    --cyan: #35d9ff;
    --blue: #4388ff;
    --green: #32e89a;
    --red: #ff4d6d;
    --yellow: #ffc857;
    --text: #edf7ff;
    --muted: #8190a7;
}

body {
    min-height: 100vh;
    font-family: Inter, Arial, sans-serif;
    color: var(--text);
    background:
        radial-gradient(circle at 20% 10%, rgba(25,115,255,.12), transparent 30%),
        radial-gradient(circle at 80% 30%, rgba(0,220,255,.08), transparent 30%),
        var(--bg);
    overflow-x: hidden;
}

body::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    opacity: .18;
    background-image:
        linear-gradient(rgba(255,255,255,.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255,255,255,.03) 1px, transparent 1px);
    background-size: 40px 40px;
}

.container {
    width: min(1200px, 94%);
    margin: auto;
    padding: 25px 0 60px;
}

/* HEADER */

.header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 35px;
}

.logo {
    display: flex;
    align-items: center;
    gap: 12px;
}

.logo-icon {
    width: 45px;
    height: 45px;
    border: 1px solid var(--cyan);
    border-radius: 13px;
    display: grid;
    place-items: center;
    color: var(--cyan);
    font-size: 23px;
    box-shadow: 0 0 25px rgba(53,217,255,.18);
}

.logo h1 {
    font-size: 21px;
    letter-spacing: 1px;
}

.logo p {
    font-size: 11px;
    color: var(--muted);
    margin-top: 3px;
}

.status {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    color: var(--green);
}

.status-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 14px var(--green);
    animation: pulse 1.4s infinite;
}

@keyframes pulse {
    50% { opacity: .35; transform: scale(.7); }
}

/* HERO */

.hero {
    text-align: center;
    margin-bottom: 28px;
}

.hero h2 {
    font-size: clamp(28px, 5vw, 52px);
    letter-spacing: -1.5px;
    margin-bottom: 12px;
}

.hero h2 span {
    color: var(--cyan);
    text-shadow: 0 0 25px rgba(53,217,255,.35);
}

.hero p {
    color: var(--muted);
    font-size: 14px;
}

/* SCANNER */

.scanner {
    padding: 8px;
    border: 1px solid var(--border);
    background: rgba(11,18,32,.75);
    border-radius: 18px;
    display: flex;
    gap: 8px;
    box-shadow: 0 20px 60px rgba(0,0,0,.3);
    backdrop-filter: blur(15px);
}

.scanner input {
    flex: 1;
    min-width: 0;
    border: 0;
    outline: 0;
    background: transparent;
    color: white;
    padding: 18px;
    font-size: 15px;
}

.scanner input::placeholder {
    color: #59677d;
}

.scan-btn {
    border: 0;
    padding: 0 28px;
    border-radius: 13px;
    color: white;
    font-weight: 700;
    cursor: pointer;
    background: linear-gradient(135deg, #159bd8, #3e6fff);
    box-shadow: 0 0 25px rgba(62,111,255,.25);
    transition: .25s;
}

.scan-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 0 35px rgba(62,111,255,.45);
}

/* RADAR */

.radar-section {
    display: none;
    text-align: center;
    margin: 35px 0;
}

.radar {
    width: 170px;
    height: 170px;
    margin: auto;
    border-radius: 50%;
    border: 1px solid rgba(53,217,255,.35);
    position: relative;
    background:
        radial-gradient(circle, transparent 28%, rgba(53,217,255,.05) 29%, transparent 30%),
        radial-gradient(circle, transparent 48%, rgba(53,217,255,.05) 49%, transparent 50%),
        radial-gradient(circle, transparent 68%, rgba(53,217,255,.05) 69%, transparent 70%);
    overflow: hidden;
}

.radar::before {
    content: "";
    position: absolute;
    width: 50%;
    height: 2px;
    left: 50%;
    top: 50%;
    transform-origin: left;
    background: linear-gradient(90deg, var(--cyan), transparent);
    animation: radar 1.5s linear infinite;
}

.radar::after {
    content: "";
    position: absolute;
    width: 7px;
    height: 7px;
    background: var(--cyan);
    border-radius: 50%;
    left: calc(50% - 3px);
    top: calc(50% - 3px);
    box-shadow: 0 0 20px var(--cyan);
}

@keyframes radar {
    from { transform: rotate(0deg); }
    to { transform: rotate(360deg); }
}

.scan-text {
    margin-top: 18px;
    color: var(--cyan);
    font-size: 13px;
    animation: blink 1s infinite;
}

@keyframes blink {
    50% { opacity: .4; }
}

/* RESULT */

#result {
    display: none;
    animation: appear .5s ease;
}

@keyframes appear {
    from {
        opacity: 0;
        transform: translateY(20px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.grid {
    display: grid;
    grid-template-columns: 1.3fr .7fr;
    gap: 18px;
    margin-top: 22px;
}

.card {
    background: linear-gradient(145deg, rgba(15,26,44,.95), rgba(8,15,27,.95));
    border: 1px solid var(--border);
    border-radius: 18px;
    padding: 22px;
    box-shadow: 0 15px 45px rgba(0,0,0,.2);
}

.card-title {
    color: #9bb0c9;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 1.3px;
    margin-bottom: 18px;
}

/* MAIN VERDICT */

.verdict {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.verdict-left {
    display: flex;
    align-items: center;
    gap: 15px;
}

.verdict-icon {
    width: 58px;
    height: 58px;
    display: grid;
    place-items: center;
    border-radius: 16px;
    font-size: 27px;
}

.safe {
    background: rgba(50,232,154,.1);
    color: var(--green);
    border: 1px solid rgba(50,232,154,.25);
}

.danger {
    background: rgba(255,77,109,.1);
    color: var(--red);
    border: 1px solid rgba(255,77,109,.25);
}

.verdict h3 {
    font-size: 25px;
}

.verdict small {
    color: var(--muted);
}

.confidence {
    text-align: right;
}

.confidence strong {
    display: block;
    font-size: 32px;
}

.confidence span {
    font-size: 11px;
    color: var(--muted);
}

/* PROGRESS */

.progress {
    height: 9px;
    background: #172235;
    border-radius: 20px;
    overflow: hidden;
    margin-top: 22px;
}

.progress-bar {
    height: 100%;
    width: 0%;
    border-radius: 20px;
    transition: width 1.2s ease;
    background: linear-gradient(90deg, var(--cyan), var(--blue));
}

/* STATS */

.stats {
    display: grid;
    grid-template-columns: repeat(3,1fr);
    gap: 10px;
    margin-top: 18px;
}

.stat {
    padding: 15px;
    border-radius: 13px;
    background: rgba(255,255,255,.025);
    border: 1px solid rgba(255,255,255,.05);
}

.stat label {
    display: block;
    color: var(--muted);
    font-size: 11px;
    margin-bottom: 6px;
}

.stat strong {
    font-size: 18px;
}

/* URL */

.url-box {
    font-family: monospace;
    color: var(--cyan);
    background: rgba(0,0,0,.25);
    border-radius: 10px;
    padding: 13px;
    word-break: break-all;
    font-size: 12px;
}

/* INTELLIGENCE */

.intel {
    display: grid;
    grid-template-columns: repeat(2,1fr);
    gap: 10px;
}

.intel-item {
    padding: 14px;
    border-radius: 12px;
    background: rgba(255,255,255,.025);
}

.intel-item label {
    display: block;
    color: var(--muted);
    font-size: 10px;
    text-transform: uppercase;
    margin-bottom: 6px;
}

.intel-item span {
    font-size: 14px;
    font-weight: 600;
}

/* FINDINGS */

.finding {
    display: flex;
    align-items: center;
    gap: 11px;
    padding: 12px 0;
    border-bottom: 1px solid rgba(255,255,255,.05);
    font-size: 13px;
}

.finding:last-child {
    border-bottom: 0;
}

.check {
    width: 25px;
    height: 25px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    font-size: 12px;
}

.check.good {
    color: var(--green);
    background: rgba(50,232,154,.1);
}

.check.bad {
    color: var(--red);
    background: rgba(255,77,109,.1);
}

.check.warn {
    color: var(--yellow);
    background: rgba(255,200,87,.1);
}

/* PROBABILITIES */

.prob {
    margin: 16px 0;
}

.prob-head {
    display: flex;
    justify-content: space-between;
    font-size: 12px;
    margin-bottom: 7px;
}

.prob-track {
    height: 7px;
    background: #172235;
    border-radius: 20px;
    overflow: hidden;
}

.prob-fill {
    height: 100%;
    width: 0;
    transition: width 1s ease;
}

/* QUICK TESTS */

.quick {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
}

.quick button {
    flex: 1;
    min-width: 180px;
    background: rgba(255,255,255,.03);
    border: 1px solid var(--border);
    color: #b8c7da;
    padding: 12px;
    border-radius: 10px;
    cursor: pointer;
    transition: .2s;
}

.quick button:hover {
    color: var(--cyan);
    border-color: rgba(53,217,255,.4);
}

/* FOOTER */

.existence-grid {
    display: grid;
    grid-template-columns: 1.2fr .8fr;
    gap: 10px;
    margin-top: 18px;
}

.existence-status {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 15px;
    border-radius: 13px;
    background: rgba(255,255,255,.025);
    border: 1px solid rgba(255,255,255,.05);
}

.existence-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    background: var(--green);
    box-shadow: 0 0 14px var(--green);
}

.existence-dot.bad {
    background: var(--red);
    box-shadow: 0 0 14px var(--red);
}

.existence-dot.warn {
    background: var(--yellow);
    box-shadow: 0 0 14px var(--yellow);
}

.existence-main strong {
    display: block;
    font-size: 16px;
}

.existence-main small {
    color: var(--muted);
    display: block;
    margin-top: 4px;
}

.existence-meta {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
}

.existence-meta .stat {
    min-width: 0;
}

@media(max-width: 800px) {
    .existence-grid {
        grid-template-columns: 1fr;
    }
}

.footer {
    text-align: center;
    color: #536177;
    font-size: 11px;
    margin-top: 35px;
}

/* MOBILE */

@media(max-width: 800px) {
    .grid {
        grid-template-columns: 1fr;
    }

    .scanner {
        flex-direction: column;
    }

    .scan-btn {
        min-height: 52px;
    }

    .stats {
        grid-template-columns: 1fr;
    }

    .header {
        align-items: flex-start;
    }

    .status {
        margin-top: 8px;
    }
}


/* ADVANCED INTELLIGENCE */
.score-wrap{display:grid;grid-template-columns:180px 1fr;gap:24px;align-items:center}
.score-ring{width:150px;height:150px;border-radius:50%;display:grid;place-items:center;background:conic-gradient(var(--cyan) 0deg,#182438 0deg);position:relative;box-shadow:0 0 35px rgba(53,217,255,.12)}
.score-ring::after{content:"";position:absolute;inset:10px;border-radius:50%;background:var(--panel)}
.score-number{position:relative;z-index:1;text-align:center}.score-number strong{display:block;font-size:36px}.score-number span{font-size:10px;color:var(--muted);letter-spacing:1px}
.risk-list{display:grid;gap:12px}.risk-row{display:grid;grid-template-columns:145px 1fr 58px;gap:10px;align-items:center;font-size:12px}.risk-track{height:8px;background:#172236;border-radius:20px;overflow:hidden}.risk-fill{height:100%;width:0;border-radius:20px;transition:width .7s ease}
.domain-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px}.domain-cell{padding:12px;border:1px solid var(--border);background:rgba(255,255,255,.025);border-radius:10px}.domain-cell label{display:block;color:var(--muted);font-size:10px;margin-bottom:6px}.domain-cell strong{font-size:12px;word-break:break-word}
.redirects{display:flex;flex-wrap:wrap;gap:8px;align-items:center}.redirect-chip{padding:9px 11px;border:1px solid var(--border);border-radius:10px;background:#0c1525;font-size:11px;word-break:break-all}.arrow{color:var(--cyan)}
.action-row{display:flex;gap:10px;flex-wrap:wrap}.action-btn{border:1px solid var(--border);background:#0d1728;color:var(--text);padding:11px 14px;border-radius:10px;cursor:pointer}.action-btn:hover{border-color:var(--cyan);box-shadow:0 0 18px rgba(53,217,255,.12)}
.history{display:grid;gap:8px}.history-row{display:flex;justify-content:space-between;align-items:center;gap:12px;padding:10px 12px;border:1px solid var(--border);border-radius:10px;background:rgba(255,255,255,.02);font-size:12px}.history-row small{color:var(--muted)}.history-main{min-width:0;flex:1;overflow:hidden}.history-url{display:block;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.history-meta{display:flex;align-items:center;gap:10px}.history-delete{border:1px solid rgba(255,77,109,.25);background:rgba(255,77,109,.07);color:#ff7b91;border-radius:8px;padding:6px 9px;cursor:pointer;font-size:11px}.history-delete:hover{background:rgba(255,77,109,.16);border-color:rgba(255,77,109,.5)}.history-clear-btn{border:1px solid rgba(255,77,109,.25);background:rgba(255,77,109,.07);color:#ff7b91;border-radius:8px;padding:7px 11px;cursor:pointer;font-size:11px}.history-clear-btn:hover{background:rgba(255,77,109,.16);border-color:rgba(255,77,109,.5)}
@media(max-width:700px){.score-wrap{grid-template-columns:1fr}.domain-grid{grid-template-columns:repeat(2,1fr)}.risk-row{grid-template-columns:105px 1fr 48px}}




/* PREMIUM CYBER SCAN ANIMATION */
.cyber-scan{display:none;margin-top:18px;padding:18px;border:1px solid rgba(53,217,255,.24);border-radius:18px;background:linear-gradient(180deg,rgba(7,20,37,.96),rgba(5,13,26,.98));box-shadow:0 0 45px rgba(0,190,255,.08),inset 0 0 35px rgba(53,217,255,.025);overflow:hidden;position:relative}
.cyber-scan:before{content:"";position:absolute;inset:0;background-image:linear-gradient(rgba(53,217,255,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(53,217,255,.045) 1px,transparent 1px);background-size:34px 34px;pointer-events:none}
.scan-steps{position:relative;z-index:2;display:flex;align-items:flex-start;justify-content:space-between;gap:4px}
.scan-step{width:105px;text-align:center;color:#5e718c;font-size:9px;letter-spacing:.2px;transition:.35s ease}.scan-step-icon{width:42px;height:42px;margin:0 auto 7px;border:1px solid #27405e;border-radius:12px;display:grid;place-items:center;font-size:20px;background:#0a1728;transition:.35s}.scan-step b{display:block;margin-top:6px;font-size:13px;color:#46617d;transition:.35s}.scan-step.active,.scan-step.done{color:#c8f7ff}.scan-step.active .scan-step-icon{color:var(--cyan);border-color:var(--cyan);box-shadow:0 0 22px rgba(53,217,255,.38);animation:scanPulse 1s infinite}.scan-step.done .scan-step-icon{color:var(--green);border-color:rgba(50,232,154,.65);box-shadow:0 0 16px rgba(50,232,154,.2)}.scan-step.done b{color:var(--green)}.scan-step.active b{color:var(--cyan)}
.scan-line{height:1px;flex:1;margin-top:21px;background:linear-gradient(90deg,#1c3048,var(--cyan),#1c3048);opacity:.35;position:relative;overflow:hidden}.scan-line:after{content:"";position:absolute;top:-2px;left:-30%;width:30%;height:5px;background:var(--cyan);filter:blur(4px);animation:lineTravel 1.2s linear infinite}
.scan-core-grid{position:relative;z-index:2;display:grid;grid-template-columns:1.2fr .7fr 1fr;gap:16px;align-items:center;margin-top:20px}.scan-url-panel,.scan-log{min-height:150px;border:1px solid rgba(53,217,255,.14);border-radius:14px;background:rgba(5,14,27,.72);padding:18px;position:relative;overflow:hidden}.scan-url-panel:before,.scan-log:before{content:"";position:absolute;inset:0;background:linear-gradient(120deg,transparent 0%,rgba(53,217,255,.035) 45%,transparent 70%);animation:panelSweep 2.2s linear infinite}.scan-kicker{position:relative;color:var(--cyan);font-size:12px;font-weight:700;letter-spacing:1px;margin-bottom:20px}.scan-url-value{position:relative;font-family:Consolas,monospace;font-size:15px;color:#eafcff;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;padding:13px;border:1px solid rgba(53,217,255,.13);background:rgba(255,255,255,.02);border-radius:9px}.scan-sweep{position:absolute;top:62px;bottom:18px;width:3px;background:var(--cyan);box-shadow:0 0 18px 5px rgba(53,217,255,.75);left:12%;animation:urlSweep 1.5s ease-in-out infinite}
.scan-orb{width:170px;height:170px;margin:auto;border-radius:50%;position:relative;display:grid;place-items:center;background:radial-gradient(circle,rgba(53,217,255,.13),transparent 58%);filter:drop-shadow(0 0 18px rgba(53,217,255,.2))}.orb-ring{position:absolute;border:1px solid rgba(53,217,255,.35);border-radius:50%;inset:14px;animation:orbSpin 5s linear infinite}.orb-ring.r2{inset:30px;border-color:rgba(74,139,255,.42);animation-direction:reverse;animation-duration:3.2s}.orb-globe{width:82px;height:82px;border-radius:50%;display:grid;place-items:center;font-size:34px;color:var(--cyan);border:1px solid rgba(53,217,255,.5);background:radial-gradient(circle at 35% 30%,rgba(53,217,255,.3),rgba(4,20,37,.95));box-shadow:0 0 35px rgba(53,217,255,.18),inset 0 0 25px rgba(53,217,255,.12);animation:orbPulse 1.5s ease-in-out infinite}.scan-log{font-family:Consolas,monospace;color:#7890ad;font-size:10px;line-height:2}.scan-log-title{font-family:Inter,Arial,sans-serif;color:var(--cyan);font-size:12px;font-weight:700;letter-spacing:.8px;margin-bottom:5px}.scan-log div:not(.scan-log-title){white-space:nowrap}.scan-log div:not(.scan-log-title):before{content:"> ";color:#2d6383}.scan-log div:nth-child(2){color:#c5eaf4}.scan-log div:nth-child(3){color:#90b3c7}.scan-log div:nth-child(4){color:#7697ae}.scan-log div:nth-child(5){color:#5f829a}.scan-log div:nth-child(6){color:#4c6f86}
@keyframes scanPulse{50%{transform:translateY(-2px) scale(1.05);box-shadow:0 0 30px rgba(53,217,255,.55)}}@keyframes lineTravel{from{left:-30%}to{left:100%}}@keyframes urlSweep{0%{left:8%;opacity:.2}50%{left:88%;opacity:1}100%{left:8%;opacity:.2}}@keyframes orbSpin{to{transform:rotate(360deg)}}@keyframes orbPulse{50%{transform:scale(1.07);box-shadow:0 0 50px rgba(53,217,255,.28),inset 0 0 30px rgba(53,217,255,.18)}}@keyframes panelSweep{from{transform:translateX(-120%)}to{transform:translateX(120%)}}
@media(max-width:800px){.scan-steps{overflow-x:auto;justify-content:flex-start;padding-bottom:8px}.scan-line{min-width:25px}.scan-core-grid{grid-template-columns:1fr}.scan-orb{order:-1}.scan-step{min-width:92px}}

/* THREAT ANALYTICS DASHBOARD */
.analytics-card{margin-top:18px;overflow:hidden}
.analytics-header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px}
.analytics-live{font-size:10px;color:var(--green);border:1px solid rgba(50,232,154,.25);background:rgba(50,232,154,.06);padding:6px 9px;border-radius:999px}
.analytics-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin-bottom:14px}
.metric{background:rgba(255,255,255,.025);border:1px solid var(--border);border-radius:12px;padding:14px}
.metric label{display:block;font-size:9px;color:var(--muted);letter-spacing:1px}
.metric strong{display:block;font-size:24px;margin-top:7px}
.metric small{display:block;color:var(--muted);font-size:10px;margin-top:4px}
.analytics-main{display:grid;grid-template-columns:1.4fr .9fr;gap:14px}
.panel-mini{background:rgba(255,255,255,.02);border:1px solid var(--border);border-radius:13px;padding:14px}
.panel-mini h4{font-size:12px;margin-bottom:12px;letter-spacing:.5px}
.trend{display:flex;align-items:end;gap:8px;height:145px;padding:8px 3px 22px}
.trend-col{flex:1;height:100%;display:flex;flex-direction:column;justify-content:end;align-items:center;gap:6px}
.trend-bar{width:100%;max-width:30px;border-radius:7px 7px 2px 2px;background:linear-gradient(180deg,var(--cyan),var(--blue));min-height:3px;transition:height .5s ease}
.trend-label{font-size:8px;color:var(--muted)}
.feed{display:flex;flex-direction:column;gap:8px;max-height:190px;overflow:auto}
.feed-item{display:grid;grid-template-columns:58px 1fr auto;gap:8px;align-items:center;padding:9px;border-radius:9px;background:rgba(255,255,255,.025);font-size:10px}
.feed-time{color:var(--muted);font-family:monospace}
.feed-url{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge{font-size:8px;padding:4px 6px;border-radius:999px;font-weight:700}
.badge.good{color:var(--green);background:rgba(50,232,154,.09)}
.badge.warn{color:var(--yellow);background:rgba(255,200,87,.09)}
.badge.bad{color:var(--red);background:rgba(255,77,109,.09)}
.indicator-list{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.indicator{display:flex;justify-content:space-between;gap:10px;padding:9px;border:1px solid rgba(255,255,255,.05);border-radius:9px;font-size:10px}
.indicator span:last-child{color:var(--cyan);font-weight:700}
.landscape{display:grid;grid-template-columns:repeat(6,1fr);gap:7px;margin-top:10px}
.zone{min-height:54px;border:1px solid var(--border);border-radius:9px;padding:8px;background:radial-gradient(circle at 50% 20%,rgba(53,217,255,.1),transparent 65%);position:relative;overflow:hidden}
.zone::after{content:"";position:absolute;width:7px;height:7px;border-radius:50%;right:8px;top:8px;background:var(--green);box-shadow:0 0 12px var(--green);opacity:.75}
.zone span{display:block;font-size:9px;color:var(--muted)}
.zone strong{display:block;margin-top:6px;font-size:13px}
.analytics-note{font-size:9px;color:#627086;margin-top:10px;line-height:1.5}
@media(max-width:800px){.analytics-grid{grid-template-columns:1fr 1fr}.analytics-main{grid-template-columns:1fr}.landscape{grid-template-columns:repeat(3,1fr)}}


/* SIDEBAR + COMMAND CENTER DASHBOARD */
body{background:#020812;}
.container{width:min(1540px,calc(100% - 250px));margin-left:225px;margin-right:20px;}
.sidebar{position:fixed;z-index:50;left:0;top:0;bottom:0;width:205px;padding:22px 14px;background:linear-gradient(180deg,#071525 0%,#04101d 70%,#020a14 100%);border-right:1px solid rgba(53,217,255,.18);box-shadow:10px 0 35px rgba(0,0,0,.35),inset -1px 0 rgba(53,217,255,.04);}
.side-brand{display:flex;gap:10px;align-items:center;padding:4px 8px 22px}.side-logo{width:38px;height:38px;border:1px solid var(--cyan);border-radius:10px;display:grid;place-items:center;color:var(--cyan);font-size:20px;box-shadow:0 0 20px rgba(53,217,255,.2)}.side-brand strong{display:block;font-size:15px;letter-spacing:.5px}.side-brand small{display:block;color:#5d7692;font-size:8px;margin-top:2px}
.side-nav{display:grid;gap:6px}.side-nav button{width:100%;display:flex;align-items:center;gap:11px;padding:11px 12px;border:1px solid transparent;border-radius:10px;background:transparent;color:#91a7bf;text-align:left;font-size:11px;cursor:pointer;transition:.2s}.side-nav button .ico{width:20px;text-align:center;font-size:15px}.side-nav button:hover{color:#dffaff;border-color:rgba(53,217,255,.14);background:rgba(53,217,255,.05)}.side-nav button.active{color:#fff;background:linear-gradient(90deg,rgba(33,130,255,.28),rgba(53,217,255,.06));border-color:rgba(53,217,255,.18);box-shadow:0 0 18px rgba(35,143,255,.12)}
.side-status{position:absolute;left:14px;right:14px;bottom:18px;padding:11px;border:1px solid rgba(50,232,154,.13);border-radius:10px;background:rgba(50,232,154,.035);font-size:9px;color:#76918c}.side-status span{color:var(--green);font-weight:700}
.dashboard-shell{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(280px,.62fr);gap:14px;margin-top:18px}.dashboard-side{display:grid;gap:14px}.dash-panel{border:1px solid var(--border);border-radius:14px;background:linear-gradient(180deg,rgba(10,23,39,.92),rgba(5,14,27,.96));padding:14px;box-shadow:0 12px 30px rgba(0,0,0,.18);overflow:hidden}.dash-title{display:flex;justify-content:space-between;align-items:center;color:#9eefff;font-size:11px;letter-spacing:.8px;margin-bottom:11px}.dash-live{font-size:8px;color:var(--green);border:1px solid rgba(50,232,154,.22);border-radius:999px;padding:4px 7px}.dash-metrics{display:grid;grid-template-columns:1fr 1fr;gap:8px}.dash-metric{padding:11px;border:1px solid rgba(255,255,255,.06);border-radius:10px;background:rgba(255,255,255,.02)}.dash-metric .micon{float:left;width:28px;height:28px;border-radius:8px;display:grid;place-items:center;background:rgba(53,217,255,.08);color:var(--cyan);margin-right:8px}.dash-metric strong{display:block;font-size:18px}.dash-metric small{font-size:8px;color:var(--muted)}.dash-metric.red .micon{color:var(--red);background:rgba(255,77,109,.09)}.dash-metric.yellow .micon{color:var(--yellow);background:rgba(255,200,87,.09)}.dash-metric.green .micon{color:var(--green);background:rgba(50,232,154,.09)}
.world-map{height:175px;border:1px solid rgba(53,217,255,.1);border-radius:12px;position:relative;overflow:hidden;background:radial-gradient(circle at 50% 45%,rgba(28,119,184,.18),transparent 48%),linear-gradient(rgba(53,217,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(53,217,255,.035) 1px,transparent 1px);background-size:auto,22px 22px,22px 22px}.world-map:before{content:"";position:absolute;inset:18% 8%;border:1px dashed rgba(53,217,255,.13);border-radius:48% 52% 44% 56%;transform:rotate(-4deg);box-shadow:35px 5px 0 -20px rgba(53,217,255,.1),-60px 20px 0 -25px rgba(53,217,255,.1)}.map-glow{position:absolute;width:130px;height:130px;left:50%;top:50%;transform:translate(-50%,-50%);border-radius:50%;border:1px solid rgba(53,217,255,.18);box-shadow:0 0 40px rgba(53,217,255,.1),inset 0 0 30px rgba(53,217,255,.05)}.map-dot{position:absolute;width:6px;height:6px;border-radius:50%;background:var(--red);box-shadow:0 0 10px var(--red);animation:mapPulse 1.7s infinite}.map-dot.g{background:var(--green);box-shadow:0 0 10px var(--green)}.map-dot.y{background:var(--yellow);box-shadow:0 0 10px var(--yellow)}.map-legend{display:flex;gap:12px;margin-top:8px;font-size:8px;color:var(--muted)}.map-legend i{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:4px}.map-legend .r{background:var(--red)}.map-legend .y{background:var(--yellow)}.map-legend .g{background:var(--green)}
.top-trend{height:120px;position:relative;border:1px solid rgba(53,217,255,.08);border-radius:10px;background:linear-gradient(rgba(53,217,255,.035) 1px,transparent 1px),linear-gradient(90deg,rgba(53,217,255,.035) 1px,transparent 1px);background-size:25px 25px}.top-trend svg{width:100%;height:100%}.top-feed{display:grid;gap:6px;max-height:180px;overflow:auto}.top-feed-row{display:grid;grid-template-columns:44px 1fr auto;gap:7px;align-items:center;padding:7px;border-bottom:1px solid rgba(255,255,255,.04);font-size:8px}.top-feed-row .time{color:#647c96}.top-feed-row .url{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#c5d8e9}.top-badge{font-size:7px;padding:3px 6px;border-radius:999px}.top-badge.bad{color:#ff8ba0;background:rgba(255,77,109,.1)}.top-badge.warn{color:#ffd77a;background:rgba(255,200,87,.1)}.top-badge.good{color:#69efb2;background:rgba(50,232,154,.1)}
.indicator-bars{display:grid;gap:8px}.ibar{display:grid;grid-template-columns:110px 1fr 25px;gap:7px;align-items:center;font-size:8px}.ibar-track{height:5px;background:#132237;border-radius:10px;overflow:hidden}.ibar-fill{height:100%;width:0;background:linear-gradient(90deg,var(--cyan),var(--blue));border-radius:10px}
#result{scroll-margin-top:20px}.card{scroll-margin-top:20px}.section-anchor{scroll-margin-top:20px}
.settings-modal{display:none;position:fixed;z-index:100;inset:0;background:rgba(0,0,0,.65);backdrop-filter:blur(5px);align-items:center;justify-content:center}.settings-modal.show{display:flex}.settings-box{width:min(430px,92%);border:1px solid rgba(53,217,255,.25);border-radius:16px;background:#071525;box-shadow:0 30px 80px rgba(0,0,0,.55);padding:20px}.settings-box h3{color:var(--cyan);margin-bottom:12px}.settings-box p{font-size:11px;color:#91a7bf;line-height:1.7}.settings-close{margin-top:15px;width:100%;padding:10px;border:1px solid rgba(53,217,255,.2);background:rgba(53,217,255,.06);color:#dffaff;border-radius:9px;cursor:pointer}
@keyframes mapPulse{50%{transform:scale(1.6);opacity:.65}}
@media(max-width:1050px){.container{width:calc(100% - 220px);margin-left:210px}.dashboard-shell{grid-template-columns:1fr}.dashboard-side{grid-template-columns:1fr 1fr}.world-map{height:145px}}
@media(max-width:800px){.sidebar{width:64px;padding:14px 8px}.side-brand div:last-child,.side-nav button span:not(.ico),.side-status{display:none}.side-brand{justify-content:center;padding-bottom:18px}.side-nav button{justify-content:center;padding:11px 4px}.container{width:calc(100% - 78px);margin-left:70px;margin-right:8px}.dashboard-side{grid-template-columns:1fr}.dashboard-shell{grid-template-columns:1fr}.dash-metrics{grid-template-columns:1fr 1fr}}

</style>
</head>

<body>

<div class="container">

<aside class="sidebar">
  <div class="side-brand"><div class="side-logo">🛡</div><div><strong>PhishGuard</strong><small>AI URL Threat Intelligence</small></div></div>
  <nav class="side-nav">
    <button class="active" data-target="homeTop" onclick="navigateDash(this,'homeTop')"><span class="ico">⌂</span><span>Home</span></button>
    <button data-target="scannerTop" onclick="navigateDash(this,'scannerTop')"><span class="ico">⌕</span><span>Scan URL</span></button>
    <button data-target="analyticsDashboard" onclick="navigateDash(this,'analyticsDashboard')"><span class="ico">▥</span><span>Analytics</span></button>
    <button data-target="historyPanel" onclick="navigateDash(this,'historyPanel')"><span class="ico">◷</span><span>History</span></button>
    <button data-target="reportTools" onclick="navigateDash(this,'reportTools')"><span class="ico">▤</span><span>Reports</span></button>
    <button onclick="openSettings()"><span class="ico">⚙</span><span>Settings</span></button>
  </nav>
  <div class="side-status"><span>● ENGINE ONLINE</span><br>Hybrid AI + domain verification</div>
</aside>

<header class="header" id="homeTop">
    <div class="logo">
        <div class="logo-icon">🛡</div>
        <div>
            <h1>PHISHGUARD</h1>
            <p>AI URL THREAT INTELLIGENCE</p>
        </div>
    </div>

    <div class="status">
        <span class="status-dot"></span>
        ENGINE ONLINE
    </div>
</header>


<section class="hero">
    <h2>See the <span>Threat</span> Before You Click</h2>
    <p>Advanced machine-learning analysis for suspicious URLs</p>
</section>


<div class="scanner section-anchor" id="scannerTop">
    <input
        id="urlInput"
        type="text"
        placeholder="Enter URL — https://example.com/login"
        autocomplete="off"
    >
    <button class="scan-btn" onclick="scanURL()">SCAN URL</button>
</div>


<div class="quick" style="margin-top:12px;">
    <button onclick="quickScan('https://www.google.com')">
        🟢 Test Google
    </button>

    <button onclick="quickScan('https://github.com')">
        🟢 Test GitHub
    </button>

    <button onclick="quickScan('http://paypal-secure-update.ml/login')">
        🔴 Test Phishing URL
    </button>
</div>


<div class="cyber-scan" id="scannerAnimation">
    <div class="scan-steps">
        <div class="scan-step active" id="stepUrl"><div class="scan-step-icon">◉</div><span>Checking<br>URL status</span><b>○</b></div>
        <div class="scan-line"></div>
        <div class="scan-step" id="stepDomain"><div class="scan-step-icon">▣</div><span>Fetching<br>domain data</span><b>○</b></div>
        <div class="scan-line"></div>
        <div class="scan-step" id="stepAI"><div class="scan-step-icon">✦</div><span>AI model<br>analyzing</span><b>○</b></div>
        <div class="scan-line"></div>
        <div class="scan-step" id="stepThreat"><div class="scan-step-icon">⌕</div><span>Checking<br>threat indicators</span><b>○</b></div>
        <div class="scan-line"></div>
        <div class="scan-step" id="stepScore"><div class="scan-step-icon">♢</div><span>Calculating<br>security score</span><b>○</b></div>
        <div class="scan-line"></div>
        <div class="scan-step" id="stepReport"><div class="scan-step-icon">▤</div><span>Generating<br>report</span><b>○</b></div>
    </div>

    <div class="scan-core-grid">
        <div class="scan-url-panel">
            <div class="scan-kicker">SCANNING URL...</div>
            <div class="scan-url-value" id="scanUrlValue">https://example.com</div>
            <div class="scan-sweep"></div>
        </div>
        <div class="scan-orb"><div class="orb-ring r1"></div><div class="orb-ring r2"></div><div class="orb-globe">✦</div></div>
        <div class="scan-log">
            <div class="scan-log-title">AI ANALYSIS</div>
            <div id="scanLogText">Initializing threat engine ...</div>
            <div>Checking domain structure ...</div>
            <div>Validating URL patterns ...</div>
            <div>Scanning threat indicators ...</div>
            <div>Processing with AI model ...</div>
        </div>
    </div>

</div>

<div class="dashboard-shell">
  <div class="dash-panel" id="dashboardCenter">
    <div class="dash-title"><span>⚡ LIVE SCAN COMMAND CENTER</span><span class="dash-live">● LIVE</span></div>
    <div class="dash-metrics">
      <div class="dash-metric"><div class="micon">▤</div><strong id="topTotal">0</strong><small>Total Scans</small></div>
      <div class="dash-metric red"><div class="micon">⚠</div><strong id="topPhishing">0</strong><small>Phishing</small></div>
      <div class="dash-metric yellow"><div class="micon">◈</div><strong id="topSuspicious">0</strong><small>Suspicious</small></div>
      <div class="dash-metric green"><div class="micon">✓</div><strong id="topLegitimate">0</strong><small>Legitimate</small></div>
    </div>
    <div class="panel-mini" style="margin-top:12px;padding:10px"><h4>📈 Threat Trends — Last 7 Days</h4><div class="top-trend" id="topTrend"></div></div>
  </div>
  <div class="dashboard-side">
    <div class="dash-panel"><div class="dash-title"><span>🌐 GLOBAL THREAT MAP</span><span class="dash-live">LAST 7 DAYS</span></div><div class="world-map"><div class="map-glow"></div><span class="map-dot" style="left:24%;top:43%"></span><span class="map-dot y" style="left:31%;top:52%"></span><span class="map-dot" style="left:42%;top:39%"></span><span class="map-dot g" style="left:50%;top:48%"></span><span class="map-dot" style="left:62%;top:42%"></span><span class="map-dot y" style="left:70%;top:55%"></span><span class="map-dot" style="left:79%;top:38%"></span><span class="map-dot g" style="left:57%;top:61%"></span></div><div class="map-legend"><span><i class="r"></i>Phishing</span><span><i class="y"></i>Suspicious</span><span><i class="g"></i>Legitimate</span></div></div>
    <div class="dash-panel"><div class="dash-title"><span>⚡ LIVE THREAT FEED</span><span class="dash-live">● LIVE</span></div><div id="topThreatFeed" class="top-feed"><div style="font-size:9px;color:var(--muted)">Run a scan to populate the feed.</div></div></div>
    <div class="dash-panel"><div class="dash-title"><span>🎯 TOP THREAT INDICATORS</span></div><div id="topIndicators" class="indicator-bars"></div></div>
  </div>
</div>

<section id="result">

    <!-- VERDICT -->

    <div class="card">

        <div class="card-title">AI Threat Assessment</div>

        <div class="verdict">

            <div class="verdict-left">

                <div id="verdictIcon" class="verdict-icon safe">
                    ✓
                </div>

                <div>
                    <h3 id="prediction">LEGITIMATE</h3>
                    <small id="modelName">AI Threat Intelligence</small>
                </div>

            </div>

            <div class="confidence">
                <strong id="confidence">0%</strong>
                <span>AI CONFIDENCE</span>
            </div>

        </div>


        <div class="progress">
            <div class="progress-bar" id="confidenceBar"></div>
        </div>


        <div class="stats">

            <div class="stat">
                <label>PHISHING PROBABILITY</label>
                <strong id="phishingProbability">0%</strong>
            </div>

            <div class="stat">
                <label>LEGITIMATE PROBABILITY</label>
                <strong id="legitimateProbability">0%</strong>
            </div>

            <div class="stat">
                <label>MODEL</label>
                <strong id="modelStat">ML</strong>
            </div>

        </div>

    </div>



    <!-- SECURITY SCORE -->
    <div class="card" style="margin-top:18px;">
        <div class="card-title">🛡 Security Score & Risk Profile</div>
        <div class="score-wrap">
            <div class="score-ring" id="scoreRing">
                <div class="score-number"><strong id="securityScore">0</strong><span>/ 100</span></div>
            </div>
            <div class="risk-list">
                <div class="risk-row"><span>Domain Risk</span><div class="risk-track"><div class="risk-fill" id="domainRiskBar"></div></div><strong id="domainRiskText">—</strong></div>
                <div class="risk-row"><span>URL Structure</span><div class="risk-track"><div class="risk-fill" id="urlRiskBar"></div></div><strong id="urlRiskText">—</strong></div>
                <div class="risk-row"><span>Encryption</span><div class="risk-track"><div class="risk-fill" id="encryptionRiskBar"></div></div><strong id="encryptionRiskText">—</strong></div>
                <div class="risk-row"><span>Threat Signals</span><div class="risk-track"><div class="risk-fill" id="threatRiskBar"></div></div><strong id="threatRiskText">—</strong></div>
            </div>
        </div>
    </div>

    <!-- DOMAIN INTELLIGENCE -->
    <div class="card" style="margin-top:18px;">
        <div class="card-title">🌐 Domain Intelligence</div>
        <div class="domain-grid">
            <div class="domain-cell"><label>HOSTNAME</label><strong id="domainHost">—</strong></div>
            <div class="domain-cell"><label>ROOT DOMAIN</label><strong id="rootDomain">—</strong></div>
            <div class="domain-cell"><label>TLD</label><strong id="domainTld">—</strong></div>
            <div class="domain-cell"><label>TRUST STATUS</label><strong id="trustStatus">—</strong></div>
            <div class="domain-cell"><label>SCHEME</label><strong id="schemeValue">—</strong></div>
            <div class="domain-cell"><label>PORT</label><strong id="domainPort">—</strong></div>
            <div class="domain-cell"><label>PATH</label><strong id="pathValue">—</strong></div>
            <div class="domain-cell"><label>QUERY PARAMS</label><strong id="queryCount">—</strong></div>
        </div>
    </div>

    <!-- AI EXPLANATION -->
    <div class="card" style="margin-top:18px;">
        <div class="card-title">🤖 AI Decision Explanation</div>
        <div id="aiExplanation" class="findings"></div>
    </div>

    <!-- REDIRECT ANALYSIS -->
    <div class="card" style="margin-top:18px;">
        <div class="card-title">🔀 Redirect Analysis</div>
        <div id="redirectSummary" style="color:var(--muted);font-size:12px;margin-bottom:12px;">No redirect data yet.</div>
        <div id="redirectChain" class="redirects"></div>
    </div>

    <!-- ACTIONS -->
    <div class="card" id="reportTools" style="margin-top:18px;">
        <div class="card-title">📄 Project Tools</div>
        <div class="action-row">
            <button class="action-btn" onclick="downloadReport()">⬇ Download Security Report</button>
            <button class="action-btn" onclick="window.print()">🖨 Print Report</button>
        </div>
    </div>

    <!-- SCAN HISTORY -->
    <div class="card" id="historyPanel" style="margin-top:18px;">
        <div class="card-title" style="display:flex;justify-content:space-between;align-items:center;gap:12px;">
            <span>📜 Recent Scan History</span>
            <button class="history-clear-btn" onclick="clearAllHistory()">🗑 Clear All</button>
        </div>
        <div id="scanHistory" class="history"><div style="color:var(--muted);font-size:12px;">No scans recorded yet.</div></div>
    </div>

    <!-- URL EXISTENCE / LIVE CHECK -->

    <div class="card" style="margin-top:18px;">

        <div class="card-title">🌐 Live URL Verification</div>

        <div class="existence-grid">

            <div class="existence-status">
                <div id="existenceDot" class="existence-dot"></div>
                <div class="existence-main">
                    <strong id="existenceStatus">CHECKING...</strong>
                    <small id="existenceMessage">Checking whether the URL is reachable...</small>
                </div>
            </div>

            <div class="existence-meta">
                <div class="stat">
                    <label>HTTP STATUS</label>
                    <strong id="httpStatusValue">—</strong>
                </div>
                <div class="stat">
                    <label>RESPONSE TIME</label>
                    <strong id="responseTimeValue">—</strong>
                </div>
            </div>

        </div>

        <div style="height:10px"></div>

        <div class="url-box" id="finalURLValue">—</div>

    </div>


    <div class="grid">

        <!-- URL INTELLIGENCE -->

        <div class="card">

            <div class="card-title">🔎 URL Intelligence</div>

            <div class="url-box" id="fullURL"></div>

            <div style="height:15px"></div>

            <div class="intel">

                <div class="intel-item">
                    <label>HTTPS</label>
                    <span id="httpsValue">—</span>
                </div>

                <div class="intel-item">
                    <label>IP ADDRESS</label>
                    <span id="ipValue">—</span>
                </div>

                <div class="intel-item">
                    <label>URL LENGTH</label>
                    <span id="lengthValue">—</span>
                </div>

                <div class="intel-item">
                    <label>SUBDOMAINS</label>
                    <span id="subdomainValue">—</span>
                </div>

                <div class="intel-item">
                    <label>SUSPICIOUS TLD</label>
                    <span id="tldValue">—</span>
                </div>

                <div class="intel-item">
                    <label>URL SHORTENER</label>
                    <span id="shortenerValue">—</span>
                </div>

                <div class="intel-item">
                    <label>@ SYMBOL</label>
                    <span id="atValue">—</span>
                </div>

                <div class="intel-item">
                    <label>PHISHING KEYWORDS</label>
                    <span id="keywordValue">—</span>
                </div>

                <div class="intel-item">
                    <label>DOMAIN LENGTH</label>
                    <span id="domainValue">—</span>
                </div>

                <div class="intel-item">
                    <label>PORT</label>
                    <span id="portValue">—</span>
                </div>

                <div class="intel-item">
                    <label>REDIRECT</label>
                    <span id="redirectValue">—</span>
                </div>

                <div class="intel-item">
                    <label>ENTROPY</label>
                    <span id="entropyValue">—</span>
                </div>

            </div>

        </div>


        <!-- SECURITY FINDINGS -->

        <div class="card">

            <div class="card-title">🛡 Security Findings</div>

            <div id="findings"></div>

        </div>

    </div>


    <!-- PROBABILITY -->

    <div class="card" style="margin-top:18px;">

        <div class="card-title">🧠 Detection Probability</div>

        <div class="prob">

            <div class="prob-head">
                <span>Phishing</span>
                <span id="phishProbText">0%</span>
            </div>

            <div class="prob-track">
                <div class="prob-fill"
                     id="phishProbBar"
                     style="background:linear-gradient(90deg,#ff355d,#ff7b54)">
                </div>
            </div>

        </div>


        <div class="prob">

            <div class="prob-head">
                <span>Legitimate</span>
                <span id="legitProbText">0%</span>
            </div>

            <div class="prob-track">
                <div class="prob-fill"
                     id="legitProbBar"
                     style="background:linear-gradient(90deg,#19d98b,#35d9ff)">
                </div>
            </div>

        </div>

    </div>


    <!-- ENGINE INFORMATION -->

    <div class="grid">

        <div class="card">

            <div class="card-title">⚙ Detection Engine</div>

            <div class="finding">
                <div class="check good">✓</div>
                <span>Machine-learning URL classifier</span>
            </div>

            <div class="finding">
                <div class="check good">✓</div>
                <span>URL structural feature analysis</span>
            </div>

            <div class="finding">
                <div class="check good">✓</div>
                <span>Suspicious keyword detection</span>
            </div>

            <div class="finding">
                <div class="check good">✓</div>
                <span>Domain and protocol analysis</span>
            </div>

        </div>


        <div class="card">

            <div class="card-title">📊 Model Information</div>

            <div class="finding">
                <div class="check good">✓</div>
                <span>Hybrid ML + domain verification</span>
            </div>

            <div class="finding">
                <div class="check good">✓</div>
                <span>URL feature extraction</span>
            </div>

            <div class="finding">
                <div class="check good">✓</div>
                <span>Probability-based prediction</span>
            </div>

            <div class="finding">
                <div class="check good">✓</div>
                <span>Local model inference</span>
            </div>

        </div>

    </div>

</section>




<!-- THREAT ANALYTICS -->
<section class="card analytics-card" id="analyticsDashboard">
    <div class="analytics-header">
        <div class="card-title" style="margin:0">📡 Cyber Threat Analytics</div>
        <div class="analytics-live">● LIVE SCAN DATA</div>
    </div>

    <div class="analytics-grid">
        <div class="metric"><label>TOTAL SCANS</label><strong id="metricTotal">0</strong><small>Browser scan history</small></div>
        <div class="metric"><label>PHISHING</label><strong id="metricPhishing">0</strong><small>High-risk detections</small></div>
        <div class="metric"><label>SUSPICIOUS</label><strong id="metricSuspicious">0</strong><small>Needs review</small></div>
        <div class="metric"><label>LEGITIMATE</label><strong id="metricLegitimate">0</strong><small>Low-risk detections</small></div>
    </div>

    <div class="analytics-main">
        <div class="panel-mini">
            <h4>📈 Scan Activity Trend</h4>
            <div class="trend" id="trendChart"></div>
            <div class="analytics-note">The chart is generated from scans performed in this browser. It is not external global threat telemetry.</div>
        </div>
        <div class="panel-mini">
            <h4>⚡ Live Threat Feed</h4>
            <div class="feed" id="threatFeed"></div>
        </div>
    </div>

    <div class="panel-mini" style="margin-top:14px;">
        <h4>🎯 Threat Indicator Frequency</h4>
        <div class="indicator-list" id="indicatorList"></div>
    </div>

    <div class="panel-mini" style="margin-top:14px;">
        <h4>🌐 Threat Landscape</h4>
        <div class="landscape" id="threatLandscape">
            <div class="zone"><span>WEB</span><strong>0 scans</strong></div>
            <div class="zone"><span>FINANCE</span><strong>0 scans</strong></div>
            <div class="zone"><span>SOCIAL</span><strong>0 scans</strong></div>
            <div class="zone"><span>GAMING</span><strong>0 scans</strong></div>
            <div class="zone"><span>GOVERNMENT</span><strong>0 scans</strong></div>
            <div class="zone"><span>OTHER</span><strong>0 scans</strong></div>
        </div>
        <div class="analytics-note">Threat Landscape summarizes your application's scan activity by URL category; it does not claim to represent real-world global attacks.</div>
    </div>
</section>


<div class="footer">
    PHISHGUARD • AI-POWERED URL SECURITY • FINAL YEAR PROJECT
</div>

</div>


<script>

function quickScan(url) {
    document.getElementById("urlInput").value = url;
    scanURL();
}


function setText(id, value) {
    const element = document.getElementById(id);

    if (element) {
        element.textContent = value;
    }
}


function showScanAnimation() {
    const animation = document.getElementById("scannerAnimation");
    const scanText = document.getElementById("scanLogText");
    const scanUrl = document.getElementById("scanUrlValue");
    const url = document.getElementById("urlInput").value.trim();

    animation.style.display = "block";
    if (scanUrl) scanUrl.textContent = url || "https://example.com";

    const ids = ["stepUrl","stepDomain","stepAI","stepThreat","stepScore","stepReport"];
    ids.forEach(id => {
        const el=document.getElementById(id);
        el.classList.remove("active","done");
        if(el) el.querySelector("b").textContent="○";
    });

    const messages = [
        "Checking URL reachability ...",
        "Fetching domain intelligence ...",
        "Running AI threat model ...",
        "Scanning phishing indicators ...",
        "Calculating security score ...",
        "Generating security report ..."
    ];
    let index=0;

    function activate(i){
        if(i>0){
            const prev=document.getElementById(ids[i-1]);
            if(prev){prev.classList.remove("active");prev.classList.add("done");prev.querySelector("b").textContent="✓";}
        }
        const el=document.getElementById(ids[i]);
        if(el){el.classList.add("active");el.querySelector("b").textContent="●";}
        if(scanText) scanText.textContent=messages[i];
    }
    activate(0);
    const interval=setInterval(()=>{
        index++;
        if(index<ids.length) activate(index);
    },520);
    return interval;
}

async function scanURL() {

    const input = document.getElementById("urlInput");
    const url = input.value.trim();

    if (!url) {
        alert("Please enter a URL first.");
        return;
    }


    document.getElementById("result").style.display = "none";

    const animationTimer = showScanAnimation();


    try {

        const response = await fetch("/check", {

            method: "POST",

            headers: {
                "Content-Type": "application/json"
            },

            body: JSON.stringify({
                url: url
            })

        });


        const data = await response.json();


        if (!response.ok || data.error) {

            document.getElementById("scannerAnimation").style.display = "none";

            alert(data.error || "Something went wrong.");

            return;
        }


        setTimeout(() => {
            clearInterval(animationTimer);
            document.getElementById("scannerAnimation").style.display = "none";
            displayResult(data);
        }, 3000);


    } catch (error) {

        clearInterval(animationTimer);

        document.getElementById("scannerAnimation").style.display = "none";

        alert("Unable to connect to the Flask server.");

    }

}


function displayResult(data) {

    document.getElementById("result").style.display = "block";


    const status = String(
        data.status || data.prediction || "UNKNOWN"
    ).toUpperCase();

    const isPhishing = status === "PHISHING";
    const isSuspicious = status === "SUSPICIOUS";
    const isLegitimate = status === "LEGITIMATE";


    const confidence =
        Number(data.confidence || 0);


    const phishingProbability =
        Number(
            data.phishing_probability ??
            data.phishing_prob ??
            (isPhishing ? confidence : 100 - confidence)
        );


    const legitimateProbability =
        Number(
            data.legitimate_probability ??
            data.legitimate_prob ??
            (isPhishing ? 100 - confidence : confidence)
        );


    /* VERDICT */

    const icon = document.getElementById("verdictIcon");

    if (isPhishing) {

        icon.className = "verdict-icon danger";
        icon.textContent = "⚠";

    } else if (isSuspicious) {

        icon.className = "verdict-icon warn";
        icon.textContent = "!";

    } else {

        icon.className = "verdict-icon safe";
        icon.textContent = "✓";

    }


    setText(
        "prediction",
        isPhishing ? "PHISHING DETECTED" :
        isSuspicious ? "SUSPICIOUS URL" :
        "LEGITIMATE"
    );

    setText(
        "modelName",
        data.model || data.model_used || "AI Threat Intelligence"
    );


    setText(
        "confidence",
        confidence.toFixed(1) + "%"
    );


    document.getElementById("confidenceBar").style.width =
        Math.min(confidence, 100) + "%";


    setText(
        "phishingProbability",
        phishingProbability.toFixed(1) + "%"
    );


    setText(
        "legitimateProbability",
        legitimateProbability.toFixed(1) + "%"
    );


    setText(
        "phishProbText",
        phishingProbability.toFixed(1) + "%"
    );


    setText(
        "legitProbText",
        legitimateProbability.toFixed(1) + "%"
    );


    setText(
        "modelStat",
        data.model || "ML"
    );


    document.getElementById("phishProbBar").style.width =
        Math.min(phishingProbability, 100) + "%";


    document.getElementById("legitProbBar").style.width =
        Math.min(legitimateProbability, 100) + "%";


    /* URL */

    setText(
        "fullURL",
        data.url || "Unknown"
    );


    /* LIVE URL EXISTENCE */

    const live = data.url_existence || {};
    const existenceDot = document.getElementById("existenceDot");
    const existenceStatus = document.getElementById("existenceStatus");
    const existenceMessage = document.getElementById("existenceMessage");

    if (existenceDot) {
        existenceDot.className = "existence-dot";
    }

    const liveStatus = String(live.status || "UNKNOWN").toUpperCase();

    if (liveStatus === "EXISTS") {
        setText("existenceStatus", "✓ URL EXISTS");
        setText("existenceMessage", live.message || "The server responded successfully.");
    } else if (liveStatus === "NOT_FOUND") {
        if (existenceDot) existenceDot.className = "existence-dot bad";
        setText("existenceStatus", "✗ URL NOT FOUND");
        setText("existenceMessage", live.message || "The server returned a not-found response.");
    } else {
        if (existenceDot) existenceDot.className = "existence-dot warn";
        setText("existenceStatus", "⚠ URL STATUS UNKNOWN");
        setText("existenceMessage", live.message || "The URL could not be verified right now.");
    }

    setText("httpStatusValue", live.status_code ?? "—");
    setText(
        "responseTimeValue",
        live.response_time_ms != null ? live.response_time_ms + " ms" : "—"
    );
    setText("finalURLValue", live.final_url || data.url || "—");


    const f = data.features || data;


    /* FEATURES */

    setText(
        "httpsValue",
        f.has_https ? "✓ Secure" : "✗ No HTTPS"
    );


    setText(
        "ipValue",
        f.has_ip || f.has_IP_in_url
            ? "⚠ Detected"
            : "✓ No"
    );


    setText(
        "lengthValue",
        f.url_length ?? "—"
    );


    setText(
        "subdomainValue",
        f.num_subdomains ?? "—"
    );


    setText(
        "tldValue",
        f.has_suspicious_tld
            ? "⚠ Suspicious"
            : "✓ Normal"
    );


    setText(
        "shortenerValue",
        f.uses_url_shortener
            ? "⚠ Yes"
            : "✓ No"
    );


    setText(
        "atValue",
        f.has_at_symbol
            ? "⚠ Present"
            : "✓ None"
    );


    setText(
        "keywordValue",
        f.num_phishing_keywords ?? "—"
    );


    setText(
        "domainValue",
        f.domain_length ?? "—"
    );


    setText(
        "portValue",
        f.has_port
            ? "⚠ Present"
            : "✓ Standard"
    );


    setText(
        "redirectValue",
        f.has_redirect
            ? "⚠ Detected"
            : "✓ None"
    );


    setText(
        "entropyValue",
        f.hostname_entropy !== undefined
            ? Number(f.hostname_entropy).toFixed(2)
            : "—"
    );


    /* FINDINGS */

    createFindings(f, isPhishing, isSuspicious);
    window.lastScanData = data;
    updateAdvanced(data, status, phishingProbability);
    saveHistory(data, status);


    window.scrollTo({
        top: document.getElementById("result").offsetTop - 20,
        behavior: "smooth"
    });

}


function createFindings(f, isPhishing, isSuspicious) {

    const findings = document.getElementById("findings");

    findings.innerHTML = "";


    const checks = [];


    checks.push({
        good: !!f.has_https,
        text: f.has_https
            ? "HTTPS encryption detected"
            : "URL does not use HTTPS"
    });


    checks.push({
        good: !(f.has_ip || f.has_IP_in_url),
        text: (f.has_ip || f.has_IP_in_url)
            ? "IP address detected in URL"
            : "No IP address detected"
    });


    checks.push({
        good: !f.has_suspicious_tld,
        text: f.has_suspicious_tld
            ? "Suspicious top-level domain detected"
            : "TLD does not match suspicious list"
    });


    checks.push({
        good: !f.uses_url_shortener,
        text: f.uses_url_shortener
            ? "URL shortener detected"
            : "No URL shortener detected"
    });


    checks.push({
        good: !f.has_at_symbol,
        text: f.has_at_symbol
            ? "@ symbol found in URL"
            : "No @ symbol detected"
    });


    const keywordCount =
        Number(f.num_phishing_keywords || 0);


    checks.push({
        good: keywordCount === 0,
        text: keywordCount > 0
            ? keywordCount + " suspicious keyword(s) detected"
            : "No suspicious keywords detected"
    });


    checks.forEach(item => {

        const row = document.createElement("div");

        row.className = "finding";


        const icon = document.createElement("div");

        icon.className =
            "check " + (item.good ? "good" : "bad");

        icon.textContent =
            item.good ? "✓" : "⚠";


        const text = document.createElement("span");

        text.textContent = item.text;


        row.appendChild(icon);
        row.appendChild(text);

        findings.appendChild(row);

    });


    if (isPhishing || isSuspicious) {

        const row = document.createElement("div");

        row.className = "finding";


        const icon = document.createElement("div");

        icon.className = isPhishing ? "check bad" : "check warn";
        icon.textContent = "⚠";


        const text = document.createElement("span");

        text.textContent = isPhishing
            ? "Machine-learning model classified this URL as phishing"
            : "Machine-learning model flagged this URL for further review";


        row.appendChild(icon);
        row.appendChild(text);

        findings.appendChild(row);
    }

}



function riskLabel(value){
    value=Number(value||0);
    return value>=70?'HIGH':value>=40?'MEDIUM':'LOW';
}
function setRisk(barId,textId,value){
    const v=Math.max(0,Math.min(100,Number(value||0)));
    const bar=document.getElementById(barId); if(bar) bar.style.width=v+'%';
    setText(textId,riskLabel(v));
}
function updateAdvanced(data,status,phishingProbability){
    const f=data.features||data;
    const d=data.domain_intelligence||{};
    const score=Number(data.security_score??(status==='PHISHING'?10:status==='SUSPICIOUS'?45:92));
    setText('securityScore',Math.round(score));
    const ring=document.getElementById('scoreRing'); if(ring) ring.style.background=`conic-gradient(var(--cyan) ${score*3.6}deg,#182438 ${score*3.6}deg)`;
    setRisk('domainRiskBar','domainRiskText',d.risk||((f.has_ip||f.has_suspicious_tld)?75:15));
    setRisk('urlRiskBar','urlRiskText',Math.min(100,(Number(f.num_phishing_keywords||0)*18)+(f.has_at_symbol?25:0)+(f.uses_url_shortener?20:0)+(Number(f.url_length||0)>150?20:0)));
    setRisk('encryptionRiskBar','encryptionRiskText',f.has_https?5:70);
    setRisk('threatRiskBar','threatRiskText',phishingProbability);
    setText('domainHost',d.hostname||'—'); setText('rootDomain',d.root_domain||'—'); setText('domainTld',d.tld||'—');
    setText('trustStatus',d.trusted?'✓ VERIFIED':'Unknown / ML analyzed'); setText('schemeValue',d.scheme||'—'); setText('domainPort',d.port||'Standard'); setText('pathValue',d.path||'/'); setText('queryCount',d.query_params??0);

    const explanation=document.getElementById('aiExplanation'); if(explanation){ explanation.innerHTML='';
        const reasons=(data.ai_explanation||[]); if(!reasons.length) reasons.push(status==='LEGITIMATE'?'No major phishing indicators detected.':'The model found signals that require caution.');
        reasons.forEach(r=>{const row=document.createElement('div');row.className='finding';const icon=document.createElement('div');icon.className='check '+(r.level==='good'?'good':r.level==='warn'?'warn':'bad');icon.textContent=r.level==='good'?'✓':'⚠';const txt=document.createElement('span');txt.textContent=r.text;row.append(icon,txt);explanation.appendChild(row);});
    }
    const live=data.url_existence||{}; const chain=live.redirect_chain||[]; setText('redirectSummary',chain.length?`${chain.length-1} redirect(s) followed before the final response.`:'No redirects detected.');
    const chainEl=document.getElementById('redirectChain'); if(chainEl){chainEl.innerHTML=''; (chain.length?chain:[data.url||'']).forEach((u,i)=>{const c=document.createElement('span');c.className='redirect-chip';c.textContent=u;chainEl.appendChild(c);if(i<(chain.length?chain.length-1:0)){const a=document.createElement('span');a.className='arrow';a.textContent='→';chainEl.appendChild(a);}})}
}
function saveHistory(data,status){
    const key='phishguard_history'; let h=[]; try{h=JSON.parse(localStorage.getItem(key)||'[]')}catch(e){}
    h.unshift({url:data.url,status,score:data.security_score??'',time:new Date().toISOString(),features:data.features||{}}); h=h.slice(0,8); localStorage.setItem(key,JSON.stringify(h)); renderHistory(); renderAnalytics();
}
function renderHistory(){
    const el=document.getElementById('scanHistory'); if(!el)return; let h=[]; try{h=JSON.parse(localStorage.getItem('phishguard_history')||'[]')}catch(e){}
    if(!h.length){el.innerHTML='<div style="color:var(--muted);font-size:12px;">No scans recorded yet.</div>';return;}
    el.innerHTML=h.map((x,i)=>`<div class="history-row">
        <div class="history-main"><span class="history-url">${escapeHtml(x.url)}</span><small>${escapeHtml(x.time)}</small></div>
        <div class="history-meta"><strong>${escapeHtml(x.status)}</strong><button class="history-delete" onclick="deleteHistoryItem(${i})" title="Delete this scan">🗑</button></div>
    </div>`).join('');
}
function deleteHistoryItem(index){
    let h=[]; try{h=JSON.parse(localStorage.getItem('phishguard_history')||'[]')}catch(e){}
    if(index<0 || index>=h.length)return;
    h.splice(index,1);
    localStorage.setItem('phishguard_history',JSON.stringify(h));
    renderHistory(); renderAnalytics();
}
function clearAllHistory(){
    let h=[]; try{h=JSON.parse(localStorage.getItem('phishguard_history')||'[]')}catch(e){}
    if(!h.length){return;}
    if(!confirm('Delete all scan history? This cannot be undone.')) return;
    localStorage.removeItem('phishguard_history');
    renderHistory(); renderAnalytics();
}
function escapeHtml(v){return String(v??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c]));}
function downloadReport(){
    if(!window.lastScanData){alert('Run a scan first.');return;}
    const d=window.lastScanData, status=String(d.status||d.prediction||'UNKNOWN').toUpperCase();
    const lines=[
        'PHISHGUARD — AI URL THREAT INTELLIGENCE REPORT','='.repeat(55),
        `URL: ${d.url||''}`,`Verdict: ${status}`,`Security Score: ${d.security_score??'—'}/100`,`AI Confidence: ${d.confidence??'—'}%`,
        `Phishing Probability: ${d.phishing_probability??'—'}%`,`Legitimate Probability: ${d.legitimate_probability??'—'}%`,
        '', 'DOMAIN INTELLIGENCE', '-'.repeat(30), JSON.stringify(d.domain_intelligence||{},null,2),
        '', 'LIVE URL VERIFICATION','-'.repeat(30),JSON.stringify(d.url_existence||{},null,2),
        '', 'AI EXPLANATION','-'.repeat(30),(d.ai_explanation||[]).map(x=>'- '+x.text).join('\n'),
        '', 'NOTE: Reachability does not mean a URL is safe.'
    ].join('\n');
    const blob=new Blob([lines],{type:'text/plain'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='phishguard-security-report.txt';a.click();URL.revokeObjectURL(a.href);
}
renderHistory();



/* THREAT ANALYTICS */
function getAnalyticsHistory(){
    try{return JSON.parse(localStorage.getItem('phishguard_history')||'[]')}catch(e){return []}
}
function classifyCategory(url){
    const u=String(url||'').toLowerCase();
    if(/bank|paypal|stripe|pay|wallet|finance|upi|credit|loan/.test(u))return 'FINANCE';
    if(/facebook|instagram|twitter|x\.com|linkedin|tiktok|social/.test(u))return 'SOCIAL';
    if(/pubg|steam|epicgames|playstation|xbox|gaming/.test(u))return 'GAMING';
    if(/gov\.|nic\.in|government|irs\.|govt/.test(u))return 'GOVERNMENT';
    if(/google|github|microsoft|apple|amazon|cloudflare|wikipedia|youtube/.test(u))return 'WEB';
    return 'OTHER';
}
function renderAnalytics(){
    renderTopDashboard();
    const h=getAnalyticsHistory();
    const total=h.length, phishing=h.filter(x=>String(x.status).toUpperCase()==='PHISHING').length;
    const suspicious=h.filter(x=>String(x.status).toUpperCase()==='SUSPICIOUS').length;
    const legitimate=h.filter(x=>String(x.status).toUpperCase()==='LEGITIMATE').length;
    setText('metricTotal',total);setText('metricPhishing',phishing);setText('metricSuspicious',suspicious);setText('metricLegitimate',legitimate);

    const trend=document.getElementById('trendChart');
    if(trend){
        trend.innerHTML='';
        const days=[];
        for(let i=6;i>=0;i--){const d=new Date();d.setDate(d.getDate()-i);const key=d.toLocaleDateString();days.push({label:d.toLocaleDateString(undefined,{weekday:'short'}),count:h.filter(x=>new Date(x.time).toLocaleDateString()===key).length});}
        const max=Math.max(1,...days.map(x=>x.count));
        days.forEach(x=>{const c=document.createElement('div');c.className='trend-col';const b=document.createElement('div');b.className='trend-bar';b.style.height=Math.max(4,(x.count/max)*100)+'%';b.title=x.count+' scan(s)';const l=document.createElement('div');l.className='trend-label';l.textContent=x.label;c.append(b,l);trend.appendChild(c);});
    }

    const feed=document.getElementById('threatFeed');
    if(feed){feed.innerHTML='';const recent=h.slice(0,8);if(!recent.length){feed.innerHTML='<div style="color:var(--muted);font-size:10px">Run a scan to populate the live feed.</div>';}recent.forEach(x=>{const row=document.createElement('div');row.className='feed-item';const t=document.createElement('div');t.className='feed-time';t.textContent=new Date(x.time).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'});const u=document.createElement('div');u.className='feed-url';u.textContent=x.url;const b=document.createElement('div');const st=String(x.status).toUpperCase();b.className='badge '+(st==='PHISHING'?'bad':st==='SUSPICIOUS'?'warn':'good');b.textContent=st;row.append(t,u,b);feed.appendChild(row);});}

    const indicators={HTTPS:0,'IP URL':0,'Suspicious TLD':0,'Shortener':0,'@ Symbol':0,'Phishing Keywords':0};
    h.forEach(x=>{const f=x.features||{};if(f.has_https)indicators.HTTPS++;if(f.has_ip||f.has_IP_in_url)indicators['IP URL']++;if(f.has_suspicious_tld)indicators['Suspicious TLD']++;if(f.uses_url_shortener)indicators.Shortener++;if(f.has_at_symbol)indicators['@ Symbol']++;if(Number(f.num_phishing_keywords||0)>0)indicators['Phishing Keywords']++;});
    const il=document.getElementById('indicatorList');if(il){il.innerHTML='';Object.entries(indicators).forEach(([k,v])=>{const d=document.createElement('div');d.className='indicator';d.innerHTML='<span>'+k+'</span><span>'+v+'</span>';il.appendChild(d);});}

    const cats={WEB:0,FINANCE:0,SOCIAL:0,GAMING:0,GOVERNMENT:0,OTHER:0};h.forEach(x=>cats[classifyCategory(x.url)]++);
    const land=document.getElementById('threatLandscape');if(land){[...land.children].forEach(z=>{const k=z.querySelector('span').textContent;z.querySelector('strong').textContent=cats[k]+' scan'+(cats[k]===1?'':'s');});}
}


function navigateDash(btn,target){
  document.querySelectorAll('.side-nav button').forEach(b=>b.classList.remove('active'));
  if(btn) btn.classList.add('active');
  const el=document.getElementById(target); if(el) el.scrollIntoView({behavior:'smooth',block:'start'});
}
function openSettings(){document.getElementById('settingsModal').classList.add('show')}
function closeSettings(){document.getElementById('settingsModal').classList.remove('show')}
function renderTopDashboard(){
  const h=getAnalyticsHistory();
  const stats={total:h.length,phishing:h.filter(x=>String(x.status).toUpperCase()==='PHISHING').length,suspicious:h.filter(x=>String(x.status).toUpperCase()==='SUSPICIOUS').length,legitimate:h.filter(x=>String(x.status).toUpperCase()==='LEGITIMATE').length};
  setText('topTotal',stats.total);setText('topPhishing',stats.phishing);setText('topSuspicious',stats.suspicious);setText('topLegitimate',stats.legitimate);
  const trend=document.getElementById('topTrend');
  if(trend){
    const days=[];for(let i=6;i>=0;i--){const d=new Date();d.setDate(d.getDate()-i);const key=d.toLocaleDateString();days.push({label:d.toLocaleDateString(undefined,{weekday:'short'}),total:h.filter(x=>new Date(x.time).toLocaleDateString()===key).length,phish:h.filter(x=>new Date(x.time).toLocaleDateString()===key&&String(x.status).toUpperCase()==='PHISHING').length});}
    const max=Math.max(1,...days.map(x=>x.total));const pts=days.map((x,i)=>`${(i*100/(days.length-1)).toFixed(1)},${100-(x.total/max)*78-10}`).join(' ');const p2=days.map((x,i)=>`${(i*100/(days.length-1)).toFixed(1)},${100-(x.phish/max)*78-10}`).join(' ');
    trend.innerHTML=`<svg viewBox="0 0 100 100" preserveAspectRatio="none"><polyline points="${pts}" fill="none" stroke="#35d9ff" stroke-width="1.6" vector-effect="non-scaling-stroke"/><polyline points="${p2}" fill="none" stroke="#ff4d6d" stroke-width="1.2" vector-effect="non-scaling-stroke"/><g fill="#35d9ff">${days.map((x,i)=>`<circle cx="${(i*100/(days.length-1)).toFixed(1)}" cy="${100-(x.total/max)*78-10}" r="1.3"/>`).join('')}</g></svg>`;
  }
  const feed=document.getElementById('topThreatFeed');
  if(feed){feed.innerHTML='';h.slice(0,6).forEach(x=>{const st=String(x.status).toUpperCase();const row=document.createElement('div');row.className='top-feed-row';row.innerHTML=`<span class="time">${new Date(x.time).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'})}</span><span class="url"></span><span class="top-badge ${st==='PHISHING'?'bad':st==='SUSPICIOUS'?'warn':'good'}">${st}</span>`;row.querySelector('.url').textContent=x.url;feed.appendChild(row)});if(!h.length)feed.innerHTML='<div style="font-size:9px;color:var(--muted)">Run a scan to populate the feed.</div>'}
  const counts={HTTPS:0,'IP URL':0,'Suspicious TLD':0,Shortener:0,'@ Symbol':0,'Phishing Keywords':0};h.forEach(x=>{const f=x.features||{};if(f.has_https)counts.HTTPS++;if(f.has_ip||f.has_IP_in_url)counts['IP URL']++;if(f.has_suspicious_tld)counts['Suspicious TLD']++;if(f.uses_url_shortener)counts.Shortener++;if(f.has_at_symbol)counts['@ Symbol']++;if(Number(f.num_phishing_keywords||0)>0)counts['Phishing Keywords']++});const maxI=Math.max(1,...Object.values(counts));const il=document.getElementById('topIndicators');if(il){il.innerHTML=Object.entries(counts).slice(0,5).map(([k,v])=>`<div class="ibar"><span>${k}</span><div class="ibar-track"><div class="ibar-fill" style="width:${v/maxI*100}%"></div></div><b>${v}</b></div>`).join('')}
}

/* ENTER KEY */

document
    .getElementById("urlInput")
    .addEventListener("keydown", function(event) {

        if (event.key === "Enter") {
            scanURL();
        }

    });

</script>


<div class="settings-modal" id="settingsModal" onclick="if(event.target===this)closeSettings()"><div class="settings-box"><h3>⚙ PhishGuard Settings</h3><p><b>Detection Engine:</b> Hybrid ML + Domain Verification<br><b>URL Verification:</b> Live HTTP/DNS check<br><b>History:</b> Stored locally in this browser<br><b>Analytics:</b> Based on scans performed in this browser<br><b>Privacy:</b> No account or external telemetry is required for the dashboard.</p><button class="settings-close" onclick="closeSettings()">CLOSE SETTINGS</button></div></div>

</body>
</html>
"""



def domain_intelligence(url):
    parsed=urlparse(url)
    hostname=(parsed.hostname or '').lower().rstrip('.')
    labels=hostname.split('.') if hostname else []
    if len(labels)>=3 and labels[-2] in {'co','com','org','net','gov','ac'}:
        root='.'.join(labels[-3:])
    elif len(labels)>=2:
        root='.'.join(labels[-2:])
    else:
        root=hostname
    trusted=detector._is_trusted_domain(hostname)
    return {
        'hostname':hostname,
        'root_domain':root,
        'tld':('.'+labels[-1]) if labels else '',
        'scheme':parsed.scheme.upper() if parsed.scheme else '',
        'port':parsed.port,
        'path':parsed.path or '/',
        'query_params':len(parse_qsl(parsed.query,keep_blank_values=True)),
        'trusted':trusted,
        'risk':15 if trusted else (75 if len(labels)>4 else 35)
    }

def build_security_score(result, live, domain):
    status=str(result.get('status') or result.get('prediction') or '').upper()
    if domain['trusted'] and status=='LEGITIMATE': return 96
    if status=='PHISHING': return max(5, round(100-float(result.get('phishing_probability',90))))
    if status=='SUSPICIOUS': return 45
    score=80
    f=result.get('features') or result
    score-=20 if f.get('has_ip') or f.get('has_IP_in_url') else 0
    score-=12 if f.get('has_suspicious_tld') else 0
    score-=10 if f.get('uses_url_shortener') else 0
    score-=8 if f.get('has_at_symbol') else 0
    score-=min(15,int(f.get('num_phishing_keywords',0))*5)
    score-=10 if not f.get('has_https') else 0
    return max(0,min(100,score))

def build_ai_explanation(result, domain):
    f=result.get('features') or result
    status=str(result.get('status') or result.get('prediction') or '').upper()
    out=[]
    if domain['trusted'] and status=='LEGITIMATE': out.append({'level':'good','text':f"Domain matches a trusted root: {domain['root_domain']}"})
    if f.get('has_https'): out.append({'level':'good','text':'HTTPS encryption is enabled.'})
    else: out.append({'level':'warn','text':'The URL does not use HTTPS.'})
    if f.get('has_ip') or f.get('has_IP_in_url'): out.append({'level':'bad','text':'An IP address is used in the URL.'})
    if f.get('has_suspicious_tld'): out.append({'level':'bad','text':'The top-level domain is on the suspicious-TLD list.'})
    if f.get('uses_url_shortener'): out.append({'level':'warn','text':'A URL-shortening service was detected.'})
    if f.get('has_at_symbol'): out.append({'level':'bad','text':'An @ symbol can obscure the actual destination.'})
    kw=int(f.get('num_phishing_keywords',0) or 0)
    if kw: out.append({'level':'warn','text':f'{kw} phishing-related keyword(s) were detected.'})
    if not any(x['level']=='bad' for x in out): out.append({'level':'good','text':'No high-severity URL structure indicators were detected.'})
    return out

def check_url_existence(url):
    """Check whether a URL is reachable without treating reachability as safety."""
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return {
            "status": "CHECK_FAILED",
            "exists": False,
            "message": "Invalid hostname."
        }

    # Do not make the demo server probe private/local network targets.
    try:
        addresses = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        for item in addresses:
            ip_text = item[4][0]
            ip_obj = ipaddress.ip_address(ip_text)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_reserved:
                return {
                    "status": "CHECK_FAILED",
                    "exists": False,
                    "message": "Local/private network URL was not probed.",
                    "status_code": None
                }
    except socket.gaierror:
        return {
            "status": "NOT_FOUND",
            "exists": False,
            "message": "Domain name could not be resolved (DNS lookup failed).",
            "status_code": None
        }
    except Exception:
        # Continue to the HTTP check; some environments restrict DNS details.
        pass

    headers = {
        "User-Agent": "PhishGuard/1.0 URL Verification",
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
    }
    started = time.perf_counter()

    try:
        try:
            response = requests.head(
                url,
                allow_redirects=True,
                timeout=6,
                headers=headers
            )

            # Some websites reject HEAD. Retry with a tiny streamed GET.
            if response.status_code in (405, 501) or response.status_code == 0:
                response = requests.get(
                    url,
                    allow_redirects=True,
                    timeout=6,
                    headers=headers,
                    stream=True
                )
        except requests.RequestException:
            # HTTPS can fail because of certificate/configuration problems.
            # Try HTTP only as an existence check; never call this phishing.
            if parsed.scheme == "https":
                http_url = "http://" + parsed.netloc + (parsed.path or "")
                if parsed.query:
                    http_url += "?" + parsed.query
                response = requests.head(
                    http_url,
                    allow_redirects=True,
                    timeout=6,
                    headers=headers
                )
            else:
                raise

        elapsed = round((time.perf_counter() - started) * 1000)
        code = response.status_code
        final_url = response.url

        if 200 <= code < 400:
            status = "EXISTS"
            message = "The URL responded and is reachable."
        elif code == 404:
            status = "NOT_FOUND"
            message = "The server responded, but this specific URL was not found."
        elif 400 <= code < 500:
            # 401/403/405 still prove that a server/resource exists.
            status = "EXISTS"
            message = f"The server responded with HTTP {code}; the resource may require access or a different request method."
        elif 500 <= code < 600:
            status = "EXISTS"
            message = f"The server is reachable but returned HTTP {code}."
        else:
            status = "UNKNOWN"
            message = f"Received an unexpected HTTP status ({code})."

        return {
            "status": status,
            "exists": status == "EXISTS",
            "message": message,
            "status_code": code,
            "final_url": final_url,
            "response_time_ms": elapsed
        }

    except requests.exceptions.Timeout:
        elapsed = round((time.perf_counter() - started) * 1000)
        return {
            "status": "UNKNOWN",
            "exists": None,
            "message": "The server did not respond within the verification timeout.",
            "status_code": None,
            "response_time_ms": elapsed
        }
    except requests.exceptions.SSLError:
        elapsed = round((time.perf_counter() - started) * 1000)
        return {
            "status": "EXISTS",
            "exists": True,
            "message": "The domain responded, but its HTTPS certificate could not be verified.",
            "status_code": None,
            "response_time_ms": elapsed
        }
    except requests.exceptions.RequestException as exc:
        elapsed = round((time.perf_counter() - started) * 1000)
        return {
            "status": "UNKNOWN",
            "exists": None,
            "message": "The URL could not be verified: " + str(exc),
            "status_code": None,
            "response_time_ms": elapsed
        }


@app.route("/")
def home():
    return render_template_string(HTML)


@app.route("/check", methods=["POST"])
def check():

    try:

        data = request.get_json(silent=True) or {}

        url = str(data.get("url", "")).strip()

        if not url:
            return jsonify({
                "error": "URL is required"
            }), 400


        # Basic normalization
        if not url.startswith(("http://", "https://")):
            url = "http://" + url


        # Check live reachability independently from phishing classification.
        # A URL can exist and still be phishing; a missing URL can also be legitimate.
        url_existence = check_url_existence(url)

        # Use your existing ML detector.
        result = detector.explain_prediction(url)

        result["url_existence"] = url_existence
        result["domain_intelligence"] = domain_intelligence(url)
        result["security_score"] = build_security_score(result, url_existence, result["domain_intelligence"])
        result["ai_explanation"] = build_ai_explanation(result, result["domain_intelligence"])


        # Make sure URL is included
        if isinstance(result, dict):
            result["url"] = url


        return jsonify(result)


    except Exception as e:

        print("ERROR:", e)

        return jsonify({
            "error": str(e)
        }), 500


if __name__ == "__main__":

    print("")
    print("=" * 60)
    print("        PHISHGUARD - AI URL THREAT DETECTOR")
    print("=" * 60)
    print("Server: http://127.0.0.1:5000")
    print("=" * 60)
    print("")

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )