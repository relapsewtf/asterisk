import React, { useEffect, useState } from 'react';
import './App.css';


function ScorePill({ score }){
const cls = score >= 70 ? 'pill high' : score >= 40 ? 'pill med' : 'pill low';
return <div className={cls}>{score}</div>
}


export default function App(){
const [findings, setFindings] = useState([]);
useEffect(()=>{
fetch('/api/findings')
.then(r=>r.json())
.then(setFindings)
.catch(()=>{
// fallback to static copy
fetch('/findings.json').then(r=>r.json()).then(setFindings).catch(()=>setFindings([]));
})
},[]);


return (
<div className="app-root">
<header className="topbar">
<h1>ExecArtefactHunter</h1>
<div className="sub">Unified execution artifact scanner</div>
</header>


<main className="grid">
{findings.length === 0 ? (
<div className="empty">No findings yet — run the collector and drop <code>findings.json</code> into the UI public folder.</div>
) : (
findings.map((f, i) => (
<div className="card" key={i}>
<div className="card-left">
<div className="path">{f.path}</div>
<div className="meta">SHA256: {f.sha256}</div>
<div className="meta">Entropy: {f.entropy.toFixed(3)}</div>
<div className="meta">PE: {f.is_pe ? 'Yes' : 'No'}</div>
</div>
<div className="card-right">
<ScorePill score={computeScore(f)} />
</div>
</div>
))
)}
</main>


<footer className="foot">Collector • Correlator • Rule Engine</footer>
</div>
)
}


function computeScore(rec){
// simple scoring for UI preview
let score = 0;
if(rec.is_pe && rec.has_icon === false && rec.requested_execution_level === 'requireAdministrator') score += 40;
if(rec.entropy > 7.0) score += 30;
// signature/USN unavailable in starter JSON: leave for later
return
