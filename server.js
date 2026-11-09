require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const crypto = require('crypto');
const path = require('path');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProd = process.env.NODE_ENV === 'production';
if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  if (isProd) throw new Error('SESSION_SECRET must be at least 32 characters in production.');
  console.warn('WARNING: Set a long random SESSION_SECRET in .env before deployment.');
}
const db = new Database(path.join(__dirname, 'encodex.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, username TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL, password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
 status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','suspended','banned')),
 points INTEGER NOT NULL DEFAULT 0 CHECK(points >= 0), referral_code TEXT NOT NULL UNIQUE,
 referred_by TEXT REFERENCES users(id), created_at TEXT NOT NULL, last_login TEXT,
 ban_reason TEXT, ban_expires_at TEXT, ban_permanent INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS activation_codes (
 code TEXT PRIMARY KEY, role TEXT NOT NULL DEFAULT 'user', created_by TEXT NOT NULL,
 created_at TEXT NOT NULL, used_by TEXT REFERENCES users(id), used_at TEXT
);
CREATE TABLE IF NOT EXISTS withdrawals (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), points INTEGER NOT NULL,
 amount_php REAL NOT NULL, method TEXT NOT NULL, account_name TEXT NOT NULL,
 account_number TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', admin_note TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS point_transactions (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), previous_balance INTEGER NOT NULL,
 delta INTEGER NOT NULL, new_balance INTEGER NOT NULL, reason TEXT, admin_id TEXT NOT NULL REFERENCES users(id),
 created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ban_history (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), action TEXT NOT NULL,
 reason TEXT, expires_at TEXT, permanent INTEGER NOT NULL DEFAULT 0,
 admin_id TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_logs (
 id TEXT PRIMARY KEY, admin_id TEXT, action TEXT NOT NULL, target_user_id TEXT,
 details TEXT NOT NULL DEFAULT '{}', ip TEXT, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS task_challenges (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), room TEXT NOT NULL,
 question TEXT NOT NULL, answer_hash TEXT NOT NULL, expires_at INTEGER NOT NULL,
 created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_bans_user ON ban_history(user_id,created_at);
CREATE INDEX IF NOT EXISTS idx_points_user ON point_transactions(user_id,created_at);
`);
const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const code = (prefix='EX', n=9) => prefix + '-' + crypto.randomBytes(n).toString('hex').slice(0,n).toUpperCase();
const hashAnswer = s => crypto.createHash('sha256').update(String(s).toLowerCase()).digest('hex');
const audit = (adminId, action, targetId=null, details={}) => db.prepare('INSERT INTO audit_logs(id,admin_id,action,target_user_id,details,ip,created_at) VALUES(?,?,?,?,?,?,?)').run(id(),adminId,action,targetId,JSON.stringify(details),null,now());

// Bootstrap exactly one initial owner from environment variables; never hard-code credentials.
if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
 const email = process.env.ADMIN_EMAIL.trim().toLowerCase();
 const existing = db.prepare('SELECT id FROM users WHERE email=?').get(email);
 if (!existing) {
  const uid=id(), username='OWNER'+crypto.randomBytes(3).toString('hex').toUpperCase();
  db.prepare(`INSERT INTO users(id,email,username,name,password_hash,role,referral_code,created_at)
   VALUES(?,?,?,?,?,'owner',?,?)`).run(uid,email,username,process.env.ADMIN_NAME||'ENCODE-X Owner',bcrypt.hashSync(process.env.ADMIN_PASSWORD,12),code('REF'),now());
  console.log('Initial owner created:',email,'username:',username);
 }
}
if (process.env.INITIAL_ACTIVATION_CODE && !db.prepare('SELECT code FROM activation_codes WHERE code=?').get(process.env.INITIAL_ACTIVATION_CODE)) {
 db.prepare('INSERT INTO activation_codes(code,role,created_by,created_at) VALUES(?,?,?,?)').run(process.env.INITIAL_ACTIVATION_CODE,'user','system',now());
}

app.disable('x-powered-by');
app.use(helmet({contentSecurityPolicy:{directives:{defaultSrc:["'self'"],scriptSrc:["'self'"],styleSrc:["'self'","'unsafe-inline'","https://fonts.googleapis.com"],fontSrc:["'self'","https://fonts.gstatic.com"],imgSrc:["'self'","data:"],connectSrc:["'self'"],objectSrc:["'none'"],upgradeInsecureRequests:isProd?[]:null}}}));
app.use(express.json({limit:'20kb'}));
app.use(session({name:'encodex.sid',store:new SQLiteStore({db:'sessions.sqlite',dir:__dirname}),secret:process.env.SESSION_SECRET||'dev-only-change-this-secret-before-deploying',resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'strict',secure:process.env.COOKIE_SECURE==='true',maxAge:1000*60*60*12}}));
app.use('/api/auth',rateLimit({windowMs:15*60*1000,limit:30,standardHeaders:true,legacyHeaders:false}));
app.use('/api', (req,res,next)=>{ if(req.method!=='GET' && req.get('origin')) { const origin=new URL(req.get('origin')).origin; const expected=`${req.protocol}://${req.get('host')}`; if(origin!==expected) return res.status(403).json({error:'Invalid request origin.'}); } next(); });
app.use(express.static(path.join(__dirname,'public')));

const publicUser = u => ({id:u.id,email:u.email,username:u.username,name:u.name,role:u.role,points:u.points,referralCode:u.referral_code,status:u.status,createdAt:u.created_at});
function currentUser(req){return req.session.userId?db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId):null;}
function requireAuth(req,res,next){const u=currentUser(req);if(!u)return res.status(401).json({error:'Please log in.'});if(u.status!=='active'){req.session.destroy(()=>{});return res.status(403).json({error:'ACCOUNT_SUSPENDED',reason:u.ban_reason||'Account access is restricted.',expiresAt:u.ban_expires_at,permanent:!!u.ban_permanent});}req.user=u;next();}
function requireAdmin(req,res,next){requireAuth(req,res,()=>{if(!['owner','admin'].includes(req.user.role))return res.status(403).json({error:'Administrator access required.'});next();});}
function cleanText(v,max=180){return String(v||'').trim().slice(0,max);}

// Automatically restore expired temporary suspensions before protected requests.
app.use((req,res,next)=>{try{db.prepare("UPDATE users SET status='active',ban_reason=NULL,ban_expires_at=NULL,ban_permanent=0 WHERE status='suspended' AND ban_permanent=0 AND ban_expires_at IS NOT NULL AND ban_expires_at<=?").run(now());}catch(e){console.error(e);}next();});
app.get('/api/health',(req,res)=>res.json({ok:true,service:'ENCODE-X',time:now()}));
app.post('/api/auth/signup',(req,res)=>{
 const email=cleanText(req.body.email,190).toLowerCase(), username=cleanText(req.body.username,24).toUpperCase(), name=cleanText(req.body.name,60), password=String(req.body.password||''), activation=cleanText(req.body.activationCode,40).toUpperCase(), referral=cleanText(req.body.referralCode,40).toUpperCase();
 if(!/^\S+@\S+\.\S+$/.test(email)||!/^[A-Z0-9_]{4,24}$/.test(username)||name.length<2||password.length<10)return res.status(400).json({error:'Enter valid details. Password must be at least 10 characters.'});
 const tx=db.transaction(()=>{const ac=db.prepare('SELECT * FROM activation_codes WHERE code=? AND used_by IS NULL').get(activation);if(!ac)throw Error('Invalid or already-used activation code.');if(db.prepare('SELECT id FROM users WHERE email=? OR username=?').get(email,username))throw Error('Email or username already exists.');const ref=referral?db.prepare('SELECT id FROM users WHERE referral_code=? AND status=\'active\'').get(referral):null;if(referral&&!ref)throw Error('Referral code was not found.');const uid=id();db.prepare(`INSERT INTO users(id,email,username,name,password_hash,role,referral_code,referred_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)`).run(uid,email,username,name,bcrypt.hashSync(password,12),'user',code('REF'),ref?.id||null,now());db.prepare('UPDATE activation_codes SET used_by=?,used_at=? WHERE code=?').run(uid,now(),activation);if(ref)audit(null,'referral_signup',uid,{referrerId:ref.id});return db.prepare('SELECT * FROM users WHERE id=?').get(uid);});
 try{const u=tx();req.session.userId=u.id;res.status(201).json({user:publicUser(u)});}catch(e){res.status(400).json({error:e.message});}
});
app.post('/api/auth/login',(req,res)=>{const email=cleanText(req.body.email,190).toLowerCase(),password=String(req.body.password||'');const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);if(!u||!bcrypt.compareSync(password,u.password_hash))return res.status(401).json({error:'Incorrect email or password.'});if(u.status!=='active')return res.status(403).json({error:'ACCOUNT_SUSPENDED',reason:u.ban_reason||'Account access is restricted.',expiresAt:u.ban_expires_at,permanent:!!u.ban_permanent});db.prepare('UPDATE users SET last_login=? WHERE id=?').run(now(),u.id);req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Could not create session.'});req.session.userId=u.id;res.json({user:publicUser(u)});});});
app.post('/api/auth/logout',(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get('/api/me',requireAuth,(req,res)=>res.json({user:publicUser(req.user)}));

app.get('/api/tasks/:room/challenge',requireAuth,(req,res)=>{
 const room=req.params.room;let question,answer;if(room==='captcha'){answer=crypto.randomBytes(3).toString('hex').slice(0,5).toUpperCase();question='Enter the 5 characters shown';}else if(room==='numbers'){answer=String(10+Math.floor(Math.random()*90));question='Type this number: '+answer;}else if(room==='math'){const a=2+Math.floor(Math.random()*18),b=2+Math.floor(Math.random()*18);answer=String(a+b);question=`${a} + ${b} = ?`;}else return res.status(404).json({error:'Unknown task room.'});
 const challengeId=id(),expires=Date.now()+2*60*1000;db.prepare('INSERT INTO task_challenges(id,user_id,room,question,answer_hash,expires_at,created_at) VALUES(?,?,?,?,?,?,?)').run(challengeId,req.user.id,room,question,hashAnswer(answer),expires,now());res.json({challengeId,question,visual:room==='captcha'?answer:null,expiresAt:expires});
});
app.post('/api/tasks/submit',requireAuth,(req,res)=>{const {challengeId,answer}=req.body||{};const ch=db.prepare('SELECT * FROM task_challenges WHERE id=? AND user_id=?').get(challengeId,req.user.id);if(!ch)return res.status(400).json({error:'Challenge not found.'});db.prepare('DELETE FROM task_challenges WHERE id=?').run(challengeId);if(ch.expires_at<Date.now()||hashAnswer(answer)!==ch.answer_hash)return res.status(400).json({error:'Incorrect or expired answer.'});const cfg={captcha:{points:10,seconds:10},numbers:{points:20,seconds:15},math:{points:30,seconds:20}}[ch.room];const last=db.prepare('SELECT created_at FROM point_transactions WHERE user_id=? AND reason=? ORDER BY created_at DESC LIMIT 1').get(req.user.id,'task:'+ch.room);if(last&&Date.now()-Date.parse(last.created_at)<cfg.seconds*1000)return res.status(429).json({error:`Please wait ${cfg.seconds} seconds between tasks in this room.`});db.prepare('UPDATE users SET points=points+? WHERE id=?').run(cfg.points,req.user.id);const updated=db.prepare('SELECT points FROM users WHERE id=?').get(req.user.id);db.prepare('INSERT INTO point_transactions(id,user_id,previous_balance,delta,new_balance,reason,admin_id,created_at) VALUES(?,?,?,?,?,?,?,?)').run(id(),req.user.id,updated.points-cfg.points,cfg.points,updated.points,'task:'+ch.room,req.user.id,now());res.json({ok:true,earned:cfg.points,balance:updated.points});
});
app.get('/api/referral',requireAuth,(req,res)=>{const count=db.prepare('SELECT COUNT(*) n FROM users WHERE referred_by=?').get(req.user.id).n;res.json({code:req.user.referral_code,count});});
app.post('/api/withdrawals',requireAuth,(req,res)=>{const points=Number(req.body.points),method=cleanText(req.body.method,20),accountName=cleanText(req.body.accountName,80),accountNumber=cleanText(req.body.accountNumber,80);if(!Number.isSafeInteger(points)||points<400||!['GCash','Maya'].includes(method)||!accountName||!accountNumber)return res.status(400).json({error:'Minimum 400 points. Complete all payout details.'});const tx=db.transaction(()=>{const u=db.prepare('SELECT points FROM users WHERE id=?').get(req.user.id);if(u.points<points)throw Error('Insufficient points.');db.prepare('UPDATE users SET points=points-? WHERE id=?').run(points,req.user.id);const wid=id(),t=now();db.prepare('INSERT INTO withdrawals(id,user_id,points,amount_php,method,account_name,account_number,status,created_at,updated_at) VALUES(?,?,?,?,?,?,? ,\'pending\',?,?)').run(wid,req.user.id,points,points/1000,method,accountName,accountNumber,t,t);db.prepare('INSERT INTO point_transactions(id,user_id,previous_balance,delta,new_balance,reason,admin_id,created_at) VALUES(?,?,?,?,?,?,?,?)').run(id(),req.user.id,u.points,-points,u.points-points,'withdrawal reserved: '+wid,req.user.id,t);return wid;});try{const wid=tx();res.status(201).json({ok:true,id:wid,message:'Request submitted. Admin review required.'});}catch(e){res.status(400).json({error:e.message});}});
app.get('/api/withdrawals',requireAuth,(req,res)=>{const rows=db.prepare('SELECT id,points,amount_php,method,status,admin_note,created_at,updated_at FROM withdrawals WHERE user_id=? ORDER BY created_at DESC').all(req.user.id);res.json({items:rows});});

// Admin-only code generation, ban controls, points ledger and audit history.
app.post('/api/admin/activation-codes',requireAdmin,(req,res)=>{const qty=Math.min(20,Math.max(1,Number(req.body.quantity)||1)),created=[];const tx=db.transaction(()=>{for(let i=0;i<qty;i++){let c;do{c=code();}while(db.prepare('SELECT code FROM activation_codes WHERE code=?').get(c));db.prepare('INSERT INTO activation_codes(code,role,created_by,created_at) VALUES(?,?,?,?)').run(c,'user',req.user.id,now());created.push(c);}audit(req.user.id,'activation_codes_generated',null,{quantity:qty});});tx();res.status(201).json({codes:created});});
app.get('/api/admin/users',requireAdmin,(req,res)=>{const q='%'+cleanText(req.query.q,80)+'%';const users=db.prepare(`SELECT id,email,username,name,role,status,points,referral_code,created_at,ban_reason,ban_expires_at,ban_permanent FROM users WHERE email LIKE ? OR username LIKE ? OR id LIKE ? ORDER BY created_at DESC LIMIT 100`).all(q,q,q);res.json({users});});
app.post('/api/admin/users/:id/ban',requireAdmin,(req,res)=>{const target=db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);if(!target)return res.status(404).json({error:'User not found.'});if(target.role==='owner')return res.status(403).json({error:'Owner account cannot be banned here.'});const reason=cleanText(req.body.reason,500);const permanent=!!req.body.permanent;let expires=null;if(!permanent){expires=req.body.expiresAt;if(!expires||!Number.isFinite(Date.parse(expires))||Date.parse(expires)<=Date.now())return res.status(400).json({error:'Choose a future expiration date for temporary suspension.'});expires=new Date(expires).toISOString();}if(!reason)return res.status(400).json({error:'A reason is required.'});const tx=db.transaction(()=>{db.prepare('UPDATE users SET status=?,ban_reason=?,ban_expires_at=?,ban_permanent=? WHERE id=?').run(permanent?'banned':'suspended',reason,expires,permanent?1:0,target.id);db.prepare('INSERT INTO ban_history(id,user_id,action,reason,expires_at,permanent,admin_id,created_at) VALUES(?,?,?,?,?,?,?,?)').run(id(),target.id,permanent?'permanent_ban':'temporary_suspend',reason,expires,permanent?1:0,req.user.id,now());audit(req.user.id,permanent?'user_permanently_banned':'user_suspended',target.id,{reason,expires});});tx();res.json({ok:true});});
app.post('/api/admin/users/:id/unban',requireAdmin,(req,res)=>{const target=db.prepare('SELECT * FROM users WHERE id=?').get(req.params.id);if(!target)return res.status(404).json({error:'User not found.'});const tx=db.transaction(()=>{db.prepare("UPDATE users SET status='active',ban_reason=NULL,ban_expires_at=NULL,ban_permanent=0 WHERE id=?").run(target.id);db.prepare('INSERT INTO ban_history(id,user_id,action,reason,admin_id,created_at) VALUES(?,?,?,?,?,?)').run(id(),target.id,'unbanned','Administrative reinstatement',req.user.id,now());audit(req.user.id,'user_unbanned',target.id,{});});tx();res.json({ok:true});});
app.get('/api/admin/ban-history',requireAdmin,(req,res)=>{const rows=db.prepare(`SELECT b.*,u.username,u.email,a.username admin_username FROM ban_history b JOIN users u ON u.id=b.user_id JOIN users a ON a.id=b.admin_id ORDER BY b.created_at DESC LIMIT 300`).all();res.json({items:rows});});
app.post('/api/admin/points',requireAdmin,(req,res)=>{const {userId,action,points,reason}=req.body||{};const amount=Number(points);if(!['add','deduct'].includes(action)||!Number.isSafeInteger(amount)||amount<=0||amount>100000000)return res.status(400).json({error:'Enter a valid positive whole-number point amount.'});const target=db.prepare('SELECT * FROM users WHERE id=?').get(userId);if(!target)return res.status(404).json({error:'User not found.'});if(target.role==='owner')return res.status(403).json({error:'Owner balance cannot be adjusted.'});const delta=action==='add'?amount:-amount;const tx=db.transaction(()=>{const fresh=db.prepare('SELECT points FROM users WHERE id=?').get(userId);const next=fresh.points+delta;if(next<0)throw Error('Deduction exceeds current balance. Negative balances are not allowed.');db.prepare('UPDATE users SET points=? WHERE id=?').run(next,userId);db.prepare('INSERT INTO point_transactions(id,user_id,previous_balance,delta,new_balance,reason,admin_id,created_at) VALUES(?,?,?,?,?,?,?,?)').run(id(),userId,fresh.points,delta,next,cleanText(reason,500)||'Admin adjustment',req.user.id,now());audit(req.user.id,'points_'+action,userId,{previous:fresh.points,delta,newBalance:next,reason:cleanText(reason,500)});return {previous:fresh.points,delta,newBalance:next};});try{res.json({ok:true,...tx()});}catch(e){res.status(400).json({error:e.message});}});
app.get('/api/admin/points-history',requireAdmin,(req,res)=>{const q=cleanText(req.query.userId,80);const rows=q?db.prepare(`SELECT p.*,u.username,u.email,a.username admin_username FROM point_transactions p JOIN users u ON u.id=p.user_id JOIN users a ON a.id=p.admin_id WHERE p.user_id=? ORDER BY p.created_at DESC LIMIT 500`).all(q):db.prepare(`SELECT p.*,u.username,u.email,a.username admin_username FROM point_transactions p JOIN users u ON u.id=p.user_id JOIN users a ON a.id=p.admin_id ORDER BY p.created_at DESC LIMIT 500`).all();res.json({items:rows});});
app.get('/api/admin/audit',requireAdmin,(req,res)=>{res.json({items:db.prepare(`SELECT l.*,a.username admin_username FROM audit_logs l LEFT JOIN users a ON a.id=l.admin_id ORDER BY l.created_at DESC LIMIT 500`).all()});});
app.get('/api/admin/withdrawals',requireAdmin,(req,res)=>res.json({items:db.prepare(`SELECT w.*,u.username,u.email FROM withdrawals w JOIN users u ON u.id=w.user_id ORDER BY w.created_at DESC LIMIT 300`).all()}));
app.post('/api/admin/withdrawals/:id/status',requireAdmin,(req,res)=>{const status=req.body.status;if(!['paid','rejected'].includes(status))return res.status(400).json({error:'Invalid status.'});const tx=db.transaction(()=>{const w=db.prepare('SELECT * FROM withdrawals WHERE id=?').get(req.params.id);if(!w||w.status!=='pending')throw Error('Request not found or already processed.');if(status==='rejected'){db.prepare('UPDATE users SET points=points+? WHERE id=?').run(w.points,w.user_id);const b=db.prepare('SELECT points FROM users WHERE id=?').get(w.user_id).points;db.prepare('INSERT INTO point_transactions(id,user_id,previous_balance,delta,new_balance,reason,admin_id,created_at) VALUES(?,?,?,?,?,?,?,?)').run(id(),w.user_id,b-w.points,w.points,b,'withdrawal refund: '+w.id,req.user.id,now());}db.prepare('UPDATE withdrawals SET status=?,admin_note=?,updated_at=? WHERE id=?').run(status,cleanText(req.body.note,300),now(),w.id);audit(req.user.id,'withdrawal_'+status,w.user_id,{withdrawalId:w.id});});try{tx();res.json({ok:true});}catch(e){res.status(400).json({error:e.message});}});

app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.listen(PORT,()=>console.log(`ENCODE-X running at http://localhost:${PORT}`));
