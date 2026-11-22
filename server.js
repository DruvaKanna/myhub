require("dotenv").config();
const crypto=require("node:crypto");
const fs=require("node:fs");
const path=require("node:path");
const http=require("node:http");
const express=require("express");
const helmet=require("helmet");
const bcrypt=require("bcryptjs");
const Database=require("better-sqlite3");
const cookieParser=require("cookie-parser");
const cookie=require("cookie");
const multer=require("multer");
const {rateLimit}=require("express-rate-limit");
const {Server}=require("socket.io");

const PORT=Number(process.env.PORT||3000);
const DATA_DIR=path.resolve(process.env.DATA_DIR||path.join(__dirname,"data"));
const UPLOAD_DIR=path.join(DATA_DIR,"uploads");
const SECRET=process.env.SESSION_SECRET||"local-development-secret-change-this-before-deploying";
const COOKIE_NAME="cc_session";
const SESSION_MS=14*24*60*60*1000;
const CODE_MS=10*60*1000;
const MAX_MB=Math.min(Math.max(Number(process.env.MAX_UPLOAD_MB||15),1),25);
const ALPHABET="ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
if(process.env.NODE_ENV==="production"&&SECRET==="local-development-secret-change-this-before-deploying")throw new Error("Set SESSION_SECRET before production startup.");
fs.mkdirSync(UPLOAD_DIR,{recursive:true});

const db=new Database(path.join(DATA_DIR,"chat-chat.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,username TEXT NOT NULL,email TEXT NOT NULL COLLATE NOCASE UNIQUE,password_hash TEXT NOT NULL,created_at INTEGER NOT NULL);"+
"CREATE TABLE IF NOT EXISTS codes(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,code TEXT NOT NULL UNIQUE,created_at INTEGER NOT NULL,expires_at INTEGER NOT NULL);"+
"CREATE TABLE IF NOT EXISTS connection_requests(id INTEGER PRIMARY KEY AUTOINCREMENT,requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,target_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,status TEXT NOT NULL DEFAULT 'pending',created_at INTEGER NOT NULL,UNIQUE(requester_id,target_id));"+
"CREATE TABLE IF NOT EXISTS connections(user_a INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,user_b INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at INTEGER NOT NULL,PRIMARY KEY(user_a,user_b),CHECK(user_a<user_b));"+
"CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,body TEXT NOT NULL DEFAULT '',created_at INTEGER NOT NULL);"+
"CREATE TABLE IF NOT EXISTS files(id INTEGER PRIMARY KEY AUTOINCREMENT,message_id INTEGER NOT NULL REFERENCES messages(id) ON DELETE CASCADE,stored_name TEXT NOT NULL UNIQUE,original_name TEXT NOT NULL,mime_type TEXT NOT NULL,size_bytes INTEGER NOT NULL);"+
"CREATE TABLE IF NOT EXISTS blocks(blocker_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,blocked_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,created_at INTEGER NOT NULL,PRIMARY KEY(blocker_id,blocked_id));"+
"CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT,reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,reported_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,reason TEXT NOT NULL,created_at INTEGER NOT NULL);"+
"CREATE INDEX IF NOT EXISTS idx_messages_pair_time ON messages(sender_id,recipient_id,created_at);"+
"CREATE INDEX IF NOT EXISTS idx_requests_target_status ON connection_requests(target_id,status);"+
"CREATE INDEX IF NOT EXISTS idx_files_message ON files(message_id);");

const app=express();
const server=http.createServer(app);
const io=new Server(server);
app.disable("x-powered-by");
app.set("trust proxy",1);
app.use(helmet({contentSecurityPolicy:{directives:{
  defaultSrc:["'self'"],baseUri:["'self'"],connectSrc:["'self'","ws:","wss:"],fontSrc:["'self'","data:"],
  formAction:["'self'"],frameAncestors:["'none'"],imgSrc:["'self'","data:"],objectSrc:["'none'"],
  scriptSrc:["'self'"],styleSrc:["'self'"]
}}}));
app.use(express.json({limit:"100kb"}));
app.use(cookieParser());

const authLimiter=rateLimit({windowMs:15*60*1000,limit:12,standardHeaders:"draft-7",legacyHeaders:false,message:{error:"Too many attempts. Please wait and try again."}});
const actionLimiter=rateLimit({windowMs:60*1000,limit:60,standardHeaders:"draft-7",legacyHeaders:false});

function safeUser(user){return{id:user.id,username:user.username,email:user.email};}
function signSession(userId){
  const body=Buffer.from(JSON.stringify({sub:userId,exp:Date.now()+SESSION_MS})).toString("base64url");
  const sig=crypto.createHmac("sha256",SECRET).update(body).digest("base64url");
  return body+"."+sig;
}
function readSession(token){
  if(!token||typeof token!=="string")return null;
  const parts=token.split(".");
  if(parts.length!==2)return null;
  const expected=crypto.createHmac("sha256",SECRET).update(parts[0]).digest("base64url");
  const a=Buffer.from(parts[1]),b=Buffer.from(expected);
  if(a.length!==b.length||!crypto.timingSafeEqual(a,b))return null;
  try{const p=JSON.parse(Buffer.from(parts[0],"base64url").toString("utf8"));return Number.isInteger(p.sub)&&p.exp>Date.now()?p.sub:null;}catch{return null;}
}
function setSession(res,id){res.cookie(COOKIE_NAME,signSession(id),{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"lax",maxAge:SESSION_MS,path:"/"});}
function requireAuth(req,res,next){
  const id=readSession(req.cookies[COOKIE_NAME]);
  if(!id)return res.status(401).json({error:"Please sign in to continue."});
  const user=db.prepare("SELECT id,username,email FROM users WHERE id=?").get(id);
  if(!user)return res.status(401).json({error:"Your session is no longer valid. Please sign in again."});
  req.user=user;next();
}
function randomCode(){let s="";for(let i=0;i<5;i++)s+=ALPHABET[crypto.randomInt(0,ALPHABET.length)];return s;}
function issueCode(userId){
  for(let i=0;i<80;i++){
    const code=randomCode(),now=Date.now();
    try{
      db.prepare("INSERT INTO codes(user_id,code,created_at,expires_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET code=excluded.code,created_at=excluded.created_at,expires_at=excluded.expires_at").run(userId,code,now,now+CODE_MS);
      return{code:code,expiresAt:now+CODE_MS};
    }catch(error){if(!String(error.message).includes("UNIQUE"))throw error;}
  }
  throw new Error("Could not generate a code. Please try again.");
}
function currentCode(id){const row=db.prepare("SELECT code,expires_at FROM codes WHERE user_id=?").get(id);return row&&row.expires_at>Date.now()?{code:row.code,expiresAt:row.expires_at}:issueCode(id);}
function pairIds(a,b){return[Math.min(Number(a),Number(b)),Math.max(Number(a),Number(b))];}
function isConnected(a,b){const p=pairIds(a,b);return!!db.prepare("SELECT 1 FROM connections WHERE user_a=? AND user_b=?").get(p[0],p[1]);}
function isBlocked(a,b){return!!db.prepare("SELECT 1 FROM blocks WHERE (blocker_id=? AND blocked_id=?) OR (blocker_id=? AND blocked_id=?)").get(a,b,b,a);}
function canChat(a,b){return Number(a)!==Number(b)&&isConnected(a,b)&&!isBlocked(a,b);}
function chatGuard(req,res,next){
  const other=Number(req.params.userId);
  if(!Number.isSafeInteger(other)||!canChat(req.user.id,other))return res.status(404).json({error:"This chat is not available."});
  req.otherUserId=other;next();
}
function cleanName(name){return path.basename(String(name||"attachment")).replace(/[\u0000-\u001f\u007f]/g,"").slice(0,120)||"attachment";}
function getMessage(id){
  const row=db.prepare("SELECT id,sender_id,recipient_id,body,created_at FROM messages WHERE id=?").get(id);
  if(!row)return null;
  row.attachments=db.prepare("SELECT id,original_name,mime_type,size_bytes FROM files WHERE message_id=? ORDER BY id").all(id);
  return row;
}
function emitMessage(message){
  io.to("user:"+message.sender_id).emit("new-message",message);
  if(message.recipient_id!==message.sender_id)io.to("user:"+message.recipient_id).emit("new-message",message);
}
function emitConnectionUpdate(...ids){for(const id of new Set(ids))io.to("user:"+id).emit("connections-updated");}

const allowed={
  ".png":["image/png"],".jpg":["image/jpeg"],".jpeg":["image/jpeg"],".gif":["image/gif"],".webp":["image/webp"],
  ".pdf":["application/pdf"],".txt":["text/plain"],".csv":["text/csv","application/vnd.ms-excel","text/plain"],
  ".doc":["application/msword","application/octet-stream"],
  ".docx":["application/vnd.openxmlformats-officedocument.wordprocessingml.document","application/octet-stream"],
  ".xls":["application/vnd.ms-excel","application/octet-stream"],
  ".xlsx":["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet","application/octet-stream"],
  ".ppt":["application/vnd.ms-powerpoint","application/octet-stream"],
  ".pptx":["application/vnd.openxmlformats-officedocument.presentationml.presentation","application/octet-stream"]
};
const upload=multer({
  storage:multer.diskStorage({destination:(_r,_f,cb)=>cb(null,UPLOAD_DIR),filename:(_r,_f,cb)=>cb(null,crypto.randomUUID())}),
  limits:{fileSize:MAX_MB*1024*1024,files:5},
  fileFilter:(_r,file,cb)=>{
    const ext=path.extname(file.originalname).toLowerCase(),mimes=allowed[ext];
    if(!mimes||!mimes.includes(file.mimetype))return cb(new Error("That file type is not supported. Try an image, PDF, text, CSV, or Office document."));
    cb(null,true);
  }
});

app.get("/healthz",(_req,res)=>res.json({ok:true,service:"chat-chat"}));
app.post("/api/auth/register",authLimiter,async(req,res,next)=>{
  try{
    const username=String(req.body.username||"").trim(),email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");
    if(!/^[A-Za-z0-9_]{2,24}$/.test(username))return res.status(400).json({error:"Username must be 2–24 characters using letters, numbers, or underscores."});
    if(email.length>254||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({error:"Enter a valid email address."});
    if(password.length<10||password.length>72)return res.status(400).json({error:"Password must be 10–72 characters long."});
    if(db.prepare("SELECT id FROM users WHERE email=?").get(email))return res.status(409).json({error:"An account with that email already exists."});
    const hash=await bcrypt.hash(password,12),result=db.prepare("INSERT INTO users(username,email,password_hash,created_at) VALUES(?,?,?,?)").run(username,email,hash,Date.now());
    const user=db.prepare("SELECT id,username,email FROM users WHERE id=?").get(result.lastInsertRowid),code=issueCode(user.id);
    setSession(res,user.id);res.status(201).json({user:safeUser(user),code:code.code,codeExpiresAt:code.expiresAt});
  }catch(error){if(String(error.message).includes("UNIQUE"))return res.status(409).json({error:"That email address is already registered."});next(error);}
});
app.post("/api/auth/login",authLimiter,async(req,res,next)=>{
  try{
    const email=String(req.body.email||"").trim().toLowerCase(),password=String(req.body.password||"");
    const user=db.prepare("SELECT id,username,email,password_hash FROM users WHERE email=?").get(email);
    if(!user||!(await bcrypt.compare(password,user.password_hash)))return res.status(401).json({error:"Email or password is incorrect."});
    const code=issueCode(user.id);setSession(res,user.id);
    res.json({user:safeUser(user),code:code.code,codeExpiresAt:code.expiresAt});
  }catch(error){next(error);}
});
app.post("/api/auth/logout",requireAuth,(req,res)=>{
  res.clearCookie(COOKIE_NAME,{httpOnly:true,secure:process.env.NODE_ENV==="production",sameSite:"lax",path:"/"});
  res.json({ok:true});
});
app.get("/api/me",requireAuth,(req,res)=>{const code=currentCode(req.user.id);res.json({user:safeUser(req.user),code:code.code,codeExpiresAt:code.expiresAt});});
app.post("/api/code/rotate",requireAuth,actionLimiter,(req,res,next)=>{try{res.json(issueCode(req.user.id));}catch(error){next(error);}});

app.get("/api/connections",requireAuth,(req,res)=>{
  const id=req.user.id;
  const accepted=db.prepare("SELECT u.id,u.username,(SELECT MAX(m.created_at) FROM messages m WHERE (m.sender_id=u.id AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=u.id)) AS last_message_at FROM connections c JOIN users u ON u.id=CASE WHEN c.user_a=? THEN c.user_b ELSE c.user_a END WHERE c.user_a=? OR c.user_b=? ORDER BY COALESCE(last_message_at,c.created_at) DESC").all(id,id,id,id,id);
  const incoming=db.prepare("SELECT r.id AS request_id,r.created_at,u.id AS user_id,u.username FROM connection_requests r JOIN users u ON u.id=r.requester_id WHERE r.target_id=? AND r.status='pending' ORDER BY r.created_at DESC").all(id);
  const outgoing=db.prepare("SELECT r.id AS request_id,r.created_at,u.id AS user_id,u.username FROM connection_requests r JOIN users u ON u.id=r.target_id WHERE r.requester_id=? AND r.status='pending' ORDER BY r.created_at DESC").all(id);
  res.json({accepted,incoming,outgoing});
});
app.post("/api/connections/invite",requireAuth,actionLimiter,(req,res)=>{
  const code=String(req.body.code||"").trim().toUpperCase();
  if(!/^[A-Z0-9]{5}$/.test(code))return res.status(400).json({error:"Enter a five-character connection code."});
  const match=db.prepare("SELECT user_id FROM codes WHERE code=? AND expires_at>?").get(code,Date.now());
  if(!match)return res.status(404).json({error:"That code is not active. Ask your friend to generate a fresh code."});
  const target=match.user_id;
  if(target===req.user.id)return res.status(400).json({error:"That is your own code."});
  if(isBlocked(req.user.id,target))return res.status(403).json({error:"This connection is not available."});
  if(isConnected(req.user.id,target))return res.status(409).json({error:"You are already connected."});
  try{
    const result=db.prepare("INSERT INTO connection_requests(requester_id,target_id,status,created_at) VALUES(?,?,'pending',?)").run(req.user.id,target,Date.now());
    emitConnectionUpdate(target);
    res.status(201).json({ok:true,requestId:result.lastInsertRowid,message:"Invite sent. Your friend must enter your current code to confirm."});
  }catch(error){if(String(error.message).includes("UNIQUE"))return res.status(409).json({error:"A connection request is already waiting."});throw error;}
});
app.post("/api/connections/confirm",requireAuth,actionLimiter,(req,res)=>{
  const requestId=Number(req.body.requestId),code=String(req.body.code||"").trim().toUpperCase();
  if(!Number.isSafeInteger(requestId)||!/^[A-Z0-9]{5}$/.test(code))return res.status(400).json({error:"Enter the other person's five-character code."});
  const invite=db.prepare("SELECT id,requester_id,target_id FROM connection_requests WHERE id=? AND target_id=? AND status='pending'").get(requestId,req.user.id);
  if(!invite)return res.status(404).json({error:"That invitation is no longer waiting."});
  const theirCode=db.prepare("SELECT code,expires_at FROM codes WHERE user_id=?").get(invite.requester_id);
  if(!theirCode||theirCode.expires_at<=Date.now()||theirCode.code!==code)return res.status(400).json({error:"The code does not match. Ask the person who invited you to show their current code."});
  if(isBlocked(req.user.id,invite.requester_id))return res.status(403).json({error:"This connection is not available."});
  const pair=pairIds(req.user.id,invite.requester_id),now=Date.now();
  db.transaction(()=>{
    db.prepare("INSERT OR IGNORE INTO connections(user_a,user_b,created_at) VALUES(?,?,?)").run(pair[0],pair[1],now);
    db.prepare("UPDATE connection_requests SET status='accepted' WHERE id=?").run(invite.id);
    db.prepare("DELETE FROM codes WHERE user_id IN (?,?)").run(pair[0],pair[1]);
    db.prepare("DELETE FROM connection_requests WHERE status='pending' AND ((requester_id=? AND target_id=?) OR (requester_id=? AND target_id=?))").run(pair[0],pair[1],pair[1],pair[0]);
    issueCode(pair[0]);issueCode(pair[1]);
  })();
  emitConnectionUpdate(pair[0],pair[1]);
  res.json({ok:true,message:"You are connected. Your chats are ready."});
});
app.post("/api/connections/:requestId/decline",requireAuth,(req,res)=>{
  const result=db.prepare("UPDATE connection_requests SET status='declined' WHERE id=? AND target_id=? AND status='pending'").run(Number(req.params.requestId),req.user.id);
  if(!result.changes)return res.status(404).json({error:"That invitation is no longer waiting."});
  res.json({ok:true});
});

app.get("/api/chats",requireAuth,(req,res)=>{
  const id=req.user.id;
  const chats=db.prepare("SELECT u.id,u.username,c.created_at,(SELECT m.body FROM messages m WHERE (m.sender_id=u.id AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=u.id) ORDER BY m.created_at DESC,m.id DESC LIMIT 1) AS last_message,(SELECT m.created_at FROM messages m WHERE (m.sender_id=u.id AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=u.id) ORDER BY m.created_at DESC,m.id DESC LIMIT 1) AS last_message_at FROM connections c JOIN users u ON u.id=CASE WHEN c.user_a=? THEN c.user_b ELSE c.user_a END WHERE (c.user_a=? OR c.user_b=?) AND NOT EXISTS(SELECT 1 FROM blocks b WHERE (b.blocker_id=? AND b.blocked_id=u.id) OR (b.blocker_id=u.id AND b.blocked_id=?)) ORDER BY COALESCE(last_message_at,c.created_at) DESC").all(id,id,id,id,id,id,id,id,id);
  res.json({chats});
});
app.get("/api/chats/:userId/messages",requireAuth,chatGuard,(req,res)=>{
  const rows=db.prepare("SELECT id,sender_id,recipient_id,body,created_at FROM messages WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?) ORDER BY created_at DESC,id DESC LIMIT 100").all(req.user.id,req.otherUserId,req.otherUserId,req.user.id).reverse();
  const messages=rows.map(row=>Object.assign(row,{attachments:db.prepare("SELECT id,original_name,mime_type,size_bytes FROM files WHERE message_id=? ORDER BY id").all(row.id)}));
  res.json({messages});
});
app.post("/api/chats/:userId/messages",requireAuth,chatGuard,actionLimiter,(req,res)=>{
  const body=String(req.body.body||"").trim();
  if(!body)return res.status(400).json({error:"Write a message first."});
  if(body.length>10000)return res.status(400).json({error:"Messages must be 10,000 characters or fewer."});
  const result=db.prepare("INSERT INTO messages(sender_id,recipient_id,body,created_at) VALUES(?,?,?,?)").run(req.user.id,req.otherUserId,body,Date.now());
  const message=getMessage(result.lastInsertRowid);emitMessage(message);res.status(201).json({message});
});
app.post("/api/chats/:userId/files",requireAuth,chatGuard,(req,res,next)=>{
  upload.array("files",5)(req,res,error=>{
    if(error)return next(error);
    try{
      const files=req.files||[];
      if(!files.length)return res.status(400).json({error:"Choose at least one supported file."});
      const caption=String(req.body.caption||"").trim().slice(0,1000);
      const body=caption||(files.length===1?"Shared a file":"Shared "+files.length+" files");
      const result=db.prepare("INSERT INTO messages(sender_id,recipient_id,body,created_at) VALUES(?,?,?,?)").run(req.user.id,req.otherUserId,body,Date.now());
      const add=db.prepare("INSERT INTO files(message_id,stored_name,original_name,mime_type,size_bytes) VALUES(?,?,?,?,?)");
      for(const file of files)add.run(result.lastInsertRowid,file.filename,cleanName(file.originalname),file.mimetype,file.size);
      const message=getMessage(result.lastInsertRowid);emitMessage(message);res.status(201).json({message});
    }catch(err){next(err);}
  });
});
app.get("/api/files/:fileId/download",requireAuth,(req,res)=>{
  const file=db.prepare("SELECT f.stored_name,f.original_name,m.sender_id,m.recipient_id FROM files f JOIN messages m ON m.id=f.message_id WHERE f.id=?").get(Number(req.params.fileId));
  const other=file?(file.sender_id===req.user.id?file.recipient_id:file.sender_id):null;
  if(!file||!canChat(req.user.id,other))return res.status(404).json({error:"File not found."});
  const target=path.join(UPLOAD_DIR,file.stored_name);
  if(!fs.existsSync(target))return res.status(404).json({error:"This file is no longer available."});
  res.setHeader("X-Content-Type-Options","nosniff");res.setHeader("Content-Type","application/octet-stream");
  res.download(target,file.original_name);
});
app.post("/api/users/:userId/block",requireAuth,(req,res)=>{
  const other=Number(req.params.userId);
  if(!Number.isSafeInteger(other)||other===req.user.id||!db.prepare("SELECT id FROM users WHERE id=?").get(other))return res.status(404).json({error:"User not found."});
  db.prepare("INSERT OR IGNORE INTO blocks(blocker_id,blocked_id,created_at) VALUES(?,?,?)").run(req.user.id,other,Date.now());
  emitConnectionUpdate(req.user.id,other);res.json({ok:true,message:"This person is blocked. The chat is no longer available."});
});
app.post("/api/users/:userId/report",requireAuth,(req,res)=>{
  const other=Number(req.params.userId),reason=String(req.body.reason||"").trim().slice(0,500);
  if(!Number.isSafeInteger(other)||other===req.user.id||!db.prepare("SELECT id FROM users WHERE id=?").get(other))return res.status(404).json({error:"User not found."});
  if(reason.length<5)return res.status(400).json({error:"Please add a little more detail to the report."});
  db.prepare("INSERT INTO reports(reporter_id,reported_id,reason,created_at) VALUES(?,?,?,?)").run(req.user.id,other,reason,Date.now());
  res.json({ok:true,message:"Report submitted. Thank you for helping keep Chat Chat safer."});
});

app.use(express.static(path.join(__dirname,"public")));
app.use((error,_req,res,_next)=>{
  if(error instanceof multer.MulterError){
    if(error.code==="LIMIT_FILE_SIZE")return res.status(413).json({error:"That file is too large. The limit is "+MAX_MB+" MB per file."});
    if(error.code==="LIMIT_FILE_COUNT")return res.status(400).json({error:"You can send up to five files at a time."});
    return res.status(400).json({error:"The upload could not be completed."});
  }
  if(error&&String(error.message||"").includes("file type is not supported"))return res.status(400).json({error:error.message});
  console.error("Request failed:",error);res.status(500).json({error:"Something went wrong. Please try again."});
});

io.use((socket,next)=>{
  try{
    const parsed=cookie.parse(socket.handshake.headers.cookie||""),id=readSession(parsed[COOKIE_NAME]);
    if(!id||!db.prepare("SELECT id FROM users WHERE id=?").get(id))return next(new Error("Unauthorized"));
    socket.userId=id;next();
  }catch{next(new Error("Unauthorized"));}
});
io.on("connection",socket=>socket.join("user:"+socket.userId));
server.listen(PORT,()=>console.log("Chat Chat is running on port "+PORT));