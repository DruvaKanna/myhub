(() => {
"use strict";
const $=s=>document.querySelector(s);
const state={authMode:"login",user:null,code:"",codeExpiresAt:0,chats:[],activeUser:null,messages:[],socket:null,selectedFiles:[],toastTimer:null,expiryTimer:null};
async function api(url,options){
  const opts=Object.assign({credentials:"same-origin"},options||{});opts.headers=Object.assign({},opts.headers||{});
  if(opts.body&&!(opts.body instanceof FormData)&&typeof opts.body!=="string"){opts.headers["Content-Type"]="application/json";opts.body=JSON.stringify(opts.body);}
  const response=await fetch(url,opts),type=response.headers.get("content-type")||"",data=type.includes("application/json")?await response.json():{};
  if(!response.ok)throw new Error(data.error||"Something went wrong.");return data;
}
function toast(message){const node=$("#toast");node.textContent=message;node.classList.add("show");clearTimeout(state.toastTimer);state.toastTimer=setTimeout(()=>node.classList.remove("show"),3000);}
function initials(name){return String(name||"?").trim().slice(0,1).toUpperCase()||"?";}
function setAuthMode(mode){
  state.authMode=mode;const registering=mode==="register";
  $("#auth-title").textContent=registering?"Create your account":"Sign in";
  $("#auth-subtitle").textContent=registering?"Set up your personal Chat Chat space.":"Pick up where your conversations left off.";
  $("#username-field").classList.toggle("hidden",!registering);$("#auth-username").required=registering;
  $("#auth-password").autocomplete=registering?"new-password":"current-password";
  $("#auth-submit").innerHTML=registering?"Create account <span aria-hidden='true'>→</span>":"Sign in <span aria-hidden='true'>→</span>";
  $("#auth-switch-copy").textContent=registering?"Already have an account?":"New to Chat Chat?";
  $("#auth-switch").textContent=registering?"Sign in":"Create an account";$("#auth-error").textContent="";
}
async function handleAuth(event){
  event.preventDefault();$("#auth-error").textContent="";
  const payload={username:$("#auth-username").value.trim(),email:$("#auth-email").value.trim(),password:$("#auth-password").value};
  try{
    const result=await api(state.authMode==="register"?"/api/auth/register":"/api/auth/login",{method:"POST",body:payload});
    state.user=result.user;state.code=result.code;state.codeExpiresAt=result.codeExpiresAt;$("#auth-password").value="";await startApp();
  }catch(error){$("#auth-error").textContent=error.message;}
}
async function boot(){
  try{const result=await api("/api/me");state.user=result.user;state.code=result.code;state.codeExpiresAt=result.codeExpiresAt;await startApp();}
  catch{$("#auth-screen").classList.remove("hidden");$("#app-screen").classList.add("hidden");}
}
async function startApp(){
  $("#auth-screen").classList.add("hidden");$("#app-screen").classList.remove("hidden");
  $("#profile-name").textContent=state.user.username;$("#profile-avatar").textContent=initials(state.user.username);$("#top-avatar").textContent=initials(state.user.username);
  renderCode();setupSocket();await Promise.all([loadChats(),loadConnections(),loadSettings()]);
}
function renderCode(){$("#my-code").textContent=state.code||"·····";$("#code-status").textContent="Your code stays active until you change it.";}
function updateExpiry(){}
async function rotateCode(){try{const result=await api("/api/code/change",{method:"POST",body:{}});state.code=result.code;state.codeExpiresAt=null;renderCode();toast("Your code changed and your contacts were removed.");}catch(error){toast(error.message);}}
async function copyCode(){
  if(!state.code)return;
  try{await navigator.clipboard.writeText(state.code);toast("Code copied.");}
  catch{toast("Copy unavailable. Your code is "+state.code);}
}
async function sendInvite(event){
  event.preventDefault();const field=$("#invite-code"),code=field.value.trim().toUpperCase();$("#invite-status").textContent="";
  if(!/^[A-Z0-9]{5}$/.test(code)){ $("#invite-status").textContent="Enter all five characters.";return; }
  try{const result=await api("/api/connections/invite",{method:"POST",body:{code}});$("#invite-status").textContent="Invite sent. Ask them to enter your code.";field.value="";toast(result.message);await loadConnections();}
  catch(error){$("#invite-status").textContent=error.message;}
}
async function loadConnections(){try{renderRequests(await api("/api/connections"));}catch(error){if(error.message)toast(error.message);}}
function renderRequests(data){
  const incoming=$("#incoming-list"),outgoing=$("#outgoing-list");incoming.replaceChildren();outgoing.replaceChildren();$("#request-count").textContent=data.incoming.length;
  if(!data.incoming.length){const empty=document.createElement("div");empty.className="list-empty";empty.textContent="No connection requests right now.";incoming.append(empty);}
  data.incoming.forEach(request=>{
    const card=document.createElement("div");card.className="request-card";
    const title=document.createElement("strong");title.textContent=request.username+" wants to connect";
    const hint=document.createElement("p");hint.textContent="Enter their current code and choose the name you want to use for them in your chats.";
    const contactName=document.createElement("input");contactName.maxLength=40;contactName.placeholder="NAME FOR THIS CONTACT";contactName.autocomplete="off";contactName.setAttribute("aria-label","Name for this contact");
    const code=document.createElement("input");code.maxLength=5;code.placeholder="THEIR CODE";code.autocomplete="off";code.setAttribute("aria-label","Their current connection code");
    code.addEventListener("input",()=>{code.value=code.value.toUpperCase().replace(/[^A-Z0-9]/g,"").slice(0,5);});
    const actions=document.createElement("div");actions.className="request-card-actions";
    const confirm=document.createElement("button");confirm.className="confirm-request";confirm.type="button";confirm.textContent="Confirm";
    confirm.addEventListener("click",async()=>{
      try{await api("/api/connections/confirm",{method:"POST",body:{requestId:request.request_id,code:code.value,contactName:contactName.value.trim()}});toast("Connected! You can start chatting.");await refreshMe();await Promise.all([loadChats(),loadConnections()]);setSidebarTab("chats");}
      catch(error){toast(error.message);}
    });
    const decline=document.createElement("button");decline.className="decline-request";decline.type="button";decline.textContent="Decline";
    decline.addEventListener("click",async()=>{try{await api("/api/connections/"+request.request_id+"/decline",{method:"POST",body:{}});await loadConnections();}catch(error){toast(error.message);}});
    actions.append(confirm,decline);card.append(title,hint,contactName,code,actions);incoming.append(card);
  });
  if(!data.outgoing.length){const empty=document.createElement("div");empty.className="list-empty";empty.textContent="No invites sent.";outgoing.append(empty);}
  else data.outgoing.forEach(request=>{const item=document.createElement("div");item.className="outgoing-item";const name=document.createElement("strong");name.textContent=request.username;const waiting=document.createElement("span");waiting.textContent="Waiting";item.append(name,waiting);outgoing.append(item);});
}
function setSidebarTab(tab){
  document.querySelectorAll(".sidebar-tab").forEach(button=>{const active=button.dataset.tab===tab;button.classList.toggle("active",active);button.setAttribute("aria-selected",active?"true":"false");});
  $("#chats-panel").classList.toggle("hidden",tab!=="chats");$("#requests-panel").classList.toggle("hidden",tab!=="requests");
  $("#topbar-title").textContent=tab==="chats"?"Messages":"Connection requests";
}
async function loadChats(){const result=await api("/api/chats");state.chats=result.chats;renderChats();}
function renderChats(){
  const list=$("#chat-list");list.replaceChildren();$("#chat-count").textContent=state.chats.length;
  if(!state.chats.length){const empty=document.createElement("div");empty.className="list-empty";empty.textContent="No chats yet. Connect with someone using their code above.";list.append(empty);return;}
  state.chats.forEach(person=>{
    const button=document.createElement("button");button.type="button";button.className="chat-item"+(state.activeUser&&state.activeUser.id===person.id?" active":"");
    const avatar=document.createElement("span");avatar.className="avatar";avatar.textContent=initials(person.username);
    const copy=document.createElement("span");copy.className="chat-item-copy";
    const name=document.createElement("strong");name.textContent=person.display_name||person.username;const code=document.createElement("span");code.className="contact-code";code.textContent=person.connection_code?"· "+person.connection_code:"";
    const preview=document.createElement("span");preview.textContent=person.last_message||"Start a conversation";
    copy.append(name,code,preview);button.append(avatar,copy);button.addEventListener("click",()=>selectChat(person));list.append(button);
  });
}
async function selectChat(person){
  state.activeUser=person;$("#empty-state").classList.add("hidden");$("#chat-view").classList.remove("hidden");
  $("#active-name").textContent=person.display_name||person.username;$("#active-code").textContent=person.connection_code||"";$("#active-avatar").textContent=initials(person.display_name||person.username);$("#topbar-title").textContent=person.username;
  renderChats();await loadMessages();closeMobileSidebar();$("#message-input").focus();
}
async function loadMessages(){
  if(!state.activeUser)return;
  const result=await api("/api/chats/"+state.activeUser.id+"/messages");state.messages=result.messages;renderMessages();
}
function appendLinkedText(parent,text){
  const pattern=/(https?:\/\/[^\s<]+)/gi;let cursor=0,match;
  while((match=pattern.exec(text))!==null){
    if(match.index>cursor)parent.append(document.createTextNode(text.slice(cursor,match.index)));
    let raw=match[0],trailing="";while(/[),.!?;:]$/.test(raw)){trailing=raw.slice(-1)+trailing;raw=raw.slice(0,-1);}
    let url;try{url=new URL(raw);}catch{parent.append(document.createTextNode(match[0]));cursor=match.index+match[0].length;continue;}
    if(url.protocol!=="http:"&&url.protocol!=="https:")parent.append(document.createTextNode(match[0]));
    else{const link=document.createElement("a");link.className="message-links";link.href=url.href;link.target="_blank";link.rel="noopener noreferrer";link.textContent=raw;parent.append(link,document.createTextNode(trailing));}
    cursor=match.index+match[0].length;
  }
  if(cursor<text.length)parent.append(document.createTextNode(text.slice(cursor)));
}
function formatBytes(value){const bytes=Number(value||0);if(bytes<1024)return bytes+" B";if(bytes<1048576)return Math.round(bytes/1024)+" KB";return(bytes/1048576).toFixed(1)+" MB";}
function renderMessages(){
  const list=$("#message-list");list.replaceChildren();const date=document.createElement("div");date.className="message-date";date.textContent="CONVERSATION";list.append(date);
  state.messages.forEach(message=>addMessageToDom(message,false));list.scrollTop=list.scrollHeight;
}
function addMessageToDom(message,scroll){
  if(scroll&&state.messages.some(item=>item.id===message.id))return;
  if(scroll)state.messages.push(message);
  const row=document.createElement("div");row.className="message-row"+(message.sender_id===state.user.id?" own":"");
  if(message.body){const bubble=document.createElement("div");bubble.className="message-bubble";appendLinkedText(bubble,message.body);row.append(bubble);}
  if(message.attachments&&message.attachments.length){
    const attachments=document.createElement("div");attachments.className="message-attachments";
    message.attachments.forEach(file=>{
      const link=document.createElement("a");link.className="attachment-card";link.href="/api/files/"+file.id+"/download";link.target="_blank";link.rel="noopener";
      const icon=document.createElement("span");icon.className="attachment-icon";icon.textContent=file.mime_type.startsWith("image/")?"▧":"▤";
      const copy=document.createElement("span");copy.className="attachment-copy";
      const name=document.createElement("strong");name.textContent=file.original_name;
      const size=document.createElement("span");size.textContent=formatBytes(file.size_bytes)+" · Download";copy.append(name,size);
      const download=document.createElement("span");download.className="attachment-download";download.textContent="↓";link.append(icon,copy,download);attachments.append(link);
    });row.append(attachments);
  }
  const time=document.createElement("span");time.className="message-time";time.textContent=new Date(message.created_at).toLocaleTimeString([],{hour:"numeric",minute:"2-digit"});row.append(time);
  $("#message-list").append(row);if(scroll)$("#message-list").scrollTop=$("#message-list").scrollHeight;
}
async function sendMessage(event){
  event.preventDefault();if(!state.activeUser)return;
  const text=$("#message-input").value.trim(),files=state.selectedFiles;if(!text&&!files.length)return;
  $("#send-button").disabled=true;
  try{
    let result;
    if(files.length){const form=new FormData();files.forEach(file=>form.append("files",file));if(text)form.append("caption",text);result=await api("/api/chats/"+state.activeUser.id+"/files",{method:"POST",body:form});}
    else result=await api("/api/chats/"+state.activeUser.id+"/messages",{method:"POST",body:{body:text}});
    addMessageToDom(result.message,true);$("#message-input").value="";state.selectedFiles=[];$("#file-input").value="";$("#selected-files").textContent="";await loadChats();
  }catch(error){toast(error.message);}finally{$("#send-button").disabled=false;}
}
function chooseFiles(fileList){
  const chosen=Array.from(fileList||[]);if(!chosen.length)return;
  if(chosen.length+state.selectedFiles.length>5){toast("You can attach up to five files at a time.");return;}
  const tooLarge=chosen.find(file=>file.size>15*1024*1024);if(tooLarge){toast(tooLarge.name+" is larger than 15 MB.");return;}
  state.selectedFiles=state.selectedFiles.concat(chosen);$("#selected-files").textContent=state.selectedFiles.map(file=>file.name).join(", ");
}
async function blockActiveUser(){
  if(!state.activeUser)return;const name=state.activeUser.username;if(!window.confirm("Block "+name+"? This will close the chat between you."))return;
  try{await api("/api/users/"+state.activeUser.id+"/block",{method:"POST",body:{}});state.activeUser=null;state.messages=[];$("#chat-view").classList.add("hidden");$("#empty-state").classList.remove("hidden");await loadChats();toast(name+" has been blocked.");}
  catch(error){toast(error.message);}
}
async function reportActiveUser(){
  if(!state.activeUser)return;const reason=window.prompt("Briefly tell us why you are reporting this person:");if(!reason)return;
  try{const result=await api("/api/users/"+state.activeUser.id+"/report",{method:"POST",body:{reason}});toast(result.message);}
  catch(error){toast(error.message);}
}
async function refreshMe(){const result=await api("/api/me");state.user=result.user;state.code=result.code;state.codeExpiresAt=null;renderCode();}
function setupSocket(){
  if(state.socket)state.socket.disconnect();if(typeof window.io!=="function")return;
  state.socket=window.io();
  state.socket.on("new-message",message=>{
    const other=message.sender_id===state.user.id?message.recipient_id:message.sender_id;
    if(state.activeUser&&state.activeUser.id===other)addMessageToDom(message,true);
    loadChats().catch(()=>{});
  });
  state.socket.on("connections-updated",()=>{refreshMe().catch(()=>{});loadConnections().catch(()=>{});loadChats().catch(()=>{});});
}
async function loadSettings(){try{const result=await api("/api/settings");applyTheme(result.theme);}catch{}}
function applyTheme(theme){document.documentElement.dataset.theme=theme||"blue";document.querySelectorAll("[data-theme-choice]").forEach(b=>b.classList.toggle("selected",b.dataset.themeChoice===document.documentElement.dataset.theme));}
async function saveTheme(theme){try{const result=await api("/api/settings/theme",{method:"POST",body:{theme}});applyTheme(result.theme);toast("Screen color updated.");}catch(error){toast(error.message);}}
function closeMobileSidebar(){$(".sidebar").classList.remove("open");}
function bindEvents(){
  $("#auth-form").addEventListener("submit",handleAuth);
  $("#auth-switch").addEventListener("click",()=>setAuthMode(state.authMode==="login"?"register":"login"));
  $("#invite-form").addEventListener("submit",sendInvite);$("#copy-code").addEventListener("click",copyCode);
  $("#settings-button").addEventListener("click",async()=>{$("#settings-modal").classList.remove("hidden");await loadSettings();});
  $("#settings-close").addEventListener("click",()=>$("#settings-modal").classList.add("hidden"));
  $("#theme-options").addEventListener("click",event=>{const button=event.target.closest("[data-theme-choice]");if(button)saveTheme(button.dataset.themeChoice);});
  $("#change-code-settings").addEventListener("click",()=>{$("#settings-modal").classList.add("hidden");$("#code-warning-modal").classList.remove("hidden");});
  $("#warning-back").addEventListener("click",()=>$("#code-warning-modal").classList.add("hidden"));
  $("#warning-yes").addEventListener("click",async()=>{$("#code-warning-modal").classList.add("hidden");await rotateCode();state.activeUser=null;$("#chat-view").classList.add("hidden");$("#empty-state").classList.remove("hidden");await Promise.all([loadChats(),loadConnections()]);});
  $("#logout-button").addEventListener("click",async()=>{
    try{await api("/api/auth/logout",{method:"POST",body:{}});}catch{}
    if(state.socket)state.socket.disconnect();clearInterval(state.expiryTimer);state.user=null;state.activeUser=null;
    $("#app-screen").classList.add("hidden");$("#auth-screen").classList.remove("hidden");setAuthMode("login");toast("You have signed out.");
  });
  document.querySelectorAll(".sidebar-tab").forEach(button=>button.addEventListener("click",()=>setSidebarTab(button.dataset.tab)));
  $("#empty-connect").addEventListener("click",()=>{$(".sidebar").classList.add("open");$("#invite-code").focus();});
  $("#mobile-menu").addEventListener("click",()=>$(".sidebar").classList.add("open"));$("#mobile-close").addEventListener("click",closeMobileSidebar);
  $("#composer").addEventListener("submit",sendMessage);$("#file-input").addEventListener("change",event=>chooseFiles(event.target.files));
  $("#block-person").addEventListener("click",blockActiveUser);$("#report-person").addEventListener("click",reportActiveUser);
  $("#message-input").addEventListener("keydown",event=>{if(event.key==="Enter"&&!event.shiftKey){event.preventDefault();$("#composer").requestSubmit();}});
  const view=$("#chat-view");
  view.addEventListener("dragover",event=>{event.preventDefault();$("#drop-hint").classList.remove("hidden");});
  view.addEventListener("dragleave",event=>{if(!view.contains(event.relatedTarget))$("#drop-hint").classList.add("hidden");});
  view.addEventListener("drop",event=>{event.preventDefault();$("#drop-hint").classList.add("hidden");chooseFiles(event.dataTransfer.files);});
}
bindEvents();setAuthMode("login");boot().catch(error=>toast(error.message));
})();