import express from 'express';
import {randomBytes,scrypt,timingSafeEqual,createHmac,generateKeyPairSync,createPrivateKey,createPublicKey,sign} from 'node:crypto';
import {promisify} from 'node:util';
import {pool} from './db.js';
import {migrate} from './schema.js';

const scr=promisify(scrypt);
const b64=x=>Buffer.from(x).toString('base64url');
const eq=(a,b)=>a.length===b.length&&timingSafeEqual(Buffer.from(a),Buffer.from(b));
const h=f=>(q,r,n)=>f(q,r,n).catch(e=>{console.error(e);r.status(500).json({error:'Error del servidor'})});

async function setting(k,make){
  const g=async()=>(await pool.query('SELECT value FROM settings WHERE key=$1',[k])).rows[0]?.value;
  return (await g())||(await pool.query('INSERT INTO settings(key,value) VALUES($1,$2) ON CONFLICT DO NOTHING',[k,make()]),await g());
}
let SESSION,PRIV,JWK;
async function init(){
  await migrate();
  SESSION=await setting('session_secret',()=>randomBytes(32).toString('hex'));
  const pem=await setting('entitlement_key',()=>generateKeyPairSync('ec',{namedCurve:'P-256'}).privateKey.export({type:'pkcs8',format:'pem'}));
  PRIV=createPrivateKey(pem);JWK=createPublicKey(PRIV).export({format:'jwk'});
}

// Sesión: uid.vence.firma (30 días)
const mac=p=>createHmac('sha256',SESSION).update(p).digest('base64url');
const session=uid=>{const p=`${uid}.${Date.now()+30*864e5}`;return p+'.'+mac(p)};
function readSession(t){
  const [uid,exp,sig]=String(t||'').split('.');if(!sig)return null;
  return eq(sig,mac(`${uid}.${exp}`))&&+exp>Date.now()?uid:null;
}
// Certificado de acceso firmado (ES256). La app lo verifica con la llave pública.
function cert(body){
  const d=b64(JSON.stringify({alg:'ES256',typ:'JWT'}))+'.'+b64(JSON.stringify(body));
  return d+'.'+sign('sha256',Buffer.from(d),{key:PRIV,dsaEncoding:'ieee-p1363'}).toString('base64url');
}
async function entitlement(uid){
  const s=(await pool.query(`SELECT s.plan_code,s.current_period_end FROM subscriptions s JOIN plans p ON p.code=s.plan_code
    WHERE s.user_id=$1 AND s.status='active' AND s.current_period_end>now() ORDER BY p.rank DESC LIMIT 1`,[uid])).rows[0];
  const tier=s?.plan_code||'none',end=s?.current_period_end||null;
  const features=(await pool.query('SELECT feature FROM plan_features WHERE plan_code=$1 ORDER BY feature',[tier])).rows.map(r=>r.feature);
  const quotas=Object.fromEntries((await pool.query('SELECT quota,monthly_limit FROM plan_quotas WHERE plan_code=$1',[tier])).rows.map(r=>[r.quota,r.monthly_limit]));
  const now=Date.now(),body={sub:uid,tier,features,quotas,period_end:end,iat:now,exp:Math.min(now+72*36e5,end?+new Date(end):Infinity)};
  return {...body,certificate:cert(body)};
}
const can=async(uid,f)=>(await entitlement(uid)).features.includes(f);

const tries=new Map();
const limited=k=>{const n=(tries.get(k)||[]).filter(t=>Date.now()-t<9e5);tries.set(k,n);return n.length>=10};
const fail=k=>tries.set(k,[...(tries.get(k)||[]),Date.now()]);

const app=express();app.set('trust proxy',1);app.use(express.json({limit:'10kb'}));
app.use((q,r,n)=>{r.set({'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'Content-Type,Authorization,X-Admin-Key','Access-Control-Allow-Methods':'GET,POST,OPTIONS'});q.method==='OPTIONS'?r.sendStatus(204):n()});
const needAuth=h(async(q,r,n)=>{const uid=readSession((q.headers.authorization||'').replace(/^Bearer /,''));if(!uid)return r.status(401).json({error:'Sesión inválida'});q.uid=uid;n()});

app.get('/health',(_,r)=>r.json({ok:true}));
app.get('/public-key',(_,r)=>r.json(JWK));
app.get('/plans',h(async(_,r)=>{
  const pl=(await pool.query("SELECT code,name,rank FROM plans WHERE active AND code<>'none' ORDER BY rank")).rows;
  const pr=(await pool.query('SELECT plan_code,period,amount_cop FROM plan_prices')).rows;
  const f=(await pool.query('SELECT plan_code,feature FROM plan_features ORDER BY feature')).rows;
  const qu=(await pool.query('SELECT plan_code,quota,monthly_limit FROM plan_quotas')).rows;
  r.json({currency:'COP',plans:pl.map(p=>({...p,
    prices:Object.fromEntries(pr.filter(x=>x.plan_code===p.code).map(x=>[x.period,+x.amount_cop])),
    features:f.filter(x=>x.plan_code===p.code).map(x=>x.feature),
    quotas:Object.fromEntries(qu.filter(x=>x.plan_code===p.code).map(x=>[x.quota,x.monthly_limit]))}))});
}));

app.post('/auth/register',h(async(q,r)=>{
  const e=String(q.body?.email||'').trim().toLowerCase(),pw=String(q.body?.password||'');
  if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)||e.length>254)return r.status(400).json({error:'Correo inválido'});
  if(pw.length<8||pw.length>200)return r.status(400).json({error:'La contraseña debe tener al menos 8 caracteres'});
  const s=randomBytes(16),k=await scr(pw,s,64);
  const i=await pool.query('INSERT INTO users(email,pass_hash) VALUES($1,$2) ON CONFLICT DO NOTHING RETURNING id',[e,s.toString('hex')+':'+k.toString('hex')]);
  if(!i.rows[0])return r.status(409).json({error:'Ese correo ya está registrado'});
  r.json({token:session(i.rows[0].id)});
}));
app.post('/auth/login',h(async(q,r)=>{
  const e=String(q.body?.email||'').trim().toLowerCase(),pw=String(q.body?.password||''),key=q.
