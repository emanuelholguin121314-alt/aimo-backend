import {pool} from './db.js';
const E=['player','library','import','search','favorites','playlists','manual_genre'];
const P=[...E,'ai_genre','auto_organize','duplicate_detection','music_analysis','batch_classify','smart_lists'];
const S=[...P,'dj_tools','advanced_library_analysis','stats','advanced_export','priority_ai'];
// [código, nombre, rango, funciones, mensual COP, anual COP, cuota mensual de análisis IA (PROVISIONAL)]
const SEED=[
  ['none','Sin suscripción',0,['player','library'],null,null,0],
  ['essential','Essential',1,E,19900,199000,0],
  ['pro','Pro',2,P,39900,399000,300],
  ['studio','Studio',3,S,79900,799000,2000]];
export async function migrate(){
  await pool.query(`
    CREATE TABLE IF NOT EXISTS settings(key text PRIMARY KEY,value text NOT NULL);
    CREATE TABLE IF NOT EXISTS users(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),email text UNIQUE NOT NULL,pass_hash text NOT NULL,created_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE IF NOT EXISTS plans(code text PRIMARY KEY,name text NOT NULL,rank int NOT NULL,active boolean NOT NULL DEFAULT true);
    CREATE TABLE IF NOT EXISTS plan_prices(plan_code text REFERENCES plans(code),period text CHECK(period IN('monthly','annual')),amount_cop bigint NOT NULL,PRIMARY KEY(plan_code,period));
    CREATE TABLE IF NOT EXISTS plan_features(plan_code text REFERENCES plans(code),feature text,PRIMARY KEY(plan_code,feature));
    CREATE TABLE IF NOT EXISTS plan_quotas(plan_code text REFERENCES plans(code),quota text,monthly_limit int NOT NULL,PRIMARY KEY(plan_code,quota));
    CREATE TABLE IF NOT EXISTS subscriptions(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),user_id uuid NOT NULL REFERENCES users(id),plan_code text NOT NULL REFERENCES plans(code),status text NOT NULL,current_period_end timestamptz NOT NULL,source text NOT NULL DEFAULT 'manual',created_at timestamptz NOT NULL DEFAULT now());`);
  // Datos iniciales: ON CONFLICT DO NOTHING para no pisar lo que se edite después.
  for(const [c,n,r,f,m,a,q] of SEED){
    await pool.query('INSERT INTO plans(code,name,rank) VALUES($1,$2,$3) ON CONFLICT DO NOTHING',[c,n,r]);
    if(m)await pool.query("INSERT INTO plan_prices VALUES($1,'monthly',$2),($1,'annual',$3) ON CONFLICT DO NOTHING",[c,m,a]);
    for(const x of f)await pool.query('INSERT INTO plan_features VALUES($1,$2) ON CONFLICT DO NOTHING',[c,x]);
    await pool.query("INSERT INTO plan_quotas VALUES($1,'ai_analyses_monthly',$2) ON CONFLICT DO NOTHING",[c,q]);
  }
}
