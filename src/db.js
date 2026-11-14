import pg from 'pg';
const raw=process.env.DATABASE_URL;
if(!raw){console.error('Falta la variable DATABASE_URL');process.exit(1)}
const u=new URL(raw);u.searchParams.delete('sslmode');u.searchParams.delete('channel_binding');
const local=/^(localhost|127\.0\.0\.1)$/.test(u.hostname);
// SSL sin verificar el certificado: aceptable para pruebas. En producción hay que verificarlo.
export const pool=new pg.Pool({connectionString:u.toString(),ssl:local?false:{rejectUnauthorized:false},max:5});
