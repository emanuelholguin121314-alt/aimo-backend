import pg from 'pg';
const raw=process.env.DATABASE_URL;
if(!raw){console.error('Falta la variable DATABASE_URL');process.exit(1)}
const u=new URL(raw);u.searchParams.delete('sslmode');u.searchParams.delete('channel_binding');
console.log('Conectando a la base de datos en',u.hostname);
const local=/^(localhost|127\.0\.0\.1)$/.test(u.hostname);
// SSL sin verificar el certificado: aceptable para pruebas. En producción hay que verificarlo.
export const pool=new pg.Pool({connectionString:u.toString(),ssl:local?false:{rejectUnauthorized:false},max:5,connectionTimeoutMillis:10000});
pool.on('error',e=>console.error('Error de la base de datos:',e.message));
