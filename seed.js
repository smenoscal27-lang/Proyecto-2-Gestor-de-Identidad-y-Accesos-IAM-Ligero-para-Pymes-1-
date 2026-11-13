/**
 * seed.js - Semillero de Datos para Demostración y Evaluación Académica
 * Inicializa los roles, usuarios de prueba y aplicaciones SSO en SQLite.
 */

const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const { initDatabase, dbGet, dbRun, dbAll, db } = require('./database');

async function runSeed() {
  console.log('===============================================================');
  console.log('🌱 Inicializando Datos Semilla (Seeds) para IAM PyME');
  console.log('===============================================================\n');

  await initDatabase();

  // 1. Asegurar roles
  console.log('1. Verificando roles en base de datos...');
  let adminRole = await dbGet('SELECT id FROM roles WHERE nombre = ?', ['Administrador']);
  if (!adminRole) {
    const res = await dbRun('INSERT INTO roles (nombre, permisos_json) VALUES (?, ?)', [
      'Administrador',
      JSON.stringify(['*'])
    ]);
    adminRole = { id: res.id };
  }

  let employeeRole = await dbGet('SELECT id FROM roles WHERE nombre = ?', ['Empleado']);
  if (!employeeRole) {
    const res = await dbRun('INSERT INTO roles (nombre, permisos_json) VALUES (?, ?)', [
      'Empleado',
      JSON.stringify(['read:profile', 'sso:access'])
    ]);
    employeeRole = { id: res.id };
  }
  console.log(`[OK] Roles configurados: Administrador (#${adminRole.id}), Empleado (#${employeeRole.id})`);

  // 2. Usuarios de Prueba
  const passwordComun = 'MiContraseñaSegura2026!';
  const passwordHash = await bcrypt.hash(passwordComun, 12);

  const usuariosSeed = [
    {
      nombre: 'Administrador TI',
      email: 'admin@pyme.com',
      rol_id: adminRole.id,
      estado: 'activo',
      '2fa_activo': 1,
      secret_2fa: 'JBSWY3DPEHPK3PXP'
    },
    {
      nombre: 'Carlos Mendoza',
      email: 'carlos.mendoza@pyme.com',
      rol_id: employeeRole.id,
      estado: 'activo',
      '2fa_activo': 0,
      secret_2fa: 'JBSWY3DPEHPK3PXP'
    },
    {
      nombre: 'Ana María Gómez',
      email: 'ana.gomez@pyme.com',
      rol_id: adminRole.id,
      estado: 'activo',
      '2fa_activo': 1,
      secret_2fa: 'HXDMVJECJJWSRZ3J'
    },
    {
      nombre: 'Lucía Fernández',
      email: 'lucia.fernandez@pyme.com',
      rol_id: employeeRole.id,
      estado: 'activo',
      '2fa_activo': 0,
      secret_2fa: 'OZZV6TRSOZZV6TRS'
    },
    {
      nombre: 'Jorge Ramírez',
      email: 'jorge.ramirez@pyme.com',
      rol_id: employeeRole.id,
      estado: 'inactivo',
      '2fa_activo': 0,
      secret_2fa: 'N5QW4Y3BOZZV6TRS'
    }
  ];

  console.log('\n2. Creando identidades de prueba...');
  for (const u of usuariosSeed) {
    const existente = await dbGet('SELECT id FROM usuarios WHERE email = ?', [u.email]);
    if (!existente) {
      const res = await dbRun(
        `INSERT INTO usuarios (nombre, email, password_hash, secret_2fa, "2fa_activo", estado, rol_id)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [u.nombre, u.email, passwordHash, u.secret_2fa, u['2fa_activo'], u.estado, u.rol_id]
      );
      console.log(`[+] Creado usuario: ${u.nombre} (${u.email}) - Rol: #${u.rol_id} - Estado: ${u.estado}`);

      // Registrar en bitácora inmutable
      await dbRun(
        `INSERT INTO bitacora_auditoria (usuario_id, accion_realizada, ip_origen, resultado)
         VALUES (?, ?, ?, ?)`,
        [res.id, 'USER_REGISTER_SUCCESS', '127.0.0.1 (System Seed)', 'EXITO']
      );

      if (u.estado === 'inactivo') {
        await dbRun(
          `INSERT INTO bitacora_auditoria (usuario_id, accion_realizada, ip_origen, resultado)
           VALUES (?, ?, ?, ?)`,
          [res.id, 'USER_OFFBOARDED_IMMEDIATE_REVOCATION', '192.168.1.1 (Admin Console)', 'EXITO']
        );
      }
    } else {
      console.log(`[*] Usuario ya existente: ${u.email}`);
    }
  }

  // 3. Aplicaciones SSO
  console.log('\n3. Creando aplicaciones federadas SSO...');
  const appsSeed = [
    { nombre_app: 'Sistema Contable & Facturación', url_destino: 'https://contabilidad.pyme.internal/sso' },
    { nombre_app: 'Gestor de Recursos & Inventario', url_destino: 'https://erp.pyme.internal/sso' },
    { nombre_app: 'Portal de Nómina & RRHH', url_destino: 'https://nomina.pyme.internal/sso' },
    { nombre_app: 'CRM & Pipeline Comercial', url_destino: 'https://crm.pyme.internal/sso' },
    { nombre_app: 'Mesa de Ayuda & Tickets TI', url_destino: 'https://soporte.pyme.internal/sso' },
    { nombre_app: 'Intranet & Documentos PyME', url_destino: 'https://intranet.pyme.internal/sso' }
  ];

  for (const app of appsSeed) {
    const existeApp = await dbGet('SELECT id FROM aplicaciones_sso WHERE nombre_app = ?', [app.nombre_app]);
    if (!existeApp) {
      const clientSecret = speakeasy.generateSecret({ length: 32 }).base32;
      await dbRun(
        'INSERT INTO aplicaciones_sso (nombre_app, url_destino, client_secret) VALUES (?, ?, ?)',
        [app.nombre_app, app.url_destino, clientSecret]
      );
      console.log(`[+] Conectada aplicación SSO: ${app.nombre_app}`);
    }
  }

  console.log('\n===============================================================');
  console.log('✅ Base de datos sembrada y lista para demostración.');
  console.log('===============================================================');

  db.close();
}

runSeed().catch(console.error);

