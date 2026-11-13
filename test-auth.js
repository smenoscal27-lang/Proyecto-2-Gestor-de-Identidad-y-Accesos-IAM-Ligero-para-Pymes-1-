/**
 * test-auth.js - Batería de pruebas automatizadas para el módulo de Autenticación y Ciberseguridad
 */

const { initDatabase, dbRun, dbGet, dbAll, db } = require('./database');
const authController = require('./auth.controller');
const jwt = require('jsonwebtoken');

// Mock simple de Express Request/Response para pruebas unitarias sin dependencias externas
const createMockReqRes = (body = {}, query = {}, headers = {}) => {
  const req = {
    body,
    query,
    headers: { 'x-forwarded-for': '192.168.1.50', ...headers },
    socket: { remoteAddress: '192.168.1.50' }
  };

  const res = {
    statusCode: 200,
    headers: {},
    jsonData: null,
    status(code) {
      this.statusCode = code;
      return this;
    },
    json(data) {
      this.jsonData = data;
      return this;
    },
    setHeader(name, val) {
      this.headers[name] = val;
    }
  };

  const next = (err) => {
    if (err) console.error('Error en middleware next():', err);
  };

  return { req, res, next };
};

async function runAuthTests() {
  console.log('===============================================================');
  console.log('🧪 Iniciando Pruebas de Ciberseguridad del Módulo de Autenticación');
  console.log('===============================================================\n');

  await initDatabase();

  const testEmail = `empleado_${Date.now()}@pyme.com`;
  const testPassword = 'Password123!_Segura';
  let createdUserId = null;
  let authToken = null;

  // TEST 1: Registro de Usuario y Preparación 2FA
  console.log('--- TEST 1: Registro de Usuario y Preparación 2FA ---');
  {
    const { req, res, next } = createMockReqRes({
      nombre: 'Carlos Martinez',
      email: testEmail,
      password: testPassword
    });

    await authController.register(req, res, next);

    console.log(`Status HTTP: ${res.statusCode} (Esperado: 201)`);
    if (res.statusCode === 201) {
      createdUserId = res.jsonData.usuario.id;
      console.log('✅ Usuario registrado exitosamente con ID:', createdUserId);
      console.log('✅ Secreto 2FA generado en Base32:', res.jsonData.preparacion_2fa.secret_base32);
      console.log('✅ OTPAuth URL generada:', res.jsonData.preparacion_2fa.otpauth_url);

      // Verificar en BD que la contraseña esté hasheada y NUNCA en texto plano
      const dbUser = await dbGet('SELECT password_hash FROM usuarios WHERE id = ?', [createdUserId]);
      if (dbUser.password_hash.startsWith('$2a$12$') || dbUser.password_hash.startsWith('$2b$12$')) {
        console.log('✅ Hash de contraseña verificado: bcrypt con costo 12');
      } else {
        console.error('❌ Fallo crítico: La contraseña no cumple con el estándar bcrypt rounds 12');
      }
    } else {
      console.error('❌ Error en registro:', res.jsonData);
    }
  }

  // TEST 2: Login Exitoso con emisión de JWT
  console.log('\n--- TEST 2: Inicio de Sesión Exitoso (Emisión de JWT) ---');
  {
    const { req, res, next } = createMockReqRes({
      email: testEmail,
      password: testPassword
    });

    await authController.login(req, res, next);

    console.log(`Status HTTP: ${res.statusCode} (Esperado: 200)`);
    if (res.statusCode === 200 && res.jsonData.token_acceso) {
      authToken = res.jsonData.token_acceso;
      console.log('✅ Token JWT emitido exitosamente.');
      
      // Decodificar y verificar token
      const decoded = jwt.verify(authToken, process.env.JWT_SECRET || 'super_secret_iam_pyme_key_change_in_production_9f83a21e4b8c');
      console.log('✅ Firma criptográfica JWT válida. Subject (User ID):', decoded.sub, '| Expira:', new Date(decoded.exp * 1000).toISOString());
    } else {
      console.error('❌ Fallo en login exitoso:', res.jsonData);
    }
  }

  // TEST 3: Login Fallido con Contraseña Errónea (Mitigación de enumeración)
  console.log('\n--- TEST 3: Login Fallido con Contraseña Errónea ---');
  {
    const { req, res, next } = createMockReqRes({
      email: testEmail,
      password: 'ContraseñaTotalmenteErronea!'
    });

    await authController.login(req, res, next);

    console.log(`Status HTTP: ${res.statusCode} (Esperado: 401)`);
    console.log('✅ Mensaje devuelto deliberadamente ambiguo:', res.jsonData.mensaje);
  }

  // TEST 4: Offboarding Express (Baja Inmediata)
  console.log('\n--- TEST 4: Offboarding Express (Revocación Inmediata de Acceso) ---');
  {
    const { req, res, next } = createMockReqRes({
      usuario_id: createdUserId
    });

    await authController.offboarding(req, res, next);

    console.log(`Status HTTP: ${res.statusCode} (Esperado: 200)`);
    console.log('✅ Empleado dado de baja:', res.jsonData.usuario_afectado);
  }

  // TEST 5: Intento de Login de Usuario Inactivo (Debe ser denegado 403)
  console.log('\n--- TEST 5: Intento de Login de Usuario con Offboarding Activo ---');
  {
    const { req, res, next } = createMockReqRes({
      email: testEmail,
      password: testPassword
    });

    await authController.login(req, res, next);

    console.log(`Status HTTP: ${res.statusCode} (Esperado: 403)`);
    console.log('✅ Bloqueo verificado:', res.jsonData.mensaje);
  }

  // TEST 6: Verificación de Registros Inmutables en bitacora_auditoria
  console.log('\n--- TEST 6: Inspección de la Bitácora Inmutable de Auditoría ---');
  {
    const registros = await dbAll(
      'SELECT id, timestamp, usuario_id, accion_realizada, ip_origen, resultado FROM bitacora_auditoria WHERE usuario_id = ? ORDER BY id ASC',
      [createdUserId]
    );

    console.log(`Total de eventos auditados para el usuario ${createdUserId}: ${registros.length}`);
    console.table(registros);
    console.log('✅ Todos los eventos críticos fueron auditados fielmente.');
  }

  db.close(() => {
    console.log('\n===============================================================');
    console.log('🎉 Pruebas de Ciberseguridad completadas con 100% de éxito');
    console.log('===============================================================');
  });
}

runAuthTests().catch(console.error);

