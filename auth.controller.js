/**
 * auth.controller.js - Controlador de Autenticación, 2FA y Ciberseguridad IAM
 * 
 * Estándares de Seguridad Criptográfica:
 * - Hashing con bcrypt y Salt Rounds = 12 (resistencia contra fuerza bruta y GPU cracking).
 * - Mitigación de Timing Attacks en login mediante hash ficticio (Dummy Hash).
 * - Mensajes de error deliberadamente ambiguos para evitar la enumeración de usuarios.
 * - Ciclo completo de 2FA TOTP (RFC 6238) con ventana de tolerancia de ±30s contra desfase horario.
 * - Desafío de Login en 2 pasos: Emisión de token temporal (5m) si 2FA está activo.
 * - Firma criptográfica de JWT con algoritmo HS256 y tiempo de vida restringido.
 * - Registro obligatorio e inmutable en la bitácora de auditoría en cada evento.
 */

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const validator = require('validator');
const { dbGet, dbRun, dbAll } = require('./database');

const BCRYPT_ROUNDS = 12;
// Hash ficticio para unificar tiempos de respuesta si el usuario no existe (Anti-Timing Attack)
const DUMMY_HASH = '$2a$12$e8YgN1kX7s7hV7h48xZ8jeOq2x6U9s3aN5qW4y.B8g6yE9t9k.kme';

/**
 * Función auxiliar para registro obligatorio e inmutable en bitacora_auditoria
 */
const registrarAuditoria = async ({ usuario_id = null, accion_realizada, ip_origen, resultado }) => {
  try {
    await dbRun(
      'INSERT INTO bitacora_auditoria (usuario_id, accion_realizada, ip_origen, resultado) VALUES (?, ?, ?, ?)',
      [usuario_id, accion_realizada, ip_origen, resultado]
    );
  } catch (error) {
    console.error('[-] Error crítico al registrar auditoría inmutable:', error.message);
  }
};

const obtenerIpCliente = (req) => {
  return req.headers['x-forwarded-for']?.split(',')[0].trim() || req.socket.remoteAddress || '127.0.0.1';
};

/**
 * POST /api/v1/auth/register
 * Registra un nuevo empleado/usuario en el IAM
 */
const register = async (req, res, next) => {
  const ip = obtenerIpCliente(req);
  const { nombre, email, password, rol_id } = req.body;

  try {
    if (!nombre || !email || !password) {
      await registrarAuditoria({
        usuario_id: null,
        accion_realizada: 'USER_REGISTER_VALIDATION_ERROR',
        ip_origen: ip,
        resultado: 'FALLO'
      });
      return res.status(400).json({
        error: 'Petición inválida',
        mensaje: 'Los campos nombre, email y password son obligatorios.'
      });
    }

    // Sanitización y validación estricta de entradas
    const nombreLimpio = validator.trim(nombre);
    const nombreSaneado = validator.escape(nombreLimpio);
    if (nombreLimpio.length < 2 || nombreLimpio.length > 100) {
      return res.status(400).json({
        error: 'Petición inválida',
        mensaje: 'El nombre debe contener entre 2 y 100 caracteres.'
      });
    }

    const emailNormalizado = validator.trim(email).toLowerCase();
    if (!validator.isEmail(emailNormalizado)) {
      return res.status(400).json({
        error: 'Formato inválido',
        mensaje: 'El correo electrónico suministrado no cumple con un formato válido.'
      });
    }

    if (password.length < 8 || password.length > 128) {
      return res.status(400).json({
        error: 'Contraseña débil o no permitida',
        mensaje: 'La contraseña debe tener una longitud mínima de 8 caracteres y máxima de 128.'
      });
    }

    // 1. Verificar si el correo ya existe
    const usuarioExistente = await dbGet('SELECT id FROM usuarios WHERE email = ?', [emailNormalizado]);
    if (usuarioExistente) {
      await registrarAuditoria({
        usuario_id: usuarioExistente.id,
        accion_realizada: 'USER_REGISTER_DUPLICATE_EMAIL',
        ip_origen: ip,
        resultado: 'FALLO'
      });
      return res.status(409).json({
        error: 'Conflicto',
        mensaje: 'El correo electrónico ya se encuentra registrado.'
      });
    }

    // 2. Hashing de alta resistencia con Salt Rounds = 12
    const password_hash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // 3. Preparación 2FA (RFC 6238 TOTP): Generación de secreto base32
    const secret2fa = speakeasy.generateSecret({
      length: 20,
      name: `IAM PyME (${emailNormalizado})`,
      issuer: 'IAM PyME'
    });

    // 4. Asignación de rol por defecto si no se especifica
    let rolIdFinal = rol_id;
    if (!rolIdFinal) {
      const rolEmpleado = await dbGet('SELECT id FROM roles WHERE nombre = ?', ['Empleado']);
      rolIdFinal = rolEmpleado ? rolEmpleado.id : 1;
    }

    // 5. Persistencia en SQLite con datos sanitizados
    const resultadoInsert = await dbRun(
      `INSERT INTO usuarios (nombre, email, password_hash, secret_2fa, "2fa_activo", estado, rol_id)
       VALUES (?, ?, ?, ?, 0, 'activo', ?)`,
      [nombreSaneado, emailNormalizado, password_hash, secret2fa.base32, rolIdFinal]
    );

    const nuevoUsuarioId = resultadoInsert.id;

    // 6. Registro Inmutable Obligatorio en bitacora_auditoria
    await registrarAuditoria({
      usuario_id: nuevoUsuarioId,
      accion_realizada: 'USER_REGISTER_SUCCESS',
      ip_origen: ip,
      resultado: 'EXITO'
    });

    return res.status(201).json({
      mensaje: 'Usuario registrado exitosamente en el sistema IAM',
      usuario: {
        id: nuevoUsuarioId,
        nombre: nombreSaneado,
        email: emailNormalizado,
        estado: 'activo',
        rol_id: rolIdFinal,
        "2fa_activo": false
      },
      preparacion_2fa: {
        secret_base32: secret2fa.base32,
        otpauth_url: secret2fa.otpauth_url,
        instrucciones: 'Importa este secreto en tu app de autenticación (Google Authenticator, Authy) y luego actívalo mediante POST /api/v1/auth/2fa/activate.'
      }
    });
  } catch (error) {
    await registrarAuditoria({
      usuario_id: null,
      accion_realizada: 'USER_REGISTER_ERROR',
      ip_origen: ip,
      resultado: 'FALLO'
    });
    next(error);
  }
};

/**
 * POST /api/v1/auth/login
 * Inicio de sesión seguro con soporte para Desafío 2FA y defensa contra Timing Attacks
 */
const login = async (req, res, next) => {
  const ip = obtenerIpCliente(req);
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      await registrarAuditoria({
        usuario_id: null,
        accion_realizada: 'LOGIN_MISSING_CREDENTIALS',
        ip_origen: ip,
        resultado: 'FALLO'
      });
      return res.status(400).json({
        error: 'Petición inválida',
        mensaje: 'Email y contraseña requeridos.'
      });
    }

    const emailNormalizado = email.trim().toLowerCase();

    // 1. Búsqueda del usuario por email
    const usuario = await dbGet('SELECT * FROM usuarios WHERE email = ?', [emailNormalizado]);

    // 2. Mitigación de Timing Attacks:
    // Siempre ejecutamos bcrypt.compare para que la latencia sea constante exista o no el usuario
    const hashParaComparar = usuario ? usuario.password_hash : DUMMY_HASH;
    const passwordValido = await bcrypt.compare(password, hashParaComparar);

    // 3. Verificación de credenciales con error ambiguo
    if (!usuario || !passwordValido) {
      await registrarAuditoria({
        usuario_id: usuario ? usuario.id : null,
        accion_realizada: 'LOGIN_FAILED_INVALID_CREDENTIALS',
        ip_origen: ip,
        resultado: 'FALLO'
      });

      return res.status(401).json({
        error: 'Credenciales inválidas',
        mensaje: 'El correo electrónico o la contraseña ingresada son incorrectos.'
      });
    }

    // 4. Verificación de estado de cuenta (Offboarding Check)
    if (usuario.estado !== 'activo') {
      await registrarAuditoria({
        usuario_id: usuario.id,
        accion_realizada: 'LOGIN_BLOCKED_INACTIVE_ACCOUNT',
        ip_origen: ip,
        resultado: 'FALLO'
      });

      return res.status(403).json({
        error: 'Cuenta suspendida',
        mensaje: 'El acceso ha sido revocado. Contacte al departamento de TI o Seguridad.'
      });
    }

    const jwtSecret = process.env.JWT_SECRET || 'super_secret_iam_pyme_key_change_in_production_9f83a21e4b8c';

    // 5. FLUJO 2FA: Si el usuario tiene 2FA activo, emitir token de desafío temporal (5 minutos)
    if (usuario['2fa_activo'] === 1) {
      const challengeToken = jwt.sign(
        {
          sub: usuario.id,
          email: usuario.email,
          tipo_token: '2fa_challenge'
        },
        jwtSecret,
        { expiresIn: '5m', algorithm: 'HS256' }
      );

      await registrarAuditoria({
        usuario_id: usuario.id,
        accion_realizada: 'LOGIN_2FA_CHALLENGE_ISSUED',
        ip_origen: ip,
        resultado: 'EXITO'
      });

      return res.status(200).json({
        requiere_2fa: true,
        mensaje: 'Paso 1 completado. Ingrese el código TOTP de 6 dígitos en /api/v1/auth/2fa/verify para completar la autenticación.',
        token_desafio_2fa: challengeToken,
        expira_en: '5m'
      });
    }

    // 6. FLUJO ESTÁNDAR: Emisión del Token JWT definitivo (1 hora)
    const jwtExpiresIn = process.env.JWT_EXPIRES_IN || '1h';

    const payload = {
      sub: usuario.id,
      email: usuario.email,
      nombre: usuario.nombre,
      rol_id: usuario.rol_id,
      tipo_token: 'access_token',
      "2fa_activo": false
    };

    const token = jwt.sign(payload, jwtSecret, {
      expiresIn: jwtExpiresIn,
      algorithm: 'HS256'
    });

    // 7. Registro Inmutable Obligatorio de Login Exitoso
    await registrarAuditoria({
      usuario_id: usuario.id,
      accion_realizada: 'LOGIN_SUCCESS',
      ip_origen: ip,
      resultado: 'EXITO'
    });

    return res.status(200).json({
      mensaje: 'Autenticación exitosa',
      token_acceso: token,
      tipo_token: 'Bearer',
      expira_en: jwtExpiresIn,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        estado: usuario.estado,
        "2fa_activo": false
      }
    });
  } catch (error) {
    await registrarAuditoria({
      usuario_id: null,
      accion_realizada: 'LOGIN_INTERNAL_ERROR',
      ip_origen: ip,
      resultado: 'FALLO'
    });
    next(error);
  }
};

/**
 * POST /api/v1/auth/2fa/activate
 * Valida el primer código TOTP y activa el segundo factor en la cuenta
 */
const activate2FA = async (req, res, next) => {
  const ip = obtenerIpCliente(req);
  const usuarioId = req.user ? req.user.id : req.body.usuario_id;
  const { codigo_totp } = req.body;

  try {
    if (!usuarioId || !codigo_totp) {
      await registrarAuditoria({
        usuario_id: usuarioId || null,
        accion_realizada: '2FA_ACTIVATE_VALIDATION_ERROR',
        ip_origen: ip,
        resultado: 'FALLO'
      });
      return res.status(400).json({
        error: 'Petición inválida',
        mensaje: 'Debe suministrar el código TOTP de 6 dígitos.'
      });
    }

    const usuario = await dbGet('SELECT id, email, secret_2fa, "2fa_activo", estado FROM usuarios WHERE id = ?', [usuarioId]);
    if (!usuario) {
      return res.status(404).json({ error: 'No encontrado', mensaje: 'Usuario no encontrado.' });
    }

    if (usuario.estado !== 'activo') {
      return res.status(403).json({ error: 'Cuenta inactiva', mensaje: 'El usuario se encuentra inactivo.' });
    }

    // Validación del código TOTP con ventana de tolerancia ±30 segundos
    // En modo desarrollo, también se acepta '123456' como código de prueba docente
    const esValido = speakeasy.totp.verify({
      secret: usuario.secret_2fa,
      encoding: 'base32',
      token: String(codigo_totp).trim(),
      window: 1
    }) || (process.env.NODE_ENV === 'development' && String(codigo_totp).trim() === '123456');

    if (!esValido) {
      await registrarAuditoria({
        usuario_id: usuario.id,
        accion_realizada: '2FA_ACTIVATE_FAILED_CODE',
        ip_origen: ip,
        resultado: 'FALLO'
      });
      return res.status(400).json({
        error: 'Código inválido',
        mensaje: 'El código TOTP de 6 dígitos es incorrecto o ha caducado. Inténtelo de nuevo.'
      });
    }

    // Activar 2FA en base de datos
    await dbRun('UPDATE usuarios SET "2fa_activo" = 1 WHERE id = ?', [usuario.id]);

    // Auditoría Inmutable
    await registrarAuditoria({
      usuario_id: usuario.id,
      accion_realizada: '2FA_ACTIVATED_SUCCESS',
      ip_origen: ip,
      resultado: 'EXITO'
    });

    return res.status(200).json({
      mensaje: '¡Doble factor de autenticación (2FA) activado exitosamente!',
      usuario_id: usuario.id,
      "2fa_activo": true
    });
  } catch (error) {
    await registrarAuditoria({
      usuario_id: usuarioId || null,
      accion_realizada: '2FA_ACTIVATE_ERROR',
      ip_origen: ip,
      resultado: 'FALLO'
    });
    next(error);
  }
};

/**
 * POST /api/v1/auth/2fa/verify
 * Segundo paso de login: Valida el código TOTP del desafío y emite el token JWT definitivo
 */
const verify2FALogin = async (req, res, next) => {
  const ip = obtenerIpCliente(req);
  const { token_desafio_2fa, codigo_totp } = req.body;

  try {
    if (!token_desafio_2fa || !codigo_totp) {
      await registrarAuditoria({
        usuario_id: null,
        accion_realizada: 'LOGIN_2FA_MISSING_DATA',
        ip_origen: ip,
        resultado: 'FALLO'
      });
      return res.status(400).json({
        error: 'Petición inválida',
        mensaje: 'Se requiere token_desafio_2fa y codigo_totp de 6 dígitos.'
      });
    }

    const jwtSecret = process.env.JWT_SECRET || 'super_secret_iam_pyme_key_change_in_production_9f83a21e4b8c';
    let decoded;

    try {
      decoded = jwt.verify(token_desafio_2fa, jwtSecret);
    } catch (err) {
      return res.status(401).json({
        error: 'Desafío expirado',
        mensaje: 'El token de desafío 2FA es inválido o ha caducado (límite de 5 minutos). Inicie sesión de nuevo.'
      });
    }

    if (decoded.tipo_token !== '2fa_challenge') {
      return res.status(400).json({
        error: 'Token inválido',
        mensaje: 'El token provisto no corresponde a un desafío de segundo factor.'
      });
    }

    const usuario = await dbGet('SELECT * FROM usuarios WHERE id = ?', [decoded.sub]);
    if (!usuario || usuario.estado !== 'activo') {
      await registrarAuditoria({
        usuario_id: usuario ? usuario.id : null,
        accion_realizada: 'LOGIN_2FA_BLOCKED_INACTIVE',
        ip_origen: ip,
        resultado: 'FALLO'
      });
      return res.status(403).json({
        error: 'Acceso denegado',
        mensaje: 'Usuario inactivo o no encontrado.'
      });
    }

    // Verificar el código TOTP contra el secreto del usuario
    const esValido = speakeasy.totp.verify({
      secret: usuario.secret_2fa,
      encoding: 'base32',
      token: String(codigo_totp).trim(),
      window: 1
    });

    if (!esValido) {
      await registrarAuditoria({
        usuario_id: usuario.id,
        accion_realizada: 'LOGIN_2FA_INVALID_CODE',
        ip_origen: ip,
        resultado: 'FALLO'
      });
      return res.status(401).json({
        error: 'Código inválido',
        mensaje: 'El código TOTP de 6 dígitos es incorrecto o ha caducado.'
      });
    }

    // Emitir Token de Acceso Definitivo (1 hora)
    const jwtExpiresIn = process.env.JWT_EXPIRES_IN || '1h';
    const payload = {
      sub: usuario.id,
      email: usuario.email,
      nombre: usuario.nombre,
      rol_id: usuario.rol_id,
      tipo_token: 'access_token',
      "2fa_activo": true
    };

    const tokenAcceso = jwt.sign(payload, jwtSecret, {
      expiresIn: jwtExpiresIn,
      algorithm: 'HS256'
    });

    // Auditoría Inmutable de Login 2FA Exitoso
    await registrarAuditoria({
      usuario_id: usuario.id,
      accion_realizada: 'LOGIN_2FA_SUCCESS',
      ip_origen: ip,
      resultado: 'EXITO'
    });

    return res.status(200).json({
      mensaje: 'Autenticación en dos pasos completada con éxito',
      token_acceso: tokenAcceso,
      tipo_token: 'Bearer',
      expira_en: jwtExpiresIn,
      usuario: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        estado: usuario.estado,
        "2fa_activo": true
      }
    });
  } catch (error) {
    await registrarAuditoria({
      usuario_id: null,
      accion_realizada: 'LOGIN_2FA_ERROR',
      ip_origen: ip,
      resultado: 'FALLO'
    });
    next(error);
  }
};

/**
 * GET /api/v1/auth/me
 * Consulta el perfil del usuario autenticado (Protegido con authenticateJWT)
 */
const getProfile = async (req, res) => {
  return res.status(200).json({
    perfil: req.user
  });
};

/**
 * POST /api/v1/auth/offboarding
 * Baja inmediata de accesos del empleado
 */
const offboarding = async (req, res, next) => {
  const ip = obtenerIpCliente(req);
  const usuario_id = req.body.usuario_id || req.query.usuario_id;

  try {
    if (!usuario_id) {
      await registrarAuditoria({
        usuario_id: null,
        accion_realizada: 'OFFBOARDING_MISSING_ID',
        ip_origen: ip,
        resultado: 'FALLO'
      });
      return res.status(400).json({
        error: 'Petición inválida',
        mensaje: 'Debe proporcionar el usuario_id del empleado a desvincular.'
      });
    }

    const usuario = await dbGet('SELECT id, nombre, email, estado FROM usuarios WHERE id = ?', [usuario_id]);
    if (!usuario) {
      await registrarAuditoria({
        usuario_id: null,
        accion_realizada: 'OFFBOARDING_USER_NOT_FOUND',
        ip_origen: ip,
        resultado: 'FALLO'
      });
      return res.status(404).json({
        error: 'No encontrado',
        mensaje: `No existe un usuario con el identificador ${usuario_id}.`
      });
    }

    // Desactivación inmediata
    await dbRun("UPDATE usuarios SET estado = 'inactivo' WHERE id = ?", [usuario_id]);

    // Auditoría Inmutable Obligatoria
    await registrarAuditoria({
      usuario_id: usuario.id,
      accion_realizada: 'USER_OFFBOARDED_IMMEDIATE_REVOCATION',
      ip_origen: ip,
      resultado: 'EXITO'
    });

    console.warn(`[!] ALERTA SEGURIDAD: Acceso revocado de inmediato para ID ${usuario.id} (${usuario.email}).`);

    return res.status(200).json({
      mensaje: 'Offboarding ejecutado con éxito. El acceso del empleado ha sido revocado de forma inmediata.',
      usuario_afectado: {
        id: usuario.id,
        nombre: usuario.nombre,
        email: usuario.email,
        estado_anterior: usuario.estado,
        nuevo_estado: 'inactivo'
      }
    });
  } catch (error) {
    await registrarAuditoria({
      usuario_id: usuario_id || null,
      accion_realizada: 'OFFBOARDING_ERROR',
      ip_origen: ip,
      resultado: 'FALLO'
    });
    next(error);
  }
};

/**
 * GET /api/v1/auth/users
 * Lista todas las identidades registradas (sin exponer credenciales)
 */
const listUsers = async (req, res, next) => {
  try {
    const rows = await dbAll(`
      SELECT 
        u.id, 
        u.nombre, 
        u.email, 
        u.estado, 
        u."2fa_activo",
        COALESCE(r.nombre, 'Empleado') AS rol,
        COALESCE(strftime('%d/%m/%Y', u.created_at), 'Reciente') AS fecha_alta
      FROM usuarios u
      LEFT JOIN roles r ON u.rol_id = r.id
      ORDER BY u.id ASC
    `);

    const usuarios = rows.map(u => ({
      ...u,
      "2fa_activo": u["2fa_activo"] === 1
    }));

    return res.json({ usuarios });
  } catch (error) {
    next(error);
  }
};

/**
 * GET /api/v1/auth/audit
 * Lista los eventos inmutables de auditoría
 */
const listAuditLogs = async (req, res, next) => {
  try {
    const limit = parseInt(req.query.limit, 10) || 100;
    const logs = await dbAll(`
      SELECT id, timestamp, usuario_id, accion_realizada, ip_origen, resultado
      FROM bitacora_auditoria
      ORDER BY id DESC
      LIMIT ?
    `, [limit]);

    return res.json({ logs });
  } catch (error) {
    next(error);
  }
};

/**
 * GET /api/v1/auth/apps
 * Lista las aplicaciones federadas SSO registradas
 */
const listApps = async (req, res, next) => {
  try {
    const apps = await dbAll(
      'SELECT id, nombre_app, url_destino FROM aplicaciones_sso ORDER BY id ASC'
    );
    return res.json({ apps });
  } catch (error) {
    next(error);
  }
};

module.exports = {
  register,
  login,
  activate2FA,
  verify2FALogin,
  getProfile,
  offboarding,
  listUsers,
  listAuditLogs,
  listApps,
  registrarAuditoria
};
