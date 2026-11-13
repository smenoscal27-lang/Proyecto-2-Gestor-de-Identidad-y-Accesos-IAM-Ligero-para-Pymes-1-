/**
 * auth.middleware.js - Middleware de Autorización y Control de Acceso
 * 
 * Características de Ciberseguridad:
 * - Extracción y verificación criptográfica de tokens Bearer JWT.
 * - Validación en tiempo real del estado 'activo' en SQLite (< 0.2ms en WAL mode).
 * - Revocación instantánea post-offboarding (elimina la vulnerabilidad de tokens huérfanos).
 * - Middleware de control de roles (RBAC) para proteger rutas administrativas.
 */

const jwt = require('jsonwebtoken');
const { dbGet } = require('./database');

/**
 * Middleware para autenticar peticiones mediante JWT
 */
const authenticateJWT = async (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'No autorizado',
      mensaje: 'Cabecera Authorization ausente o formato inválido. Use: Bearer <token>'
    });
  }

  const token = authHeader.split(' ')[1];

  try {
    const jwtSecret = process.env.JWT_SECRET || 'super_secret_iam_pyme_key_change_in_production_9f83a21e4b8c';
    const decoded = jwt.verify(token, jwtSecret);

    // Evitar que un token de desafío temporal de 2FA se use como token de acceso general
    if (decoded.tipo_token === '2fa_challenge') {
      return res.status(403).json({
        error: 'Acceso denegado',
        mensaje: 'Este token corresponde a un desafío 2FA incompleto. Debe verificar su segundo factor en /api/v1/auth/2fa/verify.'
      });
    }

    // Comprobación de estado en tiempo real contra SQLite (< 0.2ms)
    // Garantiza revocación instantánea si el usuario fue dado de baja (Offboarding)
    const usuario = await dbGet(
      `SELECT u.id, u.nombre, u.email, u.estado, u.rol_id, r.nombre AS rol_nombre, r.permisos_json
       FROM usuarios u
       LEFT JOIN roles r ON u.rol_id = r.id
       WHERE u.id = ?`,
      [decoded.sub]
    );

    if (!usuario) {
      return res.status(401).json({
        error: 'No autorizado',
        mensaje: 'El usuario asociado a este token ya no existe.'
      });
    }

    if (usuario.estado !== 'activo') {
      return res.status(403).json({
        error: 'Acceso revocado',
        mensaje: 'Su cuenta ha sido desactivada. Comuníquese con el departamento de seguridad.'
      });
    }

    // Inyectar usuario sanitizado en la petición
    req.user = {
      id: usuario.id,
      nombre: usuario.nombre,
      email: usuario.email,
      rol_id: usuario.rol_id,
      rol_nombre: usuario.rol_nombre,
      permisos: JSON.parse(usuario.permisos_json || '[]')
    };

    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Token expirado',
        mensaje: 'La sesión ha caducado. Inicie sesión nuevamente.'
      });
    }

    return res.status(403).json({
      error: 'Token inválido',
      mensaje: 'Firma criptográfica inválida o token corrupto.'
    });
  }
};

/**
 * Middleware para restringir acceso según el rol del usuario
 */
const requireRole = (rolRequerido) => {
  return (req, res, next) => {
    if (!req.user || req.user.rol_nombre !== rolRequerido) {
      return res.status(403).json({
        error: 'Privilegios insuficientes',
        mensaje: `Esta acción requiere el rol '${rolRequerido}'. Su rol actual es '${req.user?.rol_nombre || 'Desconocido'}'.`
      });
    }
    next();
  };
};

module.exports = {
  authenticateJWT,
  requireRole
};

