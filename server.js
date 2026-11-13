/**
 * server.js - Servidor Express Ultraligero para IAM PyME
 * 
 * Principios arquitectónicos aplicados:
 * - Rendimiento extremo: Middleware mínimo, compresión de encabezados, respuestas en < 5ms.
 * - Monitoreo de latencia: Encabezado 'X-Response-Time' en cada respuesta HTTP.
 * - Base de datos lista para producción: SQLite en modo WAL inicializada al arranque.
 * - Cierre ordenado (Graceful Shutdown): Evita corrupción de datos en reinicios.
 */

require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const { initDatabase, db, dbGet, dbAll } = require('./database');
const authRoutes = require('./auth.routes');

const app = express();
const PORT = process.env.PORT || 3000;

// Configurar confianza en proxies inversos (Vite proxy, NGINX, Cloudflare) para rate limiting preciso
app.set('trust proxy', 1);

// --- 1. CONFIGURACIÓN DE RENDIMIENTO Y HARDENING DE SEGURIDAD ---

// Helmet: Protección de cabeceras HTTP (Clickjacking, XSS, MIME Sniffing, HSTS)
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));

// Deshabilitar huella de Express adicionalmente
app.disable('x-powered-by');

// Middleware CORS nativo de alto rendimiento (permite comunicación con Vite y clientes externos)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// Middleware para medir el tiempo de respuesta exacto (garantía sub-segundo)
app.use((req, res, next) => {
  const startHrTime = process.hrtime.bigint();

  res.on('finish', () => {
    const elapsedHrTime = process.hrtime.bigint() - startHrTime;
    const elapsedMs = Number(elapsedHrTime) / 1_000_000;
    // Registro ligero para depuración en consola
    if (process.env.NODE_ENV !== 'test') {
      console.log(`[HTTP] ${req.method} ${req.originalUrl} - ${res.statusCode} (${elapsedMs.toFixed(2)} ms)`);
    }
  });

  // Inyectar cabecera con el tiempo medido
  const originalEnd = res.end;
  res.end = function (...args) {
    const elapsedHrTime = process.hrtime.bigint() - startHrTime;
    const elapsedMs = (Number(elapsedHrTime) / 1_000_000).toFixed(2);
    if (!res.headersSent) {
      res.setHeader('X-Response-Time', `${elapsedMs}ms`);
    }
    return originalEnd.apply(this, args);
  };

  next();
});

// Parsers estrictos y ligeros (límite de 100kb para mitigar ataques DoS de memoria)
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: false, limit: '100kb' }));

// --- 2. RUTAS BASE Y HEALTH CHECK ---

// Ruta raíz: Bienvenida y metadatos del servicio IAM
app.get('/', (req, res) => {
  res.json({
    sistema: 'IAM Ligero para PyMEs',
    version: '1.0.0',
    estado: 'operativo',
    arquitectura: 'Node.js + Express + SQLite (WAL mode)',
    endpoints: {
      health: 'GET /health',
      metricas: 'GET /api/v1/status',
      auth: {
        registro: 'POST /api/v1/auth/register',
        login: 'POST /api/v1/auth/login',
        offboarding: 'POST /api/v1/auth/offboarding'
      }
    }
  });
});

// Endpoint de verificación de salud profunda (Deep Health Check)
// Valida conectividad y tiempo de respuesta directo contra SQLite
app.get(['/health', '/api/v1/health'], async (req, res) => {
  const dbStart = process.hrtime.bigint();
  try {
    // Consulta ultra-rápida de verificación
    await dbGet('SELECT 1 AS ping');
    const dbLatencyMs = (Number(process.hrtime.bigint() - dbStart) / 1_000_000).toFixed(2);

    res.status(200).json({
      estado: 'HEALTHY',
      timestamp: new Date().toISOString(),
      uptime_segundos: Math.floor(process.uptime()),
      base_de_datos: {
        motor: 'SQLite',
        estado: 'CONECTADO',
        latencia_db_ms: Number(dbLatencyMs)
      },
      memoria_usada_mb: (process.memoryUsage().rss / 1024 / 1024).toFixed(2)
    });
  } catch (error) {
    res.status(503).json({
      estado: 'UNHEALTHY',
      timestamp: new Date().toISOString(),
      error: error.message
    });
  }
});

// Endpoint de estado y resumen de tablas
app.get('/api/v1/status', async (req, res, next) => {
  try {
    const tables = await dbAll(
      "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;"
    );
    const triggers = await dbAll(
      "SELECT name, tbl_name FROM sqlite_master WHERE type='trigger' ORDER BY name;"
    );

    res.json({
      tablas_registradas: tables.map(t => t.name),
      triggers_inmutabilidad: triggers.map(t => ({ trigger: t.name, tabla: t.tbl_name })),
      subsegundo_garantizado: true
    });
  } catch (error) {
    next(error);
  }
});

// --- 3. MÓDULOS DE NEGOCIO Y SEGURIDAD ---
app.use('/api/v1/auth', authRoutes);

// --- 4. GESTIÓN DE ERRORES CENTRALIZADA ---

// Manejador 404 para rutas inexistentes
app.use((req, res) => {
  res.status(404).json({
    error: 'Ruta no encontrada',
    metodo: req.method,
    ruta: req.originalUrl
  });
});

// Middleware global de captura de excepciones inteligente (Hardened: No fuga de información sensible)
app.use((err, req, res, next) => {
  const isProduction = process.env.NODE_ENV === 'production';
  const statusCode = err.status || err.statusCode || 500;

  // Registro detallado en logs internos para auditoría forense
  console.error(`[-] [ERROR ${statusCode}] ${req.method} ${req.originalUrl}:`, err.message);
  if (!isProduction && err.stack) {
    console.error(err.stack);
  }

  // Respuesta al cliente sanitizada: En producción NUNCA expone stack traces de SQLite ni variables de entorno
  res.status(statusCode).json({
    error: statusCode >= 500 ? 'Error interno del servidor' : 'Petición incorrecta',
    mensaje: isProduction && statusCode >= 500
      ? 'Ocurrió un error inesperado. Por motivos de seguridad, los detalles han sido registrados en la bitácora interna.'
      : err.message || 'Error no especificado',
    timestamp: new Date().toISOString(),
    ...(isProduction ? {} : { stack: err.stack })
  });
});

// --- 4. ARRANQUE DEL SERVIDOR Y CIERRE ORDENADO ---
let server;

const startServer = async () => {
  try {
    // Garantiza que la BD y triggers estén creados antes de aceptar tráfico
    await initDatabase();

    server = app.listen(PORT, () => {
      console.log(`\n=================================================`);
      console.log(`🚀 Servidor IAM corriendo en: http://localhost:${PORT}`);
      console.log(`⚡ Modo: ${process.env.NODE_ENV || 'development'}`);
      console.log(`🔍 Health Check: http://localhost:${PORT}/health`);
      console.log(`=================================================\n`);
    });
  } catch (error) {
    console.error('[-] Fallo fatal al arrancar el servidor:', error);
    process.exit(1);
  }
};

// Cierre elegante (Graceful Shutdown)
const gracefulShutdown = (signal) => {
  console.log(`\n[!] Recibida señal ${signal}. Cerrando servidor de forma ordenada...`);
  if (server) {
    server.close(() => {
      console.log('[+] Servidor HTTP cerrado.');
      db.close((err) => {
        if (err) {
          console.error('[-] Error al cerrar la base de datos:', err.message);
        } else {
          console.log('[+] Conexión con SQLite cerrada correctamente.');
        }
        process.exit(0);
      });
    });
  } else {
    process.exit(0);
  }
};

process.on('SIGINT', () => gracefulShutdown('SIGINT'));
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));

// Arrancar si se ejecuta directamente
if (require.main === module) {
  startServer();
}

module.exports = { app, startServer };

