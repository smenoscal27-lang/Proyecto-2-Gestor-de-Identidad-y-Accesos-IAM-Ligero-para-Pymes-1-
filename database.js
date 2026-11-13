/**
 * database.js - Configuración y esquema de base de datos SQLite
 * Proyecto: IAM Ligero para PyMEs
 *
 * Características de rendimiento y seguridad:
 * - WAL Mode (Write-Ahead Logging) para concurrencia y lecturas ultrarrápidas (< 1ms).
 * - Llaves foráneas habilitadas explícitamente (PRAGMA foreign_keys = ON).
 * - Triggers de inmutabilidad en bitácora de auditoría (WORM: Write Once, Read Many).
 */

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
require('dotenv').config();

const DB_PATH = path.resolve(__dirname, process.env.DB_FILE || 'iam_database.sqlite');

// Inicialización de la conexión
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('[-] Error crítico al abrir la base de datos SQLite:', err.message);
  } else {
    console.log(`[+] Conexión establecida con la base de datos SQLite: ${DB_PATH}`);
  }
});

/**
 * Envoltorios de Promesas para operaciones asíncronas con async/await
 */
const dbRun = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ id: this.lastID, changes: this.changes });
    });
  });
};

const dbGet = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
};

const dbAll = (sql, params = []) => {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
};

/**
 * Inicialización del esquema y triggers de inmutabilidad
 */
const initDatabase = async () => {
  return new Promise((resolve, reject) => {
    db.serialize(async () => {
      try {
        // 1. Pragmas de optimización y consistencia referencial
        await dbRun('PRAGMA foreign_keys = ON;');
        await dbRun('PRAGMA journal_mode = WAL;');
        await dbRun('PRAGMA synchronous = NORMAL;');
        await dbRun('PRAGMA busy_timeout = 5000;');

        // 2. Tabla: roles
        await dbRun(`
          CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL UNIQUE,
            permisos_json TEXT NOT NULL DEFAULT '[]',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
          );
        `);

        // 3. Tabla: usuarios
        await dbRun(`
          CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            secret_2fa TEXT,
            "2fa_activo" INTEGER NOT NULL DEFAULT 0 CHECK ("2fa_activo" IN (0, 1)),
            estado TEXT NOT NULL DEFAULT 'activo' CHECK (estado IN ('activo', 'inactivo')),
            rol_id INTEGER,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (rol_id) REFERENCES roles(id) ON DELETE RESTRICT
          );
        `);

        // 4. Tabla: aplicaciones_sso
        await dbRun(`
          CREATE TABLE IF NOT EXISTS aplicaciones_sso (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre_app TEXT NOT NULL,
            url_destino TEXT NOT NULL,
            client_secret TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
          );
        `);

        // 5. Tabla: bitacora_auditoria
        await dbRun(`
          CREATE TABLE IF NOT EXISTS bitacora_auditoria (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            usuario_id INTEGER,
            accion_realizada TEXT NOT NULL,
            ip_origen TEXT,
            resultado TEXT NOT NULL,
            FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE SET NULL
          );
        `);

        // 6. Índices para acelerar búsquedas críticas (sub-segundo garantizado)
        await dbRun('CREATE INDEX IF NOT EXISTS idx_usuarios_email ON usuarios(email);');
        await dbRun('CREATE INDEX IF NOT EXISTS idx_auditoria_timestamp ON bitacora_auditoria(timestamp);');
        await dbRun('CREATE INDEX IF NOT EXISTS idx_auditoria_usuario ON bitacora_auditoria(usuario_id);');

        // 7. TRIGGERS DE INMUTABILIDAD EN bitacora_auditoria (REGLA CRÍTICA DE AUDITORÍA)
        // Bloquea cualquier intento de UPDATE y aborta la transacción
        await dbRun(`
          CREATE TRIGGER IF NOT EXISTS trg_bitacora_bloquear_update
          BEFORE UPDATE ON bitacora_auditoria
          BEGIN
            SELECT RAISE(ABORT, 'Violación de seguridad: La bitácora de auditoría es estrictamente inmutable. Los UPDATE están prohibidos.');
          END;
        `);

        // Bloquea cualquier intento de DELETE y aborta la transacción
        await dbRun(`
          CREATE TRIGGER IF NOT EXISTS trg_bitacora_bloquear_delete
          BEFORE DELETE ON bitacora_auditoria
          BEGIN
            SELECT RAISE(ABORT, 'Violación de seguridad: La bitácora de auditoría es estrictamente inmutable. Los DELETE están prohibidos.');
          END;
        `);

        // 8. Roles iniciales (Principio de Menor Privilegio)
        const adminRole = await dbGet('SELECT id FROM roles WHERE nombre = ?', ['Administrador']);
        if (!adminRole) {
          await dbRun(
            'INSERT INTO roles (nombre, permisos_json) VALUES (?, ?)',
            ['Administrador', JSON.stringify(['*'])]
          );
        }

        const employeeRole = await dbGet('SELECT id FROM roles WHERE nombre = ?', ['Empleado']);
        if (!employeeRole) {
          await dbRun(
            'INSERT INTO roles (nombre, permisos_json) VALUES (?, ?)',
            ['Empleado', JSON.stringify(['read:profile'])]
          );
        }

        console.log('[+] Esquema y Triggers de inmutabilidad inicializados correctamente.');
        resolve();
      } catch (error) {
        console.error('[-] Error inicializando esquema de base de datos:', error);
        reject(error);
      }
    });
  });
};

module.exports = {
  db,
  dbRun,
  dbGet,
  dbAll,
  initDatabase
};
