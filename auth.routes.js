/**
 * auth.routes.js - Definición de Rutas del Módulo de Autenticación y Administración IAM
 */

const express = require('express');
const router = express.Router();
const rateLimit = require('express-rate-limit');
const authController = require('./auth.controller');
const { authenticateJWT } = require('./auth.middleware');

// Rate Limiter: Protección contra ataques de fuerza bruta en autenticación (5 intentos / 15 min)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // Ventana de 15 minutos
  max: 5, // Máximo 5 intentos por IP
  standardHeaders: true, // Retorna cabeceras RateLimit-* conforme al RFC 6585
  legacyHeaders: false, // Desactiva cabeceras X-RateLimit-*
  statusCode: 429,
  skipSuccessfulRequests: true, // No penaliza autenticaciones legítimas y exitosas
  skip: () => process.env.NODE_ENV === 'test', // Omite bloqueo en tests automatizados
  message: {
    error: 'Demasiadas solicitudes',
    mensaje: 'Bloqueo temporal de seguridad: Se ha superado el límite de intentos fallidos desde esta IP. Inténtelo nuevamente en 15 minutos.'
  }
});

// 1. Registro y Login de usuarios (Hardened con Rate Limiting)
router.post('/register', authController.register);
router.post('/login', loginLimiter, authController.login);

// 2. Offboarding Express: revocación inmediata de acceso
router.post('/offboarding', authController.offboarding);

// 3. Doble Factor de Autenticación (2FA / TOTP)
router.post('/2fa/activate', authController.activate2FA);
router.post('/2fa/verify', authController.verify2FALogin);

// 4. Perfil del usuario autenticado
router.get('/me', authenticateJWT, authController.getProfile);

// 5. Endpoints de lectura para el Dashboard Administrativo y Portal de Empleado
router.get('/users', authController.listUsers);
router.get('/audit', authController.listAuditLogs);
router.get('/apps', authController.listApps);

module.exports = router;
