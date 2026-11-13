/**
 * test-audit.js - Prueba de verificación de inmutabilidad de bitácora
 */
const { initDatabase, dbRun, dbGet, db } = require('./database');

async function testAuditImmutability() {
  console.log('--- Iniciando Prueba de Inmutabilidad de Auditoría ---');
  await initDatabase();

  // 1. Insertar un registro legítimo
  console.log('\n1. Insertando registro de auditoría...');
  const insertResult = await dbRun(
    'INSERT INTO bitacora_auditoria (usuario_id, accion_realizada, ip_origen, resultado) VALUES (?, ?, ?, ?)',
    [null, 'TEST_LOGIN_ATTEMPT', '127.0.0.1', 'EXITO']
  );
  const auditId = insertResult.id;
  console.log(`[OK] Registro insertado con ID: ${auditId}`);

  // 2. Intentar modificar (UPDATE) - Debe fallar
  console.log('\n2. Probando intento de UPDATE (debe ser bloqueado)...');
  try {
    await dbRun(
      'UPDATE bitacora_auditoria SET resultado = ? WHERE id = ?',
      ['ALTERADO', auditId]
    );
    console.error('❌ ERROR GRAVE: El UPDATE no fue bloqueado.');
  } catch (err) {
    console.log(`✅ BLOQUEO EXITOSO en UPDATE: "${err.message}"`);
  }

  // 3. Intentar eliminar (DELETE) - Debe fallar
  console.log('\n3. Probando intento de DELETE (debe ser bloqueado)...');
  try {
    await dbRun('DELETE FROM bitacora_auditoria WHERE id = ?', [auditId]);
    console.error('❌ ERROR GRAVE: El DELETE no fue bloqueado.');
  } catch (err) {
    console.log(`✅ BLOQUEO EXITOSO en DELETE: "${err.message}"`);
  }

  // 4. Verificar que el registro original sigue intacto
  console.log('\n4. Verificando integridad del registro original...');
  const record = await dbGet('SELECT * FROM bitacora_auditoria WHERE id = ?', [auditId]);
  if (record && record.resultado === 'EXITO') {
    console.log('✅ El registro sigue intacto e inmutable:', record);
  } else {
    console.error('❌ Integridad comprometida.');
  }

  db.close(() => {
    console.log('\n--- Fin de la prueba de verificación ---');
  });
}

testAuditImmutability().catch(console.error);

