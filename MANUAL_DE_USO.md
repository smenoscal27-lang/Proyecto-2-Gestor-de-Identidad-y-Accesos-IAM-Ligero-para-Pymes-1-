# MANUAL DE USUARIO Y OPERACIÓN TÉCNICA
## GESTOR DE IDENTIDAD Y ACCESOS (IAM) LIGERO PARA PYMES
**Documento Técnico para Rúbrica de Titulación / Evaluación Académica**  
*Versión:* 1.0.0 | *Fecha:* Noviembre 2026 | *Clasificación:* Documentación de Sistemas

---

## 1. Introducción y Resumen Ejecutivo del Sistema

El **Gestor de Identidad y Accesos Ligero para PyMEs (IAM PyME)** es una solución integral diseñada para resolver las brechas de seguridad, control de accesos y dispersión de credenciales que enfrentan las pequeñas y medianas empresas.

El sistema se compone de una arquitectura desacoplada y de alto rendimiento:
* **Backend:** Desarrollado sobre **Node.js** y **Express**, respaldado por una base de datos relacional **SQLite** configurada en modo **WAL (*Write-Ahead Logging*)**, lo que garantiza tiempos de respuesta de consulta inferiores a 1 milisegundo y cero mantenimiento de infraestructura para la empresa.
* **Frontend:** Desarrollado en **React** con **Vite** y estilización con **Tailwind CSS**, implementando una interfaz de usuario de alto contraste visual bajo estándares ergonómicos y corporativos (azul marino profundo `#0f172a` y naranja corporativo `#f97316`).
* **Seguridad Criptográfica y Hardening:** Hashing de contraseñas con **bcrypt** (costo 12), tokens **JWT** (algoritmo HMAC-SHA256) con ciclo de vida restringido, autenticación en dos factores **TOTP (RFC 6238)**, mitigación de Clickjacking/XSS con **Helmet.js**, protección contra fuerza bruta con **Rate Limiting** (5 intentos / 15 min), sanitización estricta de entradas y un esquema de auditoría inmutable bajo el estándar **WORM (*Write Once, Read Many*)**.

### 1.1 Controles de Hardening y Ciberseguridad Defensiva
Para cumplir con los más exigentes estándares académicos y normativos (OWASP Top 10):
1. **Blindaje de Cabeceras HTTP (Helmet.js):** Previene ataques de Clickjacking (`X-Frame-Options: SAMEORIGIN`), sniffing de tipos MIME (`nosniff`) e inyecciones de código malicioso.
2. **Defensa contra Ataques de Fuerza Bruta (Rate Limiting):** El endpoint `/api/v1/auth/login` restringe a un máximo de 5 intentos fallidos por IP en una ventana de 15 minutos, respondiendo con el código **HTTP 429 Too Many Requests**.
3. **Sanitización y Validación de Entradas:** El registro de identidades neutraliza caracteres HTML peligrosos mediante escape de entidades y verifica la estructura RFC de correos con la librería `validator`.
4. **Manejo de Errores Inteligente (Zero Information Leak):** En entornos productivos, el servidor suprime cualquier traza de depuración (*stack trace*) o detalle interno de la base de datos, impidiendo la recolección de inteligencia por parte de atacantes.

El presente manual detalla la operación del sistema desde dos perspectivas de usuario:
1. **Rol Administrador:** Control de ciclo de vida de identidades, asignación de roles (RBAC), revocación express de accesos e inspección de auditoría.
2. **Rol Colaborador / Empleado:** Acceso unificado a aplicaciones mediante Single Sign-On (SSO) y autogestión de seguridad con segundo factor de autenticación (2FA).

---

## 2. Rol Administrador: Directorio de Identidades (RBAC)

El módulo de administración permite al responsable de TI o Recursos Humanos gobernar todo el ciclo de vida de los empleados dentro de la organización.

### 2.1 Panel de Métricas e Indicadores Clave (KPIs)
En la parte superior de la consola se visualizan cuatro tarjetas analíticas en tiempo real:
* **Total Identidades:** Cuantificador absoluto de cuentas registradas en la base de datos.
* **Accesos Activos:** Número de empleados habilitados para autenticarse e iniciar sesión.
* **Bajas (Offboarded):** Empleados cuyo estado ha sido revocado.
* **Adopción 2FA (TOTP):** Porcentaje de colaboradores que han activado el segundo factor.
* **Monitor SQLite WAL:** Muestra la latencia en vivo del motor de base de datos (típicamente $\le$ 0.5 ms).

### 2.2 Navegación en la Tabla de Identidades
La tabla central presenta la estructura del Directorio de Identidades con las siguientes columnas:
1. **ID:** Identificador numérico único de la identidad (`#1`, `#2`, etc.).
2. **Empleado / Nombre:** Nombre completo del trabajador junto con su fecha de alta y avatar identificador.
3. **Correo Corporativo:** Dirección de correo electrónico única normalizada utilizada como nombre de usuario.
4. **Rol Asignado:** Nivel de autorización según el modelo RBAC (*Administrador* o *Empleado*).
5. **Estado 2FA:** Indicador de si el colaborador completó la activación de su token TOTP (*Activo* o *Pendiente*).
6. **Estado de Cuenta:** Badge dinámico con indicador luminoso:
   * 🟢 **Activo:** Cuenta habilitada para operar.
   * 🔴 **Inactivo (Revocado):** Cuenta suspendida inmediatamente.
7. **Acciones Rápidas:** Botón operativo de desvinculación inmediata.

### 2.3 Búsqueda y Filtrado Reactivo
* **Buscador Universal:** Permite localizar de forma instantánea cualquier registro escribiendo el nombre, correo electrónico o identificador del usuario.
* **Filtro de Estado:** Menú desplegable para segmentar entre:
  * *Todos los Estados:* Muestra el universo completo de identidades.
  * *Solo Activos:* Muestra colaboradores en funciones activas.
  * *Solo Inactivos (Baja):* Muestra el histórico de colaboradores desvinculados.

### 2.4 Procedimiento Operativo: "Offboarding Express"

> [!IMPORTANT]
> **Definición de Offboarding Express:** Procedimiento de seguridad defensiva diseñado para revocar el acceso de un empleado despedido o desvinculado de forma inmediata y en un solo clic, mitigando el riesgo de fuga de información o sabotaje post-despido.

#### Pasos para ejecutar la baja:
1. Ubique al colaborador activo en la tabla del Directorio RBAC.
2. En la columna *Acciones Rápidas*, haga clic sobre el botón rojo **"Offboarding Express"** (identificado con el icono `UserX`).
3. Aparecerá un **Modal de Confirmación Crítica** que detalla el nombre, correo e ID de la persona a desvincular.
4. Haga clic en el botón **"Revocar Acceso Inmediato"**.

#### Efectos Técnicos y de Seguridad Inmediatos:
* **Actualización en Base de Datos:** Se ejecuta la instrucción SQL `UPDATE usuarios SET estado = 'inactivo' WHERE id = ?`.
* **Revocación de Sesiones en Tiempo Real:** Aunque el empleado posea un token JWT emitido previamente con minutos u horas restantes de vigencia, el middleware de autorización del backend (`auth.middleware.js`) valida en cada petición HTTP contra SQLite que el estado del usuario sea `'activo'`. Al estar `'inactivo'`, toda petición posterior es rechazada inmediatamente con un error **HTTP 403 Forbidden**.
* **Bloqueo de Login:** Si el usuario intenta volver a ingresar sus credenciales en `/api/v1/auth/login`, el backend rechaza la solicitud indicando: *"Cuenta suspendida. El acceso ha sido revocado"*.
* **Registro Inmutable Automático:** Se inserta inmediatamente un evento en la tabla `bitacora_auditoria` con la acción `USER_OFFBOARDED_IMMEDIATE_REVOCATION` y resultado `EXITO`.

---

## 3. Rol Administrador: Módulo de Auditoría Inmutable (WORM)

La pestaña **"Bitácora Inmutable"** proporciona a los evaluadores y auditores forenses una trazabilidad completa de todos los eventos de autenticación y autorización ocurridos en el sistema.

### 3.1 Fundamento Técnico: Modelo WORM (*Write Once, Read Many*)
A diferencia de los sistemas tradicionales donde un administrador con acceso a la base de datos puede alterar o borrar registros de log para ocultar acciones indebidas, el IAM PyME implementa **Triggers nativos en SQLite** que aplican la regla estricta:

$$\text{Operación } (UPDATE \lor DELETE) \implies \text{ABORT}$$

```sql
CREATE TRIGGER trg_bitacora_bloquear_update
BEFORE UPDATE ON bitacora_auditoria
BEGIN
  SELECT RAISE(ABORT, 'Violación de seguridad: La bitácora de auditoría es estrictamente inmutable.');
END;

CREATE TRIGGER trg_bitacora_bloquear_delete
BEFORE DELETE ON bitacora_auditoria
BEGIN
  SELECT RAISE(ABORT, 'Violación de seguridad: La bitácora de auditoría es estrictamente inmutable.');
END;
```

Cualquier intento manual o por software de modificar (`UPDATE`) o eliminar (`DELETE`) una fila en `bitacora_auditoria` provocará un error a nivel de motor de base de datos (`SQLITE_CONSTRAINT`), garantizando el **principio de no repudio** exigido por normas como ISO/IEC 27001.

### 3.2 Interpretación de Columnas de la Bitácora
1. **ID Log:** Número correlativo autoincremental del evento de auditoría.
2. **Marca Temporal (UTC):** Fecha y hora exacta en la que se produjo la acción con precisión de segundos (`YYYY-MM-DD HH:MM:SS`).
3. **Usuario ID:** Identificador numérico del empleado asociado (`USR-1`, `USR-2`) o la etiqueta *Anónimo / Sistema* si se trató de una tentativa fallida con usuario no existente.
4. **Acción Realizada:** Etiqueta semántica del evento registrado:
   * `USER_REGISTER_SUCCESS`: Registro de una nueva identidad.
   * `LOGIN_SUCCESS`: Autenticación primaria exitosa.
   * `LOGIN_FAILED_INVALID_CREDENTIALS`: Intento fallido por contraseña incorrecta o correo inexistente.
   * `LOGIN_BLOCKED_INACTIVE_ACCOUNT`: Intento de inicio de sesión de un usuario con baja (offboarding).
   * `USER_OFFBOARDED_IMMEDIATE_REVOCATION`: Ejecución de baja de accesos.
   * `2FA_ACTIVATED_SUCCESS`: Activación de segundo factor.
   * `LOGIN_2FA_SUCCESS`: Validación exitosa del código TOTP.
5. **IP Origen:** Dirección IPv4 o IPv6 desde donde se originó la petición HTTP (útil para auditoría forense de redes).
6. **Resultado:** Insignia que resume el desenlace de la operación:
   * 🟢 **EXITO:** La operación fue procesada satisfactoriamente.
   * 🔴 **FALLO:** La operación fue denegada por violación de seguridad o datos erróneos.

---

## 4. Rol Empleado: Portal de Servicios SSO y Configuración 2FA

El **Portal del Colaborador** es la interfaz centralizada a la que tienen acceso los trabajadores de la empresa tras autenticarse en el IAM.

### 4.1 Catálogo de Aplicaciones Single Sign-On (SSO)
El empleado dispone de una cuadrícula visual con todas las plataformas corporativas conectadas al gestor de identidad:
* **Sistema Contable & Facturación (Finanzas):** Emisión de comprobantes y libros contables.
* **Gestor de Recursos & Inventario (Operaciones):** Almacén y órdenes de compra.
* **Portal de Nómina & RRHH (Recursos Humanos):** Descarga de recibos y constancias.
* **CRM & Pipeline Comercial (Ventas):** Gestión de clientes y cotizaciones.
* **Mesa de Ayuda & Tickets TI (Soporte):** Requerimientos técnicos y soporte interno.
* **Intranet & Documentos PyME (General):** Políticas de la compañía.

> **Operación de Ingreso:**  
> Al pulsar sobre cualquiera de las tarjetas, el sistema realiza la federación de identidad, consumiendo el token JWT emitido por el IAM para otorgar acceso inmediato al aplicativo satélite sin solicitar nuevamente usuario ni contraseña.

---

### 4.2 Módulo de Seguridad y Autogestión 2FA

En el panel lateral derecho del portal, el trabajador visualiza el estado de seguridad de su cuenta:
* **Nivel de Protección al 60%:** Indica que la cuenta únicamente está respaldada por contraseña.
* **Nivel de Protección al 100%:** Indica que la cuenta cuenta con autenticación de dos factores (2FA) activa.

---

### 4.3 Procedimiento Paso a Paso: Configurar Google Authenticator (TOTP)

Cuando el segundo factor se encuentra en estado **Pendiente**, el empleado debe seguir estos pasos para proteger su identidad:

```
[ PASO 1: Escanear QR ]  --->  [ PASO 2: Ingresar Código de 6 Dígitos ]  --->  [ ACTIVADO (100%) ]
```

1. **Iniciar Asistente:**  
   En la tarjeta lateral de seguridad, haga clic sobre el botón naranja **"Configurar Google Authenticator"**.
2. **Paso 1 - Vinculación del Dispositivo Móvil:**  
   Se abrirá una ventana emergente que presenta dos alternativas:
   * **Opción A (Recomendada):** Abra la aplicación *Google Authenticator*, *Microsoft Authenticator* o *Authy* en su teléfono inteligente, seleccione *Añadir cuenta / Escanear código QR* y apunte la cámara hacia el código presentado en pantalla.
   * **Opción B (Clave Manual):** Si la cámara de su dispositivo no funciona, copie la clave Base32 provista (ej. `JBSWY3DPEHPK3PXP`) e ingrésela manualmente en su aplicación móvil.
3. **Paso 2 - Confirmación Criptográfica:**  
   * Su aplicación móvil generará un código dinámico de **6 dígitos** que cambia cada 30 segundos.
   * Ingrese los 6 dígitos en el campo de texto provisto en la ventana modal.
4. **Validación:**  
   * Haga clic en **"Verificar y Activar 2FA"**.
   * El sistema validará el código mediante el algoritmo TOTP (RFC 6238). Al confirmarse, la ventana mostrará el mensaje de éxito *"¡Doble Factor Activado con Éxito!"*, el indicador subirá al **100%** de protección y se creará el registro correspondiente en la bitácora inmutable.

---

## 5. Entorno de Evaluación y Credenciales de Prueba

Para efectos de evaluación docente, sustentación o demostración en vivo, se proveen las siguientes identidades preconfiguradas en el sistema:

### 5.1 Tabla de Credenciales de Prueba

| Rol en el Sistema | Nombre de Usuario / Correo | Contraseña Maestra | Nivel de Privilegios | Propósito de Prueba |
| :--- | :--- | :--- | :--- | :--- |
| **Administrador** | `admin@pyme.com` | `MiContraseñaSegura2026!` | Superusuario (`*`) | Gestión de identidades, ejecución de Offboarding Express y revisión de Bitácora Inmutable. |
| **Empleado** | `carlos.mendoza@pyme.com` | `MiContraseñaSegura2026!` | `read:profile` | Acceso al Portal SSO, prueba de lanzamiento de apps y configuración de Google Authenticator (2FA). |

---

### 5.2 Guía Rápida para Levantar el Entorno de Demostración

Abra dos ventanas de terminal en la carpeta principal del proyecto (`proyecto-iam-pyme`):

#### Terminal 1 (Servidor Backend):
```powershell
npm run dev
```
* **Salida esperada:** `🚀 Servidor IAM corriendo en: http://localhost:3000`
* **Health Check verificado:** [`http://localhost:3000/health`](http://localhost:3000/health)

#### Terminal 2 (Aplicación Frontend):
```powershell
npm run frontend
```
* **Salida esperada:** `Local: http://localhost:5173/`
* Ingrese a [`http://localhost:5173/`](http://localhost:5173/) en cualquier navegador moderno.

#### Conmutación Rápida de Roles en Pantalla:
En la esquina inferior derecha de la interfaz web encontrará una **píldora flotante de navegación** que le permite cambiar en cualquier momento entre:
* **Portal Empleado (SSO):** Para evaluar la vista de colaborador y la activación de 2FA.
* **Consola Admin (RBAC):** Para evaluar la tabla de identidades, la acción de Offboarding Express y la Bitácora Inmutable.

---

*Manual elaborado y certificado conforme a las directrices de seguridad de la información, arquitectura de software y rúbricas académicas de titulación.*

