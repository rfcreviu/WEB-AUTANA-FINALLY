const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const nodemailer = require('nodemailer');
const fs = require('fs');
const config = require('./config');

// ===================================
// DEPENDENCIAS PARA OPTIMIZACIÓN DE RENDIMIENTO
// ===================================
const compression = require('compression');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cache = require('memory-cache');
const crypto = require('crypto');

// ===================================
// SISTEMA AVANZADO DE LOGGING Y ERRORES
// ===================================

const LOG_LEVELS = {
  ERROR: 'ERROR',
  WARN: 'WARN',
  INFO: 'INFO',
  DEBUG: 'DEBUG'
};

class Logger {
  constructor() {
    this.logLevel = config.server.isDevelopment ? LOG_LEVELS.DEBUG : LOG_LEVELS.INFO;
    this.logToFile = !config.server.isDevelopment;
    this.initializeLogDirectory();
  }

  initializeLogDirectory() {
    const logDir = path.join(__dirname, 'logs');
    if (!fs.existsSync(logDir)) {
      fs.mkdirSync(logDir, { recursive: true });
    }
  }

  formatMessage(level, message, data = null) {
    const timestamp = new Date().toISOString();
    const baseMessage = `[${timestamp}] [${level}] ${message}`;
    
    if (data) {
      return `${baseMessage} | Data: ${JSON.stringify(data, null, 2)}`;
    }
    return baseMessage;
  }

  writeToFile(level, formattedMessage) {
    if (!this.logToFile) return;
    
    try {
      const logFile = path.join(__dirname, 'logs', `udon-${new Date().toISOString().split('T')[0]}.log`);
      fs.appendFileSync(logFile, formattedMessage + '\n', 'utf8');
    } catch (error) {
      console.error('Error escribiendo log:', error.message);
    }
  }

  shouldLog(level) {
    const levels = Object.values(LOG_LEVELS);
    const currentLevelIndex = levels.indexOf(this.logLevel);
    const messageLevelIndex = levels.indexOf(level);
    return messageLevelIndex <= currentLevelIndex;
  }

  log(level, message, data = null) {
    if (!this.shouldLog(level)) return;

    const formattedMessage = this.formatMessage(level, message, data);
    
    // Console output con colores
    switch (level) {
      case LOG_LEVELS.ERROR:
        console.error(`❌ ${formattedMessage}`);
        break;
      case LOG_LEVELS.WARN:
        console.warn(`⚠️ ${formattedMessage}`);
        break;
      case LOG_LEVELS.INFO:
        console.info(`ℹ️ ${formattedMessage}`);
        break;
      case LOG_LEVELS.DEBUG:
        console.log(`🐛 ${formattedMessage}`);
        break;
      default:
        console.log(formattedMessage);
    }

    // Escribir a archivo
    this.writeToFile(level, formattedMessage);
  }

  error(message, data = null) {
    this.log(LOG_LEVELS.ERROR, message, data);
  }

  warn(message, data = null) {
    this.log(LOG_LEVELS.WARN, message, data);
  }

  info(message, data = null) {
    this.log(LOG_LEVELS.INFO, message, data);
  }

  debug(message, data = null) {
    this.log(LOG_LEVELS.DEBUG, message, data);
  }
}

// Instancia global del logger
const logger = new Logger();

// Manejador global de errores no capturados
process.on('uncaughtException', (error) => {
  logger.error('Error no capturado:', {
    message: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
  
  console.error('🚨 ERROR CRÍTICO - El servidor se cerrará para evitar estado inconsistente');
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Promise rechazada no manejada:', {
    reason: reason,
    promise: promise,
    timestamp: new Date().toISOString()
  });
});

// Función helper para manejar errores de operaciones asíncronas
const handleAsync = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch((error) => {
      logger.error('Error en operación asíncrona:', {
        endpoint: req.originalUrl,
        method: req.method,
        error: error.message,
        stack: error.stack,
        body: req.body,
        user: req.user?.username || 'anonymous'
      });
      
      res.status(500).json({ 
        error: 'Error interno del servidor',
        message: config.server.isDevelopment ? error.message : 'Ha ocurrido un error inesperado',
        timestamp: new Date().toISOString()
      });
    });
  };
};

// Middleware para logging de requests
const requestLogger = (req, res, next) => {
  const start = Date.now();
  
  // Log de request entrante
  logger.info('Request entrante:', {
    method: req.method,
    url: req.originalUrl,
    userAgent: req.get('User-Agent'),
    ip: req.ip || req.connection.remoteAddress,
    timestamp: new Date().toISOString()
  });

  // Interceptar la respuesta para logging
  const originalSend = res.send;
  res.send = function(data) {
    const duration = Date.now() - start;
    
    logger.info('Response enviada:', {
      method: req.method,
      url: req.originalUrl,
      statusCode: res.statusCode,
      duration: `${duration}ms`,
      timestamp: new Date().toISOString()
    });
    
    // Log de errores HTTP
    if (res.statusCode >= 400) {
      logger.warn('Response con error:', {
        method: req.method,
        url: req.originalUrl,
        statusCode: res.statusCode,
        errorData: data,
        user: req.user?.username || 'anonymous'
      });
    }
    
    originalSend.call(this, data);
  };
  
  next();
};

logger.info('Sistema de logging inicializado', {
  logLevel: logger.logLevel,
  logToFile: logger.logToFile,
  environment: config.server.isDevelopment ? 'development' : 'production'
});

// ===================================
// SISTEMA AVANZADO DE CACHING Y OPTIMIZACIÓN
// ===================================

class CacheManager {
  constructor() {
    this.cache = cache;
    this.defaultTTL = config.server.isDevelopment ? 300000 : 900000; // 5min dev, 15min prod
    this.maxCacheSize = 50 * 1024 * 1024; // 50MB máximo
    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0
    };
    
    logger.info('Cache Manager inicializado', {
      defaultTTL: this.defaultTTL,
      maxCacheSize: this.maxCacheSize,
      environment: config.server.isDevelopment ? 'development' : 'production'
    });
  }

  generateKey(...parts) {
    const keyString = parts.join(':');
    // Incluir prefijo para permitir invalidación por categoría
    if (keyString.includes('/api/restaurants')) {
      return `restaurants:${crypto.createHash('md5').update(keyString).digest('hex')}`;
    }
    if (keyString.includes('/tables')) {
      return `tables:${crypto.createHash('md5').update(keyString).digest('hex')}`;
    }
    return crypto.createHash('md5').update(keyString).digest('hex');
  }

  set(key, value, ttl = this.defaultTTL) {
    try {
      // Verificar tamaño de cache
      if (this.cache.size() > this.maxCacheSize) {
        this.cache.clear();
        logger.warn('Cache limpiado por exceder tamaño máximo', {
          previousSize: this.cache.size(),
          maxSize: this.maxCacheSize
        });
      }

      const success = this.cache.put(key, value, ttl);
      this.stats.sets++;
      
      logger.debug('Cache SET', {
        key: key.substring(0, 20) + '...',
        valueSize: JSON.stringify(value).length,
        ttl,
        success
      });
      
      return success;
    } catch (error) {
      logger.error('Error en cache SET', {
        key,
        error: error.message
      });
      return false;
    }
  }

  get(key) {
    try {
      const value = this.cache.get(key);
      
      if (value !== null) {
        this.stats.hits++;
        logger.debug('Cache HIT', {
          key: key.substring(0, 20) + '...'
        });
      } else {
        this.stats.misses++;
        logger.debug('Cache MISS', {
          key: key.substring(0, 20) + '...'
        });
      }
      
      return value;
    } catch (error) {
      logger.error('Error en cache GET', {
        key,
        error: error.message
      });
      this.stats.misses++;
      return null;
    }
  }

  del(key) {
    try {
      const deleted = this.cache.del(key);
      this.stats.deletes++;
      
      logger.debug('Cache DELETE', {
        key: key.substring(0, 20) + '...',
        deleted
      });
      
      return deleted;
    } catch (error) {
      logger.error('Error en cache DELETE', {
        key,
        error: error.message
      });
      return false;
    }
  }

  clear() {
    try {
      this.cache.clear();
      logger.info('Cache completamente limpiado');
      return true;
    } catch (error) {
      logger.error('Error limpiando cache', {
        error: error.message
      });
      return false;
    }
  }

  getStats() {
    const hitRate = this.stats.hits + this.stats.misses > 0 
      ? (this.stats.hits / (this.stats.hits + this.stats.misses) * 100).toFixed(2)
      : 0;

    return {
      ...this.stats,
      hitRate: `${hitRate}%`,
      cacheSize: this.cache.size(),
      keys: this.cache.keys().length
    };
  }

  // Middleware para caching automático de responses
  middleware(ttl = this.defaultTTL) {
    return (req, res, next) => {
      // Solo cachear GET requests
      if (req.method !== 'GET') {
        return next();
      }

      // No cachear rutas de admin o con parámetros sensibles
      if (req.path.includes('/admin') || req.path.includes('/login') || req.query.token) {
        return next();
      }

      const cacheKey = this.generateKey(req.originalUrl, req.get('Accept') || '');
      const cachedResponse = this.get(cacheKey);

      if (cachedResponse) {
        logger.debug('Respuesta servida desde cache', {
          url: req.originalUrl,
          cacheKey: cacheKey.substring(0, 20) + '...'
        });
        
        res.set('X-Cache', 'HIT');
        res.set('X-Cache-Key', cacheKey.substring(0, 10));
        return res.json(cachedResponse);
      }

      // Interceptar response para guardar en cache
      const originalJson = res.json;
      res.json = (data) => {
        // Solo cachear responses exitosas
        if (res.statusCode === 200 && data) {
          this.set(cacheKey, data, ttl);
          logger.debug('Respuesta guardada en cache', {
            url: req.originalUrl,
            cacheKey: cacheKey.substring(0, 20) + '...',
            dataSize: JSON.stringify(data).length
          });
        }
        
        res.set('X-Cache', 'MISS');
        res.set('X-Cache-Key', cacheKey.substring(0, 10));
        return originalJson.call(res, data);
      };

      next();
    };
  }
}

// Instancia global del cache manager
const cacheManager = new CacheManager();

// Rate limiting para prevenir abuso
const createRateLimiter = (windowMs, max, message) => {
  return rateLimit({
    windowMs,
    max,
    message: {
      error: 'Demasiadas peticiones',
      message,
      retryAfter: Math.ceil(windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
      logger.warn('Rate limit excedido', {
        ip: req.ip,
        url: req.originalUrl,
        userAgent: req.get('User-Agent')
      });
      
      res.status(429).json({
        error: 'Demasiadas peticiones',
        message,
        retryAfter: Math.ceil(windowMs / 1000)
      });
    }
  });
};

// Rate limiters específicos
const generalLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutos
  100, // máximo 100 requests por IP
  'Demasiadas peticiones desde esta IP, inténtelo de nuevo en 15 minutos'
);

const authLimiter = createRateLimiter(
  15 * 60 * 1000, // 15 minutos
  5, // máximo 5 intentos de login por IP
  'Demasiados intentos de autenticación, inténtelo de nuevo en 15 minutos'
);

const reservationLimiter = createRateLimiter(
  60 * 1000, // 1 minuto
  10, // máximo 10 reservas por minuto por IP
  'Demasiadas reservas en poco tiempo, inténtelo de nuevo en 1 minuto'
);

// Configuración de compresión
const compressionConfig = compression({
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false;
    }
    return compression.filter(req, res);
  },
  level: config.server.isDevelopment ? 6 : 9, // Más compresión en producción
  threshold: 1024, // Solo comprimir respuestas > 1KB
  chunkSize: 16 * 1024 // 16KB chunks
});

// Configuración de seguridad con Helmet (CSP TEMPORALMENTE RELAJADO PARA DEBUG)
const helmetConfig = helmet({
  contentSecurityPolicy: false, // TEMPORALMENTE DESHABILITADO PARA DEBUG
  crossOriginEmbedderPolicy: false,
  hidePoweredBy: false
});

logger.info('Sistema de caching y optimización inicializado', {
  cacheDefaultTTL: cacheManager.defaultTTL,
  cacheMaxSize: cacheManager.maxCacheSize,
  compressionLevel: config.server.isDevelopment ? 6 : 9,
  rateLimitingEnabled: true
});

// Inicializar y validar configuración
logger.info('Iniciando validación de configuración...');
if (!config.initializeConfiguration()) {
  logger.error('Error crítico de configuración. El servidor no puede iniciarse.');
  process.exit(1);
}
logger.info('Configuración validada exitosamente');

const app = express();
const PORT = config.server.port;

// ===================================
// CONFIGURACIÓN DE MIDDLEWARE OPTIMIZADO
// ===================================

// 1. Seguridad (debe ir primero)
app.use(helmetConfig);

// 2. Rate limiting general
app.use(generalLimiter);

// 3. Compresión de respuestas
app.use(compressionConfig);

// 4. CORS
app.use(cors());

// 5. Parsing de JSON con límite de tamaño
app.use(express.json({ limit: '10mb' }));

// 6. Archivos estáticos con cache optimizado
app.use(express.static('public', {
  maxAge: config.server.isDevelopment ? '1h' : '1d', // Cache más largo en producción
  etag: true,
  lastModified: true,
  cacheControl: true,
  immutable: !config.server.isDevelopment, // Archivos inmutables en producción
  setHeaders: (res, filePath) => {
    // Headers específicos para diferentes tipos de archivos
    const ext = path.extname(filePath).toLowerCase();
    
    if (['.js', '.css'].includes(ext)) {
      res.setHeader('Cache-Control', config.server.isDevelopment 
        ? 'public, max-age=3600' // 1 hora en desarrollo
        : 'public, max-age=86400, immutable' // 1 día en producción
      );
    } else if (['.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp'].includes(ext)) {
      res.setHeader('Cache-Control', config.server.isDevelopment 
        ? 'public, max-age=7200' // 2 horas en desarrollo
        : 'public, max-age=604800, immutable' // 1 semana en producción
      );
    } else if (['.mp4', '.webm', '.ogg'].includes(ext)) {
      res.setHeader('Cache-Control', config.server.isDevelopment 
        ? 'public, max-age=3600' // 1 hora en desarrollo
        : 'public, max-age=2592000, immutable' // 30 días en producción
      );
    } else if (['.html'].includes(ext)) {
      res.setHeader('Cache-Control', 'public, max-age=3600'); // 1 hora para HTML
    }
    
    // Headers de seguridad adicionales para archivos estáticos
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
  }
}));

// 7. Cache middleware para APIs (aplicar a rutas específicas después)
// Se aplica individualmente en cada ruta

// 8. Logging de requests
app.use(requestLogger);

// Middleware para manejo de errores de parsing JSON
app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    logger.error('Error de parsing JSON:', {
      error: err.message,
      body: err.body,
      url: req.originalUrl
    });
    
    return res.status(400).json({
      error: 'JSON inválido en el cuerpo de la petición',
      message: 'Por favor, verifique el formato del JSON enviado'
    });
  }
  next();
});

// ===================================
// SISTEMA DE PERSISTENCIA DE DATOS
// ===================================

const DATA_DIR = path.join(__dirname, 'data');
const RESTAURANTS_FILE = path.join(DATA_DIR, 'restaurants.json');
const RESERVATIONS_FILE = path.join(DATA_DIR, 'reservations.json');
const COUNTER_FILE = path.join(DATA_DIR, 'counter.json');
const TRACKING_LINKS_FILE = path.join(DATA_DIR, 'tracking-links.json');

// Asegurar que el directorio de datos existe
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Función para cargar datos desde archivo JSON
function loadDataFromFile(filePath, defaultValue = {}) {
  const fileName = path.basename(filePath);
  
  try {
    if (fs.existsSync(filePath)) {
      const data = fs.readFileSync(filePath, 'utf8');
      const parsedData = JSON.parse(data);
      
      logger.info(`Archivo cargado exitosamente: ${fileName}`, {
        fileName,
        dataSize: JSON.stringify(parsedData).length,
        recordCount: Array.isArray(parsedData) ? parsedData.length : Object.keys(parsedData).length
      });
      
      return parsedData;
    } else {
      logger.warn(`Archivo no encontrado: ${fileName}, usando datos por defecto`, {
        fileName,
        filePath,
        defaultValueType: typeof defaultValue
      });
      return defaultValue;
    }
  } catch (error) {
    logger.error(`Error cargando archivo: ${fileName}`, {
      fileName,
      filePath,
      error: error.message,
      stack: error.stack
    });
    return defaultValue;
  }
}

// Función para guardar datos en archivo JSON
function saveDataToFile(filePath, data) {
  const fileName = path.basename(filePath);
  
  try {
    // Crear backup del archivo existente si existe
    if (fs.existsSync(filePath)) {
      const backupPath = `${filePath}.backup`;
      fs.copyFileSync(filePath, backupPath);
      logger.debug(`Backup creado: ${fileName}.backup`);
    }
    
    const jsonData = JSON.stringify(data, null, 2);
    fs.writeFileSync(filePath, jsonData, 'utf8');
    
    logger.info(`Datos guardados exitosamente: ${fileName}`, {
      fileName,
      dataSize: jsonData.length,
      recordCount: Array.isArray(data) ? data.length : Object.keys(data).length,
      timestamp: new Date().toISOString()
    });
    
    return true;
  } catch (error) {
    logger.error(`Error guardando archivo: ${fileName}`, {
      fileName,
      filePath,
      error: error.message,
      stack: error.stack,
      dataType: typeof data
    });
    return false;
  }
}

// Función para guardar restaurantes
function saveRestaurants() {
  return saveDataToFile(RESTAURANTS_FILE, restaurants);
}

// Función para guardar reservas
function saveReservations() {
  return saveDataToFile(RESERVATIONS_FILE, reservations);
}

// Función para guardar contador
function saveCounter() {
  return saveDataToFile(COUNTER_FILE, { value: reservationCounter });
}

// Función para guardar tracking links
function saveTrackingLinks() {
  return saveDataToFile(TRACKING_LINKS_FILE, trackingLinks);
}

// Cargar datos al iniciar el servidor
logger.info('Iniciando carga de datos desde archivos...');

// Base de datos en memoria (ahora con persistencia)
let restaurants = loadDataFromFile(RESTAURANTS_FILE, {
  'alisios': {
    name: 'UDON CC ALISIOS',
    schedule: {
      'Dom - Jue': '12:00 - 23:00',
      'Vie - Sáb': '12:00 - 24:00'
    },
    admin: {
      username: 'admin_alisios',
      password: '$2a$10$4QvVPKZXASGOmqq2PGoBWui69HhgioPwSdoUOeCVI4qvM2aDoD8/u'
    },
    tables: [
      { id: 1, name: "Terraza 1", capacity: 4, available: true },
      { id: 2, name: "Ventana Norte", capacity: 2, available: true },
      { id: 3, name: "Terraza 2", capacity: 6, available: true },
      { id: 4, name: "Rincón Íntimo", capacity: 2, available: true },
      { id: 5, name: "Mesa Central", capacity: 4, available: true },
      { id: 6, name: "Junto a Barra", capacity: 3, available: true },
      { id: 7, name: "Ventana Sur", capacity: 2, available: true },
      { id: 8, name: "Familiar Grande", capacity: 8, available: true },
      { id: 9, name: "Mesa 9", capacity: 4, available: true },
      { id: 10, name: "Mesa 10", capacity: 2, available: true },
      { id: 11, name: "Mesa 11", capacity: 3, available: true },
      { id: 12, name: "Mesa 12", capacity: 4, available: true },
      { id: 13, name: "Mesa 13", capacity: 2, available: true },
      { id: 14, name: "Mesa 14", capacity: 5, available: true },
      { id: 15, name: "Mesa 15", capacity: 3, available: true },
      { id: 16, name: "Mesa 16", capacity: 4, available: true },
      { id: 17, name: "Mesa 17", capacity: 2, available: true },
      { id: 18, name: "Mesa 18", capacity: 6, available: true },
      { id: 19, name: "Mesa 19", capacity: 3, available: true },
      { id: 20, name: "Mesa 20", capacity: 4, available: true }
    ]
  },
  'meridiano': {
    name: 'UDON CC MERIDIANO',
    schedule: {
      'Lun - Dom': '11:30 - 23:30'
    },
    admin: {
      username: 'admin_meridiano',
      password: '$2a$10$3kSut4epXHYNh6B8wf9m.OQnkQFvYH0N2hmtbEnB5jsdy6FC93fSu'
    },
    tables: [
      { id: 1, name: "Sala Principal 1", capacity: 4, available: true },
      { id: 2, name: "Sala Principal 2", capacity: 2, available: true },
      { id: 3, name: "Zona VIP", capacity: 6, available: true },
      { id: 4, name: "Entrada Derecha", capacity: 4, available: true },
      { id: 5, name: "Entrada Izquierda", capacity: 2, available: true },
      { id: 6, name: "Privado A", capacity: 8, available: true },
      { id: 7, name: "Privado B", capacity: 6, available: true },
      { id: 8, name: "Barra Alta 1", capacity: 2, available: true },
      { id: 9, name: "Barra Alta 2", capacity: 2, available: true },
      { id: 10, name: "Centro 1", capacity: 4, available: true },
      { id: 11, name: "Centro 2", capacity: 4, available: true },
      { id: 12, name: "Mesa 12", capacity: 3, available: true },
      { id: 13, name: "Mesa 13", capacity: 4, available: true },
      { id: 14, name: "Mesa 14", capacity: 2, available: true },
      { id: 15, name: "Mesa 15", capacity: 5, available: true },
      { id: 16, name: "Mesa 16", capacity: 3, available: true },
      { id: 17, name: "Mesa 17", capacity: 4, available: true },
      { id: 18, name: "Mesa 18", capacity: 2, available: true },
      { id: 19, name: "Mesa 19", capacity: 6, available: true },
      { id: 20, name: "Mesa 20", capacity: 4, available: true },
      { id: 21, name: "Mesa 21", capacity: 3, available: true },
      { id: 22, name: "Mesa 22", capacity: 2, available: true },
      { id: 23, name: "Mesa 23", capacity: 5, available: true },
      { id: 24, name: "Mesa 24", capacity: 4, available: true },
      { id: 25, name: "Mesa 25", capacity: 3, available: true }
    ]
  },
  'ruizalda': {
    name: 'UDON RUIZ DE ALDA',
    schedule: {
      'Mar - Dom': '12:30 - 22:30',
      'Lunes': 'Cerrado'
    },
    admin: {
      username: 'admin_ruizalda',
      password: '$2a$10$mO3.3o/i5O9l35idgycfPunAv5usx9EQzATnl.Mgdroj/S5lYlSC6'
    },
    tables: [
      { id: 1, name: "Ventanal 1", capacity: 4, available: true },
      { id: 2, name: "Ventanal 2", capacity: 2, available: true },
      { id: 3, name: "Rincón Tranquilo", capacity: 2, available: true },
      { id: 4, name: "Mesa Redonda", capacity: 6, available: true },
      { id: 5, name: "Junto Cocina", capacity: 4, available: true },
      { id: 6, name: "Mesa Alta 1", capacity: 2, available: true },
      { id: 7, name: "Mesa Alta 2", capacity: 2, available: true },
      { id: 8, name: "Familia", capacity: 8, available: true },
      { id: 9, name: "Pareja 1", capacity: 2, available: true },
      { id: 10, name: "Pareja 2", capacity: 2, available: true },
      { id: 11, name: "Centro", capacity: 4, available: true },
      { id: 12, name: "Esquina", capacity: 3, available: true },
      { id: 13, name: "Mesa 13", capacity: 4, available: true },
      { id: 14, name: "Mesa 14", capacity: 2, available: true },
      { id: 15, name: "Mesa 15", capacity: 5, available: true },
      { id: 16, name: "Mesa 16", capacity: 3, available: true },
      { id: 17, name: "Mesa 17", capacity: 4, available: true },
      { id: 18, name: "Mesa 18", capacity: 2, available: true }
    ]
  }
});

// Base de datos de reservas y contador
let reservations = loadDataFromFile(RESERVATIONS_FILE, []);
let reservationCounter = loadDataFromFile(COUNTER_FILE, { value: 1 }).value;

// Base de datos de tracking links
let trackingLinks = loadDataFromFile(TRACKING_LINKS_FILE, []);

logger.info('Datos cargados exitosamente', {
  restaurantCount: Object.keys(restaurants).length,
  reservationCount: reservations.length,
  currentCounter: reservationCounter,
  trackingLinksCount: trackingLinks.length,
  restaurants: Object.keys(restaurants)
});

// Sistema de liberación automática de mesas
function autoReleaseExpiredTables() {
  try {
    const now = new Date();
    logger.debug('Iniciando verificación de mesas expiradas', {
      currentTime: now.toISOString(),
      totalReservations: reservations.length
    });
    
    let releasedTables = 0;
    const releasedReservations = [];
    
    reservations.forEach(reservation => {
      // Solo verificar reservas confirmadas (no canceladas ni completadas)
      if (reservation.status !== 'confirmed') {
        return;
      }
      
      try {
        // Calcular la fecha y hora de la reserva
        const reservationDateTime = new Date(`${reservation.date}T${reservation.time}:00`);
        
        // Agregar 3 horas (3 * 60 * 60 * 1000 = 10800000 ms)
        const expirationTime = new Date(reservationDateTime.getTime() + (3 * 60 * 60 * 1000));
        
        // Si han pasado más de 3 horas, liberar la mesa
        if (now >= expirationTime) {
          const restaurantData = restaurants[reservation.restaurant];
          if (restaurantData) {
            const table = restaurantData.tables.find(t => t.id === reservation.tableId);
            if (table && !table.available) {
              table.available = true;
              reservation.status = 'completada'; // Marcar como completada automáticamente
              releasedTables++;
              
              const releaseInfo = {
                reservationId: reservation.id,
                tableId: reservation.tableId,
                restaurant: reservation.restaurant,
                customerName: reservation.name,
                originalTime: reservation.time,
                originalDate: reservation.date,
                expirationTime: expirationTime.toISOString(),
                releasedAt: now.toISOString()
              };
              
              releasedReservations.push(releaseInfo);
              
              logger.info(`Mesa liberada automáticamente`, releaseInfo);
            }
          }
        }
      } catch (error) {
        logger.error('Error procesando reserva para liberación automática', {
          reservationId: reservation.id,
          error: error.message,
          reservationData: reservation
        });
      }
    });
    
    if (releasedTables > 0) {
      logger.info(`Liberación automática completada`, {
        tablesReleased: releasedTables,
        reservationsCompleted: releasedReservations.length,
        details: releasedReservations
      });
      
      // Invalidar cache relacionado con mesas y restaurantes
      try {
        // Limpiar cache de restaurantes y mesas
        cacheManager.clear();
        logger.debug('Cache invalidado tras liberación automática de mesas');
      } catch (cacheError) {
        logger.warn('Error invalidando cache tras liberación automática', {
          error: cacheError.message
        });
      }
      
      // Guardar cambios en archivos
      const saveSuccess = saveReservations() && saveRestaurants();
      if (!saveSuccess) {
        logger.error('Error guardando datos tras liberación automática de mesas');
      }
    } else {
      logger.debug('Verificación de liberación automática completada - no hay mesas para liberar');
    }
  } catch (error) {
    logger.error('Error crítico en liberación automática de mesas', {
      error: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
  }
}

// Ejecutar verificación cada 15 minutos (15 * 60 * 1000 = 900000 ms)
setInterval(autoReleaseExpiredTables, 15 * 60 * 1000);

// Ejecutar verificación inicial al iniciar el servidor
autoReleaseExpiredTables();

// Usuario especial para gestión de datos
const dataUser = {
  username: 'data',
  password: '$2a$10$IoD3tFVR01cr8wdChjx0tOcK1TzqJJmYWU7UC/vqXeFbmqRCBl3MC',
  type: 'data_manager'
};

// Middleware de autenticación
const authenticateToken = (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      logger.warn('Intento de acceso sin token', {
        url: req.originalUrl,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      return res.status(401).json({ error: 'Token de acceso requerido' });
    }

    jwt.verify(token, config.server.jwtSecret, (err, user) => {
      if (err) {
        logger.warn('Token inválido recibido', {
          url: req.originalUrl,
          method: req.method,
          error: err.message,
          tokenPreview: token.substring(0, 20) + '...',
          ip: req.ip
        });
        return res.status(403).json({ error: 'Token inválido' });
      }
      
      logger.debug('Autenticación exitosa', {
        username: user.username,
        userType: user.type || 'restaurant_admin',
        restaurant: user.restaurant,
        url: req.originalUrl
      });
      
      req.user = user;
      next();
    });
  } catch (error) {
    logger.error('Error en middleware de autenticación', {
      error: error.message,
      stack: error.stack,
      url: req.originalUrl
    });
    res.status(500).json({ error: 'Error interno de autenticación' });
  }
};

// Rutas de autenticación
app.post('/api/login', authLimiter, handleAsync(async (req, res) => {
  const { username, password, restaurant } = req.body;
  
  logger.info('Intento de login', {
    username,
    restaurant,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });

  // Validación de campos requeridos
  if (!username || !password) {
    logger.warn('Login fallido - campos faltantes', {
      username: username || 'missing',
      hasPassword: !!password,
      restaurant
    });
    return res.status(400).json({ error: 'Usuario y contraseña son requeridos' });
  }

  // Verificar si es el usuario especial 'data'
  if (username === 'data') {
    try {
      if (username !== dataUser.username) {
        logger.warn('Login fallido - usuario data inválido', { username });
        return res.status(401).json({ error: 'Credenciales inválidas' });
      }

      const validPassword = await bcrypt.compare(password, dataUser.password);
      if (!validPassword) {
        logger.warn('Login fallido - contraseña incorrecta para usuario data', { username });
        return res.status(401).json({ error: 'Credenciales inválidas' });
      }

      const token = jwt.sign(
        { username, type: 'data_manager' },
        config.server.jwtSecret,
        { expiresIn: '24h' }
      );

      logger.info('Login exitoso - gestor de datos', {
        username,
        type: 'data_manager',
        ip: req.ip
      });

      res.json({
        token,
        type: 'data_manager',
        username: 'Gestor de Datos'
      });
      return;
    } catch (error) {
      logger.error('Error en login de usuario data', {
        username,
        error: error.message,
        stack: error.stack
      });
      return res.status(500).json({ error: 'Error interno durante autenticación' });
    }
  }

  // Login normal para restaurantes
  if (!restaurant) {
    logger.warn('Login fallido - restaurante no especificado', { username });
    return res.status(400).json({ error: 'Restaurante es requerido' });
  }

  if (!restaurants[restaurant]) {
    logger.warn('Login fallido - restaurante inválido', { username, restaurant });
    return res.status(400).json({ error: 'Restaurante no válido' });
  }

  try {
    const restaurantData = restaurants[restaurant];
    
    if (username !== restaurantData.admin.username) {
      logger.warn('Login fallido - usuario incorrecto', {
        attemptedUsername: username,
        restaurant,
        expectedUsername: restaurantData.admin.username
      });
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const validPassword = await bcrypt.compare(password, restaurantData.admin.password);
    if (!validPassword) {
      logger.warn('Login fallido - contraseña incorrecta', {
        username,
        restaurant
      });
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { username, restaurant },
      config.server.jwtSecret,
      { expiresIn: '24h' }
    );

    logger.info('Login exitoso - administrador de restaurante', {
      username,
      restaurant,
      restaurantName: restaurantData.name,
      ip: req.ip
    });

    res.json({ 
      token, 
      restaurant,
      restaurantName: restaurantData.name
    });
  } catch (error) {
    logger.error('Error en login de restaurante', {
      username,
      restaurant,
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Error interno durante autenticación' });
  }
}));

// ===================================
// ENDPOINT: CAMBIO DE CONTRASEÑA PARA RESTAURANTES
// ===================================
app.post('/api/admin/change-password', authenticateToken, authLimiter, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  const { username, restaurant } = req.user;

  // Validaciones de entrada
  if (!currentPassword || !newPassword) {
    logger.warn('Intento de cambio de contraseña con datos faltantes', {
      username,
      restaurant,
      missingFields: {
        currentPassword: !currentPassword,
        newPassword: !newPassword
      }
    });
    return res.status(400).json({ error: 'Contraseña actual y nueva contraseña son requeridas' });
  }

  // Validar que la nueva contraseña tenga una longitud mínima
  if (newPassword.length < 8) {
    logger.warn('Intento de cambio de contraseña con nueva contraseña muy corta', {
      username,
      restaurant,
      newPasswordLength: newPassword.length
    });
    return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 8 caracteres' });
  }

  try {
    const restaurantData = restaurants[restaurant];
    
    if (!restaurantData) {
      logger.error('Restaurante no encontrado durante cambio de contraseña', {
        username,
        restaurant
      });
      return res.status(404).json({ error: 'Restaurante no encontrado' });
    }

    // Verificar contraseña actual
    const validCurrentPassword = await bcrypt.compare(currentPassword, restaurantData.admin.password);
    if (!validCurrentPassword) {
      logger.warn('Intento de cambio de contraseña con contraseña actual incorrecta', {
        username,
        restaurant
      });
      return res.status(401).json({ error: 'Contraseña actual incorrecta' });
    }

    // Verificar que la nueva contraseña no sea igual a la actual
    const samePassword = await bcrypt.compare(newPassword, restaurantData.admin.password);
    if (samePassword) {
      logger.warn('Intento de cambio de contraseña con la misma contraseña', {
        username,
        restaurant
      });
      return res.status(400).json({ error: 'La nueva contraseña debe ser diferente a la actual' });
    }

    // Hashear nueva contraseña
    const saltRounds = 10;
    const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

    // Actualizar contraseña en memoria
    restaurants[restaurant].admin.password = hashedNewPassword;

    // Guardar cambios en archivo
    const saveSuccess = saveRestaurants();
    if (!saveSuccess) {
      logger.error('Error al guardar nueva contraseña en archivo', {
        username,
        restaurant
      });
      return res.status(500).json({ error: 'Error al guardar la nueva contraseña' });
    }

    logger.info('Contraseña cambiada exitosamente', {
      username,
      restaurant,
      restaurantName: restaurantData.name,
      ip: req.ip,
      timestamp: new Date().toISOString()
    });

    res.json({ 
      success: true, 
      message: 'Contraseña actualizada correctamente' 
    });

  } catch (error) {
    logger.error('Error durante cambio de contraseña', {
      username,
      restaurant,
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Error interno durante el cambio de contraseña' });
  }
});

// ===================================
// ENDPOINTS: SISTEMA DE TRACKING DE ENLACES
// ===================================

// Generar enlace de tracking
app.post('/api/admin/tracking-links', authenticateToken, authLimiter, async (req, res) => {
  const { name } = req.body;
  const { username } = req.user;

  // Solo el usuario 'data' puede gestionar tracking links
  if (username !== 'data') {
    logger.warn('Intento de acceso no autorizado a tracking links', {
      username,
      requestedAction: 'create_tracking_link'
    });
    return res.status(403).json({ error: 'Acceso denegado. Solo el gestor de datos puede crear enlaces de tracking.' });
  }

  if (!name || typeof name !== 'string' || name.trim().length === 0) {
    return res.status(400).json({ error: 'El nombre del enlace es requerido' });
  }

  try {
    // Generar ID único para el enlace
    const linkId = crypto.randomBytes(8).toString('hex');
    
    // Crear nuevo enlace
    const newLink = {
      id: linkId,
      name: name.trim(),
      url: `/track/${linkId}`,
      fullUrl: `${req.protocol}://${req.get('host')}/track/${linkId}`,
      clicks: 0,
      createdAt: new Date().toISOString(),
      createdBy: username,
      lastClick: null
    };

    // Añadir a la lista
    trackingLinks.push(newLink);

    // Guardar en archivo
    const saveSuccess = saveTrackingLinks();
    if (!saveSuccess) {
      logger.error('Error al guardar nuevo tracking link', {
        linkId,
        name: name.trim(),
        username
      });
      return res.status(500).json({ error: 'Error al guardar el enlace de tracking' });
    }

    logger.info('Tracking link creado exitosamente', {
      linkId,
      name: name.trim(),
      fullUrl: newLink.fullUrl,
      username,
      totalLinks: trackingLinks.length
    });

    res.json({
      success: true,
      link: newLink,
      message: 'Enlace de tracking creado correctamente'
    });

  } catch (error) {
    logger.error('Error creando tracking link', {
      name: name?.trim(),
      username,
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Error interno al crear el enlace de tracking' });
  }
});

// Obtener todos los enlaces de tracking
app.get('/api/admin/tracking-links', authenticateToken, (req, res) => {
  const { username } = req.user;

  // Solo el usuario 'data' puede ver tracking links
  if (username !== 'data') {
    logger.warn('Intento de acceso no autorizado a tracking links', {
      username,
      requestedAction: 'get_tracking_links'
    });
    return res.status(403).json({ error: 'Acceso denegado. Solo el gestor de datos puede ver enlaces de tracking.' });
  }

  try {
    // Ordenar por fecha de creación (más recientes primero)
    const sortedLinks = [...trackingLinks].sort((a, b) => 
      new Date(b.createdAt) - new Date(a.createdAt)
    );

    logger.debug('Enlaces de tracking servidos', {
      totalLinks: sortedLinks.length,
      totalClicks: sortedLinks.reduce((sum, link) => sum + link.clicks, 0),
      username
    });

    res.json({
      links: sortedLinks,
      summary: {
        totalLinks: sortedLinks.length,
        totalClicks: sortedLinks.reduce((sum, link) => sum + link.clicks, 0),
        averageClicks: sortedLinks.length > 0 ? 
          Math.round(sortedLinks.reduce((sum, link) => sum + link.clicks, 0) / sortedLinks.length * 100) / 100 : 0
      }
    });

  } catch (error) {
    logger.error('Error obteniendo tracking links', {
      username,
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Error interno al obtener enlaces de tracking' });
  }
});

// Eliminar enlace de tracking
app.delete('/api/admin/tracking-links/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { username } = req.user;

  // Solo el usuario 'data' puede eliminar tracking links
  if (username !== 'data') {
    logger.warn('Intento de eliminación no autorizada de tracking link', {
      username,
      linkId: id,
      requestedAction: 'delete_tracking_link'
    });
    return res.status(403).json({ error: 'Acceso denegado. Solo el gestor de datos puede eliminar enlaces de tracking.' });
  }

  try {
    const linkIndex = trackingLinks.findIndex(link => link.id === id);
    
    if (linkIndex === -1) {
      return res.status(404).json({ error: 'Enlace de tracking no encontrado' });
    }

    const deletedLink = trackingLinks[linkIndex];
    trackingLinks.splice(linkIndex, 1);

    // Guardar cambios
    const saveSuccess = saveTrackingLinks();
    if (!saveSuccess) {
      // Restaurar enlace si no se pudo guardar
      trackingLinks.splice(linkIndex, 0, deletedLink);
      logger.error('Error al guardar después de eliminar tracking link', {
        linkId: id,
        username
      });
      return res.status(500).json({ error: 'Error al eliminar el enlace de tracking' });
    }

    logger.info('Tracking link eliminado exitosamente', {
      linkId: id,
      linkName: deletedLink.name,
      clicks: deletedLink.clicks,
      username,
      remainingLinks: trackingLinks.length
    });

    res.json({ 
      success: true, 
      message: 'Enlace de tracking eliminado correctamente' 
    });

  } catch (error) {
    logger.error('Error eliminando tracking link', {
      linkId: id,
      username,
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Error interno al eliminar el enlace de tracking' });
  }
});

// ===================================
// ENDPOINT PARA GESTIÓN DE DATOS DE CLIENTES
// ===================================

// Rutas alias para el usuario 'data' - mantener compatibilidad con documentación
app.get('/api/data/tracking-links', authenticateToken, (req, res) => {
  const { username } = req.user;

  // Solo el usuario 'data' puede ver tracking links
  if (username !== 'data') {
    logger.warn('Intento de acceso no autorizado a tracking links', {
      username,
      requestedAction: 'get_tracking_links'
    });
    return res.status(403).json({ error: 'Acceso denegado. Solo el gestor de datos puede gestionar tracking links.' });
  }

  try {
    const linksWithFullUrl = trackingLinks.map(link => ({
      ...link,
      fullUrl: `${req.protocol}://${req.get('host')}/track/${link.id}`
    }));

    const summary = {
      totalLinks: trackingLinks.length,
      totalClicks: trackingLinks.reduce((sum, link) => sum + (link.clicks || 0), 0),
      averageClicks: trackingLinks.length > 0 ? 
        (trackingLinks.reduce((sum, link) => sum + (link.clicks || 0), 0) / trackingLinks.length) : 0
    };

    logger.debug('Tracking links servidos', {
      totalLinks: trackingLinks.length,
      username
    });

    res.json({
      links: linksWithFullUrl,
      summary
    });
  } catch (error) {
    logger.error('Error al obtener tracking links', {
      error: error.message,
      username
    });
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});

// Obtener datos de clientes para el gestor de datos
app.get('/api/data/customers', authenticateToken, (req, res) => {
  const { username } = req.user;

  // Solo el usuario 'data' puede ver datos de clientes
  if (username !== 'data') {
    logger.warn('Intento de acceso no autorizado a datos de clientes', {
      username,
      requestedAction: 'get_customer_data'
    });
    return res.status(403).json({ error: 'Acceso denegado. Solo el gestor de datos puede ver información de clientes.' });
  }

  try {
    // Procesar datos de reservas para extraer información de clientes
    const customers = [];
    const customerMap = new Map();

    reservations.forEach(reservation => {
      const customerKey = `${reservation.name}_${reservation.email}`;
      
      if (!customerMap.has(customerKey)) {
        customerMap.set(customerKey, {
          id: customerKey,
          name: reservation.name,
          email: reservation.email,
          phone: reservation.phone || '',
          reservationCount: 0,
          restaurants: new Set(),
          firstReservation: reservation.date,
          lastReservation: reservation.date,
          totalGuests: 0,
          averageGuests: 0,
          preferredTimes: [],
          status: {
            confirmed: 0,
            pending: 0,
            cancelled: 0,
            completed: 0
          }
        });
      }

      const customer = customerMap.get(customerKey);
      customer.reservationCount++;
      customer.restaurants.add(reservation.restaurant);
      customer.totalGuests += (reservation.guests || reservation.people || 0);
      
      // Contar estados correctamente
      const status = reservation.status;
      if (status === 'confirmed' || status === 'confirmada') {
        customer.status.confirmed++;
      } else if (status === 'pending') {
        customer.status.pending++;
      } else if (status === 'cancelled') {
        customer.status.cancelled++;
      } else if (status === 'completed' || status === 'completada') {
        customer.status.completed++;
      }
      
      customer.preferredTimes.push(reservation.time);

      // Actualizar fechas
      if (new Date(reservation.date) < new Date(customer.firstReservation)) {
        customer.firstReservation = reservation.date;
      }
      if (new Date(reservation.date) > new Date(customer.lastReservation)) {
        customer.lastReservation = reservation.date;
      }
    });

    // Convertir Map a Array y calcular estadísticas finales
    customerMap.forEach(customer => {
      customer.restaurants = Array.from(customer.restaurants);
      customer.averageGuests = customer.reservationCount > 0 ? 
        (customer.totalGuests / customer.reservationCount).toFixed(1) : 0;
      
      // Calcular restaurante principal (el que más reservas tiene)
      const restaurantCount = {};
      reservations.filter(r => `${r.name}_${r.email}` === customer.id).forEach(r => {
        restaurantCount[r.restaurant] = (restaurantCount[r.restaurant] || 0) + 1;
      });
      
      customer.restaurant = Object.keys(restaurantCount).reduce((a, b) => 
        restaurantCount[a] > restaurantCount[b] ? a : b, customer.restaurants[0] || 'unknown');
      
      // Mapear a nombre legible del restaurante
      const restaurantNames = {
        'alisios': 'UDON CC ALISIOS',
        'meridiano': 'UDON MERIDIANO',
        'ruizalda': 'UDON RUIZ ALDA'
      };
      customer.restaurant = restaurantNames[customer.restaurant] || customer.restaurant;
      
      // Cambiar field name para consistencia con frontend
      customer.totalReservations = customer.reservationCount;
      
      // Encontrar hora preferida (moda)
      const timeFreq = {};
      customer.preferredTimes.forEach(time => {
        timeFreq[time] = (timeFreq[time] || 0) + 1;
      });
      customer.preferredTime = Object.keys(timeFreq).reduce((a, b) => 
        timeFreq[a] > timeFreq[b] ? a : b, customer.preferredTimes[0] || '');
      
      delete customer.preferredTimes; // Limpiar array temporal
      customers.push(customer);
    });

    // Ordenar por número de reservas (clientes más frecuentes primero)
    customers.sort((a, b) => b.reservationCount - a.reservationCount);

    // Estadísticas generales
    const stats = {
      totalCustomers: customers.length,
      totalReservations: reservations.length,
      averageReservationsPerCustomer: customers.length > 0 ? 
        (reservations.length / customers.length).toFixed(1) : 0,
      restaurantStats: {},
      statusStats: {
        confirmed: reservations.filter(r => r.status === 'confirmed' || r.status === 'completada').length,
        pending: reservations.filter(r => r.status === 'pending').length,
        cancelled: reservations.filter(r => r.status === 'cancelled').length,
        completed: reservations.filter(r => r.status === 'completed' || r.status === 'completada').length
      }
    };

    // Estadísticas por restaurante
    Object.keys(restaurants).forEach(restaurantId => {
      const restaurant = restaurants[restaurantId];
      const restaurantReservations = reservations.filter(r => r.restaurant === restaurantId);
      const restaurantCustomers = customers.filter(c => c.restaurants.includes(restaurantId));
      
      stats.restaurantStats[restaurantId] = {
        name: restaurant.name,
        totalCustomers: restaurantCustomers.length,
        totalReservations: restaurantReservations.length,
        averageGuests: restaurantReservations.length > 0 ?
          (restaurantReservations.reduce((sum, r) => sum + (r.guests || r.people || 0), 0) / restaurantReservations.length).toFixed(1) : 0
      };
    });

    logger.debug('Datos de clientes servidos', {
      totalCustomers: customers.length,
      totalReservations: reservations.length,
      username
    });

    res.json({
      customers: customers.slice(0, 100), // Limitar a 100 clientes para rendimiento
      summary: stats,
      // Agregar campos directos que espera el frontend
      totalCustomers: customers.length,
      totalReservations: reservations.length,
      lastUpdated: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Error obteniendo datos de clientes', {
      username,
      error: error.message,
      stack: error.stack
    });
    res.status(500).json({ error: 'Error interno al obtener datos de clientes' });
  }
});

// Ruta de tracking - redirige a la página principal y cuenta la visita
app.get('/track/:id', (req, res) => {
  const { id } = req.params;

  try {
    const linkIndex = trackingLinks.findIndex(link => link.id === id);
    
    if (linkIndex === -1) {
      logger.warn('Intento de acceso a tracking link inexistente', {
        linkId: id,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      // Redirigir a la página principal aunque el enlace no exista
      return res.redirect('/');
    }

    // Incrementar contador
    trackingLinks[linkIndex].clicks++;
    trackingLinks[linkIndex].lastClick = new Date().toISOString();

    // Guardar cambios (sin bloquear la redirección)
    setImmediate(() => {
      const saveSuccess = saveTrackingLinks();
      if (saveSuccess) {
        logger.info('Click de tracking registrado', {
          linkId: id,
          linkName: trackingLinks[linkIndex].name,
          totalClicks: trackingLinks[linkIndex].clicks,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          timestamp: trackingLinks[linkIndex].lastClick
        });
      } else {
        logger.error('Error al guardar click de tracking', {
          linkId: id,
          linkName: trackingLinks[linkIndex].name
        });
      }
    });

    // Redirigir inmediatamente a la página principal
    res.redirect('/');

  } catch (error) {
    logger.error('Error procesando tracking link', {
      linkId: id,
      ip: req.ip,
      error: error.message,
      stack: error.stack
    });
    // Redirigir a la página principal en caso de error
    res.redirect('/');
  }
});

// Función para formatear horarios para mostrar al público
function formatScheduleForDisplay(schedule) {
  const dayNames = {
    'monday': 'Lunes',
    'tuesday': 'Martes', 
    'wednesday': 'Miércoles',
    'thursday': 'Jueves',
    'friday': 'Viernes',
    'saturday': 'Sábado',
    'sunday': 'Domingo'
  };
  
  if (!schedule || typeof schedule !== 'object') {
    return 'Horarios no disponibles';
  }
  
  // Agrupar días con el mismo horario
  const scheduleGroups = {};
  
  Object.entries(schedule).forEach(([day, daySchedule]) => {
    // Manejar días cerrados sin campos open/close
    if (!daySchedule || daySchedule.closed === true) {
      const scheduleKey = 'CERRADO';
      if (!scheduleGroups[scheduleKey]) {
        scheduleGroups[scheduleKey] = [];
      }
      scheduleGroups[scheduleKey].push(dayNames[day] || day);
    } else if (daySchedule.open && daySchedule.close) {
      const scheduleKey = `${daySchedule.open}-${daySchedule.close}`;
      if (!scheduleGroups[scheduleKey]) {
        scheduleGroups[scheduleKey] = [];
      }
      scheduleGroups[scheduleKey].push(dayNames[day] || day);
    }
  });
  
  // Convertir a formato legible
  const formattedSchedule = {};
  
  Object.entries(scheduleGroups).forEach(([timeRange, days]) => {
    if (timeRange === 'CERRADO') {
      days.forEach(day => {
        formattedSchedule[day] = 'Cerrado';
      });
    } else {
      const dayRange = days.length === 1 ? days[0] : `${days[0]} - ${days[days.length - 1]}`;
      formattedSchedule[dayRange] = timeRange.replace('-', ' - ');
    }
  });
  
  return formattedSchedule;
}

// Rutas públicas para clientes
app.get('/api/restaurants', cacheManager.middleware(600000), (req, res) => { // Cache 10 minutos
  const restaurantList = Object.keys(restaurants).map(key => ({
    id: key,
    name: restaurants[key].name,
    schedule: formatScheduleForDisplay(restaurants[key].schedule),
    availableTables: restaurants[key].tables.filter(table => table.available).length
  }));
  
  logger.debug('Lista de restaurantes servida', {
    restaurantCount: restaurantList.length,
    totalTables: restaurantList.reduce((sum, r) => sum + r.availableTables, 0)
  });
  
  res.json(restaurantList);
});

app.get('/api/restaurants/:id/tables', cacheManager.middleware(300000), (req, res) => { // Cache 5 minutos
  const { id } = req.params;
  const { date, time } = req.query; // Obtener fecha y hora desde query parameters
  const restaurant = restaurants[id];
  
  logger.debug('Solicitud de mesas para restaurante', {
    restaurantId: id,
    date,
    time,
    found: !!restaurant
  });
  
  if (!restaurant) {
    return res.status(404).json({ error: 'Restaurante no encontrado' });
  }

  let availableTables = restaurant.tables.filter(table => table.available);
  
  // Si se proporcionan fecha y hora, aplicar validación completa
  if (date && time) {
    // Primero validar horarios de servicio del restaurante
    const timeValidation = validateReservationTime(date, time, id);
    if (!timeValidation.allowed) {
      logger.info('Mesas no disponibles por restricción de servicio', {
        restaurantId: id,
        date,
        time,
        reason: timeValidation.reason,
        message: timeValidation.message
      });
      
      // Devolver array vacío si el horario no está permitido
      return res.json({
        tables: [],
        blocked: true,
        reason: timeValidation.reason,
        message: timeValidation.message,
        currentService: timeValidation.currentService,
        currentServiceTime: timeValidation.currentServiceTime
      });
    }
    
    // Luego filtrar mesas considerando conflictos de horario (buffer de 1 hora)
    availableTables = getAvailableTablesForDateTime(id, date, time);
    
    logger.debug('Mesas disponibles después de verificar todos los filtros', {
      restaurantId: id,
      date,
      time,
      finalTableCount: availableTables.length
    });
  }
  
  res.json(availableTables);
});

// Endpoint para obtener detalles completos del restaurante (incluyendo schedule)
app.get('/api/restaurants/:id/details', cacheManager.middleware(600000), (req, res) => { // Cache 10 minutos
  const { id } = req.params;
  const restaurant = restaurants[id];
  
  logger.debug('Solicitud de detalles para restaurante', {
    restaurantId: id,
    found: !!restaurant
  });
  
  if (!restaurant) {
    return res.status(404).json({ error: 'Restaurante no encontrado' });
  }

  // Devolver información completa del restaurante incluyendo schedule
  const restaurantDetails = {
    id: id,
    name: restaurant.name,
    schedule: restaurant.schedule, // Schedule completo con formato día: {open, close, closed}
    formattedSchedule: formatScheduleForDisplay(restaurant.schedule), // Schedule formateado para mostrar
    availableTables: restaurant.tables.filter(table => table.available).length,
    totalTables: restaurant.tables.length
  };
  
  logger.debug('Detalles de restaurante servidos', {
    restaurantId: id,
    restaurantName: restaurant.name,
    totalTables: restaurantDetails.totalTables,
    availableTables: restaurantDetails.availableTables
  });
  
  res.json(restaurantDetails);
});

// ===================================
// FUNCIONES DE VALIDACIÓN DE HORARIOS DE SERVICIO
// ===================================

// Configuración de servicios de restaurante
const SERVICE_SCHEDULE = {
  lunch: {
    name: 'Almuerzo',
    startTime: '13:00',
    endTime: '15:00',
    cutoffTime: '13:00' // No más reservas después de esta hora
  },
  dinner: {
    name: 'Cena', 
    startTime: '20:30',
    endTime: '22:00',
    cutoffTime: '20:30' // No más reservas después de esta hora
  }
};

// Función para determinar qué servicio corresponde a una hora
function getServiceForTime(time) {
  const timeNum = parseFloat(time.replace(':', '.'));
  
  // Almuerzo: 13:00 - 15:00
  if (timeNum >= 13.00 && timeNum <= 15.00) {
    return 'lunch';
  }
  
  // Cena: 20:30 - 22:00
  if (timeNum >= 20.30 && timeNum <= 22.00) {
    return 'dinner';
  }
  
  // Horarios fuera de servicio
  return null;
}

// Función para validar si se puede hacer una reserva en un horario específico
function validateReservationTime(date, time, restaurantId) {
  const now = new Date();
  const reservationDate = new Date(date);
  
  // Obtener datos de la fecha actual
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const reservationDay = new Date(reservationDate.getFullYear(), reservationDate.getMonth(), reservationDate.getDate());
  
  // NUEVA VALIDACIÓN: Verificar horarios del restaurante
  if (restaurantId && restaurants[restaurantId]) {
    const restaurant = restaurants[restaurantId];
    const dayNames = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
    const dayOfWeek = dayNames[reservationDate.getDay()];
    const daySchedule = restaurant.schedule[dayOfWeek];
    
    if (!daySchedule || daySchedule.closed === true) {
      const dayNameSpanish = {
        'monday': 'lunes',
        'tuesday': 'martes', 
        'wednesday': 'miércoles',
        'thursday': 'jueves',
        'friday': 'viernes',
        'saturday': 'sábados',
        'sunday': 'domingos'
      };
      
      return {
        allowed: false,
        reason: 'Restaurante cerrado',
        message: `El restaurante está cerrado los ${dayNameSpanish[dayOfWeek]}.`,
        restaurantClosed: true
      };
    }
    
    if (daySchedule.open && daySchedule.close) {
      const reservationTimeNum = parseFloat(time.replace(':', '.'));
      const openTimeNum = parseFloat(daySchedule.open.replace(':', '.'));
      const closeTimeNum = parseFloat(daySchedule.close.replace(':', '.'));
      
      if (reservationTimeNum < openTimeNum || reservationTimeNum > closeTimeNum) {
        return {
          allowed: false,
          reason: 'Fuera del horario',
          message: `El restaurante solo acepta reservas de ${daySchedule.open} a ${daySchedule.close}. La hora seleccionada (${time}) está fuera del horario de funcionamiento.`,
          restaurantSchedule: `${daySchedule.open} - ${daySchedule.close}`,
          outOfSchedule: true
        };
      }
    }
  }
  
  // Si la reserva es para un día futuro, permitir (si pasó validación de horarios)
  if (reservationDay > today) {
    return { allowed: true };
  }
  
  // Si la reserva es para hoy, verificar si está en un servicio actual
  if (reservationDay.getTime() === today.getTime()) {
    const currentTime = now.getHours() + (now.getMinutes() / 60);
    const reservationTimeNum = parseFloat(time.replace(':', '.'));
    const service = getServiceForTime(time);
    
    // VALIDACIÓN: No permitir reservas para horas que ya pasaron hoy
    if (reservationTimeNum < currentTime) {
      const currentHour = now.getHours();
      const currentMinute = now.getMinutes();
      const currentTimeFormatted = `${currentHour.toString().padStart(2, '0')}:${currentMinute.toString().padStart(2, '0')}`;
      
      return {
        allowed: false,
        reason: 'Hora ya pasada',
        message: `No se pueden hacer reservas para las ${time} porque esa hora ya ha pasado (son las ${currentTimeFormatted}). Puedes reservar para horarios posteriores de hoy o para mañana.`,
        timePassed: true,
        currentTime: currentTimeFormatted
      };
    }
    
    // Si la hora de reserva está dentro de un servicio definido
    if (service) {
      const serviceConfig = SERVICE_SCHEDULE[service];
      const serviceStartTime = parseFloat(serviceConfig.startTime.replace(':', '.'));
      const serviceEndTime = parseFloat(serviceConfig.endTime.replace(':', '.'));
      
      // Verificar si estamos ACTUALMENTE DENTRO del período de servicio
      if (currentTime >= serviceStartTime && currentTime <= serviceEndTime) {
        const currentHour = now.getHours();
        const currentMinute = now.getMinutes();
        const currentTimeFormatted = `${currentHour.toString().padStart(2, '0')}:${currentMinute.toString().padStart(2, '0')}`;
        
        // Calcular cuando termina el servicio
        const endHour = Math.floor(serviceEndTime);
        const endMinute = Math.round((serviceEndTime - endHour) * 60);
        const serviceEndFormatted = `${endHour.toString().padStart(2, '0')}:${endMinute.toString().padStart(2, '0')}`;
        
        return {
          allowed: false,
          reason: 'Servicio en curso',
          message: `⏰ Lo sentimos, no se pueden hacer reservas para el ${serviceConfig.name.toLowerCase()} porque el servicio ya ha comenzado (son las ${currentTimeFormatted} y el ${serviceConfig.name.toLowerCase()} es de ${serviceConfig.startTime} a ${serviceConfig.endTime}). Puedes reservar cuando termine el servicio (después de las ${serviceEndFormatted}) o para mañana.`,
          currentService: serviceConfig.name,
          currentServiceTime: `${serviceConfig.startTime}-${serviceConfig.endTime}`,
          serviceInProgress: true
        };
      }
    }
    
    return { allowed: true };
  }
  
  // Si la reserva es para el pasado, no permitir
  if (reservationDay < today) {
    return {
      allowed: false,
      reason: 'Fecha en el pasado',
      message: 'No se pueden hacer reservas para fechas pasadas'
    };
  }
  
  return { allowed: true };
}

// ===================================
// FUNCIÓN DE BLOQUEO DE MESAS POR RANGO HORARIO
// ===================================

/**
 * Verifica si una mesa está disponible en una fecha/hora específica
 * considerando un buffer de 1 hora antes y después de reservas existentes
 */
function isTableAvailableAtTime(tableId, requestedDate, requestedTime, restaurantId, excludeReservationId = null) {
  // Convertir fecha y hora solicitada a minutos desde medianoche para comparación
  const requestedDateTime = new Date(`${requestedDate}T${requestedTime}:00`);
  const requestedMinutes = requestedDateTime.getHours() * 60 + requestedDateTime.getMinutes();
  
  // Filtrar reservas para el mismo restaurante, fecha y mesa
  const conflictingReservations = reservations.filter(reservation => {
    // Excluir la reserva que se está editando (para casos de modificación)
    if (excludeReservationId && reservation.id === excludeReservationId) {
      return false;
    }
    
    // Solo considerar reservas confirmadas (no canceladas ni completadas)
    if (reservation.status === 'cancelada' || reservation.status === 'cancelled' || 
        reservation.status === 'completada' || reservation.status === 'completed') {
      return false;
    }
    
    return reservation.restaurant === restaurantId &&
           reservation.date === requestedDate &&
           reservation.tableId === tableId;
  });
  
  logger.debug('Verificando disponibilidad de mesa', {
    tableId,
    requestedDate,
    requestedTime,
    restaurantId,
    conflictingReservationsCount: conflictingReservations.length,
    excludeReservationId
  });
  
  // Verificar cada reserva existente
  for (const reservation of conflictingReservations) {
    const reservationDateTime = new Date(`${reservation.date}T${reservation.time}:00`);
    const reservationMinutes = reservationDateTime.getHours() * 60 + reservationDateTime.getMinutes();
    
    // Calcular rango de bloqueo: 1 hora antes y 1 hora después
    const bufferMinutes = 60; // 1 hora
    const blockStartMinutes = reservationMinutes - bufferMinutes;
    const blockEndMinutes = reservationMinutes + bufferMinutes;
    
    logger.debug('Verificando conflicto con reserva existente', {
      reservationId: reservation.id,
      reservationTime: reservation.time,
      reservationMinutes,
      blockStartMinutes,
      blockEndMinutes,
      requestedMinutes,
      wouldConflict: requestedMinutes >= blockStartMinutes && requestedMinutes <= blockEndMinutes
    });
    
    // Si la hora solicitada está dentro del rango de bloqueo
    if (requestedMinutes >= blockStartMinutes && requestedMinutes <= blockEndMinutes) {
      const blockStartHour = Math.floor(blockStartMinutes / 60);
      const blockStartMin = blockStartMinutes % 60;
      const blockEndHour = Math.floor(blockEndMinutes / 60);
      const blockEndMin = blockEndMinutes % 60;
      
      const blockStartTime = `${blockStartHour.toString().padStart(2, '0')}:${blockStartMin.toString().padStart(2, '0')}`;
      const blockEndTime = `${blockEndHour.toString().padStart(2, '0')}:${blockEndMin.toString().padStart(2, '0')}`;
      
      logger.info('Mesa bloqueada por conflicto de horario', {
        tableId,
        requestedTime,
        conflictingReservationTime: reservation.time,
        blockRange: `${blockStartTime} - ${blockEndTime}`,
        conflictingReservationId: reservation.id
      });
      
      return {
        available: false,
        reason: 'Mesa ocupada',
        message: `La mesa no está disponible a las ${requestedTime} debido a una reserva existente a las ${reservation.time}. Las mesas se bloquean 1 hora antes y después de cada reserva.`,
        conflictingReservation: {
          time: reservation.time,
          name: reservation.name,
          blockRange: `${blockStartTime} - ${blockEndTime}`
        }
      };
    }
  }
  
  return { available: true };
}

// Función para obtener mesas disponibles en una fecha/hora específica
function getAvailableTablesForDateTime(restaurantId, date, time) {
  const restaurant = restaurants[restaurantId];
  if (!restaurant) {
    return [];
  }
  
  const availableTables = restaurant.tables.filter(table => {
    // Primero verificar disponibilidad básica
    if (!table.available) {
      return false;
    }
    
    // Luego verificar conflictos de horario
    const timeCheck = isTableAvailableAtTime(table.id, date, time, restaurantId);
    return timeCheck.available;
  });
  
  logger.debug('Mesas disponibles después de verificar conflictos', {
    restaurantId,
    date,
    time,
    totalTables: restaurant.tables.length,
    basicAvailable: restaurant.tables.filter(t => t.available).length,
    finalAvailable: availableTables.length
  });
  
  return availableTables;
}

// ===================================
// ENDPOINTS: RESERVAS
// ===================================

// Crear reserva
app.post('/api/reservations', reservationLimiter, handleAsync(async (req, res) => {
  const { restaurant, tableId, customerName, customerPhone, customerEmail, date, time, guests, consents } = req.body;
  
  logger.info('Nueva solicitud de reserva', {
    restaurant,
    tableId,
    customerName,
    customerEmail: customerEmail ? `${customerEmail.substring(0, 3)}***` : null,
    date,
    time,
    guests,
    ip: req.ip,
    hasConsents: !!consents
  });

  // ===================================
  // VALIDACIÓN DE HORARIOS DE SERVICIO
  // ===================================
  const timeValidation = validateReservationTime(date, time, restaurant);
  if (!timeValidation.allowed) {
    logger.warn('Reserva rechazada por restricción de servicio actual', {
      date,
      time,
      reason: timeValidation.reason,
      message: timeValidation.message,
      restaurant,
      customerName,
      currentService: timeValidation.currentService,
      currentServiceTime: timeValidation.currentServiceTime
    });
    
    return res.status(400).json({
      error: timeValidation.reason,
      message: timeValidation.message,
      currentService: timeValidation.currentService,
      currentServiceTime: timeValidation.currentServiceTime
    });
  }

  // Validación de consentimiento obligatorio (RGPD)
  if (!consents || !consents.dataProcessing) {
    logger.warn('Reserva rechazada - falta consentimiento obligatorio', {
      hasConsents: !!consents,
      dataProcessing: consents?.dataProcessing
    });
    return res.status(400).json({ 
      error: 'Es obligatorio aceptar la Política de Privacidad para procesar la reserva' 
    });
  }

  // Log del consentimiento para auditoría
  logger.info('Consentimientos RGPD registrados', {
    dataProcessing: consents.dataProcessing,
    marketing: consents.marketing || false,
    timestamp: consents.timestamp,
    version: consents.version || '1.0',
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    action: 'CONSENT_GRANTED',
    purpose: 'RESERVATION_PROCESSING',
    lawfulBasis: 'CONSENT_ARTICLE_6_1_A',
    retentionPeriod: '2_YEARS',
    customerContact: customerEmail ? `${customerEmail.substring(0, 3)}***` : 'NO_EMAIL'
  });

  // Validaciones básicas
  if (!restaurant || !tableId || !customerName || !customerPhone || !date || !time || !guests) {
    logger.warn('Reserva rechazada - campos obligatorios faltantes', {
      restaurant: !!restaurant,
      tableId: !!tableId,
      customerName: !!customerName,
      customerPhone: !!customerPhone,
      date: !!date,
      time: !!time,
      guests: !!guests
    });
    return res.status(400).json({ error: 'Todos los campos son obligatorios' });
  }

  if (!restaurants[restaurant]) {
    logger.warn('Reserva rechazada - restaurante no válido', { restaurant });
    return res.status(400).json({ error: 'Restaurante no válido' });
  }

  const table = restaurants[restaurant].tables.find(t => t.id === tableId);
  
  if (!table) {
    logger.warn('Reserva rechazada - mesa no encontrada', { restaurant, tableId });
    return res.status(400).json({ error: 'Mesa no encontrada' });
  }

  if (!table.available) {
    logger.warn('Reserva rechazada - mesa no disponible', { 
      restaurant, 
      tableId, 
      tableName: table.name 
    });
    return res.status(400).json({ error: 'Mesa no disponible' });
  }

  // ===================================
  // VALIDACIÓN DE CONFLICTOS DE HORARIO
  // ===================================
  const tableAvailability = isTableAvailableAtTime(tableId, date, time, restaurant);
  if (!tableAvailability.available) {
    logger.warn('Reserva rechazada - conflicto de horario', {
      restaurant,
      tableId,
      tableName: table.name,
      requestedDate: date,
      requestedTime: time,
      reason: tableAvailability.reason,
      conflictingReservation: tableAvailability.conflictingReservation
    });
    
    return res.status(400).json({
      error: tableAvailability.reason,
      message: tableAvailability.message,
      conflictingReservation: tableAvailability.conflictingReservation
    });
  }

  if (guests > table.capacity) {
    logger.warn('Reserva rechazada - capacidad excedida', { 
      restaurant, 
      tableId, 
      guests, 
      capacity: table.capacity 
    });
    return res.status(400).json({ error: `La mesa seleccionada tiene capacidad para ${table.capacity} personas máximo` });
  }

  // Crear reserva
  const reservation = {
    id: reservationCounter++,
    name: customerName,
    email: customerEmail,
    phone: customerPhone,
    restaurant,
    restaurantName: restaurants[restaurant].name,
    tableId,
    tableName: table.name,
    date,
    time,
    guests: guests,
    status: 'confirmed',
    createdAt: new Date().toISOString(),
    consents: {
      dataProcessing: consents.dataProcessing,
      marketing: consents.marketing || false,
      timestamp: consents.timestamp || new Date().toISOString(),
      version: consents.version || '1.0',
      ip: req.ip,
      userAgent: req.get('User-Agent')
    }
  };

  logger.info('Reserva creada exitosamente', {
    reservationId: reservation.id,
    restaurant: reservation.restaurant,
    customerName: reservation.name,
    tableId: reservation.tableId,
    date: reservation.date,
    time: reservation.time,
    guests: reservation.guests,
    serviceValidated: timeValidation.allowed
  });

  reservations.push(reservation);
  
  // Marcar la mesa como ocupada
  table.available = false;
  
  logger.info('Mesa marcada como ocupada', {
    restaurant,
    tableId,
    tableName: table.name,
    reservationId: reservation.id
  });

  // Guardar datos
  const saveSuccess = saveReservations() && saveRestaurants() && saveCounter();
  if (!saveSuccess) {
    logger.error('Error guardando datos de reserva', {
      reservationId: reservation.id,
      restaurant,
      tableId
    });
    return res.status(500).json({ error: 'Error interno al guardar la reserva' });
  }
  
  // Invalidar cache relacionado
  try {
    cacheManager.clear();
    logger.debug('Cache invalidado tras crear reserva');
  } catch (cacheError) {
    logger.warn('Error invalidando cache tras crear reserva', {
      error: cacheError.message
    });
  }

  // Enviar email de confirmación de forma asíncrona
  let emailStatus = { success: false };
  if (customerEmail) {
    try {
      // Esta función se ejecutará en segundo plano
      sendConfirmationEmail(reservation).then((emailResult) => {
        logger.info('Resultado del envío de email', {
          reservationId: reservation.id,
          success: emailResult.success,
          error: emailResult.error
        });
      }).catch((emailError) => {
        logger.error('Error enviando email de confirmación', {
          reservationId: reservation.id,
          error: emailError.message
        });
      });
      
      emailStatus.success = true; // Asumimos éxito para no bloquear la respuesta
    } catch (error) {
      logger.error('Error iniciando envío de email', {
        reservationId: reservation.id,
        error: error.message
      });
    }
  }

  const response = { 
    message: 'Reserva realizada con éxito',
    emailSent: emailStatus.success,
    spamWarning: customerEmail ? 'Por favor, revise su bandeja de spam si no recibe el email de confirmación en los próximos minutos.' : null,
    reservation: {
      id: reservation.id,
      restaurant: reservation.restaurantName,
      date: reservation.date,
      time: reservation.time,
      guests: reservation.guests
    },
    serviceInfo: {
      serviceName: getServiceForTime(time) ? SERVICE_SCHEDULE[getServiceForTime(time)]?.name : 'Horario libre',
      validatedForCurrentService: true
    }
  };
  
  res.json(response);
}));

// ===================================
// CONFIGURACIÓN DE EMAIL Y FUNCIONES AUXILIARES
// ===================================

// Función para enviar email de confirmación (simplificada para este ejemplo)
async function sendConfirmationEmail(reservationData) {
  try {
    // Aquí iría la lógica real de envío de email
    // Por ahora retornamos éxito simulado
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

// ===================================
// ENDPOINTS ADMINISTRATIVOS PARA MESAS Y RESERVAS
// ===================================

// Endpoint para obtener reservas (admin)
app.get('/api/admin/reservations', authenticateToken, (req, res) => {
  const { restaurant } = req.user;
  
  if (!restaurant) {
    return res.status(403).json({ error: 'Acceso denegado' });
  }
  
  const restaurantReservations = reservations.filter(r => r.restaurant === restaurant);
  
  logger.debug('Reservas del restaurante servidas', {
    restaurant,
    reservationCount: restaurantReservations.length
  });
  
  res.json(restaurantReservations);
});

// Endpoint para actualizar estado de reservas (admin)
app.put('/api/admin/reservations/:id', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const { restaurant } = req.user;
  
  const reservation = reservations.find(r => r.id == id && r.restaurant === restaurant);
  
  if (!reservation) {
    return res.status(404).json({ error: 'Reserva no encontrada' });
  }
  
  reservation.status = status;
  
  // Si se cancela o completa, liberar la mesa
  if (status === 'cancelled' || status === 'completed') {
    const table = restaurants[restaurant].tables.find(t => t.id === reservation.tableId);
    if (table) {
      table.available = true;
    }
  }
  
  saveReservations() && saveRestaurants();
  
  logger.info('Estado de reserva actualizado', {
    reservationId: id,
    newStatus: status,
    restaurant
  });
  
  res.json({ message: 'Estado actualizado correctamente' });
});

// Endpoint para obtener estadísticas (admin)
app.get('/api/admin/stats', authenticateToken, (req, res) => {
  const { restaurant } = req.user;
  
  const restaurantReservations = reservations.filter(r => r.restaurant === restaurant);
  const restaurantData = restaurants[restaurant];
  
  const stats = {
    totalReservations: restaurantReservations.length,
    totalTables: restaurantData.tables.length,
    availableTables: restaurantData.tables.filter(t => t.available).length,
    todayReservations: restaurantReservations.filter(r => r.date === new Date().toISOString().split('T')[0]).length,
    statusBreakdown: {
      confirmed: restaurantReservations.filter(r => 
        r.status === 'confirmed' || r.status === 'confirmada'
      ).length,
      pending: restaurantReservations.filter(r => 
        r.status === 'pending' || r.status === 'pendiente'
      ).length,
      cancelled: restaurantReservations.filter(r => 
        r.status === 'cancelled' || r.status === 'cancelada'
      ).length,
      completed: restaurantReservations.filter(r => 
        r.status === 'completed' || r.status === 'completada'
      ).length
    }
  };
  
  logger.debug('Estadísticas calculadas para restaurante', {
    restaurant,
    stats,
    totalReservationsInDB: restaurantReservations.length
  });
  
  res.json(stats);
});

// ===================================
// ENDPOINTS DE ADMINISTRACIÓN FALTANTES
// ===================================

// Obtener mesas del restaurante (admin)
app.get('/api/admin/tables', authenticateToken, (req, res) => {
  const { restaurant, type } = req.user;
  
  logger.debug('Solicitud de mesas para administración', {
    restaurant,
    type,
    username: req.user.username
  });
  
  // Si es un gestor de datos, devolver todas las mesas de todos los restaurantes
  if (type === 'data_manager') {
    const allTables = [];
    Object.keys(restaurants).forEach(restaurantId => {
      const restaurantData = restaurants[restaurantId];
      if (restaurantData && restaurantData.tables) {
        restaurantData.tables.forEach(table => {
          allTables.push({
            ...table,
            restaurantId,
            restaurantName: restaurantData.name
          });
        });
      }
    });
    return res.json(allTables);
  }
  
  // Si es admin de restaurante, verificar el restaurante
  if (!restaurant || !restaurants[restaurant]) {
    return res.status(404).json({ error: 'Restaurante no encontrado' });
  }
  
  const restaurantData = restaurants[restaurant];
  res.json(restaurantData.tables || []);
});

// Eliminar reserva (admin)
app.delete('/api/admin/reservations/:id', authenticateToken, handleAsync(async (req, res) => {
  const { restaurant } = req.user;
  const { id } = req.params;
  
  logger.info('Eliminando reserva', {
    reservationId: id,
    restaurant,
    username: req.user.username
  });
  
  const reservationIndex = reservations.findIndex(r => 
    r.id === parseInt(id) && r.restaurant === restaurant
  );
  
  if (reservationIndex === -1) {
    return res.status(404).json({ error: 'Reserva no encontrada' });
  }
  
  const reservation = reservations[reservationIndex];
  
  // Liberar mesa si está ocupada
  if (restaurants[restaurant] && reservation.tableId) {
    const table = restaurants[restaurant].tables.find(t => t.id === reservation.tableId);
    if (table) {
      table.available = true;
      logger.debug('Mesa liberada al eliminar reserva', {
        tableId: reservation.tableId,
        tableName: table.name,
        reservationId: id
      });
    }
  }
  
  // Eliminar reserva
  reservations.splice(reservationIndex, 1);
  
  // Guardar cambios
  const saveSuccess = saveReservations() && saveRestaurants();
  if (!saveSuccess) {
    logger.error('Error al guardar después de eliminar reserva', {
      reservationId: id,
      restaurant
    });
    return res.status(500).json({ error: 'Error al eliminar la reserva' });
  }
  
  // Invalidar cache
  cacheManager.clear();
  
  logger.info('Reserva eliminada exitosamente', {
    reservationId: id,
    customerName: reservation.name,
    restaurant,
    username: req.user.username
  });
  
  res.json({ 
    message: 'Reserva eliminada correctamente',
    deletedReservation: {
      id: reservation.id,
      customerName: reservation.name,
      date: reservation.date,
      time: reservation.time
    }
  });
}));

// Actualizar horarios del restaurante (admin)
app.put('/api/admin/schedule', authenticateToken, handleAsync(async (req, res) => {
  const { restaurant } = req.user;
  const { schedule } = req.body;
  
  logger.info('Actualizando horarios de restaurante', {
    restaurant,
    username: req.user.username,
    newSchedule: schedule
  });
  
  if (!restaurant || !restaurants[restaurant]) {
    return res.status(404).json({ error: 'Restaurante no encontrado' });
  }
  
  if (!schedule || typeof schedule !== 'object') {
    return res.status(400).json({ error: 'Datos de horarios inválidos' });
  }
  
  // Validar formato de horarios
  const validDays = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday'];
  for (const [day, daySchedule] of Object.entries(schedule)) {
    if (!validDays.includes(day)) {
      return res.status(400).json({ error: `Día inválido: ${day}` });
    }
    
    if (!daySchedule.closed && (!daySchedule.open || !daySchedule.close)) {
      return res.status(400).json({ error: `Horarios faltantes para ${day}` });
    }
    
    if (!daySchedule.closed && daySchedule.open >= daySchedule.close && daySchedule.close !== '24:00') {
      return res.status(400).json({ error: `Horarios inválidos para ${day}` });
    }
  }
  
  // Actualizar horarios
  restaurants[restaurant].schedule = schedule;
  
  // Guardar cambios
  const saveSuccess = saveRestaurants();
  if (!saveSuccess) {
    logger.error('Error al guardar horarios actualizados', {
      restaurant,
      username: req.user.username
    });
    return res.status(500).json({ error: 'Error al guardar los horarios' });
  }
  
  // Invalidar cache relacionado
  cacheManager.clear();
  
  logger.info('Horarios actualizados exitosamente', {
    restaurant,
    username: req.user.username,
    updatedSchedule: schedule
  });
  
  res.json({ 
    message: 'Horarios actualizados correctamente',
    schedule: schedule
  });
}));

// Obtener horarios actuales del restaurante (admin)
app.get('/api/admin/schedule', authenticateToken, (req, res) => {
  const { restaurant } = req.user;
  
  logger.debug('Solicitud de horarios para administración', {
    restaurant,
    username: req.user.username
  });
  
  if (!restaurant || !restaurants[restaurant]) {
    return res.status(404).json({ error: 'Restaurante no encontrado' });
  }
  
  const restaurantData = restaurants[restaurant];
  res.json({
    schedule: restaurantData.schedule,
    restaurantName: restaurantData.name
  });
});

// Añadir nueva mesa (admin)
app.post('/api/admin/tables', authenticateToken, handleAsync(async (req, res) => {
  const { restaurant: userRestaurant, type } = req.user;
  const { restaurantId, name, capacity } = req.body;
  
  logger.info('Añadiendo nueva mesa', {
    userRestaurant,
    type,
    requestedRestaurant: restaurantId,
    username: req.user.username,
    tableName: name,
    capacity
  });
  
  // Determinar el restaurante objetivo
  let targetRestaurant;
  if (type === 'data_manager') {
    // El gestor de datos debe especificar el restaurante en el body
    if (!restaurantId) {
      return res.status(400).json({ error: 'restaurantId es requerido para gestores de datos' });
    }
    targetRestaurant = restaurantId;
  } else {
    // Admin de restaurante usa su propio restaurante
    targetRestaurant = userRestaurant;
  }
  
  if (!targetRestaurant || !restaurants[targetRestaurant]) {
    return res.status(404).json({ error: 'Restaurante no encontrado' });
  }
  
  if (!name || !capacity || capacity < 1 || capacity > 20) {
    return res.status(400).json({ error: 'Datos de mesa inválidos. Nombre requerido y capacidad entre 1-20' });
  }
  
  const restaurantData = restaurants[targetRestaurant];
  
  // Verificar que no existe una mesa con el mismo nombre
  const existingTable = restaurantData.tables.find(t => t.name.toLowerCase() === name.toLowerCase());
  if (existingTable) {
    return res.status(400).json({ error: 'Ya existe una mesa con ese nombre' });
  }
  
  // Generar nuevo ID
  const maxId = restaurantData.tables.length > 0 ? Math.max(...restaurantData.tables.map(t => t.id)) : 0;
  const newTable = {
    id: maxId + 1,
    name: name.trim(),
    capacity: parseInt(capacity),
    available: true
  };
  
  // Añadir mesa
  restaurantData.tables.push(newTable);
  
  // Guardar cambios
  const saveSuccess = saveRestaurants();
  if (!saveSuccess) {
    logger.error('Error al guardar nueva mesa', {
      restaurant: targetRestaurant,
      tableName: name
    });
    return res.status(500).json({ error: 'Error al guardar la nueva mesa' });
  }
  
  // Invalidar cache
  cacheManager.clear();
  
  logger.info('Mesa añadida exitosamente', {
    restaurant: targetRestaurant,
    tableId: newTable.id,
    tableName: newTable.name,
    capacity: newTable.capacity,
    username: req.user.username
  });
  
  res.status(201).json({ 
    message: 'Mesa añadida correctamente',
    table: newTable,
    totalTables: restaurantData.tables.length
  });
}));

// Eliminar mesa (admin)
app.delete('/api/admin/tables/:id', authenticateToken, handleAsync(async (req, res) => {
  const { restaurant: userRestaurant, type } = req.user;
  const { id } = req.params;
  const { restaurantId } = req.query; // Para gestores de datos
  const tableId = parseInt(id);
  
  logger.info('Eliminando mesa', {
    userRestaurant,
    type,
    requestedRestaurant: restaurantId,
    username: req.user.username,
    tableId
  });
  
  // Determinar el restaurante objetivo
  let targetRestaurant;
  if (type === 'data_manager') {
    if (!restaurantId) {
      return res.status(400).json({ error: 'restaurantId es requerido en query params para gestores de datos' });
    }
    targetRestaurant = restaurantId;
  } else {
    targetRestaurant = userRestaurant;
  }
  
  if (!targetRestaurant || !restaurants[targetRestaurant]) {
    return res.status(404).json({ error: 'Restaurante no encontrado' });
  }
  
  if (!tableId || isNaN(tableId)) {
    return res.status(400).json({ error: 'ID de mesa inválido' });
  }
  
  const restaurantData = restaurants[targetRestaurant];
  const tableIndex = restaurantData.tables.findIndex(t => t.id === tableId);
  
  if (tableIndex === -1) {
    return res.status(404).json({ error: 'Mesa no encontrada' });
  }
  
  const table = restaurantData.tables[tableIndex];
  
  // Verificar si hay reservas activas para esta mesa
  const activeReservations = reservations.filter(r => 
    r.restaurant === targetRestaurant && 
    r.tableId === tableId &&
    new Date(r.date + 'T' + r.time) >= new Date()
  );
  
  if (activeReservations.length > 0) {
    return res.status(400).json({ 
      error: 'No se puede eliminar la mesa porque tiene reservas activas',
      activeReservations: activeReservations.length
    });
  }
  
  // Eliminar mesa
  restaurantData.tables.splice(tableIndex, 1);
  
  // Guardar cambios
  const saveSuccess = saveRestaurants();
  if (!saveSuccess) {
    logger.error('Error al guardar después de eliminar mesa', {
      restaurant: targetRestaurant,
      tableId,
      tableName: table.name
    });
    return res.status(500).json({ error: 'Error al eliminar la mesa' });
  }
  
  // Invalidar cache
  cacheManager.clear();
  
  logger.info('Mesa eliminada exitosamente', {
    restaurant: targetRestaurant,
    tableId,
    tableName: table.name,
    username: req.user.username
  });
  
  res.json({ 
    message: 'Mesa eliminada correctamente',
    deletedTable: {
      id: table.id,
      name: table.name,
      capacity: table.capacity
    },
    totalTables: restaurantData.tables.length
  });
}));

// Actualizar mesa (admin)
app.put('/api/admin/tables/:id', authenticateToken, handleAsync(async (req, res) => {
  const { restaurant: userRestaurant, type } = req.user;
  const { id } = req.params;
  const { restaurantId, name, capacity, available } = req.body;
  const tableId = parseInt(id);
  
  logger.info('Actualizando mesa', {
    userRestaurant,
    type,
    requestedRestaurant: restaurantId,
    username: req.user.username,
    tableId,
    updates: { name, capacity, available }
  });
  
  // Determinar el restaurante objetivo
  let targetRestaurant;
  if (type === 'data_manager') {
    if (!restaurantId) {
      return res.status(400).json({ error: 'restaurantId es requerido para gestores de datos' });
    }
    targetRestaurant = restaurantId;
  } else {
    targetRestaurant = userRestaurant;
  }
  
  if (!targetRestaurant || !restaurants[targetRestaurant]) {
    return res.status(404).json({ error: 'Restaurante no encontrado' });
  }
  
  if (!tableId || isNaN(tableId)) {
    return res.status(400).json({ error: 'ID de mesa inválido' });
  }
  
  const restaurantData = restaurants[targetRestaurant];
  const table = restaurantData.tables.find(t => t.id === tableId);
  
  if (!table) {
    return res.status(404).json({ error: 'Mesa no encontrada' });
  }
  
  // Validar datos si se proporcionan
  if (name && name.trim() !== table.name) {
    const existingTable = restaurantData.tables.find(t => 
      t.id !== tableId && t.name.toLowerCase() === name.trim().toLowerCase()
    );
    if (existingTable) {
      return res.status(400).json({ error: 'Ya existe una mesa con ese nombre' });
    }
    table.name = name.trim();
  }
  
  if (capacity && (capacity < 1 || capacity > 20)) {
    return res.status(400).json({ error: 'Capacidad debe estar entre 1 y 20' });
  }
  
  if (capacity) table.capacity = parseInt(capacity);
  if (typeof available === 'boolean') table.available = available;
  
  // Guardar cambios
  const saveSuccess = saveRestaurants();
  if (!saveSuccess) {
    logger.error('Error al guardar actualización de mesa', {
      restaurant,
      tableId,
      tableName: table.name
    });
    return res.status(500).json({ error: 'Error al actualizar la mesa' });
  }
  
  // Invalidar cache
  cacheManager.clear();
  
  logger.info('Mesa actualizada exitosamente', {
    restaurant,
    tableId,
    tableName: table.name,
    capacity: table.capacity,
    available: table.available,
    username: req.user.username
  });
  
  res.json({ 
    message: 'Mesa actualizada correctamente',
    table: {
      id: table.id,
      name: table.name,
      capacity: table.capacity,
      available: table.available
    }
  });
}));

// Actualizar todas las mesas del restaurante (admin)
app.put('/api/admin/tables', authenticateToken, handleAsync(async (req, res) => {
  const { restaurant: userRestaurant, type } = req.user;
  const { restaurantId, tables } = req.body;
  
  logger.info('Actualizando todas las mesas', {
    userRestaurant,
    type,
    requestedRestaurant: restaurantId,
    username: req.user.username,
    tableCount: tables?.length
  });
  
  // Determinar el restaurante objetivo
  let targetRestaurant;
  if (type === 'data_manager') {
    if (!restaurantId) {
      return res.status(400).json({ error: 'restaurantId es requerido para gestores de datos' });
    }
    targetRestaurant = restaurantId;
  } else {
    targetRestaurant = userRestaurant;
  }
  
  if (!targetRestaurant || !restaurants[targetRestaurant]) {
    return res.status(404).json({ error: 'Restaurante no encontrado' });
  }
  
  if (!tables || !Array.isArray(tables)) {
    return res.status(400).json({ error: 'Se requiere un array de mesas válido' });
  }
  
  const restaurantData = restaurants[targetRestaurant];
  
  // Validar todas las mesas antes de hacer cambios
  const validatedTables = [];
  const usedNames = new Set();
  
  for (const tableData of tables) {
    const { id, name, capacity, available } = tableData;
    
    // Validar ID
    if (!id || isNaN(parseInt(id))) {
      return res.status(400).json({ error: `ID de mesa inválido: ${id}` });
    }
    
    // Validar nombre
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
      return res.status(400).json({ error: `Nombre de mesa inválido para mesa ID ${id}` });
    }
    
    // Verificar nombres duplicados
    const trimmedName = name.trim().toLowerCase();
    if (usedNames.has(trimmedName)) {
      return res.status(400).json({ error: `Nombre duplicado: ${name}` });
    }
    usedNames.add(trimmedName);
    
    // Validar capacidad
    if (!capacity || isNaN(parseInt(capacity)) || capacity < 1 || capacity > 20) {
      return res.status(400).json({ error: `Capacidad inválida para mesa ${name}. Debe ser entre 1-20` });
    }
    
    // Validar disponibilidad
    if (typeof available !== 'boolean') {
      return res.status(400).json({ error: `Estado de disponibilidad inválido para mesa ${name}` });
    }
    
    validatedTables.push({
      id: parseInt(id),
      name: name.trim(),
      capacity: parseInt(capacity),
      available: available
    });
  }
  
  // Verificar que todas las mesas existen en el restaurante
  for (const tableData of validatedTables) {
    const existingTable = restaurantData.tables.find(t => t.id === tableData.id);
    if (!existingTable) {
      return res.status(404).json({ error: `Mesa con ID ${tableData.id} no encontrada` });
    }
  }
  
  // Actualizar las mesas
  let updatedCount = 0;
  for (const tableData of validatedTables) {
    const table = restaurantData.tables.find(t => t.id === tableData.id);
    if (table) {
      table.name = tableData.name;
      table.capacity = tableData.capacity;
      table.available = tableData.available;
      updatedCount++;
    }
  }
  
  // Guardar cambios
  const saveSuccess = saveRestaurants();
  if (!saveSuccess) {
    logger.error('Error al guardar actualización de mesas', {
      restaurant: targetRestaurant,
      updatedCount
    });
    return res.status(500).json({ error: 'Error al actualizar las mesas' });
  }
  
  // Invalidar cache
  cacheManager.clear();
  
  logger.info('Mesas actualizadas exitosamente', {
    restaurant: targetRestaurant,
    updatedCount,
    username: req.user.username
  });
  
  res.json({ 
    message: 'Configuración de mesas actualizada correctamente',
    updatedCount,
    tables: validatedTables
  });
}));

// ===================================
// INICIAR SERVIDOR
// ===================================
app.listen(PORT, () => {
  logger.info(`Servidor UDON Reservas iniciado en puerto ${PORT}`);
  logger.info(`Ambiente: ${config.server.nodeEnv}`);
  logger.info(`Fecha de inicio: ${new Date().toISOString()}`);
});
