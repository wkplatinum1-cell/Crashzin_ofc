const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const VIDEOS_FILE = path.join(DATA_DIR, 'videos.json');
const PROFILE_FILE = path.join(DATA_DIR, 'profile.json');

const STORAGE_LIMIT = 5 * 1024 * 1024 * 1024; // 5 GB
const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `${crypto.randomUUID()}${ext}`);
  }
});

const upload = multer({
  storage,
limits: {
  fileSize: STORAGE_LIMIT,
  files: 2
},
fileFilter: (_req, file, cb) => {
  if (file.fieldname === 'video' && !file.mimetype.startsWith('video/')) {
    return cb(new Error('Envie apenas arquivos de vídeo no campo de vídeo.'));
  }

  if (file.fieldname === 'thumbnail' && !file.mimetype.startsWith('image/')) {
    return cb(new Error('A thumbnail deve ser uma imagem PNG ou JPG.'));
  }

  cb(null, true);
}
});
function getVideos() {
  try {
    const data = JSON.parse(fs.readFileSync(VIDEOS_FILE, 'utf8'));
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function getStorageUsage() {
  return getVideos().reduce((total, video) => {
    const filePath = path.join(UPLOAD_DIR, video.filename);

    if (!fs.existsSync(filePath)) return total;

    return total + fs.statSync(filePath).size;
  }, 0);
}

function saveVideos(videos) {
  fs.writeFileSync(VIDEOS_FILE, JSON.stringify(videos, null, 2), 'utf8');
}

fs.mkdirSync(UPLOAD_DIR, { recursive: true });

if (!fs.existsSync(VIDEOS_FILE)) {
  fs.writeFileSync(VIDEOS_FILE, '[]', 'utf8');
}

if (!fs.existsSync(PROFILE_FILE)) {
  fs.writeFileSync(PROFILE_FILE, '{}', 'utf8');
}
const PORT = Number(process.env.PORT || 3000);
const OWNER_PASSWORD = process.env.OWNER_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

if (!OWNER_PASSWORD || OWNER_PASSWORD.length < 12) {
  console.error('ERRO: configure OWNER_PASSWORD no arquivo .env com pelo menos 12 caracteres.');
  process.exit(1);
}
if (!SESSION_SECRET || SESSION_SECRET.length < 32) {
  console.error('ERRO: configure SESSION_SECRET no arquivo .env com pelo menos 32 caracteres aleatórios.');
  process.exit(1);
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.set('trust proxy', 1);
app.use(session({
  name: 'crashzin.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 2 * 60 * 60 * 1000
  }
  // Para publicar em produção, configure um armazenamento persistente de sessões.
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { ok: false, message: 'Muitas tentativas. Espere 15 minutos e tente novamente.' }
});

function requireOwner(req, res, next) {
  if (req.session && req.session.isOwner === true) return next();
  return res.status(401).json({ ok: false, message: 'Faça login como dono para continuar.' });
}

app.get('/api/auth/status', (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ authenticated: !!(req.session && req.session.isOwner === true) });
});

app.post('/api/auth/login', loginLimiter, (req, res, next) => {
  const supplied = typeof req.body.password === 'string' ? req.body.password : '';
  if (supplied.length > 256 || supplied !== OWNER_PASSWORD) {
    return res.status(401).json({ ok: false, message: 'Senha incorreta. Tente novamente.' });
  }
  req.session.regenerate((err) => {
    if (err) return next(err);
    req.session.isOwner = true;
    req.session.save((saveErr) => {
      if (saveErr) return next(saveErr);
      res.set('Cache-Control', 'no-store');
      res.json({ ok: true });
    });
  });
});

app.post('/api/auth/logout', (req, res, next) => {
  if (!req.session) return res.json({ ok: true });
  req.session.destroy((err) => {
    if (err) return next(err);
    res.clearCookie('crashzin.sid', { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
    res.json({ ok: true });
  });
});

// Exemplo de rota protegida: qualquer operação administrativa no servidor deve usar este middleware.
app.get('/api/admin/check', requireOwner, (_req, res) => res.json({ ok: true, message: 'Sessão de dono validada no servidor.' }));
// Lista os vídeos e informa o uso do armazenamento.
app.get('/api/videos', (_req, res) => {
  const videos = getVideos().filter(video =>
    fs.existsSync(path.join(UPLOAD_DIR, video.filename))
  );

  res.json({
    videos: videos.map(video => ({
      id: video.id,
      title: video.title,
      category: video.category,
      description: video.description,
      filename: video.filename,
      thumbnail: video.thumbnail || null,
      size: fs.statSync(path.join(UPLOAD_DIR, video.filename)).size,
      url: `/api/videos/file/${encodeURIComponent(video.id)}`
    })),
    storageUsed: getStorageUsage(),
    storageLimit: STORAGE_LIMIT
  });
});

// Envia um vídeo, exigindo login do dono.
app.post('/api/videos', requireOwner, upload.fields([
  { name: 'video', maxCount: 1 },
  { name: 'thumbnail', maxCount: 1 }
]), (req, res) => {
  const file = req.files?.video?.[0];
  const thumbnail = req.files?.thumbnail?.[0];

  if (!file) {
    return res.status(400).json({
      ok: false,
      message: 'Selecione um vídeo.'
    });
  }

  const used = getStorageUsage();
  const totalSize = file.size + (thumbnail?.size || 0);

  if (used + totalSize > STORAGE_LIMIT) {
    fs.unlinkSync(file.path);

    if (thumbnail) {
      fs.unlinkSync(thumbnail.path);
    }

    return res.status(413).json({
      ok: false,
      message: 'O limite total de 5 GB foi atingido.'
    });
  }

  const videos = getVideos();

  const video = {
    id: crypto.randomUUID(),
    filename: file.filename,
    thumbnail: thumbnail ? thumbnail.filename : null,
    title: String(req.body.title || 'Vídeo').slice(0, 150),
    category: String(req.body.category || 'Geral').slice(0, 80),
    description: String(req.body.description || '').slice(0, 2000),
    size: totalSize,
    createdAt: new Date().toISOString()
  };

  videos.push(video);
  saveVideos(videos);

  res.status(201).json({ ok: true, video });
});
// Reproduz um vídeo cadastrado.
app.get('/api/videos/file/:id', (req, res) => {
  const video = getVideos().find(item => item.id === req.params.id);

  if (!video) {
    return res.status(404).json({ ok: false, message: 'Vídeo não encontrado.' });
  }

  const filePath = path.join(UPLOAD_DIR, video.filename);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ ok: false, message: 'Arquivo não encontrado.' });
  }

  res.sendFile(filePath);
});
app.get('/api/videos/thumbnail/:id', (req, res) => {
  const video = getVideos().find(item => item.id === req.params.id);

  if (!video || !video.thumbnail) {
    return res.status(404).json({
      ok: false,
      message: 'Thumbnail não encontrada.'
    });
  }

  const filePath = path.join(UPLOAD_DIR, video.thumbnail);

  if (!fs.existsSync(filePath)) {
    return res.status(404).json({
      ok: false,
      message: 'Arquivo da thumbnail não encontrado.'
    });
  }

  res.sendFile(filePath);
});

// Exclui um vídeo e libera o espaço ocupado.
app.delete('/api/videos/:id', requireOwner, (req, res) => {
  const videos = getVideos();
  const video = videos.find(item => item.id === req.params.id);

  if (!video) {
    return res.status(404).json({ ok: false, message: 'Vídeo não encontrado.' });
  }

  const filePath = path.join(UPLOAD_DIR, video.filename);

  if (fs.existsSync(filePath)) {
    fs.unlinkSync(filePath);
  }

  saveVideos(videos.filter(item => item.id !== video.id));

  res.json({
    ok: true,
    storageUsed: getStorageUsage(),
    storageLimit: STORAGE_LIMIT
  });
});
app.use(express.static(path.join(__dirname), {
  index: 'index.html',
  dotfiles: 'ignore',
  setHeaders(res, filePath) {
    if (filePath.endsWith('index.html')) res.setHeader('Cache-Control', 'no-store');
  }
}));

app.use((err, _req, res, _next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({
        ok: false,
        message: 'O vídeo ultrapassa o limite permitido por arquivo.'
      });
    }

    return res.status(400).json({
      ok: false,
      message: 'Não foi possível processar o upload.'
    });
  }

  if (err.message === 'Envie apenas arquivos de vídeo.') {
    return res.status(400).json({
      ok: false,
      message: err.message
    });
  }

  console.error(err);
  res.status(500).json({
    ok: false,
    message: 'Erro interno do servidor.'
  });
});

app.listen(PORT, () => console.log(`Crashzin_ofc rodando em http://localhost:${PORT}`));
