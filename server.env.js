const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const OWNER_PASSWORD = process.env.OWNER_PASSWORD;7654$$@@crashzin
const SESSION_SECRET = process.env.SESSION_SECRET;by Crashzin_ofc

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

app.use(express.static(path.join(__dirname), {
  index: 'index.html',
  dotfiles: 'ignore',
  setHeaders(res, filePath) {
    if (filePath.endsWith('index.html')) res.setHeader('Cache-Control', 'no-store');
  }
}));

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ ok: false, message: 'Erro interno do servidor.' });
});

app.listen(PORT, () => console.log(`Crashzin_ofc rodando em http://localhost:${PORT}`));
