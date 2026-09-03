// Подключение необходимых модулей и моделей
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const app = express();
const port = process.env.PORT || 3000;
const nodemailer = require('nodemailer');
const crypto = require('crypto');


const passwordResetSchema = new mongoose.Schema({
  email: String,
  token: String,
  expiresAt: Date,
});

const PasswordReset = mongoose.model('PasswordReset', passwordResetSchema);

// отправка e-mail
async function sendResetEmail(email, token) {
  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    }
  });

  const resetLink = `${process.env.FRONTEND_URL}/?token=${token}`;

  await transporter.sendMail({
    from: `"Caprizon" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "Password Reset",
    html: `<p>To reset your password, click the link below:</p><a href="${resetLink}">${resetLink}</a>`
  });
}


const allowedOrigins = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.length === 0 || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('Origin is not allowed by CORS'));
  },
}));
app.use(bodyParser.json());



// Подключение к MongoDB
//mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

mongoose.connect(process.env.MONGODB_URI);

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB error:'));
db.once('open', () => console.log('✅ Connected to MongoDB'));

// Схемы
const tokenSchema = new mongoose.Schema({
  name: String,
  symbol: String,
  adminId: { type: String, required: true },
  totalSupply: { type: Number, default: 0 },
  members: { type: [String], default: [] },
  rules: { type: [String], default: [] },
  lastRulesUpdate: { type: Date },
});

// 🔒 Уникальность комбинации name + adminId
tokenSchema.index({ name: 1, adminId: 1 }, { unique: true });

const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  token: String,
  role: { type: String, default: 'user' },
  tokenBalances: { type: Map, of: Number, default: {} },
  isPremium: { type: Boolean, default: false },
  premiumUntil: { type: Date },
  transactionCount: { type: Number, default: 0 },
  createdTokens: { type: Number, default: 0 },
});

const transactionSchema = new mongoose.Schema({
  from: String,
  to: String,
  amount: Number,
  message: String,
  tokenId: String,
  timestamp: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);
const Token = mongoose.model('Token', tokenSchema);
const Transaction = mongoose.model('Transaction', transactionSchema);

function normalizeEmail(value) {
  return String(value || '').trim().toLowerCase();
}

function exactEmailPattern(value) {
  const escaped = String(value || '').trim().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^${escaped}$`, 'i');
}

async function verifyPassword(user, candidate) {
  const stored = String(user.password || '');
  if (stored.startsWith('$2')) {
    return bcrypt.compare(candidate, stored);
  }

  if (stored !== candidate) return false;

  // Transparently upgrade legacy plaintext passwords after a valid login.
  user.password = await bcrypt.hash(candidate, 12);
  await user.save();
  return true;
}

async function authenticatedUser(req) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return null;
  return User.findOne({ token });
}

// Регистрация
app.post('/api/register', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');
  const name = String(req.body.name || '').trim();
  if (!email || !name || password.length < 8) {
    return res.status(400).json({ error: 'Name, valid email and password of at least 8 characters are required' });
  }
  const existing = await User.findOne({ email: exactEmailPattern(email) });
  if (existing) return res.status(400).json({ error: 'Email already registered' });

  const user = new User({
  name,
  email,
  password: await bcrypt.hash(password, 12),
  token: `token-${crypto.randomBytes(32).toString('hex')}`,
  createdTokens: 0,       
  isPremium: true,
});

  await user.save();
  res.json({ token: user.token, userId: user._id.toString() });
});

// GET /api/users/me
app.get('/api/users/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const user = await User.findOne({ token }, 'name email');
  if (!user) return res.status(403).json({ error: 'Invalid token' });

  res.json({
    userId: user._id.toString(),
    name: user.name,
    email: user.email,
    isPremium: true,
  });
});


// Новая схема для запросов на токены
const requestSchema = new mongoose.Schema({
  requesterId: { type: String, required: true },   // кто запросил
  ownerId:     { type: String, required: true },   // у кого запрашивают
  tokenId:     { type: String, required: true },
  amount:      { type: Number, required: true },
  message:     { type: String },
  status:      { type: String, enum: ['pending','approved','rejected'], default: 'pending' },
  createdAt:   { type: Date, default: Date.now },
});

// Модели

const Request = mongoose.model('Request', requestSchema);

// Создание токена
app.post('/api/tokens/create', async (req, res) => {
  const header = req.headers.authorization?.split(' ')[1];
  const { name, symbol } = req.body;

  const admin = await User.findOne({ token: header });
  if (!admin) return res.status(403).json({ error: 'Admin not found or invalid token' });
  // Проверка на повтор имени у того же администратора
  const existing = await Token.findOne({ name, adminId: admin._id.toString() });
  if (existing) return res.status(400).json({ error: 'You already created a token with this name' });

  const token = new Token({
    name,
    symbol,
    adminId: admin._id.toString(),
    members: [admin._id.toString()] // Добавляем администратора в список участников
  });
  admin.createdTokens += 1;
  await admin.save();
  await token.save();

  res.json({ tokenId: token._id.toString() });
});

app.post('/api/forgot-password', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const user = await User.findOne({ email: exactEmailPattern(email) });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 1000 * 60 * 15); // 15 минут

  await PasswordReset.deleteMany({ email }); // удалить старые
  await new PasswordReset({ email, token, expiresAt }).save();
  await sendResetEmail(email, token);

  res.json({ success: true });
});

// Legacy compatibility for old clients that still display a promo-code form.
app.post('/api/promo-codes/redeem', async (req, res) => {
  const authToken = req.headers.authorization?.split(' ')[1];
  const user = await User.findOne({ token: authToken });
  if (!user) return res.status(403).json({ error: 'Invalid token' });
  res.json({ success: true, message: 'All Caprizon features are already free' });
});

app.post('/api/promo-codes/create-once', async (req, res) => {
  res.status(410).json({ error: 'Promo codes are no longer used' });
});


app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  if (String(newPassword || '').length < 8) {
    return res.status(400).json({ error: 'Password must contain at least 8 characters' });
  }
  const reset = await PasswordReset.findOne({ token });

  if (!reset || reset.expiresAt < new Date()) {
    return res.status(400).json({ error: 'Invalid or expired token' });
  }

  const user = await User.findOne({ email: reset.email });
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.password = await bcrypt.hash(newPassword, 12);
  await user.save();
  await PasswordReset.deleteOne({ token });

  res.json({ success: true });
});

// Логин
app.post('/api/login', async (req, res) => {
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || '');
  const user = await User.findOne({ email: exactEmailPattern(email) });
  if (!user || !(await verifyPassword(user, password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  res.json({ token: user.token, userId: user._id.toString() });
});

// Эндпоинт: получить список всех токенов (включая adminId)
app.get('/api/tokens', async (req, res) => {
  try {
    const user = await authenticatedUser(req);
    const query = user
      ? { $or: [{ adminId: user._id.toString() }, { members: user._id.toString() }] }
      : {};
    const tokens = await Token.find(query).lean();
    res.json(tokens.map(t => ({
      tokenId: t._id.toString(),
      name: t.name,
      symbol: t.symbol,
      totalSupply: t.totalSupply,
      adminId: t.adminId,
      members: t.members,
      lastRulesUpdate: t.lastRulesUpdate,
    })));
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Эмиссия токена (mint)
app.post('/api/tokens/mint', async (req, res) => {
  try {
    const header = req.headers.authorization?.split(' ')[1];
    const { tokenId, userId, amount } = req.body;

    const admin = await User.findOne({ token: header });
    if (!admin) return res.status(403).json({ error: 'Admin authentication failed' });

    const token = await Token.findById(tokenId);
    if (!token) return res.status(404).json({ error: 'Token not found' });

    const target = await User.findById(userId);
    if (!target) return res.status(404).json({ error: 'Target user not found' });

    if (token.adminId !== admin._id.toString()) {
      return res.status(403).json({ error: 'Access denied' });
    }
    if (!token.members.includes(userId)) {
      return res.status(403).json({ error: 'User not in token members' });
    }

    // Обновляем балансы
    const current = target.tokenBalances.get(tokenId) || 0;
    target.tokenBalances.set(tokenId, current + amount);
    await target.save();

    // Увеличиваем общее предложение
    token.totalSupply += amount;
    await token.save();

    // Сохраняем запись об эмиссии
    await new Transaction({
      from: admin._id.toString(),
      to: userId,
      amount,
      message: 'Mint Tokens',
      tokenId,
    }).save();

    res.json({ success: true });
  } catch (err) {
    console.error('Mint failed: ', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/users/upgrade', async (req, res) => {
  const authToken = req.headers.authorization?.split(' ')[1];
  const user = await User.findOne({ token: authToken });
  if (!user) return res.status(403).json({ error: 'Invalid token' });
  res.json({ success: true, note: 'All Caprizon features are free' });
});

// Удалить свой запрос (любой статус)
app.delete('/api/requests/:requestId', async (req, res) => {
  try {
    const header = req.headers.authorization?.split(' ')[1];
    const user = await User.findOne({ token: header });
    if (!user) return res.status(403).json({ error: 'Invalid token' });

    const { requestId } = req.params;
    const request = await Request.findById(requestId);
    if (!request) return res.status(404).json({ error: 'Request not found' });

    if (request.requesterId !== user._id.toString()) {
      return res.status(403).json({ error: 'You can only delete your own requests' });
    }

    await request.deleteOne();
    res.json({ success: true, message: 'Request deleted' });
  } catch (err) {
    console.error('Error deleting request:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Эндпоинт для поиска пользователя по e-mail
app.post('/api/users/search', async (req, res) => {
  const requester = await authenticatedUser(req);
  if (!requester) return res.status(403).json({ error: 'Invalid token' });
  const email = normalizeEmail(req.body.email);

  const user = await User.findOne({ email: exactEmailPattern(email) });
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  res.json({ userId: user._id.toString() });
});

// Получить имя пользователя по userId
app.get('/api/users/by-id/:id', async (req, res) => {
  const requester = await authenticatedUser(req);
  if (!requester) return res.status(403).json({ error: 'Invalid token' });
  const user = await User.findById(req.params.id, 'name email');
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({ name: user.name, email: user.email });
});

app.post('/api/tokens/set-rules', async (req, res) => {
  const header = req.headers.authorization?.split(' ')[1];
  const { tokenId, rules } = req.body;

  const admin = await User.findOne({ token: header });
  const token = await Token.findById(tokenId);

  if (!admin || !token || token.adminId !== admin._id.toString()) {
    return res.status(403).json({ error: 'Access denied' });
  }

  token.rules = Array.isArray(rules) ? rules : [];
  token.lastRulesUpdate = new Date();
  await token.save();

  res.json({ success: true });
});

// Получение отправленных запросов для пользователя
app.get('/api/requests/sent/:requesterId', async (req, res) => {
  try {
    const header = req.headers.authorization?.split(' ')[1];
    const user = await User.findOne({ token: header });

    if (!user || user._id.toString() !== req.params.requesterId) {
      return res.status(403).json({ error: 'Invalid auth or requesterId mismatch' });
    }

    const requests = await Request.find({ requesterId: user._id.toString() }).sort({ createdAt: -1 });

    const enriched = await Promise.all(requests.map(async (req) => {
      const owner = await User.findById(req.ownerId, 'name email');
      return {
        ...req.toObject(),
	requestId: req._id.toString(),
        ownerName: owner ? (owner.name || owner.email) : req.ownerId,
      };
    }));

    res.json(enriched);
  } catch (err) {
    console.error('Error fetching sent requests:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/tokens/:tokenId/rules', async (req, res) => {
  const user = await authenticatedUser(req);
  if (!user) return res.status(403).json({ error: 'Invalid token' });
  const token = await Token.findById(req.params.tokenId);
  if (!token) return res.status(404).json({ error: 'Token not found' });
  if (!token.members.includes(user._id.toString())) {
    return res.status(403).json({ error: 'Access denied' });
  }
  res.json({ rules: token.rules });
});

// Назначить участника токена
app.post('/api/tokens/assign-user', async (req, res) => {
  const header = req.headers.authorization?.split(' ')[1];
  const { tokenId, userId } = req.body;

  if (!mongoose.Types.ObjectId.isValid(userId)) {
    return res.status(400).json({ error: 'Invalid user ID format' });
  }

  const admin = await User.findOne({ token: header });
  const token = await Token.findById(tokenId);

  if (!admin || !token || token.adminId !== admin._id.toString()) {
    return res.status(403).json({ error: 'Access denied' });
  }

  const user = await User.findById(userId);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }

  // Добавляем пользователя в список участников токена
  if (!token.members.includes(userId)) {
    token.members.push(userId);
  }

  await token.save();

  res.json({ success: true });
});


// Назначить администратора токена
app.post('/api/tokens/assign-admin', async (req, res) => {
  const header = req.headers.authorization?.split(' ')[1];
  const { tokenId, userId } = req.body;

  if (!mongoose.Types.ObjectId.isValid(userId)) {
    return res.status(400).json({ error: 'Invalid user ID format' });
  }

  const admin = await User.findOne({ token: header });
  const token = await Token.findById(tokenId);

  if (!admin || !token || token.adminId !== admin._id.toString()) {
    return res.status(403).json({ error: 'Access denied' });
  }

  token.adminId = userId;
  await token.save();

  res.json({ success: true });
});

// Добавить участника токена
app.post('/api/tokens/add-member', async (req, res) => {
  const header = req.headers.authorization?.split(' ')[1];
  const { tokenId, userId } = req.body;

  const admin = await User.findOne({ token: header });
  const token = await Token.findById(tokenId);

  if (!admin || !token || token.adminId !== admin._id.toString()) {
    return res.status(403).json({ error: 'Access denied' });
  }

  if (!token.members.includes(userId)) {
    token.members.push(userId);
    await token.save();
  }

  res.json({ success: true });
});

// Балансы пользователя
app.get('/api/balances/:userId', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const user = await User.findById(req.params.userId);
  if (!user || user.token !== token) return res.status(403).json({ error: 'Invalid token' });

  res.json({ balances: Object.fromEntries(user.tokenBalances) });
});

// Перевод токенов
app.post('/api/transfer', async (req, res) => {
  const header = req.headers.authorization?.split(' ')[1];
  const { fromUserId, toUserId, amount, message, tokenId } = req.body;
  const amt = parseFloat(amount);

  const from = await User.findById(fromUserId);
  const to = await User.findById(toUserId);
  const token = await Token.findById(tokenId);

  if (!from || !to || from.token !== header || isNaN(amt) || amt <= 0 || !token) {
    return res.status(400).json({ error: 'Invalid transfer' });
  }
  if (!token.members.includes(toUserId)) {
    return res.status(403).json({ error: 'Recipient not in token members' });
  }

  const fromBal = from.tokenBalances.get(tokenId) || 0;
  if (fromBal < amt) return res.status(400).json({ error: 'Insufficient funds' });

  from.tokenBalances.set(tokenId, fromBal - amt);
  const toBal = to.tokenBalances.get(tokenId) || 0;
  to.tokenBalances.set(tokenId, toBal + amt);
  from.transactionCount += 1;
  await from.save();
  await to.save();

  await new Transaction({ from: fromUserId, to: toUserId, amount: amt, message, tokenId }).save();
  res.json({ success: true });
});


// Создание запроса на получение токенов
app.post('/api/requests', async (req, res) => {
  try {
    const header = req.headers.authorization?.split(' ')[1];
    const { requesterId, ownerId, tokenId, amount, message } = req.body;
    const user = await User.findOne({ token: header });
    if (!user || user._id.toString() !== requesterId) {
      return res.status(403).json({ error: 'Invalid auth or requesterId mismatch' });
    }
    const token = await Token.findById(tokenId);
    if (!token || !token.members.includes(ownerId)) {
      return res.status(403).json({ error: 'Owner is not a member of this token' });
    }
    const reqDoc = new Request({ requesterId, ownerId, tokenId, amount, message });
    await reqDoc.save();
    res.json({ success: true, requestId: reqDoc._id.toString() });
  } catch (err) {
    console.error('Error creating request:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Получение входящих запросов для владельца токена
app.get('/api/requests/incoming/:ownerId', async (req, res) => {
  try {
    const header = req.headers.authorization?.split(' ')[1];
    const owner = await User.findOne({ token: header });
    if (!owner) return res.status(403).json({ error: 'Invalid token' });
    if (!owner || owner._id.toString() !== req.params.ownerId) {
      return res.status(403).json({ error: 'Invalid auth or ownerId mismatch' });
    }
   const requests = await Request.find({ ownerId: owner._id.toString(), status: 'pending' }).sort({ createdAt: -1 });

   const enriched = await Promise.all(requests.map(async (req) => {
   const user = await User.findById(req.requesterId, 'name email');
   return {
    ...req.toObject(),
    requesterName: user ? (user.name || user.email) : req.requesterId,
  };
}));

res.json(enriched);

  } catch (err) {
    console.error('Error fetching incoming requests:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Ответ на запрос: approve или reject
app.post('/api/requests/:requestId/respond', async (req, res) => {
  try {
    const header = req.headers.authorization?.split(' ')[1];
    const owner = await User.findOne({ token: header });
    const { action } = req.body;
    const { requestId } = req.params;

    const reqDoc = await Request.findById(requestId);
    if (!reqDoc) return res.status(404).json({ error: 'Request not found' });
    if (reqDoc.ownerId !== owner._id.toString()) {
      return res.status(403).json({ error: 'Not authorized to respond' });
    }
    if (reqDoc.status !== 'pending') {
      return res.status(400).json({ error: 'Request already handled' });
    }

    if (action === 'approve') {
      const from = await User.findById(reqDoc.ownerId);
      const to = await User.findById(reqDoc.requesterId);
      const token = await Token.findById(reqDoc.tokenId);

      const ownerBal = from.tokenBalances.get(reqDoc.tokenId) || 0;
      if (ownerBal < reqDoc.amount) {
        return res.status(400).json({ error: 'Insufficient funds' });
      }
      // Переводим токены
      from.tokenBalances.set(reqDoc.tokenId, ownerBal - reqDoc.amount);
      const toBal = to.tokenBalances.get(reqDoc.tokenId) || 0;
      to.tokenBalances.set(reqDoc.tokenId, toBal + reqDoc.amount);
      await from.save();
      await to.save();

      // Записываем транзакцию
      await new Transaction({
        from: reqDoc.ownerId,
        to: reqDoc.requesterId,
        amount: reqDoc.amount,
        message: reqDoc.message || 'Request Approved',
        tokenId: reqDoc.tokenId,
      }).save();

      // Отмечаем запрос как обработанный
      reqDoc.status = 'approved';
      await reqDoc.save();

      return res.json({ success: true, action: 'approved' });
    } else if (action === 'reject') {
      reqDoc.status = 'rejected';
      await reqDoc.save();
      return res.json({ success: true, action: 'rejected' });
    } else {
      return res.status(400).json({ error: 'Invalid action' });
    }
  } catch (err) {
    console.error('Error responding to request:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Эндпоинт для получения пользователей токена
app.get('/api/users/token/:tokenId', async (req, res) => {
  const { tokenId } = req.params;
  const user = await authenticatedUser(req);
  if (!user) return res.status(403).json({ error: 'Invalid token' });
  const token = await Token.findById(tokenId);

  if (!token) {
    return res.status(404).json({ error: 'Token not found' });
  }

  if (!token.members.includes(user._id.toString())) {
    return res.status(403).json({ error: 'Access denied' });
  }

  const users = await User.find(
    { '_id': { $in: token.members } },
    '_id name email',
  );
  res.json(users);
});


app.delete('/api/users/delete', async (req, res) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Token missing' });
  }

  try {
    const user = await User.findOne({ token });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    await user.deleteOne();
    res.json({ success: true, message: 'Account deleted' });
  } catch (err) {
    console.error('❌ Error deleting account:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Legacy compatibility for published mobile clients.
app.get('/api/users/check-subscription', async (req, res) => {
  const authToken = req.headers.authorization?.split(' ')[1];
  if (!authToken) return res.status(401).json({ error: 'Missing token' });

  const user = await User.findOne({ token: authToken });
  if (!user) return res.status(403).json({ error: 'Invalid token' });

  res.json({ isPremium: true, note: 'All Caprizon features are free' });
});


// История транзакций по токену с отображением имён
app.get('/api/transactions/token/:tokenId', async (req, res) => {
  try {
    const user = await authenticatedUser(req);
    if (!user) return res.status(403).json({ error: 'Invalid token' });
    const token = await Token.findById(req.params.tokenId);
    if (!token || !token.members.includes(user._id.toString())) {
      return res.status(403).json({ error: 'Access denied' });
    }
    const txs = await Transaction.find({ tokenId: req.params.tokenId }).sort({ timestamp: -1 });

    const populated = await Promise.all(txs.map(async tx => {
      let fromUser = null;
      let toUser = null;

      try {
        fromUser = await User.findById(tx.from, 'name email');
      } catch (_) {}
      try {
        toUser = await User.findById(tx.to, 'name email');
      } catch (_) {}

      return {
        ...tx.toObject(),
        fromName: fromUser ? (fromUser.name || fromUser.email) : tx.from,
        toName: toUser ? (toUser.name || toUser.email) : tx.to,
      };
    }));

    res.json(populated);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Запуск сервера
app.listen(port, () => console.log(`🚀 Caprizon backend running at ${port}`));
