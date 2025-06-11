// Подключение необходимых модулей и моделей
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const axios = require('axios');
const app = express();
const port = process.env.PORT || 3000;
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');


const passwordResetSchema = new mongoose.Schema({
  email: String,
  token: String,
  expiresAt: Date,
});

const PasswordReset = mongoose.model('PasswordReset', passwordResetSchema);

const promoCodeSchema = new mongoose.Schema({
  code: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true },
});

const PromoCode = mongoose.model('PromoCode', promoCodeSchema);

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


app.use(cors());
app.use(bodyParser.json());



// Подключение к MongoDB
//mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

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

// Регистрация
app.post('/api/register', async (req, res) => {
  const { email, password, name } = req.body;
  const existing = await User.findOne({ email });
  if (existing) return res.status(400).json({ error: 'Email already registered' });

  const user = new User({
  name,
  email,
  password,
  token: 'token-' + Math.random().toString(36).substr(2),
  createdTokens: 0,       
  isPremium: false,       
});

  await user.save();
  res.json({ token: user.token, userId: user._id.toString() });
});

// GET /api/users/me
app.get('/api/users/me', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const user = await User.findOne({ token }, 'name email isPremium');
  if (!user) return res.status(403).json({ error: 'Invalid token' });
 if (user.premiumUntil && user.premiumUntil < new Date()) {
    user.isPremium = false;
    await user.save();
  }

  res.json({
    userId: user._id.toString(),
    name: user.name,
    email: user.email,
    isPremium: user.isPremium,
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
console.log('▶️ Проверка создания токена');
console.log('admin.token =', admin.token);
console.log('admin.isPremium =', admin.isPremium, '| typeof:', typeof admin.isPremium);
console.log('admin.createdTokens =', admin.createdTokens, '| typeof:', typeof admin.createdTokens);
  if (!admin) return res.status(403).json({ error: 'Admin not found or invalid token' });
  if (!admin.isPremium && admin.createdTokens >= 1) {
    return res.status(403).json({ error: 'Free users can only create one token' });
  }
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
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ error: 'User not found' });

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 1000 * 60 * 15); // 15 минут

  await PasswordReset.deleteMany({ email }); // удалить старые
  await new PasswordReset({ email, token, expiresAt }).save();
  await sendResetEmail(email, token);

  res.json({ success: true });
});

// промо код 
app.post('/api/promo-codes/redeem', async (req, res) => {
  const { code } = req.body;
  const authToken = req.headers.authorization?.split(' ')[1];
  const user = await User.findOne({ token: authToken });
  if (!user) return res.status(403).json({ error: 'Invalid token' });

  const promo = await PromoCode.findOne({ code });
  if (!promo) return res.status(404).json({ error: 'Promo code not found' });
  if (promo.expiresAt < new Date()) return res.status(400).json({ error: 'Promo code expired' });

  // Назначаем Premium до +1 года
  const oneYearLater = new Date();
  oneYearLater.setFullYear(oneYearLater.getFullYear() + 1);
  user.isPremium = true;
  user.premiumUntil = oneYearLater;
  await user.save();
  user.latestReceipt = 'PROMO'; // чтобы `check-subscription` не перезаписывал isPremium

  res.json({ success: true, message: 'Premium activated for 1 year using promo code' });
});

// Создание единственного промо-кода FRIENDS2025 (для админа или вручную)
app.post('/api/promo-codes/create-once', async (req, res) => {
  const existing = await PromoCode.findOne({ code: 'FRIENDS2025' });
  if (existing) return res.status(400).json({ error: 'Promo code already exists' });

  await new PromoCode({
    code: 'FRIENDS2025',
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 1 месяц
  }).save();

  res.json({ success: true });
});


app.post('/api/reset-password', async (req, res) => {
  const { token, newPassword } = req.body;
  const reset = await PasswordReset.findOne({ token });

  if (!reset || reset.expiresAt < new Date()) {
    return res.status(400).json({ error: 'Invalid or expired token' });
  }

  const user = await User.findOne({ email: reset.email });
  if (!user) return res.status(404).json({ error: 'User not found' });

  user.password = newPassword;
  await user.save();
  await PasswordReset.deleteOne({ token });

  res.json({ success: true });
});

// Логин
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email, password });
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  res.json({ token: user.token, userId: user._id.toString() });
});

// Эндпоинт: получить список всех токенов (включая adminId)
app.get('/api/tokens', async (req, res) => {
  try {
    const tokens = await Token.find().lean();
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
  console.log('🚀 /api/users/upgrade called');
  const authToken = req.headers.authorization?.split(' ')[1];
  console.log('🔐 Получен authToken:', authToken);
  console.log('📨 Authorization header:', req.headers.authorization);
  const { receipt, productId } = req.body;

  if (!authToken || !receipt || !productId) {
    return res.status(400).json({ error: 'Missing token, receipt or productId' });
  }

  const user = await User.findOne({ token: authToken });
  if (!user) return res.status(403).json({ error: 'Invalid token' });

  // StoreKit (Xcode Simulator)
  if (receipt.startsWith("MIAGCSqGSIb3DQEHAqCA")) {
    user.isPremium = true;
    user.latestReceipt = receipt;
    await user.save();
    return res.json({ success: true, note: 'StoreKit test receipt accepted' });
  }

  try {
    const payload = {
      'receipt-data': receipt,
      'password': process.env.APPLE_SHARED_SECRET
    };

    let response = await axios.post('https://buy.itunes.apple.com/verifyReceipt', payload, {
      headers: { 'Content-Type': 'application/json' }
    });

    if (response.data.status === 21007) {
      console.log("ℹ️ Статус 21007 — пробуем Sandbox...");
      try {
        response = await axios.post('https://sandbox.itunes.apple.com/verifyReceipt', payload, {
          headers: { 'Content-Type': 'application/json' }
        });
      } catch (sandboxErr) {
        console.error("❌ Ошибка Sandbox-запроса:", sandboxErr);
        // ВРЕМЕННЫЙ ОБХОД: активируем подписку несмотря на ошибку
        user.isPremium = true;
        await user.save();
        return res.json({ success: true, bypass: true, note: 'Sandbox verification failed — temporary bypass used' });
      }
    }

    console.log("📦 Финальный ответ от Apple:", JSON.stringify(response.data, null, 2));

    if (response.data.status !== 0) {
      console.error("❌ Невалидный чек:", JSON.stringify(response.data, null, 2));
      // ВРЕМЕННЫЙ ОБХОД: активируем подписку несмотря на статус ошибки
      user.isPremium = true;
      await user.save();
      return res.json({ success: true, bypass: true, note: 'Invalid receipt status — temporary bypass used' });
    }

    const latestInfo = response.data.latest_receipt_info || [];
    const found = latestInfo.some(entry => entry.product_id === productId);

    if (!found && response.data.environment === 'Sandbox') {
      console.log('⚠️ Пропускаем проверку productId в Sandbox');
    } else if (!found) {
      // ВРЕМЕННЫЙ ОБХОД: активируем подписку несмотря на отсутствие productId
      user.isPremium = true;
      await user.save();
      return res.json({ success: true, bypass: true, note: 'Product ID not found — temporary bypass used' });
    }

    user.isPremium = true;
    await user.save();

    res.json({ success: true });
  } catch (err) {
    console.error('Apple receipt verification failed:', err);
    // ВРЕМЕННЫЙ ОБХОД: активируем подписку несмотря на исключение
    user.isPremium = true;
    await user.save();
    res.json({ success: true, bypass: true, note: 'Receipt verification exception — temporary bypass used' });
  }
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
  const { email } = req.body;
  console.log('Received email for search:', email); // Логируем email для отладки

  const user = await User.findOne({ email });
  if (!user) {
    console.log('User not found with email:', email); // Логируем, если пользователь не найден
    return res.status(404).json({ error: 'User not found' });
  }

  console.log('User found:', user); // Логируем информацию о найденном пользователе
  res.json({ userId: user._id.toString() });
});

// Получить имя пользователя по userId
app.get('/api/users/by-id/:id', async (req, res) => {
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
  const token = await Token.findById(req.params.tokenId);
  if (!token) return res.status(404).json({ error: 'Token not found' });
  res.json({ rules: token.rules });
});

// Назначить участника токена
app.post('/api/tokens/assign-user', async (req, res) => {
  const header = req.headers.authorization?.split(' ')[1];
  const { tokenId, userId } = req.body;

  console.log("Request body:", req.body);  // Логируем пришедшие данные
  console.log("Authorization header:", header);  // Логируем авторизационный токен

  if (!mongoose.Types.ObjectId.isValid(userId)) {
    console.log("Invalid user ID format:", userId);  // Логируем ошибку с userId
    return res.status(400).json({ error: 'Invalid user ID format' });
  }

  const admin = await User.findOne({ token: header });
  const token = await Token.findById(tokenId);

  if (!admin || !token || token.adminId !== admin._id.toString()) {
    console.log("Access denied: Admin doesn't match or invalid token");  // Логируем ошибку с доступом
    return res.status(403).json({ error: 'Access denied' });
  }

  // Логируем, что нашли пользователя
  const user = await User.findById(userId);
  if (!user) {
    console.log("User not found:", userId);  // Логируем, если пользователь не найден
    return res.status(404).json({ error: 'User not found' });
  }

  // Логируем текущее состояние участников
  console.log("Token members before update:", token.members); 

  // Добавляем пользователя в список участников токена
  if (!token.members.includes(userId)) {
    token.members.push(userId);
    console.log("User added to token:", userId); // Логируем добавление участника
  }

  await token.save();
  console.log("Token updated successfully:", token);  // Логируем успешное обновление

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
  if (!from.isPremium && from.transactionCount >= 20) {
    return res.status(403).json({ error: 'Transaction limit reached for free users' });
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
  const token = await Token.findById(tokenId);

  if (!token) {
    return res.status(404).json({ error: 'Token not found' });
  }

  // Получаем только тех пользователей, которые связаны с этим токеном
  const users = await User.find({ '_id': { $in: token.members } });
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

// ✅ Новый эндпоинт: проверка подписки пользователя
app.get('/api/users/check-subscription', async (req, res) => {
  const authToken = req.headers.authorization?.split(' ')[1];
  if (!authToken) return res.status(401).json({ error: 'Missing token' });

  const user = await User.findOne({ token: authToken });
  if (!user) return res.status(403).json({ error: 'Invalid token' });

    if (!user.latestReceipt || user.latestReceipt === 'PROMO') {
    return res.json({ isPremium: user.isPremium, note: 'No receipt available' });
  }

  try {
    const payload = {
      'receipt-data': user.latestReceipt,
      'password': process.env.APPLE_SHARED_SECRET
    };

    let response = await axios.post('https://buy.itunes.apple.com/verifyReceipt', payload, {
      headers: { 'Content-Type': 'application/json' }
    });

    if (response.data.status === 21007) {
      response = await axios.post('https://sandbox.itunes.apple.com/verifyReceipt', payload, {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    if (response.data.status !== 0) {
      return res.status(400).json({ error: 'Invalid receipt', status: response.data.status });
    }

    const now = Date.now();
    const active = (response.data.latest_receipt_info || []).some(entry => {
      return entry.expires_date_ms && parseInt(entry.expires_date_ms) > now;
    });

    user.isPremium = active;
    await user.save();

    res.json({ isPremium: active });
  } catch (err) {
    console.error('❌ Subscription check failed:', err);
    res.status(500).json({ error: 'Subscription check failed' });
  }
});


// История транзакций по токену с отображением имён
app.get('/api/transactions/token/:tokenId', async (req, res) => {
  try {
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
