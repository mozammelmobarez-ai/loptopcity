const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const https = require('https');
const http = require('http');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const os = require('os');

// ===========================================
// تنظیمات
// ===========================================
const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'laptop-city-secret-key-2024';
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'uploads');
const PRODUCTS_UPLOADS = path.join(UPLOADS_DIR, 'products');
const PUBLIC_DIR = path.join(__dirname, 'public');

// ساخت پوشه‌ها
[DATA_DIR, UPLOADS_DIR, PRODUCTS_UPLOADS].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ===========================================
// پیدا کردن IP شبکه LAN
// ===========================================
function getLanIPs() {
  const ips = [];
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        ips.push({ name, ip: iface.address });
      }
    }
  }
  return ips;
}

// ===========================================
// Middleware
// ===========================================
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use('/uploads', express.static(UPLOADS_DIR));

// لاگ درخواست‌ها
app.use((req, res, next) => {
  const time = new Date().toLocaleTimeString('fa-IR');
  console.log(`[${time}] ${req.method} ${req.originalUrl}`);
  next();
});

// ===========================================
// Multer
// ===========================================
const diskStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, PRODUCTS_UPLOADS),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname) || '.jpg';
    cb(null, `${Date.now()}-${Math.random().toString(36).substr(2, 9)}${ext}`);
  }
});
const upload = multer({
  storage: diskStorage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (/jpeg|jpg|png|gif|webp/.test(file.mimetype)) cb(null, true);
    else cb(new Error('فقط تصاویر مجاز هستند'));
  }
});

// ===========================================
// توابع دیتابیس
// ===========================================
function readJSON(filename) {
  const filepath = path.join(DATA_DIR, filename);
  try {
    if (fs.existsSync(filepath)) {
      return JSON.parse(fs.readFileSync(filepath, 'utf8'));
    }
  } catch (e) {
    console.error(`❌ خطا در خواندن ${filename}:`, e.message);
  }
  return [];
}

function writeJSON(filename, data) {
  try {
    fs.writeFileSync(
      path.join(DATA_DIR, filename),
      JSON.stringify(data, null, 2),
      'utf8'
    );
    return true;
  } catch (e) {
    console.error(`❌ خطا در نوشتن ${filename}:`, e.message);
    return false;
  }
}

// ===========================================
// تصاویر
// ===========================================
function getFullImageUrl(imagePath, req) {
  if (!imagePath) return 'https://via.placeholder.com/300x200?text=No+Image';
  if (imagePath.startsWith('http://') || imagePath.startsWith('https://')) return imagePath;
  if (imagePath.startsWith('/uploads')) {
    return `${req.protocol}://${req.get('host')}${imagePath}`;
  }
  return imagePath;
}

function downloadImage(url) {
  return new Promise((resolve, reject) => {
    const filename = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}.jpg`;
    const filepath = path.join(PRODUCTS_UPLOADS, filename);
    const file = fs.createWriteStream(filepath);
    const proto = url.startsWith('https') ? https : http;
    proto.get(url, (res) => {
      if (res.statusCode === 200) {
        res.pipe(file);
        file.on('finish', () => { file.close(); resolve(`/uploads/products/${filename}`); });
      } else if ([301, 302].includes(res.statusCode) && res.headers.location) {
        downloadImage(res.headers.location).then(resolve).catch(reject);
      } else {
        reject(new Error(`دانلود ناموفق: ${res.statusCode}`));
      }
    }).on('error', reject);
  });
}

function saveBase64Image(base64) {
  const m = base64.match(/^data:image\/([a-zA-Z]+);base64,(.+)$/);
  if (!m) return null;
  const filename = `${Date.now()}-${Math.random().toString(36).substr(2, 9)}.${m[1]}`;
  fs.writeFileSync(path.join(PRODUCTS_UPLOADS, filename), Buffer.from(m[2], 'base64'));
  return `/uploads/products/${filename}`;
}

async function processImage(image) {
  if (!image) return null;
  if (image.startsWith('data:image')) return saveBase64Image(image);
  if (image.startsWith('http')) {
    try { return await downloadImage(image); }
    catch { return image; }
  }
  if (image.startsWith('/uploads')) return image;
  return null;
}

// ===========================================
// Middleware احراز هویت
// ===========================================
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'لطفاً وارد شوید' });
  }
  try {
    req.user = jwt.verify(h.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'نشست شما منقضی شده، دوباره وارد شوید' });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'دسترسی فقط برای مدیر' });
  }
  next();
}

// ===========================================
// API: سلامت
// ===========================================
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', time: new Date().toISOString() });
});

// ===========================================
// API: احراز هویت
// ===========================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const users = readJSON('users.json');
    const user = users.find(u => u.email === email);
    if (!user) return res.status(401).json({ error: 'ایمیل یا رمز عبور اشتباه است' });

    let valid = false;
    if (user.password.startsWith('$2')) {
      valid = await bcrypt.compare(password, user.password);
    } else {
      valid = (user.password === password);
      if (valid) {
        user.password = await bcrypt.hash(password, 10);
        writeJSON('users.json', users);
      }
    }
    if (!valid) return res.status(401).json({ error: 'ایمیل یا رمز عبور اشتباه است' });

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    const { password: _, ...safe } = user;
    console.log(`✅ ورود: ${user.name} (${user.role})`);
    res.json({ user: safe, token });
  } catch (e) {
    console.error('❌ خطا ورود:', e);
    res.status(500).json({ error: 'خطای سرور' });
  }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
      return res.status(400).json({ error: 'همه فیلدها الزامی است' });
    }
    const users = readJSON('users.json');
    if (users.find(u => u.email === email)) {
      return res.status(400).json({ error: 'این ایمیل قبلاً ثبت شده' });
    }
    const user = {
      id: `user-${Date.now()}`,
      name,
      email,
      password: await bcrypt.hash(password, 10),
      role: 'user',
      createdAt: new Date().toISOString()
    };
    users.push(user);
    writeJSON('users.json', users);
    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      JWT_SECRET,
      { expiresIn: '7d' }
    );
    const { password: _, ...safe } = user;
    console.log(`✅ ثبت‌نام: ${user.name}`);
    res.status(201).json({ user: safe, token });
  } catch (e) {
    console.error('❌ خطا ثبت‌نام:', e);
    res.status(500).json({ error: 'خطای سرور' });
  }
});

app.get('/api/auth/me', auth, (req, res) => {
  const users = readJSON('users.json');
  const user = users.find(u => u.id === req.user.id);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  const { password: _, ...safe } = user;
  res.json(safe);
});

// ===========================================
// API: محصولات
// ===========================================
app.get('/api/products', (req, res) => {
  const products = readJSON('products.json').map(p => ({
    ...p, image: getFullImageUrl(p.image, req)
  }));
  res.json(products);
});

app.get('/api/products/:id', (req, res) => {
  const p = readJSON('products.json').find(x => x.id === req.params.id);
  if (!p) return res.status(404).json({ error: 'محصول یافت نشد' });
  res.json({ ...p, image: getFullImageUrl(p.image, req) });
});

app.post('/api/products', auth, adminOnly, async (req, res) => {
  try {
    const products = readJSON('products.json');
    const imagePath = await processImage(req.body.image) || '';
    const product = {
      id: `prod-${Date.now()}`,
      ...req.body,
      image: imagePath,
      createdAt: new Date().toISOString()
    };
    products.push(product);
    writeJSON('products.json', products);
    console.log(`✅ محصول جدید: ${product.name}`);
    res.status(201).json({ ...product, image: getFullImageUrl(imagePath, req) });
  } catch (e) {
    console.error('❌ خطا محصول:', e);
    res.status(500).json({ error: 'خطا در افزودن محصول' });
  }
});

app.put('/api/products/:id', auth, adminOnly, async (req, res) => {
  try {
    const products = readJSON('products.json');
    const i = products.findIndex(p => p.id === req.params.id);
    if (i === -1) return res.status(404).json({ error: 'محصول یافت نشد' });
    let imagePath = products[i].image;
    if (req.body.image && req.body.image !== products[i].image) {
      const newPath = await processImage(req.body.image);
      if (newPath) imagePath = newPath;
    }
    products[i] = { ...products[i], ...req.body, image: imagePath, id: req.params.id };
    writeJSON('products.json', products);
    res.json({ ...products[i], image: getFullImageUrl(imagePath, req) });
  } catch (e) {
    res.status(500).json({ error: 'خطا در ویرایش' });
  }
});

app.delete('/api/products/:id', auth, adminOnly, (req, res) => {
  const products = readJSON('products.json');
  const i = products.findIndex(p => p.id === req.params.id);
  if (i === -1) return res.status(404).json({ error: 'محصول یافت نشد' });
  const deleted = products.splice(i, 1)[0];
  writeJSON('products.json', products);
  console.log(`🗑️ محصول حذف شد: ${deleted.name}`);
  res.json({ success: true });
});

// ===========================================
// API: آپلود تصویر
// ===========================================
app.post('/api/upload', auth, upload.single('image'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'فایلی انتخاب نشده' });
  const p = `/uploads/products/${req.file.filename}`;
  res.json({ path: p, url: getFullImageUrl(p, req) });
});

app.post('/api/upload-url', auth, async (req, res) => {
  try {
    if (!req.body.url) return res.status(400).json({ error: 'URL وارد نشده' });
    const p = await downloadImage(req.body.url);
    res.json({ path: p, url: getFullImageUrl(p, req) });
  } catch (e) {
    res.status(500).json({ error: 'خطا در دانلود تصویر' });
  }
});

// ===========================================
// API: کاربران
// ===========================================
app.get('/api/users', auth, adminOnly, (req, res) => {
  res.json(readJSON('users.json').map(({ password, ...u }) => u));
});

app.delete('/api/users/:id', auth, adminOnly, (req, res) => {
  const users = readJSON('users.json');
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
  if (user.role === 'admin') return res.status(403).json({ error: 'حذف ادمین ممکن نیست' });
  writeJSON('users.json', users.filter(u => u.id !== req.params.id));
  console.log(`🗑️ کاربر حذف شد: ${user.name}`);
  res.json({ success: true });
});

// ===========================================
// API: سفارشات
// ===========================================
app.get('/api/orders', auth, (req, res) => {
  const orders = readJSON('orders.json');
  const products = readJSON('products.json');
  const users = readJSON('users.json');

  let list = req.user.role === 'admin' ? orders : orders.filter(o => o.userId === req.user.id);

  const result = list.map(order => {
    const user = users.find(u => u.id === order.userId);
    return {
      ...order,
      userName: order.userName || (user ? user.name : 'ناشناس'),
      userEmail: order.userEmail || (user ? user.email : ''),
      items: (order.items || []).map(item => {
        const product = products.find(p => p.id === item.productId);
        return {
          ...item,
          product: product
            ? { ...product, image: getFullImageUrl(product.image, req) }
            : { id: item.productId, name: 'محصول حذف شده', price: item.price || 0, image: '', brand: '' }
        };
      })
    };
  });

  res.json(result);
});

app.post('/api/orders', auth, (req, res) => {
  try {
    const orders = readJSON('orders.json');
    const products = readJSON('products.json');
    const users = readJSON('users.json');
    const user = users.find(u => u.id === req.user.id);

    const items = (req.body.items || []).map(item => {
      const pid = item.productId || (item.product ? item.product.id : null);
      const product = products.find(p => p.id === pid);
      return {
        productId: pid,
        quantity: item.quantity,
        price: product ? product.price : (item.price || 0)
      };
    });

    const total = items.reduce((s, i) => s + i.price * i.quantity, 0);

    const order = {
      id: `order-${Date.now()}`,
      userId: req.user.id,
      userName: user ? user.name : 'ناشناس',
      userEmail: user ? user.email : '',
      items,
      total,
      status: 'pending',
      shipping: req.body.shipping || {},
      notes: '',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    // کاهش موجودی
    items.forEach(item => {
      const p = products.find(x => x.id === item.productId);
      if (p) p.stock = Math.max(0, p.stock - item.quantity);
    });
    writeJSON('products.json', products);

    orders.push(order);
    writeJSON('orders.json', orders);
    console.log(`✅ سفارش جدید: ${order.id}`);
    res.status(201).json(order);
  } catch (e) {
    console.error('❌ خطا سفارش:', e);
    res.status(500).json({ error: 'خطا در ثبت سفارش' });
  }
});

app.get('/api/orders/:id', auth, (req, res) => {
  const orders = readJSON('orders.json');
  const order = orders.find(o => o.id === req.params.id);
  if (!order) return res.status(404).json({ error: 'سفارش یافت نشد' });
  if (req.user.role !== 'admin' && order.userId !== req.user.id) {
    return res.status(403).json({ error: 'دسترسی ندارید' });
  }
  res.json(order);
});

app.put('/api/orders/:id', auth, adminOnly, (req, res) => {
  const orders = readJSON('orders.json');
  const i = orders.findIndex(o => o.id === req.params.id);
  if (i === -1) return res.status(404).json({ error: 'سفارش یافت نشد' });
  if (req.body.status) orders[i].status = req.body.status;
  if (req.body.notes !== undefined) orders[i].notes = req.body.notes;
  orders[i].updatedAt = new Date().toISOString();
  writeJSON('orders.json', orders);
  console.log(`✏️ سفارش ${req.params.id} → ${orders[i].status}`);
  res.json(orders[i]);
});

app.delete('/api/orders/:id', auth, adminOnly, (req, res) => {
  const orders = readJSON('orders.json');
  const i = orders.findIndex(o => o.id === req.params.id);
  if (i === -1) return res.status(404).json({ error: 'سفارش یافت نشد' });
  orders.splice(i, 1);
  writeJSON('orders.json', orders);
  console.log(`🗑️ سفارش حذف شد: ${req.params.id}`);
  res.json({ success: true });
});

// ===========================================
// API: نظرات
// ===========================================
app.get('/api/reviews', (req, res) => {
  res.json(readJSON('reviews.json'));
});

app.post('/api/reviews', auth, (req, res) => {
  try {
    const reviews = readJSON('reviews.json');
    const users = readJSON('users.json');
    const user = users.find(u => u.id === req.user.id);
    const review = {
      id: `review-${Date.now()}`,
      userId: req.user.id,
      userName: user ? user.name : 'ناشناس',
      productId: req.body.productId || null,
      rating: req.body.rating,
      comment: req.body.comment,
      createdAt: new Date().toISOString()
    };
    reviews.push(review);
    writeJSON('reviews.json', reviews);
    res.status(201).json(review);
  } catch (e) {
    res.status(500).json({ error: 'خطا در ثبت نظر' });
  }
});

// ===========================================
// API: چت‌ها
// ===========================================
app.get('/api/chats', auth, (req, res) => {
  const chats = readJSON('chats.json');
  let list = req.user.role === 'admin' ? chats : chats.filter(c => c.userId === req.user.id);
  res.json(list);
});

app.get('/api/chats/order/:orderId', auth, (req, res) => {
  const chats = readJSON('chats.json');
  const chat = chats.find(c => c.orderId === req.params.orderId);
  if (!chat) return res.status(404).json({ error: 'چت یافت نشد' });
  if (req.user.role !== 'admin' && chat.userId !== req.user.id) {
    return res.status(403).json({ error: 'دسترسی ندارید' });
  }
  res.json(chat);
});

app.get('/api/chats/user/:userId', auth, (req, res) => {
  const chats = readJSON('chats.json');
  // فقط ادمین یا خود کاربر
  if (req.user.role !== 'admin' && req.user.id !== req.params.userId) {
    return res.status(403).json({ error: 'دسترسی ندارید' });
  }
  const userChats = chats.filter(c => c.userId === req.params.userId);
  res.json(userChats);
});

app.post('/api/chats', auth, (req, res) => {
  try {
    const chats = readJSON('chats.json');
    const orders = readJSON('orders.json');
    const users = readJSON('users.json');
    
    const { orderId, userId } = req.body;
    
    // اگر orderId داده شده، چک کن سفارش وجود داره
    let order = null;
    let targetUserId = userId;
    let targetUserName = 'کاربر';
    
    if (orderId) {
      order = orders.find(o => o.id === orderId);
      if (!order) return res.status(404).json({ error: 'سفارش یافت نشد' });
      targetUserId = order.userId;
      targetUserName = order.userName || 'کاربر';
      
      // چک کن چت برای این سفارش وجود نداره
      const exists = chats.find(c => c.orderId === orderId);
      if (exists) return res.json(exists);
    } else if (userId) {
      // چت مستقیم با کاربر (بدون سفارش)
      const user = users.find(u => u.id === userId);
      if (!user) return res.status(404).json({ error: 'کاربر یافت نشد' });
      targetUserName = user.name;
      
      // چک کن چت مستقیم وجود نداره
      const exists = chats.find(c => c.userId === userId && !c.orderId);
      if (exists) return res.json(exists);
    } else {
      return res.status(400).json({ error: 'orderId یا userId الزامی است' });
    }
    
    const chat = {
      id: `chat-${Date.now()}`,
      orderId: orderId || null,
      orderNumber: order ? order.id.slice(-6) : null,
      userId: targetUserId,
      userName: targetUserName,
      adminId: req.user.role === 'admin' ? req.user.id : null,
      messages: [],
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
    
    chats.push(chat);
    writeJSON('chats.json', chats);
    console.log(`💬 چت جدید: ${chat.id}`);
    res.status(201).json(chat);
  } catch (e) {
    console.error('❌ خطا چت:', e);
    res.status(500).json({ error: 'خطا در ایجاد چت' });
  }
});

app.post('/api/chats/:chatId/messages', auth, (req, res) => {
  try {
    const chats = readJSON('chats.json');
    const i = chats.findIndex(c => c.id === req.params.chatId);
    if (i === -1) return res.status(404).json({ error: 'چت یافت نشد' });
    
    const chat = chats[i];
    if (req.user.role !== 'admin' && chat.userId !== req.user.id) {
      return res.status(403).json({ error: 'دسترسی ندارید' });
    }
    
    const users = readJSON('users.json');
    const user = users.find(u => u.id === req.user.id);
    
    const message = {
      id: `msg-${Date.now()}`,
      chatId: chat.id,
      senderId: req.user.id,
      senderName: user ? user.name : 'ناشناس',
      senderRole: req.user.role,
      content: req.body.content,
      createdAt: new Date().toISOString(),
      read: false
    };
    
    chat.messages.push(message);
    chat.updatedAt = new Date().toISOString();
    writeJSON('chats.json', chats);
    
    console.log(`💬 پیام جدید در ${chat.id}: ${message.content.substring(0, 30)}...`);
    res.status(201).json(message);
  } catch (e) {
    console.error('❌ خطا پیام:', e);
    res.status(500).json({ error: 'خطا در ارسال پیام' });
  }
});

app.put('/api/chats/:chatId/read', auth, (req, res) => {
  const chats = readJSON('chats.json');
  const chat = chats.find(c => c.id === req.params.chatId);
  if (!chat) return res.status(404).json({ error: 'چت یافت نشد' });
  
  // علامت‌گذاری پیام‌های طرف مقابل به عنوان خوانده شده
  chat.messages.forEach(m => {
    if (m.senderId !== req.user.id) m.read = true;
  });
  chat.updatedAt = new Date().toISOString();
  writeJSON('chats.json', chats);
  res.json({ success: true });
});

app.get('/api/chats/unread', auth, (req, res) => {
  const chats = readJSON('chats.json');
  let count = 0;
  chats.forEach(chat => {
    if (req.user.role === 'admin' || chat.userId === req.user.id) {
      chat.messages.forEach(m => {
        if (!m.read && m.senderId !== req.user.id) count++;
      });
    }
  });
  res.json({ count });
});

// ===========================================
// API: آمار
// ===========================================
app.get('/api/stats', auth, adminOnly, (req, res) => {
  const products = readJSON('products.json');
  const users = readJSON('users.json');
  const orders = readJSON('orders.json');
  const reviews = readJSON('reviews.json');
  res.json({
    totalProducts: products.length,
    totalUsers: users.length,
    totalOrders: orders.length,
    totalRevenue: orders.reduce((s, o) => s + (o.total || 0), 0),
    happyCustomers: reviews.filter(r => r.rating >= 4).length,
    recentOrders: orders.slice(-5).reverse()
  });
});

// ===========================================
// سرو فایل‌های فرانت‌اند (بیلد شده)
// ===========================================

// پیدا کردن پوشه فرانت‌اند بیلد شده
function findFrontendDir() {
  const candidates = [
    path.join(__dirname, 'public'),           // backend/public
    path.join(__dirname, '..', 'dist'),        // ../dist (خروجی Vite)
    path.join(__dirname, '..', 'build'),       // ../build (خروجی CRA)
  ];
  for (const dir of candidates) {
    if (fs.existsSync(path.join(dir, 'index.html'))) {
      return dir;
    }
  }
  return null;
}

const FRONTEND_DIR = findFrontendDir();

if (FRONTEND_DIR) {
  app.use(express.static(FRONTEND_DIR));
  
  // React Router - همه مسیرهای غیر-API → index.html
  app.get('*', (req, res) => {
    if (req.originalUrl.startsWith('/api/')) {
      return res.status(404).json({ error: `مسیر یافت نشد: ${req.method} ${req.originalUrl}` });
    }
    res.sendFile(path.join(FRONTEND_DIR, 'index.html'));
  });
  
  console.log(`🌐 فرانت‌اند سرو می‌شود از: ${FRONTEND_DIR}`);
} else {
  console.log('⚠️ فرانت‌اند یافت نشد! ابتدا بیلد کنید:');
  console.log('   cd .. && npm run build');
  console.log('');
  
  // صفحه راهنما بجای 404
  app.get('/', (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html lang="fa" dir="rtl">
      <head>
        <meta charset="UTF-8">
        <title>لپ‌تاپ سیتی - سرور</title>
        <style>
          body { font-family: Tahoma, sans-serif; background: #0f172a; color: #e2e8f0; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; }
          .box { background: #1e293b; padding: 40px; border-radius: 16px; max-width: 500px; text-align: center; border: 1px solid #334155; }
          h1 { color: #14b8a6; margin-bottom: 10px; }
          .status { background: #065f46; color: #6ee7b7; padding: 8px 16px; border-radius: 8px; display: inline-block; margin: 10px 0; }
          .warn { background: #78350f; color: #fbbf24; padding: 12px; border-radius: 8px; margin: 15px 0; text-align: right; }
          code { background: #334155; padding: 2px 8px; border-radius: 4px; direction: ltr; display: inline-block; }
          .api { margin-top: 20px; text-align: right; }
          .api a { color: #14b8a6; text-decoration: none; display: block; padding: 4px 0; }
          .api a:hover { text-decoration: underline; }
        </style>
      </head>
      <body>
        <div class="box">
          <h1>🖥️ لپ‌تاپ سیتی</h1>
          <div class="status">✅ سرور API فعال است</div>
          <div class="warn">
            ⚠️ فرانت‌اند بیلد نشده! برای بیلد:<br>
            <code>cd .. && npm run build</code><br>
            سپس سرور را ری‌استارت کنید
          </div>
          <div class="api">
            <strong>API های فعال:</strong>
            <a href="/api/health">/api/health - سلامت سرور</a>
            <a href="/api/products">/api/products - محصولات</a>
            <a href="/api/reviews">/api/reviews - نظرات</a>
          </div>
        </div>
      </body>
      </html>
    `);
  });
  
  app.use((req, res) => {
    if (req.originalUrl.startsWith('/api/')) {
      return res.status(404).json({ error: `مسیر یافت نشد: ${req.method} ${req.originalUrl}` });
    }
    res.redirect('/');
  });
}

// ===========================================
// ساخت کاربران پیش‌فرض
// ===========================================
async function initDatabase() {
  const users = readJSON('users.json');

  // ادمین
  let admin = users.find(u => u.email === 'admin');
  if (!admin) {
    users.push({
      id: 'user-admin',
      name: 'مدیر سیستم',
      email: 'admin',
      password: await bcrypt.hash('admin', 10),
      role: 'admin',
      createdAt: new Date().toISOString()
    });
    console.log('✅ کاربر ادمین ساخته شد (admin / admin)');
  } else {
    admin.role = 'admin';
    // همیشه رمز ادمین رو ریست کن
    admin.password = await bcrypt.hash('admin', 10);
  }

  // کاربر تست
  if (!users.find(u => u.email === 'user@example.com')) {
    users.push({
      id: 'user-test',
      name: 'کاربر تست',
      email: 'user@example.com',
      password: await bcrypt.hash('123456', 10),
      role: 'user',
      createdAt: new Date().toISOString()
    });
    console.log('✅ کاربر تست ساخته شد (user@example.com / 123456)');
  }

  writeJSON('users.json', users);
}

// ===========================================
// اجرا
// ===========================================
app.listen(PORT, '0.0.0.0', async () => {
  console.log('');
  console.log('╔════════════════════════════════════════════════════╗');
  console.log('║                                                    ║');
  console.log('║         🖥️  سرور لپ‌تاپ سیتی فعال شد               ║');
  console.log('║                                                    ║');
  console.log('╠════════════════════════════════════════════════════╣');
  console.log('║                                                    ║');
  console.log(`║   📍 محلی:    http://localhost:${PORT}               ║`);

  const lanIPs = getLanIPs();
  lanIPs.forEach(({ name, ip }) => {
    const url = `http://${ip}:${PORT}`;
    console.log(`║   🌐 شبکه:   ${url.padEnd(35)}║`);
  });

  console.log('║                                                    ║');
  console.log('╠════════════════════════════════════════════════════╣');
  console.log('║                                                    ║');
  console.log('║   👤 ادمین:    admin / admin                       ║');
  console.log('║   👤 کاربر:    user@example.com / 123456           ║');
  console.log('║                                                    ║');
  console.log('╚════════════════════════════════════════════════════╝');
  console.log('');

  await initDatabase();

  const products = readJSON('products.json');
  const users = readJSON('users.json');
  const orders = readJSON('orders.json');
  const reviews = readJSON('reviews.json');
  console.log(`📦 محصولات: ${products.length} | 👥 کاربران: ${users.length} | 📋 سفارشات: ${orders.length} | ⭐ نظرات: ${reviews.length}`);
  console.log('');

  if (lanIPs.length > 0) {
    console.log('📱 برای دسترسی از موبایل یا دستگاه دیگر در شبکه:');
    lanIPs.forEach(({ ip }) => {
      console.log(`   → http://${ip}:${PORT}`);
    });
    console.log('');
  }
});
