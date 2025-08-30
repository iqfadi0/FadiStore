const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;

// Paths
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const PRODUCTS_PATH = path.join(DATA_DIR, 'products.json');
const CONFIG_PATH = path.join(DATA_DIR, 'config.json');

// Ensure folders exist
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR);
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);


function ensureConfig() {
  if (!fs.existsSync(CONFIG_PATH)) {
    const defaultHash = bcrypt.hashSync('1122Fadi!!@@@', 10);
    fs.writeFileSync(CONFIG_PATH, JSON.stringify({ passwordHash: defaultHash }, null, 2));
    console.log('Config created with default password: 1122Fadi!!@@@');
  }
}
ensureConfig();

// Helpers: load/save JSON
function loadJSON(p, fallback) {
  try { return JSON.parse(fs.readFileSync(p, 'utf-8')); }
  catch { return fallback; }
}
function saveJSON(p, data) {
  fs.writeFileSync(p, JSON.stringify(data, null, 2));
}

// Ensure products file exists
if (!fs.existsSync(PRODUCTS_PATH)) saveJSON(PRODUCTS_PATH, []);

// Multer for uploads
const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, UPLOAD_DIR),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${Date.now()}-${uuidv4()}${ext}`);
  }
});
const upload = multer({ storage });

// App setup
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use(session({
  secret: process.env.SESSION_SECRET || 'super-secret-session',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 } // 1 hour
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session && req.session.isAdmin) return next();
  return res.redirect('/adminF');
}

// ROUTES

// Public: One-page products
app.get('/', (req, res) => {
  const products = loadJSON(PRODUCTS_PATH, []);
  res.render('index', { products });
});

// Admin login page
app.get('/adminF', (req, res) => {
  if (req.session && req.session.isAdmin) return res.redirect('/adminF/dashboard');
  res.render('admin_login', { error: null });
});

// Admin login action
app.post('/adminF/login', async (req, res) => {
  const { password } = req.body;
  const cfg = loadJSON(CONFIG_PATH, null);
  if (!cfg || !cfg.passwordHash) return res.render('admin_login', { error: 'Config not found' });

  const ok = await bcrypt.compare(password, cfg.passwordHash);
  if (ok) {
    req.session.isAdmin = true;
    return res.redirect('/adminF/dashboard');
  }
  return res.render('admin_login', { error: 'Invalid password' });
});

// Admin logout
app.post('/adminF/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/adminF'));
});

// Admin dashboard
app.get('/adminF/dashboard', requireAuth, (req, res) => {
  const products = loadJSON(PRODUCTS_PATH, []);
  res.render('admin_dashboard', { products, message: null, error: null });
});

// Add product
app.post('/adminF/products', requireAuth, upload.single('image'), (req, res) => {
  const products = loadJSON(PRODUCTS_PATH, []);
  const id = uuidv4();
  const description = (req.body.description || '').toString().trim();

  let imagePath = null;
  if (req.file) imagePath = `/uploads/${req.file.filename}`;

  products.unshift({ id, imagePath, description }); // newest first
  saveJSON(PRODUCTS_PATH, products);
  res.redirect('/adminF/dashboard');
});

// Edit product
app.post('/adminF/products/:id', requireAuth, upload.single('image'), (req, res) => {
  const { id } = req.params;
  const products = loadJSON(PRODUCTS_PATH, []);
  const idx = products.findIndex(p => p.id === id);
  if (idx === -1) return res.status(404).send('Not found');

  const description = (req.body.description || '').toString().trim();
  if (description) products[idx].description = description;

  if (req.file) {
    if (products[idx].imagePath) {
      const old = path.join(__dirname, products[idx].imagePath);
      fs.existsSync(old) && fs.unlink(old, () => {});
    }
    products[idx].imagePath = `/uploads/${req.file.filename}`;
  }

  saveJSON(PRODUCTS_PATH, products);
  res.redirect('/adminF/dashboard');
});

// Delete product
app.post('/adminF/products/:id/delete', requireAuth, (req, res) => {
  const { id } = req.params;
  const products = loadJSON(PRODUCTS_PATH, []);
  const prod = products.find(p => p.id === id);
  const filtered = products.filter(p => p.id !== id);

  if (prod && prod.imagePath) {
    const filePath = path.join(__dirname, prod.imagePath);
    fs.existsSync(filePath) && fs.unlink(filePath, () => {});
  }

  saveJSON(PRODUCTS_PATH, filtered);
  res.redirect('/adminF/dashboard');
});

// Change password (directly, no current password needed)
app.post('/adminF/password', requireAuth, async (req, res) => {
  const { newPassword } = req.body;
  const cfg = loadJSON(CONFIG_PATH, null);
  const products = loadJSON(PRODUCTS_PATH, []);

  if (!newPassword || newPassword.length < 6) {
    return res.render('admin_dashboard', { products, message: null, error: 'New password must be at least 6 characters' });
  }

  cfg.passwordHash = await bcrypt.hash(newPassword, 10);
  saveJSON(CONFIG_PATH, cfg);
  res.render('admin_dashboard', { products, message: 'Password updated successfully', error: null });
});

// 404 fallback
app.use((_, res) => res.status(404).send('Not Found'));

app.listen(PORT, () => console.log(`Fadi Store running on port ${PORT}`));
