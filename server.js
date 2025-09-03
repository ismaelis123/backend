const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' })); // Para imágenes base64

// Conexión a MongoDB Atlas (reemplaza con tu URI)
mongoose.connect('mongodb+srv://romeroismael965_db_user:fCyXb9FVh8c83rHR@cluster0.lo4ka9m.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('Conectado a MongoDB'))
  .catch(err => console.error('Error MongoDB:', err));

// Secreto para JWT
const JWT_SECRET = 'tu-secreto-muy-seguro'; // Cambia esto

// Credenciales fijas del admin (tú)
const ADMIN_USERNAME = 'romeroismael965_db_user'; // Usa el mismo usuario de MongoDB Atlas
const ADMIN_PASSWORD = 'fCyXb9FVh8c83rHR'; // Usa la misma contraseña de MongoDB Atlas
const ADMIN_HASH = bcrypt.hashSync(ADMIN_PASSWORD, 10);

// Esquema de usuario (para clientes)
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'client' }
});
const User = mongoose.model('User', userSchema);

// Esquema de producto (sin stock, con descripción)
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String, required: true },
  category: { type: String, required: true },
  price: { type: Number, required: true },
  image: { type: String, required: true }, // base64
});
const Product = mongoose.model('Product', productSchema);

// Esquema de promoción
const promotionSchema = new mongoose.Schema({
  title: { type: String, required: true },
  description: { type: String, required: true },
  date: { type: Date, required: true },
  image: { type: String }, // Opcional, base64
});
const Promotion = mongoose.model('Promotion', promotionSchema);

// Middleware para verificar JWT
const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ message: 'Token inválido' });
  }
};

// Middleware para verificar admin
const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'No eres admin' });
  next();
};

// Rutas de autenticación
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashed = await bcrypt.hash(password, 10);
    const user = new User({ username, password: hashed, role: 'client' });
    await user.save();
    res.json({ message: 'Cliente registrado' });
  } catch (err) {
    res.status(400).json({ message: 'Error al registrar: ' + err.message });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  // Login admin (credenciales fijas)
  if (username === ADMIN_USERNAME && bcrypt.compareSync(password, ADMIN_HASH)) {
    const token = jwt.sign({ username, role: 'admin' }, JWT_SECRET, { expiresIn: '1h' });
    return res.json({ token, role: 'admin' });
  }
  // Login cliente
  const user = await User.findOne({ username });
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).json({ message: 'Credenciales inválidas' });
  }
  const token = jwt.sign({ username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.json({ token, role: user.role });
});

// Rutas de productos
app.get('/api/products', async (req, res) => {
  const { category } = req.query;
  const filter = category && category !== 'Todos' ? { category } : {};
  const products = await Product.find(filter);
  res.json(products);
});

app.post('/api/products', authMiddleware, adminMiddleware, async (req, res) => {
  const { name, description, category, price, image } = req.body;
  try {
    const product = new Product({ name, description, category, price, image });
    await product.save();
    res.json({ message: 'Producto subido' });
  } catch (err) {
    res.status(400).json({ message: 'Error al subir: ' + err.message });
  }
});

app.put('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { id } = req.params;
  const { name, description, category, price, image } = req.body;
  try {
    const product = await Product.findByIdAndUpdate(
      id,
      { name, description, category, price, image },
      { new: true, runValidators: true }
    );
    if (!product) return res.status(404).json({ message: 'Producto no encontrado' });
    res.json({ message: 'Producto actualizado', product });
  } catch (err) {
    res.status(400).json({ message: 'Error al actualizar: ' + err.message });
  }
});

app.delete('/api/products/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const product = await Product.findByIdAndDelete(id);
    if (!product) return res.status(404).json({ message: 'Producto no encontrado' });
    res.json({ message: 'Producto eliminado' });
  } catch (err) {
    res.status(400).json({ message: 'Error al eliminar: ' + err.message });
  }
});

// Rutas de promociones
app.get('/api/promotions', async (req, res) => {
  const promotions = await Promotion.find();
  res.json(promotions);
});

app.post('/api/promotions', authMiddleware, adminMiddleware, async (req, res) => {
  const { title, description, date, image } = req.body;
  try {
    const promotion = new Promotion({ title, description, date: new Date(date), image });
    await promotion.save();
    res.json({ message: 'Promoción subida' });
  } catch (err) {
    res.status(400).json({ message: 'Error al subir: ' + err.message });
  }
});

app.put('/api/promotions/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { id } = req.params;
  const { title, description, date, image } = req.body;
  try {
    const promotion = await Promotion.findByIdAndUpdate(
      id,
      { title, description, date: new Date(date), image },
      { new: true, runValidators: true }
    );
    if (!promotion) return res.status(404).json({ message: 'Promoción no encontrada' });
    res.json({ message: 'Promoción actualizada', promotion });
  } catch (err) {
    res.status(400).json({ message: 'Error al actualizar: ' + err.message });
  }
});

app.delete('/api/promotions/:id', authMiddleware, adminMiddleware, async (req, res) => {
  const { id } = req.params;
  try {
    const promotion = await Promotion.findByIdAndDelete(id);
    if (!promotion) return res.status(404).json({ message: 'Promoción no encontrada' });
    res.json({ message: 'Promoción eliminada' });
  } catch (err) {
    res.status(400).json({ message: 'Error al eliminar: ' + err.message });
  }
});

// Datos iniciales (opcional)
const seedData = async () => {
  if (await Product.countDocuments() > 0) return;
  const products = [
    { name: 'Zapatillas Nike', description: 'Zapatillas cómodas para deporte', category: 'Calzado', price: 50, image: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg==' },
    { name: 'Camisa Polo', description: 'Camisa elegante para cualquier ocasión', category: 'Ropa', price: 20, image: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg==' },
    { name: 'Pañales Huggies', description: 'Pañales absorbentes para bebés', category: 'Bebé', price: 15, image: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg==' },
    { name: 'Almohada Suave', description: 'Almohada cómoda para el hogar', category: 'Hogar', price: 25, image: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg==' },
  ];
  await Product.insertMany(products);
};
seedData();

app.listen(3000, () => console.log('Servidor en puerto 3000'));