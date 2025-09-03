const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();

app.use(cors());
app.use(express.json({ limit: '10mb' })); // Para manejar base64 grandes

// Conexión a MongoDB Atlas (reemplaza con tu URI)
mongoose.connect('mongodb+srv://romeroismael965_db_user:fCyXb9FVh8c83rHR@cluster0.lo4ka9m.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => console.log('Conectado a MongoDB'))
  .catch(err => console.error(err));

// Secreto para JWT
const JWT_SECRET = 'tu-secreto-super-seguro'; // Cambia esto por algo fuerte

// Esquema de Usuario (con rol admin)
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, default: 'user' } // 'admin' para subir productos
});
const User = mongoose.model('User', userSchema);

// Esquema de Producto (imagen como base64)
const productSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { type: String, required: true },
  price: { type: Number, required: true },
  image: { type: String, required: true }, // base64 string
  stock: { type: Number, required: true }
});
const Product = mongoose.model('Product', productSchema);

// Middleware para verificar JWT y admin
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

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'No eres admin' });
  next();
};

// Rutas de autenticación
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hashed });
  // Hacer el primer usuario admin
  if (await User.countDocuments() === 0) user.role = 'admin';
  await user.save();
  res.json({ message: 'Usuario registrado' });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !await bcrypt.compare(password, user.password)) {
    return res.status(401).json({ message: 'Credenciales inválidas' });
  }
  const token = jwt.sign({ id: user._id, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
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
  const { name, category, price, image, stock } = req.body;
  const product = new Product({ name, category, price, image, stock });
  await product.save();
  res.json({ message: 'Producto subido' });
});

// Datos iniciales (opcional, ejecuta una vez)
const seedData = async () => {
  if (await Product.countDocuments() > 0) return;
  const products = [
    { name: 'Zapatillas Adidas', category: 'Calzado', price: 60, image: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAACklEQVR4nGMAAQAABQABDQottAAAAABJRU5ErkJggg==', stock: 10 }, // base64 ejemplo
    // Agrega más...
  ];
  await Product.insertMany(products);
};
seedData();

app.listen(3000, () => console.log('Servidor en puerto 3000'));