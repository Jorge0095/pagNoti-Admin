const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs').promises;
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 4000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// Database connection
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || 'Yorch0711!',
  database: process.env.DB_NAME || 'news_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
};

const pool = mysql.createPool(dbConfig);

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.sendStatus(401);
  }

  jwt.verify(token, process.env.JWT_SECRET || 'cisco123', (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Initialize database tables - ESTA FUNCIÓN FALTABA
async function initDatabase() {
  try {
    console.log('Initializing database...');
    
    // Crear tabla usuarios
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS usuarios (
        ID INT AUTO_INCREMENT PRIMARY KEY,
        nombre VARCHAR(100) NOT NULL,
        email VARCHAR(100) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        rol ENUM('admin', 'usuario') DEFAULT 'usuario',
        fechaCreacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Crear tabla notas
    await pool.execute(`
      CREATE TABLE IF NOT EXISTS notas (
        ID INT AUTO_INCREMENT PRIMARY KEY,
        Titulo VARCHAR(255) NOT NULL,
        Contenido TEXT NOT NULL,
        categoria ENUM('politica', 'deportes', 'tecnologia', 'economia', 'salud', 'entretenimiento') NOT NULL,
        imagen VARCHAR(255),
        visible BOOLEAN DEFAULT TRUE,
        autorID INT,
        FechaCreacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        fechaActualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (autorID) REFERENCES usuarios(ID)
      )
    `);

    // Crear usuario admin por defecto si no existe
    const [existingAdmin] = await pool.execute('SELECT * FROM usuarios WHERE email = ?', ['admin@news.com']);
    if (existingAdmin.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.execute(
        'INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)',
        ['Administrator', 'admin@news.com', hashedPassword, 'admin']
      );
      console.log('Default admin user created');
    }

    // Crear directorio de uploads si no existe
    try {
      await fs.access('public/uploads');
    } catch (error) {
      await fs.mkdir('public/uploads', { recursive: true });
      console.log('Created uploads directory');
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
  }
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// Auth routes
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    const [rows] = await pool.execute('SELECT * FROM usuarios WHERE email = ?', [email]);
    
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign(
      { id: user.ID, email: user.email, rol: user.rol },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    res.json({ 
      token, 
      user: { 
        id: user.ID, 
        nombre: user.nombre, 
        email: user.email, 
        rol: user.rol 
      } 
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/logout', (req, res) => {
  res.json({ message: 'Logged out successfully' });
});

// Protected admin routes
app.get('/api/notas', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      'SELECT * FROM notas WHERE autorID = ? ORDER BY FechaCreacion DESC',
      [req.user.id]
    );
    res.json(rows);
  } catch (error) {
    console.error('Error fetching admin news:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/notas', authenticateToken, upload.single('imagen'), async (req, res) => {
  try {
    const { titulo, contenido, categoria } = req.body;
    const imagen = req.file ? `/uploads/${req.file.filename}` : null;
    
    const [result] = await pool.execute(
      'INSERT INTO notas (Titulo, Contenido, categoria, imagen, autorID) VALUES (?, ?, ?, ?, ?)',
      [titulo, contenido, categoria, imagen, req.user.id]
    );
    
    res.json({ id: result.insertId, message: 'News created successfully' });
  } catch (error) {
    console.error('Error creating news:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/notas/:id', authenticateToken, upload.single('imagen'), async (req, res) => {
  try {
    const { titulo, contenido, categoria } = req.body;
    const imagen = req.file ? `/uploads/${req.file.filename}` : undefined;
    
    let query = 'UPDATE notas SET Titulo = ?, Contenido = ?, categoria = ?';
    let params = [titulo, contenido, categoria];
    
    if (imagen) {
      query += ', imagen = ?';
      params.push(imagen);
    }
    
    query += ' WHERE ID = ? AND autorID = ?';
    params.push(req.params.id, req.user.id);
    
    const [result] = await pool.execute(query, params);
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'News article not found or unauthorized' });
    }
    
    res.json({ message: 'News updated successfully' });
  } catch (error) {
    console.error('Error updating news:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/notas/:id', authenticateToken, async (req, res) => {
  try {
    const [result] = await pool.execute(
      'DELETE FROM notas WHERE ID = ? AND autorID = ?',
      [req.params.id, req.user.id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'News article not found or unauthorized' });
    }
    
    res.json({ message: 'News deleted successfully' });
  } catch (error) {
    console.error('Error deleting news:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.patch('/api/notas/:id/visibility', authenticateToken, async (req, res) => {
  try {
    const { visible } = req.body;
    
    const [result] = await pool.execute(
      'UPDATE notas SET visible = ? WHERE ID = ? AND autorID = ?',
      [visible, req.params.id, req.user.id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'News article not found or unauthorized' });
    }
    
    res.json({ message: 'Visibility updated successfully' });
  } catch (error) {
    console.error('Error updating visibility:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Initialize database and start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`Admin Server running on port ${PORT}`);
    console.log(`Admin panel available at: http://localhost:${PORT}/admin`);
    console.log(`Default admin: admin@news.com / admin123`);
  });
}).catch(console.error);

module.exports = app;