const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.ADMIN_PORT || 4000;

// Middleware
app.use(express.json({ limit: '10mb' })); // Increased limit for image uploads
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
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

// JWT middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Unauthorized - No token provided' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'cisco123', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Forbidden - Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Initialize database tables
async function initDatabase() {
  try {
    console.log('Initializing database...');
    
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

    await pool.execute(`
      CREATE TABLE IF NOT EXISTS notas (
        ID INT AUTO_INCREMENT PRIMARY KEY,
        Titulo VARCHAR(255) NOT NULL,
        Contenido TEXT NOT NULL,
        categoria ENUM('politica', 'deportes', 'tecnologia', 'economia', 'salud', 'entretenimiento') NOT NULL,
        visible BOOLEAN DEFAULT TRUE,
        autorID INT,
        FechaCreacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        fechaActualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (autorID) REFERENCES usuarios(ID)
      )
    `);

    await pool.execute(`
      CREATE TABLE IF NOT EXISTS nota_imagenes (
        ID INT AUTO_INCREMENT PRIMARY KEY,
        notaID INT NOT NULL,
        imagen LONGBLOB NOT NULL,
        mime_type VARCHAR(50) NOT NULL,
        orden INT DEFAULT 0,
        FOREIGN KEY (notaID) REFERENCES notas(ID) ON DELETE CASCADE
      )
    `);

    const [existingAdmin] = await pool.execute('SELECT * FROM usuarios WHERE email = ?', ['admin@news.com']);
    if (existingAdmin.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await pool.execute(
        'INSERT INTO usuarios (nombre, email, password, rol) VALUES (?, ?, ?, ?)',
        ['Administrator', 'admin@news.com', hashedPassword, 'admin']
      );
      console.log('Default admin user created');
    }

    console.log('Database initialized successfully');
  } catch (error) {
    console.error('Error initializing database:', error);
    process.exit(1);
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
      process.env.JWT_SECRET || 'cisco123',
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

// News routes
app.get('/api/notas', authenticateToken, async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT 
        n.*,
        ni.imagen as primera_imagen,
        ni.mime_type as imagen_mime_type,
        CASE WHEN ni.imagen IS NOT NULL THEN 1 ELSE 0 END as hasImages
      FROM notas n 
      LEFT JOIN (
        SELECT DISTINCT 
          notaID, 
          FIRST_VALUE(imagen) OVER (PARTITION BY notaID ORDER BY orden, ID) as imagen,
          FIRST_VALUE(mime_type) OVER (PARTITION BY notaID ORDER BY orden, ID) as mime_type
        FROM nota_imagenes
      ) ni ON n.ID = ni.notaID
      WHERE n.autorID = ? 
      GROUP BY n.ID, ni.imagen, ni.mime_type
      ORDER BY n.FechaCreacion DESC
    `, [req.user.id]);
    
    // Convert the result to include image information
    const notes = rows.map(row => {
      const note = { ...row };
      
      // Add image data if available
      if (note.primera_imagen) {
        note.imagen = `data:${note.imagen_mime_type};base64,${note.primera_imagen.toString('base64')}`;
      }
      
      // Clean up the response
      delete note.primera_imagen;
      delete note.imagen_mime_type;
      
      return note;
    });
    
    res.json(notes);
  } catch (error) {
    console.error('Error fetching news:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/notas', authenticateToken, async (req, res) => {
  try {
    const { titulo, contenido, categoria, imagenes } = req.body;
    
    if (!titulo || !contenido || !categoria) {
      return res.status(400).json({ error: 'Title, content, and category are required' });
    }

    // Start transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // First create the note
      const [result] = await connection.execute(
        'INSERT INTO notas (Titulo, Contenido, categoria, autorID) VALUES (?, ?, ?, ?)',
        [titulo, contenido, categoria, req.user.id]
      );
      
      // Then handle images if any
      if (imagenes && imagenes.length > 0) {
        for (const img of imagenes.slice(0, 5)) { // Limit to 5 images
          await connection.execute(
            'INSERT INTO nota_imagenes (notaID, imagen, mime_type, orden) VALUES (?, ?, ?, ?)',
            [result.insertId, Buffer.from(img.data, 'base64'), img.mimeType, img.orden || 0]
          );
        }
      }
      
      // Commit transaction
      await connection.commit();
      
      // Get the full created note with images
      const [newNote] = await pool.execute(
        'SELECT * FROM notas WHERE ID = ?',
        [result.insertId]
      );
      
      res.status(201).json({ 
        id: result.insertId,
        message: 'News created successfully',
        nota: newNote[0]
      });
    } catch (error) {
      // Rollback transaction on error
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error creating news:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.put('/api/notas/:id', authenticateToken, async (req, res) => {
  try {
    const { titulo, contenido, categoria, imagenes } = req.body;
    
    if (!titulo || !contenido || !categoria) {
      return res.status(400).json({ error: 'Title, content, and category are required' });
    }

    // Start transaction
    const connection = await pool.getConnection();
    await connection.beginTransaction();

    try {
      // First update the note
      const [result] = await connection.execute(
        'UPDATE notas SET Titulo = ?, Contenido = ?, categoria = ? WHERE ID = ? AND autorID = ?',
        [titulo, contenido, categoria, req.params.id, req.user.id]
      );
      
      if (result.affectedRows === 0) {
        await connection.rollback();
        return res.status(404).json({ error: 'News article not found or unauthorized' });
      }
      
      // Handle images if any
      if (imagenes && imagenes.length > 0) {
        // First delete existing images for this note
        await connection.execute(
          'DELETE FROM nota_imagenes WHERE notaID = ?',
          [req.params.id]
        );
        
        // Then add new images
        for (const img of imagenes.slice(0, 5)) {
          await connection.execute(
            'INSERT INTO nota_imagenes (notaID, imagen, mime_type, orden) VALUES (?, ?, ?, ?)',
            [req.params.id, Buffer.from(img.data, 'base64'), img.mimeType, img.orden || 0]
          );
        }
      }
      
      // Commit transaction
      await connection.commit();
      
      res.json({ 
        message: 'News updated successfully',
        nota: {
          ID: req.params.id,
          Titulo: titulo,
          Contenido: contenido,
          categoria: categoria
        }
      });
    } catch (error) {
      // Rollback transaction on error
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  } catch (error) {
    console.error('Error updating news:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.delete('/api/notas/:id', authenticateToken, async (req, res) => {
  try {
    // MySQL foreign key with ON DELETE CASCADE will handle image deletion automatically
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
    
    if (typeof visible !== 'boolean') {
      return res.status(400).json({ error: 'Visibility must be a boolean value' });
    }

    const [result] = await pool.execute(
      'UPDATE notas SET visible = ? WHERE ID = ? AND autorID = ?',
      [visible, req.params.id, req.user.id]
    );
    
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'News article not found or unauthorized' });
    }
    
    res.json({ 
      message: 'Visibility updated successfully',
      visible: visible
    });
  } catch (error) {
    console.error('Error updating visibility:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get images for a note
app.get('/api/notas/:id/imagenes', authenticateToken, async (req, res) => {
  try {
    // First verify the user owns this note or has permission to view it
    const [noteCheck] = await pool.execute(
      'SELECT autorID FROM notas WHERE ID = ?',
      [req.params.id]
    );
    
    if (noteCheck.length === 0 || noteCheck[0].autorID !== req.user.id) {
      return res.status(404).json({ error: 'Note not found or unauthorized' });
    }
    
    const [rows] = await pool.execute(
      'SELECT imagen, mime_type FROM nota_imagenes WHERE notaID = ? ORDER BY orden, ID',
      [req.params.id]
    );
    
    res.json(rows.map(row => ({
      data: row.imagen.toString('base64'),
      mimeType: row.mime_type
    })));
  } catch (error) {
    console.error('Error fetching images:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Internal server error' });
});

// Initialize database and start server
initDatabase().then(() => {
  app.listen(PORT, () => {
    console.log(`\nAdmin Server running on port ${PORT}`);
    console.log(`Admin panel available at: http://localhost:${PORT}`);
    console.log(`Default admin credentials: admin@news.com / admin123\n`);
  });
}).catch(err => {
  console.error('Failed to initialize server:', err);
  process.exit(1);
});

module.exports = app;