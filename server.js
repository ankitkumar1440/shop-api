// server.js - Complete backend with Supabase
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT;

const corsOptions = {
    origin: [
        'https://13.228.225.19',
        'https://54.254.162.138',
        ],
    credentials: true,
};

app.use(cors(corsOptions));
app.use(express.json());

// Supabase configuration
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

// Environment variables
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;
const JWT_SECRET = process.env.JWT_SECRET;

// Add this after your API routes and before the 404 handler

// Serve static files (your frontend)
app.use(express.static(path.join(__dirname, 'public')));

// Serve the login page
app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Catch all other routes and serve index.html (for SPA)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use('/uploads', express.static('uploads'));

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit
    fileFilter: (req, file, cb) => {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// Initialize database tables
async function initializeDatabase() {
    try {
        console.log('🔄 Initializing database tables...');
        
        // Check if admin user exists
        const { data: existingAdmin } = await supabase
            .from('users')
            .select('*')
            .eq('username', ADMIN_USERNAME)
            .single();

        if (!existingAdmin) {
            console.log('Creating admin user...');
            const hashedPassword = await bcrypt.hash(ADMIN_PASSWORD, 10);
            
            const { error } = await supabase
                .from('users')
                .insert([
                    {
                        username: ADMIN_USERNAME,
                        password: hashedPassword,
                        role: 'admin'
                    }
                ]);
            
            if (error) {
                console.error('Error creating admin:', error);
            } else {
                console.log(`✅ Admin user created: ${ADMIN_USERNAME}`);
            }
        } else {
            console.log('✅ Admin user already exists');
        }
        
    } catch (error) {
        console.error('Database initialization error:', error);
    }
}

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Routes

// Health check
app.get('/', (req, res) => {
    res.json({ 
        message: 'Server is running successfully!',
        timestamp: new Date().toISOString(),
        database: 'Supabase'
    });
});

app.get('/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        database: 'Supabase Connected'
    });
});

// Authentication Routes
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }

        // Get user from Supabase
        const { data: user, error } = await supabase
            .from('users')
            .select('*')
            .eq('username', username)
            .single();

        if (error || !user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { userId: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.json({
            message: 'Login successful',
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.get('/api/auth/verify', authenticateToken, (req, res) => {
    res.json({
        valid: true,
        user: {
            id: req.user.userId,
            username: req.user.username,
            role: req.user.role
        }
    });
});

// Product Routes

// Get all products (public)
app.get('/api/products', async (req, res) => {
    try {
        const { data: products, error } = await supabase
            .from('products')
            .select('*')
            .order('created_at', { ascending: false });

        if (error) {
            throw error;
        }

        res.json(products || []);
    } catch (error) {
        console.error('Get products error:', error);
        res.status(500).json({ message: 'Failed to fetch products' });
    }
});

// Get single product (public)
app.get('/api/products/:id', async (req, res) => {
    try {
        const { data: product, error } = await supabase
            .from('products')
            .select('*')
            .eq('id', req.params.id)
            .single();

        if (error || !product) {
            return res.status(404).json({ message: 'Product not found' });
        }

        res.json(product);
    } catch (error) {
        console.error('Get product error:', error);
        res.status(500).json({ message: 'Failed to fetch product' });
    }
});

// Add new product (admin only)
app.post('/api/products', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { name, price } = req.body;

        if (!name || !price) {
            return res.status(400).json({ message: 'Name and price are required' });
        }

        const productData = {
            name,
            price: parseFloat(price),
            available: true
        };

        if (req.file) {
            productData.image = `/uploads/${req.file.filename}`;
        }

        const { data: product, error } = await supabase
            .from('products')
            .insert([productData])
            .select()
            .single();

        if (error) {
            throw error;
        }

        res.status(201).json({
            message: 'Product added successfully',
            product
        });
    } catch (error) {
        console.error('Add product error:', error);
        res.status(500).json({ message: 'Failed to add product' });
    }
});

// Update product (admin only)
app.put('/api/products/:id', authenticateToken, upload.single('image'), async (req, res) => {
    try {
        const { name, price, available } = req.body;
        const updateData = {};

        if (name) updateData.name = name;
        if (price) updateData.price = parseFloat(price);
        if (available !== undefined) updateData.available = available === 'true';

        if (req.file) {
            updateData.image = `/uploads/${req.file.filename}`;
        }

        const { data: product, error } = await supabase
            .from('products')
            .update(updateData)
            .eq('id', req.params.id)
            .select()
            .single();

        if (error || !product) {
            return res.status(404).json({ message: 'Product not found' });
        }

        res.json({
            message: 'Product updated successfully',
            product
        });
    } catch (error) {
        console.error('Update product error:', error);
        res.status(500).json({ message: 'Failed to update product' });
    }
});

// Toggle product availability (admin only)
app.patch('/api/products/:id/toggle', authenticateToken, async (req, res) => {
    try {
        // First get the current product
        const { data: currentProduct, error: fetchError } = await supabase
            .from('products')
            .select('available')
            .eq('id', req.params.id)
            .single();

        if (fetchError || !currentProduct) {
            return res.status(404).json({ message: 'Product not found' });
        }

        // Toggle availability
        const { data: product, error: updateError } = await supabase
            .from('products')
            .update({ available: !currentProduct.available })
            .eq('id', req.params.id)
            .select()
            .single();

        if (updateError) {
            throw updateError;
        }

        res.json({
            message: 'Product status updated successfully',
            product
        });
    } catch (error) {
        console.error('Toggle product error:', error);
        res.status(500).json({ message: 'Failed to update product status' });
    }
});

// Delete product (admin only)
app.delete('/api/products/:id', authenticateToken, async (req, res) => {
    try {
        // First get the product to delete associated image
        const { data: product } = await supabase
            .from('products')
            .select('image')
            .eq('id', req.params.id)
            .single();

        // Delete from database
        const { error } = await supabase
            .from('products')
            .delete()
            .eq('id', req.params.id);

        if (error) {
            throw error;
        }

        // Delete associated image file if it exists
        if (product && product.image) {
            const imagePath = path.join(__dirname, product.image);
            if (fs.existsSync(imagePath)) {
                fs.unlinkSync(imagePath);
            }
        }

        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        console.error('Delete product error:', error);
        res.status(500).json({ message: 'Failed to delete product' });
    }
});

// Search products (public)
app.get('/api/products/search/:query', async (req, res) => {
    try {
        const query = req.params.query;
        
        const { data: products, error } = await supabase
            .from('products')
            .select('*')
            .ilike('name', `%${query}%`)
            .order('created_at', { ascending: false });

        if (error) {
            throw error;
        }

        res.json(products || []);
    } catch (error) {
        console.error('Search products error:', error);
        res.status(500).json({ message: 'Failed to search products' });
    }
});

// Error handling middleware
app.use((error, req, res, next) => {
    if (error instanceof multer.MulterError) {
        if (error.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ message: 'File too large. Maximum size is 5MB.' });
        }
    }
    
    if (error.message === 'Only image files are allowed!') {
        return res.status(400).json({ message: 'Only image files are allowed!' });
    }

    console.error('Unhandled error:', error);
    res.status(500).json({ message: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
    res.status(404).json({ message: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`📊 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`🗄️ Database: Supabase`);
    
    // Initialize database after server starts
    setTimeout(initializeDatabase, 1000);
});


module.exports = app;



