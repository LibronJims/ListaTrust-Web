const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

// Middleware imports
const { loginLimiter, apiLimiter } = require('./middleware/rateLimiter');
const { sanitizeInput, validateRegister, validateLogin } = require('./middleware/validator');
const authMiddleware = require('./middleware/auth');

const app = express();

// ========== SECURITY MIDDLEWARE ==========
app.use(helmet()); // Security headers
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));
app.use(express.json({ limit: '10kb' })); // Limit payload size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(sanitizeInput); // XSS protection

// Static files
app.use(express.static(path.join(__dirname, '../frontend')));

// ========== DATABASE CONNECTION ==========
let db;
try {
    db = mysql.createPool({
        host: process.env.DB_HOST,
        user: process.env.DB_USER,
        password: process.env.DB_PASSWORD,
        database: process.env.DB_NAME,
        waitForConnections: true,
        connectionLimit: 10,
        queueLimit: 0,
        enableKeepAlive: true,
        keepAliveInitialDelay: 0
    });

    // Test connection
    db.getConnection((err, connection) => {
        if (err) {
            console.error('❌ DATABASE CONNECTION FAILED:');
            console.error(err.message);
            console.error('\n✅ FIX:');
            console.error('1. Start XAMPP MySQL');
            console.error('2. Create database "lista_trust"');
            console.error('3. Check credentials in .env');
        } else {
            console.log('✅ Database connected successfully');
            connection.release();
        }
    });
} catch (error) {
    console.error('❌ Database setup error:', error.message);
}

// Promise wrapper for db
const dbPromise = db ? db.promise() : null;

// ========== AUTH ROUTES ==========

// REGISTER (UPDATED - with username unique check)
app.post('/api/register', apiLimiter, validateRegister, async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        // Check database connection
        if (!dbPromise) {
            return res.status(500).json({ 
                success: false, 
                error: 'Service unavailable' 
            });
        }
        
        // Check if email exists
        const [emailCheck] = await dbPromise.query(
            'SELECT id FROM users WHERE email = ?',
            [email]
        );
        
        if (emailCheck.length > 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Email already registered' 
            });
        }
        
        // CHECK IF USERNAME EXISTS (NEW)
        const [usernameCheck] = await dbPromise.query(
            'SELECT id FROM users WHERE username = ?',
            [username]
        );
        
        if (usernameCheck.length > 0) {
            return res.status(400).json({ 
                success: false, 
                error: 'Username already taken. Please choose another.' 
            });
        }
        
        // Hash password
        const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 10);
        
        // Insert user
        const [result] = await dbPromise.query(
            'INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, NOW())',
            [username, email, hashedPassword]
        );
        
        console.log(`✅ New user registered: ${email} (${username})`);
        
        res.json({ 
            success: true, 
            message: 'Registration successful' 
        });
        
    } catch (error) {
        console.error('❌ Register error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Registration failed' 
        });
    }
});

// LOGIN
app.post('/api/login', loginLimiter, validateLogin, async (req, res) => {
    try {
        const { email, password } = req.body;
        
        // Check database connection
        if (!dbPromise) {
            return res.status(500).json({ 
                success: false, 
                error: 'Service unavailable' 
            });
        }
        
        // Get user
        const [users] = await dbPromise.query(
            'SELECT id, username, email, password FROM users WHERE email = ?',
            [email]
        );
        
        if (users.length === 0) {
            // Generic error for security
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid email or password' 
            });
        }
        
        const user = users[0];
        
        // Compare password
        const valid = await bcrypt.compare(password, user.password);
        if (!valid) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid email or password' 
            });
        }
        
        // Create token
        const token = jwt.sign(
            { 
                id: user.id, 
                email: user.email, 
                username: user.username 
            },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRE || '1h' }
        );
        
        console.log(`✅ User logged in: ${email}`);
        
        res.json({ 
            success: true, 
            token,
            user: { 
                id: user.id, 
                username: user.username, 
                email: user.email 
            }
        });
        
    } catch (error) {
        console.error('❌ Login error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Login failed' 
        });
    }
});

// VERIFY TOKEN
app.get('/api/verify', authMiddleware, (req, res) => {
    res.json({ 
        success: true, 
        user: req.user 
    });
});

// LOGOUT
app.post('/api/logout', authMiddleware, (req, res) => {
    // JWT is stateless - client removes token
    res.json({ 
        success: true, 
        message: 'Logged out successfully' 
    });
});

// ========== PROTECTED ROUTES ==========

// DASHBOARD DATA
app.get('/api/dashboard-data', authMiddleware, apiLimiter, async (req, res) => {
    try {
        // In production, this would come from database
        // For now, return sample data
        res.json({
            success: true,
            customers: [
                { 
                    id: 1,
                    name: "Anne Laureen Fernandez", 
                    phone: "0978 345 3456", 
                    status: "pending", 
                    debt: 550,
                    lastPayment: "2024-02-15"
                },
                { 
                    id: 2,
                    name: "Justin Rafael Resquif", 
                    phone: "0945 678 3456", 
                    status: "success", 
                    debt: 200,
                    lastPayment: "2024-02-16"
                },
                { 
                    id: 3,
                    name: "Annabelle De Guzman", 
                    phone: "0924 706 3456", 
                    status: "danger", 
                    debt: 1500,
                    lastPayment: "2024-02-01"
                }
            ]
        });
        
    } catch (error) {
        console.error('❌ Dashboard error:', error.message);
        res.status(500).json({ 
            success: false, 
            error: 'Failed to load dashboard data' 
        });
    }
});

// ========== FRONTEND ROUTES ==========

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/login.html'));
});

app.get('/signup', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/signup.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '../frontend/dashboard.html'));
});

// ========== ERROR HANDLING ==========

// 404 handler
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, '../frontend/404.html'));
});

// Global error handler
app.use((err, req, res, next) => {
    console.error('❌ Unhandled error:', err.message);
    res.status(500).json({ 
        success: false, 
        error: 'Internal server error' 
    });
});

// ========== START SERVER ==========
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log('\n✅ ==================================');
    console.log(`✅ ListaTrust Server Running`);
    console.log(`✅ Port: ${PORT}`);
    console.log(`✅ URL: http://localhost:${PORT}`);
    console.log('✅ ==================================\n');
});