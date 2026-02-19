const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mysql = require('mysql2');
const cors = require('cors');
const helmet = require('helmet');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const { generateMFASecret, generateQRCode, verifyMFAToken } = require('./middleware/mfa');
const csrf = require('csurf');
const cookieParser = require('cookie-parser');
const mongoSanitize = require('mongo-sanitize');
const { checkRole } = require('./middleware/rbac');
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

// NoSQL injection protection
app.use((req, res, next) => {
    if (req.body) {
        req.body = mongoSanitize(req.body);
    }
    if (req.query) {
        req.query = mongoSanitize(req.query);
    }
    if (req.params) {
        req.params = mongoSanitize(req.params);
    }
    next();
});


app.use(session({
    secret: process.env.SESSION_SECRET || 'listatrust_session_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(cookieParser());
app.use(csrf({ cookie: true }));
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});
app.get('/api/csrf-token', (req, res) => {
    res.json({ csrfToken: req.csrfToken() });
});

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

// ========== GOOGLE OAUTH STRATEGY ========== 
// ADD THIS RIGHT HERE ↓
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback'
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const [users] = await dbPromise.query(
            'SELECT * FROM users WHERE email = ?',
            [profile.emails[0].value]
        );
        if (users.length > 0) return done(null, users[0]);
        const [result] = await dbPromise.query(
            'INSERT INTO users (username, email, password, created_at) VALUES (?, ?, ?, NOW())',
            [profile.displayName, profile.emails[0].value, 'GOOGLE_AUTH']
        );
        const [newUser] = await dbPromise.query(
            'SELECT * FROM users WHERE id = ?', [result.insertId]
        );
        return done(null, newUser[0]);
    } catch (error) {
        return done(error, null);
    }
}));
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
    const [users] = await dbPromise.query('SELECT * FROM users WHERE id = ?', [id]);
    done(null, users[0]);
});

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
            'SELECT id, username, email, password, role FROM users WHERE email = ?',
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
                username: user.username,
                role: user.role
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

app.post('/api/logout', authMiddleware, async (req, res) => {
    try {
        if (dbPromise) {
            await dbPromise.query(
                'DELETE FROM sessions WHERE user_id = ?',
                [req.user.id]
            );
        }
        res.json({ success: true, message: 'Logged out successfully' });
    } catch (error) {
        console.error('❌ Logout error:', error.message);
        res.status(500).json({ success: false, error: 'Logout failed' });
    }
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

app.post('/api/mfa/setup', authMiddleware, async (req, res) => {
    try {
        const secret = generateMFASecret(req.user.username);
        const qrCode = await generateQRCode(secret.otpauth_url);
        await dbPromise.query('UPDATE users SET mfa_secret = ? WHERE id = ?', [secret.base32, req.user.id]);
        res.json({ success: true, qrCode, secret: secret.base32 });
    } catch (error) {
        res.status(500).json({ success: false, error: 'MFA setup failed' });
    }
});

app.post('/api/mfa/enable', authMiddleware, async (req, res) => {
    try {
        const { token } = req.body;
        const [users] = await dbPromise.query('SELECT mfa_secret FROM users WHERE id = ?', [req.user.id]);
        const isValid = verifyMFAToken(users[0].mfa_secret, token);
        if (isValid) {
            await dbPromise.query('UPDATE users SET mfa_enabled = TRUE WHERE id = ?', [req.user.id]);
            res.json({ success: true, message: 'MFA enabled successfully!' });
        } else {
            res.json({ success: false, error: 'Invalid token. Try again.' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: 'MFA enable failed' });
    }
});

app.post('/api/mfa/verify', authMiddleware, async (req, res) => {
    try {
        const { token } = req.body;
        const [users] = await dbPromise.query('SELECT mfa_secret, mfa_enabled FROM users WHERE id = ?', [req.user.id]);
        if (!users[0].mfa_enabled) return res.json({ success: false, error: 'MFA not enabled' });
        const isValid = verifyMFAToken(users[0].mfa_secret, token);
        res.json({ success: isValid, error: isValid ? null : 'Invalid MFA token' });
    } catch (error) {
        res.status(500).json({ success: false, error: 'MFA verification failed' });
    }
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/' }),
    (req, res) => {
        const token = jwt.sign(
            { id: req.user.id, email: req.user.email, username: req.user.username, role: req.user.role },
            process.env.JWT_SECRET,
            { expiresIn: process.env.JWT_EXPIRE || '1h' }
        );
        res.redirect(`/dashboard?token=${token}`);
    }
);

// ========== ADMIN ROUTES ==========
app.get('/api/admin/users', authMiddleware, checkRole(['admin']), async (req, res) => {
    try {
        const [users] = await dbPromise.query(
            'SELECT id, username, email, role, created_at FROM users'
        );
        res.json({ success: true, users });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Failed to fetch users' });
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