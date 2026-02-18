const { body, validationResult } = require('express-validator');
const xss = require('xss');

// Sanitize input
const sanitizeInput = (req, res, next) => {
    // Sanitize string inputs
    if (req.body) {
        Object.keys(req.body).forEach(key => {
            if (typeof req.body[key] === 'string') {
                req.body[key] = xss(req.body[key].trim());
            }
        });
    }
    next();
};

// Validation rules
const validateRegister = [
    body('username')
        .trim()
        .isLength({ min: 3, max: 50 }).withMessage('Username must be 3-50 characters')
        .matches(/^[a-zA-Z0-9_ ]+$/).withMessage('Username can only contain letters, numbers, spaces and underscores')
        .escape(),
    
    body('email')
        .trim()
        .isEmail().withMessage('Valid email required')
        .normalizeEmail()
        .isLength({ max: 100 }).withMessage('Email too long'),
    
    body('password')
        .isLength({ min: 6 }).withMessage('Password must be at least 6 characters')
        .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
        .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
        .matches(/[0-9]/).withMessage('Password must contain at least one number'),
    
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: errors.array()[0].msg // Only show first error
            });
        }
        next();
    }
];

const validateLogin = [
    body('email')
        .trim()
        .isEmail().withMessage('Valid email required')
        .normalizeEmail(),
    
    body('password')
        .notEmpty().withMessage('Password required'),
    
    (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ 
                success: false, 
                error: 'Invalid credentials' // Generic error for security
            });
        }
        next();
    }
];

module.exports = { 
    sanitizeInput, 
    validateRegister, 
    validateLogin 
};