// Check if user has required role
const checkRole = (roles) => {
    return (req, res, next) => {
        if (!req.user) {
            return res.status(401).json({ 
                success: false, 
                error: 'Unauthorized' 
            });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ 
                success: false, 
                error: 'Access denied. Insufficient permissions.' 
            });
        }

        next();
    };
};

module.exports = { checkRole };