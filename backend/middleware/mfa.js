const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const generateMFASecret = (username) => {
    return speakeasy.generateSecret({ name: `ListaTrust (${username})` });
};
const generateQRCode = async (otpauthUrl) => {
    return await QRCode.toDataURL(otpauthUrl);
};
const verifyMFAToken = (secret, token) => {
    return speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
};

module.exports = { generateMFASecret, generateQRCode, verifyMFAToken };