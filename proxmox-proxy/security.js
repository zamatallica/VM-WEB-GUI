import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import axios from 'axios';

// Function to retrieve public IP address in Node.js
async function getCurrentPublicIP() {
    try {
        const response = await axios.get('https://api64.ipify.org?format=json', { timeout: 5000 });
        return response.data.ip;
    } catch (error) {
        console.error("Failed to retrieve public IP:", error.message);
        return null;
    }
}

// Async function to initialize trusted IPs
async function initializeRateLimiter() {
    const serverIP = await getCurrentPublicIP();

    // Define trusted IPs (internal services, backend, localhost)
    const TRUSTED_IPS = new Set(["127.0.0.1", "localhost", "192.168.1.17"]);
    if (serverIP) TRUSTED_IPS.add(serverIP); // Only add server IP if it's valid

    console.log(`Trusted IPs: ${Array.from(TRUSTED_IPS).join(', ')}`);

    // Custom rate limiting function to allow trusted IPs
    return rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // Limit each IP to 100 requests per windowMs
        keyGenerator: (req) => req.ip, // Identify users by IP
        skip: (req) => TRUSTED_IPS.has(req.ip), // 🚀 Exempt trusted IPs!
        message: (req, res) => `Too many requests from this IP: ${req.ip}`
    });
}

// Security headers (unchanged)
export const securityHeaders = helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            connectSrc: [
                "'self'", 
                process.env.FRONTEND_URL,
                `wss://${process.env.FRONTEND_DOMAIN}`
            ],
            scriptSrc: ["'self'", "'unsafe-eval'"],  // Tighten for production
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"]
        }
    },
    crossOriginResourcePolicy: { policy: "same-site" },
    crossOriginEmbedderPolicy: true
});

// Export a function instead of a constant
export default initializeRateLimiter;
