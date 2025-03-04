import rateLimit from 'express-rate-limit';
import helmet from 'helmet';

// Rate limiting
export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP',
});

// Security headers
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