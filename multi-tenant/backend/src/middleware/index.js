import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";

export const securityMiddleware = [
  helmet(),
  cors({
    origin: process.env.FRONTEND_URL || "http://localhost:3000",
    credentials: true,
  }),
];

export const sensorRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 100000,  // Increased from 1000 to 100000 to handle sensor packet volume
  message: { error: "Too many sensor requests" },
  skipSuccessfulRequests: true,
});

export const errorHandler = (err, req, res, next) => {
  console.error(err.stack);
  res.status(err.status || 500).json({ error: err.message || "Internal server error" });
};
