import express from "express";
import nodemailer from "nodemailer";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const app = express();

// 1. Security Headers (Protects against common web attacks)
app.use(helmet());

// 2. Rate Limiting (Prevents bots from spamming your API)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // Limit each IP to 50 requests per window
  message: { success: false, error: "Too many requests, please try again later." }
});
app.use("/api/", limiter);

app.use(cors({
  origin: "*", // In production, replace "*" with your actual domain (e.g., "https://yourdomain.com")
  methods: ["POST"],
  allowedHeaders: ["Content-Type"]
}));

app.use(express.json({ limit: "10kb" })); // Limit payload size to prevent DDoS

/**
 * SMTP CONFIGURATION
 * WARNING: Hardcoding here is high-risk. 
 * If you must do this, ensure this file is NEVER shared or committed to Git.
 */
const transporter = nodemailer.createTransport({
  host: "smtp.hostinger.com",
  port: 465, // Changed to 465 (SMTPS) for better production security
  secure: true, 
  auth: {
    user: "info@investariseglobal.com",
    pass: "<InfO@#21" 
  },
  pool: true, // Uses pooled connections for better performance/scaling
  maxConnections: 5,
  maxMessages: 100
});

// Verify connection on startup
transporter.verify((error) => {
  if (error) console.error("SMTP Connection Failed ❌", error);
  else console.log("SMTP Server is ready ✅");
});

/**
 * VALIDATION
 */
const validateEmailRequest = (data) => {
  const { to, subject, htmlContent } = data;
  if (!to || !/^\S+@\S+\.\S+$/.test(to)) return "Valid recipient email required.";
  if (!subject || subject.trim().length < 3) return "Subject too short.";
  if (!htmlContent || htmlContent.trim().length < 10) return "Content too short.";
  return null;
};

/**
 * SEND-EMAIL ENDPOINT
 */
app.post("/api/send-email", async (req, res) => {
  const validationError = validateEmailRequest(req.body);
  if (validationError) {
    return res.status(400).json({ success: false, error: validationError });
  }

  const { to, subject, htmlContent } = req.body;

  try {
    const info = await transporter.sendMail({
      from: `"Investarise" <info@investariseglobal.com>`, 
      to,
      subject,
      html: htmlContent 
    });

    console.log(`Email sent to ${to}: ${info.messageId}`);
    return res.status(200).json({ success: true, message: "Email sent successfully" });

  } catch (error) {
    console.error("Mail Error ❌", error.message);
    return res.status(500).json({
      success: false,
      error: "Failed to send email. Please try again later."
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Production Mail API running on port ${PORT}`);
});