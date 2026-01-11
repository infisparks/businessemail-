import express from "express";
import nodemailer from "nodemailer";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";

const app = express();

/* ===============================
   SECURITY MIDDLEWARE
================================ */
app.use(helmet());

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { success: false, error: "Too many requests, try later." }
});
app.use("/api/", limiter);

app.use(cors({
  origin: "*", // 🔴 Change to your domain in production
  methods: ["POST"],
  allowedHeaders: ["Content-Type"]
}));

app.use(express.json({ limit: "10kb" }));

/* ===============================
   GOOGLE WORKSPACE SMTP CONFIG
================================ */
const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,              // ✅ Gmail STARTTLS
  secure: false,          // ❗ MUST be false for port 587
  auth: {
    user: "info@investariseglobal.com",
    pass: "btbvmksqohgrkeii" // ✅ Google App Password (NO SPACES)
  },
  pool: true,
  maxConnections: 5,
  maxMessages: 100
});

// Verify SMTP connection
transporter.verify((error) => {
  if (error) {
    console.error("SMTP Connection Failed ❌", error);
  } else {
    console.log("Google SMTP is ready ✅");
  }
});

/* ===============================
   VALIDATION
================================ */
const validateEmailRequest = (data) => {
  const { to, subject, htmlContent } = data;

  if (!to || !/^\S+@\S+\.\S+$/.test(to)) {
    return "Valid recipient email required.";
  }
  if (!subject || subject.trim().length < 3) {
    return "Subject too short.";
  }
  if (!htmlContent || htmlContent.trim().length < 10) {
    return "Email content too short.";
  }
  return null;
};

/* ===============================
   SEND EMAIL API
================================ */
app.post("/api/send-email", async (req, res) => {
  const error = validateEmailRequest(req.body);
  if (error) {
    return res.status(400).json({ success: false, error });
  }

  const { to, subject, htmlContent } = req.body;

  try {
    const info = await transporter.sendMail({
      from: `"InvestArise Global" <info@investariseglobal.com>`,
      to,
      subject,
      html: htmlContent
    });

    console.log(`Email sent → ${to} | ID: ${info.messageId}`);

    return res.status(200).json({
      success: true,
      message: "Email sent successfully"
    });

  } catch (err) {
    console.error("Mail Error ❌", err);
    return res.status(500).json({
      success: false,
      error: "Failed to send email"
    });
  }
});

/* ===============================
   SERVER START
================================ */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Mail API running on port ${PORT}`);
});
