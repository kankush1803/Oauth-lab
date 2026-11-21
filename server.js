/**
 * server.js
 *
 * Express application entry point for the Google OAuth 2.0 Authentication System.
 *
 * Responsibilities:
 * 1. Load environment variables from .env.
 * 2. Initialize Express and configure built-in body parsers.
 * 3. Configure express-session securely (cookie settings for dev/production).
 * 4. Initialize Passport and restore login state from the session.
 * 5. Register authentication routes.
 * 6. Serve static frontend assets (HTML, CSS).
 * 7. Add a 404 handler for unknown routes.
 * 8. Add a centralized error handler that never exposes secrets.
 * 9. Start the HTTP server.
 *
 * Session storage:
 *   - Development: default in-memory MemoryStore (fine for local dev).
 *   - Production: the code path warns and requires a production store
 *     (e.g. connect-redis) instead of MemoryStore.
 */

// 1. Load environment variables (PORT, GOOGLE_CLIENT_ID, etc.).
require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("path");
const passport = require("./config/passport");
const authRoutes = require("./routes/auth.routes");

// Fail fast if required environment variables are missing.
// This protects against starting with missing Google OAuth credentials.
const requiredEnv = ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "SESSION_SECRET"];
const missing = requiredEnv.filter((key) => !process.env[key]);
if (missing.length > 0) {
  throw new Error(
    `Missing required environment variables: ${missing.join(", ")}. Copy .env.example to .env and fill in your values.`
  );
}

const app = express();
const PORT = process.env.PORT || 3003;
const isProduction = process.env.NODE_ENV === "production";

// 2. Configure built-in body parsers.
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// 3. Configure express-session securely.
//
//   secret:         used to sign the session ID cookie (from env).
//   resave:         don't save session if unmodified.
//   saveUninitialized: don't save empty sessions (avoids issuing cookies for bots).
//   cookie:
//     - httpOnly:   prevents client-side JS from reading the session cookie.
//     - secure:     true only over HTTPS (production).
//     - sameSite:   lax in dev, none in production (behind HTTPS).
//     - maxAge:     24 hours.
//
// MemoryStore is the default and is acceptable for local development,
// but it must NOT be used in production (it does not scale across instances
// and is lost on restart). In production, swap for connect-redis or similar.
const sessionConfig = {
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: "connect.sid",
  cookie: {
    httpOnly: true,
    secure: isProduction, // true only over HTTPS
    sameSite: isProduction ? "lax" : "lax",
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
};

if (isProduction) {
  if (!process.env.SESSION_STORE) {
    console.warn(
      "WARNING: Running in production without a production session store. " +
        "MemoryStore is not suitable for production. " +
        "Set SESSION_STORE (e.g. connect-redis) and configure a store."
    );
  }
  sessionConfig.cookie.secure = true;
  sessionConfig.cookie.sameSite = "lax";
}

app.use(session(sessionConfig));

// 4. Initialize Passport and restore login state from the session.
app.use(passport.initialize());
app.use(passport.session());

// 5. Register authentication routes.
app.use(authRoutes);

// 6. Serve static frontend assets (HTML, CSS) from public/ and views/.
//    Views are served directly by the route handlers; static files (CSS)
//    are served from public/.
app.use(express.static("public"));
app.use("/style.css", express.static("public/style.css"));

// Serve the views directory so HTML files can be referenced if needed.
// (Routes use sendFile for the HTML pages.)
app.use("/views", express.static("views"));

// Root route: homepage.
app.get("/", function (req, res) {
  res.sendFile(path.resolve(__dirname, "views/index.html"));
});

// 7. 404 handler for unknown routes.
app.use(function (req, res) {
  res.status(404).send(`
    <html>
      <head><title>404 - Not Found</title></head>
      <body style="font-family:sans-serif;text-align:center;padding:4rem;">
        <h1>404 - Page Not Found</h1>
        <p>The requested route does not exist.</p>
        <a href="/" style="color:#1a73e8;text-decoration:none;">&larr; Return to homepage</a>
      </body>
    </html>
  `);
});

// 8. Centralized error handler.
//    Never expose stack traces, credentials, or internal details to the client.
app.use(function (err, req, res, next) {
  console.error("Server error:", err);

  const message =
    process.env.NODE_ENV === "production"
      ? "An unexpected error occurred."
      : err.message || "An unexpected error occurred.";

  res.status(500).send(`
    <html>
      <head><title>500 - Server Error</title></head>
      <body style="font-family:sans-serif;text-align:center;padding:4rem;">
        <h1>500 - Server Error</h1>
        <p>${message}</p>
        <a href="/" style="color:#1a73e8;text-decoration:none;">&larr; Return to homepage</a>
      </body>
    </html>
  `);
});

// 9. Start the server.
app.listen(PORT, function () {
  console.log(`Server running in ${process.env.NODE_ENV || "development"} mode`);
  console.log(`Listening on http://localhost:${PORT}`);
  console.log(`Google OAuth callback: ${process.env.GOOGLE_CALLBACK_URL || "http://localhost:3003/auth/google/callback"}`);
});

module.exports = app;
