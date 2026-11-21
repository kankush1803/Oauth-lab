/**
 * routes/auth.routes.js
 *
 * Authentication routes for Google OAuth 2.0.
 *
 * Routes:
 *   GET  /auth/google                 - Starts the Google OAuth flow.
 *   GET  /auth/google/callback        - Google OAuth callback (Passport authenticates).
 *   POST /auth/logout                 - Destroys the session and logs the user out.
 *   GET  /login                       - Login page (for unauthenticated users).
 *   GET  /dashboard                   - Protected dashboard (authenticated users only).
 */

const express = require("express");
const path = require("path");
const passport = require("../config/passport");
const { ensureAuthenticated } = require("../middleware/auth.middleware");

const router = express.Router();

/**
 * GET /auth/google
 *
 * Redirects the user to Google's consent screen to begin the OAuth flow.
 * If authentication fails, the user is redirected to /login.
 */
router.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

/**
 * GET /auth/google/callback
 *
 * Google redirects the user here after they grant (or deny) permission.
 * Passport verifies the authorization code and retrieves the user profile.
 *
 * On success: user is logged into the session and redirected to /dashboard.
 * On failure:  user is redirected to /login.
 */
router.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

/**
 * POST /auth/logout
 *
 * Destroys the user's session, clears the session cookie,
 * and redirects to the homepage.
 */
router.post("/auth/logout", function (req, res, next) {
  // req.logout is provided by Passport to clear the authenticated user.
  req.logout(function (err) {
    if (err) {
      return next(err);
    }

    // Destroy the entire session and clear the session cookie.
    req.session.destroy(function (destroyErr) {
      if (destroyErr) {
        return next(destroyErr);
      }

      res.clearCookie("connect.sid");
      return res.redirect("/");
    });
  });
});

/**
 * GET /login
 *
 * Displays the login page for users who are not authenticated.
 * Authenticated users are redirected to the dashboard.
 */
router.get("/login", function (req, res) {
  if (req.isAuthenticated()) {
    return res.redirect("/dashboard");
  }

  res.sendFile(path.resolve(__dirname, "../views/login.html"));
});

/**
 * GET /dashboard
 *
 * Protected route. Only authenticated users can view their profile.
 * Unauthenticated users are redirected to /login by the middleware.
 */
router.get("/dashboard", ensureAuthenticated, function (req, res) {
  res.sendFile(path.resolve(__dirname, "../views/dashboard.html"));
});

module.exports = router;
