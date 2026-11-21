/**
 * middleware/auth.middleware.js
 *
 * Authentication middleware for protecting routes.
 *
 * ensureAuthenticated checks whether the current request has an
 * authenticated user in the session (set by Passport after a successful
 * Google OAuth login).
 *
 * If the user is authenticated, the request proceeds to the next handler.
 * If not, the user is redirected to /login to sign in first.
 */

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  // Unauthorized access: redirect unauthenticated users to the login page.
  return res.redirect("/login");
}

module.exports = {
  ensureAuthenticated,
};
