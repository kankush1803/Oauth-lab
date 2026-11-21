const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

/**
 * config/passport.js
 *
 * Configures Passport.js with the Google OAuth 2.0 strategy.
 *
 * OAuth 2.0 Flow:
 * 1. User clicks "Login with Google" on the homepage.
 * 2. Express redirects the user to Google's consent screen.
 * 3. User signs in and grants permission.
 * 4. Google redirects back to /auth/google/callback with an authorization code.
 * 5. Passport exchanges the code for a Google profile (no tokens are stored).
 * 6. The user is serialized into the session and redirected to /dashboard.
 *
 * Secrets (GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET) are loaded from
 * environment variables and never hardcoded or logged.
 */

// Fail fast if required Google OAuth credentials are missing.
// This prevents the app from starting with an invalid OAuth configuration.
if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
  throw new Error(
    "Missing Google OAuth credentials. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your .env file."
  );
}

// Use the configured callback URL, falling back to a local default.
const callbackURL =
  process.env.GOOGLE_CALLBACK_URL ||
  "http://localhost:3003/auth/google/callback";

// Attach the Google OAuth 2.0 strategy to Passport.
// Scopes: "profile" (name, picture, id) and "email" (email address).
// Access tokens and refresh tokens are intentionally NOT stored or logged.
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: callbackURL,
      scope: ["profile", "email"],
    },
    function (accessToken, refreshToken, profile, done) {
      // The Google profile contains the user's identity information.
      // We do not log accessToken, refreshToken, or any other credentials.
      const user = {
        id: profile.id, // Google profile ID
        name: profile.displayName, // User's full name
        email:
          profile.emails && profile.emails.length > 0
            ? profile.emails[0].value
            : null, // Primary email address
        picture:
          profile.photos && profile.photos.length > 0
            ? profile.photos[0].value
            : null, // Profile picture URL
        provider: "google",
      };

      // Handle the case where Google did not return an email address.
      if (!user.email) {
        return done(new Error("Google profile did not include an email address."), null);
      }

      return done(null, user);
    }
  )
);

/**
 * serializeUser
 *
 * Determines which data of the user object should be stored in the session.
 * Only the minimal user profile is stored (no tokens).
 */
passport.serializeUser(function (user, done) {
  done(null, {
    id: user.id,
    name: user.name,
    email: user.email,
    picture: user.picture,
    provider: user.provider,
  });
});

/**
 * deserializeUser
 *
 * Retrieves the user object from the session on each subsequent request.
 * Since we do not use a database, the serialized user is returned directly.
 */
passport.deserializeUser(function (user, done) {
  done(null, user);
});

module.exports = passport;
