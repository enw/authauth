console.log("authauth");

var passport = require('passport')
  , GoogleStrategy = require('passport-google').Strategy;

// Passport session setup.
//   To support persistent login sessions, Passport needs to be able to
//   serialize users into and deserialize users out of the session.  Typically,
//   this will be as simple as storing the user ID when serializing, and finding
//   the user by ID when deserializing.  However, since this example does not
//   have a database of user records, the complete Google profile is serialized
//   and deserialized.
passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  done(null, obj);
});

// TEMPORARY AUTHORIZATION (will be replaced by auth service)
// For now now this is a simple list of Google OpenIDs tokens
// using a google openid with a non-google (my) will *not* be secure unless
// security is managed on the server-side by doing something like inspecting
// incoming headers and only authorizing things referred by a valid url.
function userIsAllowedOnSite(site, email, cb) {
    var userIsAllowedOnSite = {
        "http://localhost:3000/" : {
//                "https://www.google.com/accounts/o8/id?id=AItOawlDzU91WfQO5lN5DFtRrVN1yZlWXjv70CI":1
                "elliot.winard@gmail.com":1
        }
    };

    // asynchronous verification, for effect...
    process.nextTick(function () {
      // check for authorization
      cb(null, userIsAllowedOnSite[APP_ROOT][email] != undefined);
    });

}
var APP_ROOT="http://localhost:3000/";

// Use the GoogleStrategy within Passport.
//   Strategies in passport require a `validate` function, which accept
//   credentials (in this case, an OpenID identifier and profile), and invoke a
//   callback with a user object.
passport.use(new GoogleStrategy({
    returnURL: 'http://localhost:3000/auth/google/return',
    realm: 'http://localhost:3000/'
  },
  function(identifier, profile, done) {
      // asynchronously check for authorization
      return userIsAllowedOnSite(APP_ROOT, profile.emails[0].value, function (err, isAllowed) {
          if (isAllowed) {
              // To keep the example simple, the user's Google profile is returned to
              // represent the logged-in user.  In a typical application, you would want
              // to associate the Google account with a user record in your database,
              // and return that user instead.
              profile.identifier = identifier;
              return done(null, profile);
          } else {
              return done("sorry, you don't have permission to use this site. ciao. Ask to have your email added - "+profile.emails[0].value);
          }
      });
  })
);

// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
passport.ensureAuthenticated = function () {return function (req, res, next) {
  function isAuthURL(url) {
      var isAuthURL = {
          '/login':1,
          '/favicon.ico':1,
          '/auth/google':1
      };
      return isAuthURL[url] || url.indexOf("/auth/google") == 0;
  }
  if (req.isAuthenticated() || isAuthURL(req.url)) { return next(); }
  res.redirect('/login')
}}

module.exports = passport;
