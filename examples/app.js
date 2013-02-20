var express = require('express')
  , passport = require('passport')
  , util = require('util')
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
function userIsAllowedOnSite(site, identifier, cb) {
    var userIsAllowedOnSite = {
        "http://localhost:3000/" : {
                "https://www.google.com/accounts/o8/id?id=AItOawlDzU91WfQO5lN5DFtRrVN1yZlWXjv70CI":1
        }
    };

    // asynchronous verification, for effect...
    process.nextTick(function () {
      // check for authorization
      cb(null, userIsAllowedOnSite[APP_ROOT][identifier] != undefined);
    });
}

//
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
      return userIsAllowedOnSite(APP_ROOT, identifier, function (err, isAllowed) {
          if (isAllowed) {
              // To keep the example simple, the user's Google profile is returned to
              // represent the logged-in user.  In a typical application, you would want
              // to associate the Google account with a user record in your database,
              // and return that user instead.
              profile.identifier = identifier;
              return done(null, profile);
          } else {
              return done("sorry, you don't have permission to use this site. ciao. your Google openID is "+identifier);
          }
      });
  })
);


var app = express.createServer();

// configure Express
app.configure(function() {
  app.set('views', __dirname + '/views');
  app.set('view engine', 'ejs');
//  app.use(express.logger());
  app.use(express.cookieParser());
  app.use(express.bodyParser());
  app.use(express.methodOverride());
  app.use(express.session({ secret: 'keyboard cat' }));
  // Initialize Passport!  Also use passport.session() middleware, to support
  // persistent login sessions (recommended).
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(app.router);
  app.use(express.static(__dirname + '/../../public'));
});


app.get('/', function(req, res){
  res.render('index', { user: req.user });
});

app.get('/account', ensureAuthenticated, function(req, res){
  res.render('account', { user: req.user });
});

app.get('/login', function(req, res){
  res.render('login', { user: req.user });
});

// GET /auth/google
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  The first step in Google authentication will involve redirecting
//   the user to google.com.  After authenticating, Google will redirect the
//   user back to this application at /auth/google/return
app.get('/auth/google', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });

// GET /auth/google/return
//   Use passport.authenticate() as route middleware to authenticate the
//   request.  If authentication fails, the user will be redirected back to the
//   login page.  Otherwise, the primary route function function will be called,
//   which, in this example, will redirect the user to the home page.
app.get('/auth/google/return', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
  });

app.get('/logout', function(req, res){
  req.logout();
  res.redirect('/');
});

app.listen(3000);


// Simple route middleware to ensure user is authenticated.
//   Use this route middleware on any resource that needs to be protected.  If
//   the request is authenticated (typically via a persistent login session),
//   the request will proceed.  Otherwise, the user will be redirected to the
//   login page.
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) { return next(); }
  res.redirect('/login')
}

console.log("go to http://localhost:3000.  Only elliot.at.frog@gmail.com (mail for password) is allowed to use the app.")