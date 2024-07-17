require('dotenv').config();

var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
const expressSesssion = require('express-session');
const passport = require('passport');
const { Issuer, Strategy } = require('openid-client');

// ensure all required environment variables are set
const requiredEnvVars = ['OIDC_PROVIDER_URL', 'OIDC_CLIENT_ID'];
requiredEnvVars.forEach(name => {
  if (!process.env[name]) {
    console.error(`Error: Environment variable ${name} is not set.`);
    process.exit(1);
  }
})

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);

Issuer.discover(process.env.OIDC_PROVIDER_URL)
  .then(criiptoIssuer => {
    var client = new criiptoIssuer.Client({
      client_id: process.env.OIDC_CLIENT_ID,
      client_secret: process.env.OIDC_CLIENT_SECRET,
      redirect_uris: [ process.env.OIDC_REDIRECT_URL || 'http://localhost:3000/auth/callback' ],
      post_logout_redirect_uris: [ process.env.OIDC_POST_REDIRECT_URL || 'http://localhost:3000/logout/callback' ],
      token_endpoint_auth_method: process.env.OIDC_TOKEN_ENDPOINT_AUTH_METHOD || 'none'
    });

    app.use(
      expressSesssion({
        secret: 'keyboard cat',
        resave: false,
        saveUninitialized: true
      })
    );

    app.use(passport.initialize());
    app.use(passport.session());

    let TokenSet;
    passport.use(
      'oidc',
      new Strategy({ client }, (tokenSet, userinfo, done) => {
        TokenSet = tokenSet;
        return done(null, tokenSet.claims());
      })
    );

    // handles serialization and deserialization of authenticated user
    passport.serializeUser(function(user, done) {
      done(null, user);
    });
    passport.deserializeUser(function(user, done) {
      done(null, user);
    });

    // start authentication request
    app.get('/auth', (req, res, next) => {
      passport.authenticate('oidc', { acr_values: 'urn:grn:authn:no:bankid' })(req, res, next);
    });

    // authentication callback
    app.get('/auth/callback', (req, res, next) => {
      passport.authenticate('oidc', {
        successRedirect: '/users',
        failureRedirect: '/'
      })(req, res, next);
    });

    app.use('/users', usersRouter);

    // start logout request
    app.get('/logout', (req, res) => {
      res.redirect(client.endSessionUrl({
        id_token_hint: TokenSet.id_token
      }));
    });

    // logout callback
    app.get('/logout/callback', (req, res) => {
      // clears the persisted user from the local storage
      req.logout();
      // redirects the user to a public route
      res.redirect('/');
    });


    // catch 404 and forward to error handler
    app.use(function(req, res, next) {
      next(createError(404));
    });

    // error handler
    app.use(function(err, req, res, next) {
      // set locals, only providing error in development
      res.locals.message = err.message;
      res.locals.error = req.app.get('env') === 'development' ? err : {};

      // render the error page
      res.status(err.status || 500);
      res.render('error');
    });
  });

module.exports = app;
