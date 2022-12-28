const bodyParser = require('body-parser'),
      { default: mongoose } = require('mongoose'), 
        express = require('express'),
        passport = require('passport'),
        localStrategy = require('passport-local'),
        passportLocalMongoose = require('passport-local-mongoose');

let app = express();
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended: true}))

app.use(require("express-session")({
    secret: "Master",
    resave: false,
    saveUninitialized: false
}));

mongoose.set('strictQuery', true);
mongoose.connect('mongodb://127.0.0.1:27017/users');

app.use(passport.initialize());
app.use(passport.session());

passport.use(new LocalStrategy(function verify(username, password, cb) {
    mongoose.findOne('SELECT * FROM users WHERE username = ?', [ username ], function(err, row) {
      if (err) { return cb(err); }
      if (!row) { return cb(null, false, { message: 'Incorrect username or password.' }); }
  
      crypto.pbkdf2(password, row.salt, 310000, 32, 'sha256', function(err, hashedPassword) {
        if (err) { return cb(err); }
        if (!crypto.timingSafeEqual(row.hashed_password, hashedPassword)) {
          return cb(null, false, { message: 'Incorrect username or password.' });
        }
        return cb(null, row);
      });
    });
  }));

const port = process.env.PORT || 3000;

app.listen(port, function () {
    console.log("Servidor en linea");
});

app.get("/", function(req, res){
    res.render("index");
});

app.get("/home", isLoggedIn, function (req, res) {
    res.render("home");
});

app.get("/login", function(req, res){
    res.render("login");
});

app.get("/logout", function(req, res){
    req.logout();
    res.redirect("/");
});

function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect("/login");
}

app.post("/login", passport.authenticate("local", {
        successRedirect: "/home",
        failureRedirect: "/login"
    }), function (req, res) {
});