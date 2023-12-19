require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");

const findOrCreate = require("mongoose-findorcreate");

const passport=require("passport");
const passportOpenidconnect = require("passport-openidconnect");
const session=require("express-session")
const passportLocalMongoose=require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy= require('passport-github2').Strategy;
const app=express();


app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

app.use(session({
  secret:"Our little secret.",
  resave:false,
  saveUninitialized:false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema=new mongoose.Schema({
  email:String,
  password:String,
  googleId:String,
  secret:String,
  githubId:String
});

userSchema.plugin(findOrCreate);
userSchema.plugin(passportLocalMongoose);

const User=new mongoose.model("User",userSchema);
passport.use(User.createStrategy());
passport.serializeUser(function(user,done){
  done(null,user._id);
});
passport.deserializeUser(function(id,cb){
  User.findOrCreate({_id:id}, function (err, user) {
        if (err) { return cb(err)}
        return cb(null, user);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new GitHubStrategy({
    clientID: process.env.CLIENTID,
    clientSecret: process.env.CLIENTSECRET,
    callbackURL: "http://localhost:3000/auth/github/secrets",
    },
  function(accessToken, refreshToken, profile, done) {
      User.findOrCreate({ githubId: profile.id }, function (err, user) {
      return done(err, user);
    });
  }
));

app.get("/",function(req,res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate('google', { scope: ['profile'] })
);

app.get("/auth/google/secrets",
  passport.authenticate('google', { failureRedirect: "/login" }),
  function(req, res) {
     res.redirect("/secrets");
  });

  app.get('/auth/github',
  passport.authenticate('github', { scope: [ 'user:email' ] }));

app.get('/auth/github/secrets',
  passport.authenticate('github', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });


app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.get("/secrets", function(req, res) {
  User.find({ "secret": { $ne: null } })
    .then(function(foundUsers) {
      res.render("secrets", { usersWithSecrets: foundUsers });
    })
    .catch(function(err) {
      console.log(err);
      res.redirect("/login");
    });
});

app.get("/submit", function(req, res) {
  if (req.isAuthenticated()) {
      res.render("submit");
  } else {
      res.redirect("/login");
  }
});

app.post("/submit", function(req, res) {
  const submittedSecret = req.body.secret;

  User.findById(req.user._id)
  .then(function(foundUser) {
    if (foundUser) {
      foundUser.secret = submittedSecret;
    return foundUser.save();
    }
  })
  .then(function() {
    res.redirect("/secrets");
  })
  .catch(function(err) {
    console.log(err);
  });
});


app.get("/logout", function(req, res, next) {
  req.logout(function(err) {
    if (err) { return next(err); }
    res.redirect("/");
  });
});

app.post("/register",function(req,res){

  User.register({username:req.body.username}, req.body.password, function(err, user) {
  if (err) {
    console.log(err);
    res.redirect("/register");
  }else{
    passport.authenticate("local")(req,res,function(){
      res.redirect("/secrets");
    });
  }
});
});

app.post("/login",function(req,res){
  const user=new User({
  username:req.body.username,
  password:req.body.password
  });
  req.login(user,function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req,res,function(){
        res.redirect("/secrets");
      });
    }
  })
});



app.listen(3000,function(){
  console.log("Server Started on port 3000.");
});
