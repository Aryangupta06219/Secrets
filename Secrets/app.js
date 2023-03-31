require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const app=express();

// console.log(process.env.API_KEY);

app.use(express.static("public"));
app.set('view engine','ejs');
app.use(bodyParser.urlencoded({extended:true}));

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema=new mongoose.Schema({
  email:String,
  password:String
});
// const secret = "MySmallSecret."; // key used to encrypt database
// userSchema.plugin(encrypt, { secret: secret }); // encrypt both email and password so it is difficult to search for the password.
userSchema.plugin(encrypt, { secret: process.env.API_KEY, encryptedFields: ['password']});

const User=new mongoose.model("User",userSchema);

app.get("/",function(req,res){
  res.render("home");
});

app.get("/login",function(req,res){
  res.render("login");
});

app.get("/register",function(req,res){
  res.render("register");
});

app.post("/register",function(req,res){
  const newUser=new User({
    email:req.body.username,
    password:req.body.password
  });
  newUser.save().then(()=>{
        res.render("secrets");
    }).catch((err)=>{
        console.log(err);
    });
});

app.post("/login",function(req,res){
  const username=req.body.username;
  const  password=req.body.password;
  User.findOne({email:username}).then((foundUser)=>{
    if(foundUser){
      if(foundUser.password===password){
        res.render("secrets");
      }
    }
    }).catch((err)=>{
        console.log(err);
    });
  });



app.listen(3000,function(){
  console.log("Server Started on port 3000.");
});
