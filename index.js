import express from "express";
import bodyParser from "body-parser";
import pg from "pg"
import bcrypt from "bcrypt"
import session from "express-session"
import passport from "passport"
import { Strategy } from "passport-local";
import dotenv from "dotenv"
import GoogleStrategy from 'passport-google-oauth2'
const app = express();
const port = 3000;
const saltRounds = 10

dotenv.config("");

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: process.env.DATABASE,
  password: process.env.PASSWORD,
  port: process.env.PORT
})

db.connect()

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(session({
  secret: process.env.SESSION_SECRET, 
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false } 
}));

app.use(passport.initialize())
app.use(passport.session())

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    const result = await db.query("SELECT secret FROM users WHERE email = $1",[req.user.email])
    if(result.rows[0].secret){
      const data = {secret:result.rows[0].secret}
      res.render("secrets.ejs",data)
    }
    else{
      const data = {secret:""}
      res.render("secrets.ejs",data) 
    }
    
  }
  else {
    res.render("register.ejs");
  }
})

app.get("/submit",(req,res)=>{
  if(req.isAuthenticated()){
    res.render("submit.ejs")
  }
  else{
    res.render("login.ejs")
  }
})

app.post("/submit",async(req,res)=>{
  if(req.isAuthenticated()){
    const secret = req.body.secret
    await db.query("UPDATE users SET secret = $1 WHERE email = $2",[secret,req.user.email])
    res.redirect("/secrets")
  }
  else{
    res.render("login.ejs")
  }
})

"/auth/google",
passport.authenticate("google", {
  scope: ["profile", "email"],
});

app.get(
"/auth/google/secrets",
passport.authenticate("google", {
  successRedirect: "/secrets",
  failureRedirect: "/login",
})
);


app.get("/logout",(req,res)=>{
  req.logout((err)=>{
    if(err){
      console.log(err)
    }
    else{
      res.redirect("/")
    }
  })
})

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            console.log("success");
            res.redirect("/secrets");
          });
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login",passport.authenticate("local",{
  successRedirect:"/secrets",
  failureRedirect:"/login"
}));

passport.use("local",new Strategy(async function verify(username, password, cb) {
  const response = await db.query("SELECT * FROM users WHERE email = $1", [username])
  if (response.rows.length > 0) {
    const user = response.rows[0]
    const storedHashedPassword = user.password
    bcrypt.compare(password, storedHashedPassword, (err, result) => {
      if (err) {
        return cb(err)
      }
      else {
        if(result){
          return cb(null,user)
        }
        else{
          return cb(null,false)
        }
      }
    })
  }
  else {
    res.send("User not found!")
  }
}))

passport.use("google", new GoogleStrategy({
  clientID : process.env.CLIENT_ID,
  clientSecret : process.env.CLIENT_SECRET,
  callbackURL:"http://localhost:3000/auth/google/secrets",
  userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
},async(accessToken,refreshToken,profile,cb)=>{
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1",[profile.email])
    if(result.rows.length === 0){
      const newUser = await db.query("INSERT INTO users (email,password) VALUES ($1 , $2)",[profile.email,"google"])
      cb(null,newUser.rows[0])
    }
    else{
      cb(null,result.rows[0])
    }
  } catch (error) {
    cb(err)
  }
}))

passport.serializeUser((user,cb)=>{
  cb(null,user)
})

passport.deserializeUser((user,cb)=>{
  cb(null,user)
})

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
