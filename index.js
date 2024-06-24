import express from "express";
import bodyParser from "body-parser";
import Cred from "./models/cred.js";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
      maxAge: 1000 * 60 * 60 + 24,
    },
  })
);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(passport.initialize());
app.use(passport.session());

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secretes", async (req, res) => {
  // console.log(req.user);
  if (req.isAuthenticated()) {
    //print secret from db
    try {
      const username = req.user.username;
      const result = await Cred.findOne({ username: username });
      // console.log(result);
      const secret = result.secret;
      if (secret) {
        res.render("secrets.ejs", { secret: secret });
      } else {
        res.render("secrets.ejs", {
          secret: "You Should Submit A Secret First !",
        });
      }
    } catch (err) {
      console.log(err);
    }
  } else {
    res.redirect("/login");
  }
});

//submit route inly for authenticated user
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

//the strategy it uses is "google" specified  here and used below to authenticate
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secretes",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secretes",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Check if username already exists
    const existingUser = await Cred.findOne({ username: username });
    if (existingUser) {
      console.error("Email already exists");
      return res.status(400).send("Email already exists");
    }

    // Hash the password
    bcrypt.hash(password, saltRounds, async (err, hash) => {
      if (err) {
        console.log("Error while generating hash!");
        return res.status(500).send("Error while generating hash");
      } else {
        // Create new user credentials
        const cred = new Cred({
          username: username,
          password: hash,
        });

        // Save the new user to the database
        const savedProduct = await cred.save();
        console.log("Product saved successfully:", savedProduct);

        // Log in the user after successful registration
        req.login(cred, (err) => {
          if (err) {
            console.log(err);
            return res.status(500).send("Error logging in after registration");
          }
          res.redirect("/secretes");
        });
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Error registering user");
  }
});

app.post("/submit", async (req, res) => {
  const secret = req.body.secret;
  // console.log(req.user);
  //to whom we should submit it will come from authentications callback i.e. cb
  try {
    const username = req.user.username;
    const updatedUser = await Cred.findOneAndUpdate(
      { username: username }, // filter
      { secret: secret }, // update
      { new: true } // options: return the updated document
    );
    console.log(updatedUser);
    res.redirect("/secretes");
  } catch (err) {
    console.log(err);
  }
});

//if u r having 1 strategy then it's  optional to add it or not but more than that u have to
passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      const user = await Cred.findOne({ username: username });
      if (user != null) {
        bcrypt.compare(password, user.password, (err, result) => {
          if (err) {
            return cb(err);
          } else {
            if (result) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("No Such User Found!");
      }
    } catch (err) {
      return cb(err);
    }
  })
);

//this middleware is for Oauth google  stratrgy
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "http://googleapis.com/oauth2/v3/userinfo",
    },
    async function (accessToken, refreshToken, profile, cb) {
      try {
        const guser = profile.emails[0].value;
        const user = await Cred.findOne({ username: guser });

        if (user) {
          // if user is already there then send the message
          console.error("Email already exists");
          return cb(null, false, { message: "Email already exists" });
        }

        // Hash the password
        const password = "google";
        bcrypt.hash(password, saltRounds, async (err, hash) => {
          if (err) {
            console.log("Error while generating hash!");
            return res.status(500).send("Error while generating hash");
          } else {
            // Create new user credentials
            const newUser = new Cred({
              username: guser,
              password: hash, // saving with a placeholder password since none is provided
            });
            const savedProduct = await newUser.save();
            cb(null, newUser);
          }
        });
      } catch (err) {
        cb(err);
      }
    }
  )
);

passport.serializeUser((user, cb) => {
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  cb(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
