//jshint esversion:6
import dotenv from "dotenv";
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import LocalStrategy from "passport-local";
import PgSession from "connect-pg-simple";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
// import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

// Load environment variables from .env file
dotenv.config();

const app = express();
const port = process.env.PORT;
const saltRounds = process.env.SALT_ROUNDS;

console.log(process.env.ENCRYPTION_KEY);

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

// Set up session management with PostgreSQL store
const PgStore = PgSession(session);
app.use(
  session({
    store: new PgStore({
      conObject: {
        user: "postgres",
        host: "localhost",
        database: "userDB",
        password: process.env.DB_PW, // Replace with your actual database password
        port: process.env.DB_PORT,
      },
    }),
    secret: process.env.SESSION_KEY,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days in milliseconds
    },
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "userDB",
  password: process.env.DB_PW,
  port: process.env.DB_PORT,
});
db.connect();

// Passport serialize and deserialize functions
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    const user = result.rows[0];
    done(null, user);
  } catch (error) {
    done(error);
  }
});

async function hashPassword(password) {
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  console.log(`Hashed Password: ${hashedPassword}`);
  return hashedPassword;
}

export async function createUser(email, password) {
  const hashedPassword = await hashPassword(password);
  console.log(`Hashed PW: ${hashedPassword}`);
  const result = await db.query(
    "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
    [email, hashedPassword]
  );
  return result.rows[0];
}

export async function getUserByEmail(email) {
  const results = await db.query("SELECT * FROM users WHERE email = $1", [
    email,
  ]);
  const user = results.rows[0];
  return user;
}

export async function comparePasswords(plainPassword, hashedPassword) {
  // Implement your password comparison logic (e.g., using bcrypt)
  // Replace this with your actual comparison logic
  const verifyPassword = await bcrypt.compare(plainPassword, hashedPassword);
  console.log(`verify: ${verifyPassword}`);
  return verifyPassword;
}

//Configure Passport to use Google strategy
passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async function (accessToken, refreshToken, profile, cb) {
      console.log("Google Authentication Callback:", profile);
      console.log("Google Authentication Callback:", profile.email);
      console.log("Google Authentication Access Token:", accessToken);
      console.log("Google Authentication refreshToken:", refreshToken);

      try {
        const result = await db.query(
          "SELECT * FROM users WHERE google_id = $1",
          [profile.id]
        );

        if (result.rows.length > 0) {
          const user = result.rows[0];
          console.log("User Exists:", user);
          return cb(null, user);
        } else {
          const result = await db.query(
            "INSERT INTO users (google_id) VALUES ($1) RETURNING *",
            [profile.id]
          );
          const user = result.rows[0];
          console.log("New User Created:", user);
          return cb(null, user);
        }
      } catch (error) {
        console.error("Error during Google Authentication:", error);
        return cb(error);
      }
    }
  )
);

// Configure Passport to use local strategy
passport.use(
  "local-login",
  new LocalStrategy(async function verify(email, password, done) {
    try {
      const user = await getUserByEmail(email);

      if (!user) {
        console.log("Incorrect email.");
        return done(null, false, { message: "Incorrect email." });
      }

      const isPasswordValid = await comparePasswords(password, user.password);

      console.log(isPasswordValid);

      if (!isPasswordValid) {
        console.log("Incorrect PW.");
        return done(null, false, { message: "Incorrect password." });
      }

      console.log("LOGGED IN");
      return done(null, user);
    } catch (error) {
      console.log("ERROR LOGIN");
      return done(error);
    }
  })
);

//For registration
passport.use(
  "local-register",
  new LocalStrategy(
    {
      passReqToCallback: true, // Allows you to pass additional fields to the callback
    },
    async (req, email, password, done) => {
      try {
        const existingUser = await getUserByEmail(email);

        if (existingUser) {
          return done(null, false, { message: "Email already taken." });
        }

        const newUser = await createUser(email, password);

        return done(null, newUser);
      } catch (error) {
        return done(error);
      }
    }
  )
);

// Function to ensure key length is 32 bytes
// function getValidKey(encryptionKey) {
//   const keyBuffer = Buffer.from(encryptionKey);
//   // Pad the key to ensure it is 32 bytes long
//   const paddedKey = Buffer.alloc(32, keyBuffer);
//   return paddedKey;
// }

// Function to encrypt data
// function encryptData(data, encryptionKey) {
//   const algorithm = "aes-256-cbc";
//   const iv = randomBytes(16);

//   // Use the validKey instead of Buffer.from(encryptionKey)
//   const validKey = getValidKey(encryptionKey);
//   console.log("iv:", iv.toString("hex"));
//   console.log("iv length:", iv.length);

//   const cipher = createCipheriv(algorithm, validKey, iv);
//   let encryptedData = cipher.update(data, "utf-8", "hex");
//   encryptedData += cipher.final("hex");
//   console.log("encryptedPassword:", encryptedData);

//   return { iv: iv.toString("hex"), encryptedPassword: encryptedData };
// }

// Function to decrypt data
// function decryptData(encryptedData, encryptionKey, iv) {
//   const algorithm = "aes-256-cbc";

//   // Use the validKey instead of Buffer.from(encryptionKey)
//   const validKey = getValidKey(encryptionKey);

//   const decipher = createDecipheriv(
//     algorithm,
//     validKey,
//     Buffer.from(iv, "hex")
//   );
//   let decryptedData = decipher.update(encryptedData, "hex", "utf-8");
//   decryptedData += decipher.final("utf-8");
//   return decryptedData;
// }

// const encryptionKey = process.env.ENCRYPTION_KEY;

//Routes
app.get("/", isAuthenticated, (req, res) => {
  res.redirect("/secrets");
});

app.get("/secrets", async (req, res) => {
  const result = await db.query(
    "SELECT secrets FROM users WHERE secrets IS NOT NULL"
  );
  const secrets = result.rows;
  console.log(secrets);
  if (secrets.length > 0) {
    res.render("secrets.ejs", { secrets: secrets });
  } else {
    res.render("secrets.ejs");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/home" }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect("/");
  }
);

app.get("/home", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/submit", isAuthenticated, (req, res) => {
  res.render("submit.ejs");
});

app.post("/submit", isAuthenticated, async (req, res) => {
  const secret = req.body.secret;
  const userID = req.user.id;
  console.log(secret);
  console.log(req.user);
  const result = await db.query(
    "UPDATE users SET secrets = $1 WHERE id = $2 RETURNING *",
    [secret, userID]
  );
  console.log(result.rows[0]);
  res.redirect("/");
});

app.post(
  "/register",
  passport.authenticate("local-register", {
    successRedirect: "/",
    failureRedirect: "/register",
  })
);

app.post(
  "/login",
  passport.authenticate("local-login", {
    successRedirect: "/",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).send("Error logging out");
    }
    res.redirect("/");
  });
});

// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/home");
}

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
