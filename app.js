//jshint esversion:6
import dotenv from "dotenv";
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import { createCipheriv, createDecipheriv, randomBytes } from "crypto";

// Load environment variables from .env file
dotenv.config();

const app = express();
const port = 3000;

console.log(process.env.ENCRYPTION_KEY);

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "userDB",
  password: "3bkr@2251998",
  port: 5432,
});
db.connect();

// Function to ensure key length is 32 bytes
function getValidKey(encryptionKey) {
  const keyBuffer = Buffer.from(encryptionKey);
  // Pad the key to ensure it is 32 bytes long
  const paddedKey = Buffer.alloc(32, keyBuffer);
  return paddedKey;
}

// Function to encrypt data
function encryptData(data, encryptionKey) {
  const algorithm = "aes-256-cbc";
  const iv = randomBytes(16);

  // Use the validKey instead of Buffer.from(encryptionKey)
  const validKey = getValidKey(encryptionKey);
  console.log("iv:", iv.toString("hex"));
  console.log("iv length:", iv.length);

  const cipher = createCipheriv(algorithm, validKey, iv);
  let encryptedData = cipher.update(data, "utf-8", "hex");
  encryptedData += cipher.final("hex");
  console.log("encryptedPassword:", encryptedData);

  return { iv: iv.toString("hex"), encryptedPassword: encryptedData };
}

// Function to decrypt data
function decryptData(encryptedData, encryptionKey, iv) {
  const algorithm = "aes-256-cbc";

  // Use the validKey instead of Buffer.from(encryptionKey)
  const validKey = getValidKey(encryptionKey);

  const decipher = createDecipheriv(
    algorithm,
    validKey,
    Buffer.from(iv, "hex")
  );
  let decryptedData = decipher.update(encryptedData, "hex", "utf-8");
  decryptedData += decipher.final("utf-8");
  return decryptedData;
}

const encryptionKey = process.env.ENCRYPTION_KEY;

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  // Encrypt data before storing in the database
  const { iv, encryptedPassword } = encryptData(password, encryptionKey);
  console.log("iv:", iv);
  console.log("iv length:", iv.length);
  console.log("encryptedPassword:", encryptedPassword);
  try {
    await db.query(
      "INSERT INTO users (email, password, iv) VALUES ($1, $2, $3)",
      [email, encryptedPassword, iv]
    );
    res.render("secrets.ejs");
  } catch (err) {
    console.log(err);
    res.status(500).send(err.message);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  try {
    const results = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    const user = results.rows[0];
    console.log(user);

    // Decrypt the stored password from the database
    const decryptedPassword = decryptData(
      user.password,
      encryptionKey,
      user.iv
    );

    console.log(`Decrypted PW: ${decryptedPassword}`);

    // Comparing the user-entered password with the decrypted password
    if (decryptedPassword === password) {
      // Passwords match
      console.log("Password is correct");
      res.render("secrets.ejs");
    } else {
      // Passwords don't match
      console.log("Password is incorrect");
      res.status(500).send("Wrong password!");
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Wrong Email!");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
