
const express = require("express");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const app = express();
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

const DATA_FILE = path.join(__dirname, "data.json");
const sessions = new Map();
const banks = ["X BANK"];

const ACCESS_CODES = {
  "55555": 500000,
  "11111": 1000000,
  "74747": 1000000000,
  "66666": 1000000000000
};

function loadData() {
  try {
    const data = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
    return {
      users: Array.isArray(data.users) ? data.users : [],
      transactions: Array.isArray(data.transactions)
        ? data.transactions : []
    };
  } catch {
    return { users: [], transactions: [] };
  }
}

let db = loadData();

function saveData() {
  const temp = DATA_FILE + ".tmp";
  fs.writeFileSync(temp, JSON.stringify(db), { mode: 0o600 });
  fs.renameSync(temp, DATA_FILE);
}

const id = () => crypto.randomUUID();
const token = () => crypto.randomBytes(32).toString("hex");

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function checkPassword(password, user) {
  const attempted = crypto.scryptSync(password, user.salt, 64);
  const original = Buffer.from(user.passwordHash, "hex");
  return original.length === attempted.length &&
    crypto.timingSafeEqual(attempted, original);
}

function safeUser(user) {
  return {
    firstName: user.firstName,
    middleName: user.middleName,
    surname: user.surname,
    name: [user.firstName, user.middleName, user.surname]
      .filter(Boolean).join(" "),
    email: user.email,
    accountNumber: user.accountNumber,
    balanceKobo: user.balanceKobo
  };
}

function currentUser(req) {
  const header = req.get("authorization") || "";
  const bearer = header.startsWith("Bearer ") ? header.slice(7) : "";
  const userId = sessions.get(bearer);
  return db.users.find(u => u.id === userId);
}

function auth(req, res, next) {
  const user = currentUser(req);
  if (!user) {
    return res.status(401).json({ error: "Please sign in again." });
  }
  req.user = user;
  next();
}

function record({ from, to, amountKobo, type }) {
  const tx = {
    id: id(),
    reference: "XB" + Date.now() + crypto.randomBytes(5).toString("hex").toUpperCase(),
    type,
    fromId: from?.id || null,
    fromName: from ? safeUser(from).name : "X BANK",
    fromNumber: from?.accountNumber || "",
    toId: to?.id || null,
    toName: to ? safeUser(to).name : "X BANK",
    toNumber: to?.accountNumber || "",
    amountKobo,
    paymentMethod: "X BANK",
    createdAt: new Date().toISOString()
  };
  db.transactions.unshift(tx);
  return tx;
}

app.get("/api/status", (req, res) => {
  res.json({ bank: "X BANK", ready: true });
});

app.post("/api/register", (req, res) => {
  const { firstName, middleName, surname, email, accountNumber, password } =
    req.body || {};

  if (![firstName, surname, email, accountNumber, password]
      .every(v => typeof v === "string")) {
    return res.status(400).json({ error: "Complete all required fields." });
  }

  if (firstName.trim().length < 2 || surname.trim().length < 2 ||
      firstName.length > 60 || surname.length > 60 ||
      (middleName && (typeof middleName !== "string" || middleName.length > 60))) {
    return res.status(400).json({ error: "Check the name fields." });
  }

  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }

  if (!/^\d{10}$/.test(accountNumber)) {
    return res.status(400).json({
      error: "Your account number must contain exactly 10 digits."
    });
  }

  if (password.length < 8 || password.length > 128) {
    return res.status(400).json({
      error: "Password must be at least 8 characters."
    });
  }

  if (db.users.some(u => u.accountNumber === accountNumber)) {
    return res.status(409).json({ error: "That account number is taken." });
  }

  if (db.users.some(u => u.email.toLowerCase() === email.trim().toLowerCase())) {
    return res.status(409).json({ error: "That email is already registered." });
  }

  const hashed = hashPassword(password);
  const user = {
    id: id(),
    firstName: firstName.trim(),
    middleName: (middleName || "").trim(),
    surname: surname.trim(),
    email: email.trim(),
    accountNumber,
    salt: hashed.salt,
    passwordHash: hashed.hash,
    balanceKobo: 0
  };

  db.users.push(user);
  saveData();

  const session = token();
  sessions.set(session, user.id);
  res.status(201).json({ token: session, user: safeUser(user) });
});

app.post("/api/login", (req, res) => {
  const { accountNumber, password } = req.body || {};
  const user = db.users.find(u => u.accountNumber === accountNumber);

  if (!user || typeof password !== "string" || !checkPassword(password, user)) {
    return res.status(401).json({ error: "Incorrect account number or password." });
  }

  const session = token();
  sessions.set(session, user.id);
  res.json({ token: session, user: safeUser(user) });
});

app.post("/api/logout", auth, (req, res) => {
  const bearer = (req.get("authorization") || "").slice(7);
  sessions.delete(bearer);
  res.json({ ok: true });
});

app.get("/api/me", auth, (req, res) => {
  res.json({ user: safeUser(req.user) });
});

app.get("/api/recipient/:number", auth, (req, res) => {
  const number = req.params.number;
  if (!/^\d{10}$/.test(number)) {
    return res.status(400).json({ error: "Enter a 10-digit account number." });
  }

  const recipient = db.users.find(u => u.accountNumber === number);
  if (!recipient) {
    return res.status(404).json({ error: "X BANK account not found." });
  }

  res.json({
    name: safeUser(recipient).name,
    accountNumber: recipient.accountNumber,
    bank: "X BANK"
  });
});

app.post("/api/add-money", auth, (req, res) => {
  const { code } = req.body || {};
  if (typeof code !== "string" || !Object.hasOwn(ACCESS_CODES, code)) {
    return res.status(400).json({ error: "Invalid access code." });
  }

  const amountKobo = ACCESS_CODES[code] * 100;
  if (!Number.isSafeInteger(req.user.balanceKobo + amountKobo)) {
    return res.status(400).json({ error: "Balance limit reached." });
  }

  req.user.balanceKobo += amountKobo;
  const tx = record({
    from: null, to: req.user, amountKobo, type: "Credit"
  });
  saveData();

  res.json({
    user: safeUser(req.user),
    receipt: tx,
    message: "Balance updated."
  });
});

app.post("/api/transfer", auth, (req, res) => {
  const { recipientNumber, amount } = req.body || {};
  if (typeof recipientNumber !== "string" ||
      !/^\d{10}$/.test(recipientNumber)) {
    return res.status(400).json({ error: "Enter a valid 10-digit recipient number." });
  }

  if (typeof amount !== "number" || !Number.isFinite(amount) ||
      amount <= 0 || amount > 1000000000000) {
    return res.status(400).json({ error: "Enter a valid transfer amount." });
  }

  const amountKobo = Math.round(amount * 100);
  if (!Number.isSafeInteger(amountKobo) || amountKobo < 1) {
    return res.status(400).json({ error: "Enter a valid amount." });
  }

  const recipient = db.users.find(u => u.accountNumber === recipientNumber);
  if (!recipient) {
    return res.status(404).json({ error: "Recipient account not found." });
  }

  if (recipient.id === req.user.id) {
    return res.status(400).json({ error: "You cannot transfer to yourself." });
  }

  if (req.user.balanceKobo < amountKobo) {
    return res.status(400).json({ error: "Insufficient balance." });
  }

  if (!Number.isSafeInteger(recipient.balanceKobo + amountKobo)) {
    return res.status(400).json({ error: "Recipient balance limit reached." });
  }

  req.user.balanceKobo -= amountKobo;
  recipient.balanceKobo += amountKobo;

  const tx = record({
    from: req.user, to: recipient, amountKobo, type: "Transfer"
  });
  saveData();

  res.json({
    user: safeUser(req.user),
    receipt: tx,
    message: "Transfer completed."
  });
});

app.get("/api/transactions", auth, (req, res) => {
  const transactions = db.transactions
    .filter(tx => tx.fromId === req.user.id || tx.toId === req.user.id)
    .slice(0, 100);
  res.json({ transactions });
});

app.get("/api/receipt/:reference", auth, (req, res) => {
  const tx = db.transactions.find(t => t.reference === req.params.reference);
  if (!tx || (tx.fromId !== req.user.id && tx.toId !== req.user.id)) {
    return res.status(404).json({ error: "Receipt not found." });
  }
  res.json({ receipt: tx });
});

app.use("/api", (req, res) => {
  res.status(404).json({ error: "API route not found." });
});

const port = process.env.PORT || 3000;
app.listen(port, "0.0.0.0", () => {
  console.log("X BANK is running on port " + port);
});
