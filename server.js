
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: "1mb" }));

const DATA_FILE = path.join(__dirname, "data.json");

const ACCESS_CODES = {
  "55555": 500000,
  "11111": 1000000,
  "74747": 1000000000,
  "66666": 1000000000000
};

const sessions = new Map();

function createEmptyDatabase() {
  return { users: [], transactions: [] };
}

function loadDatabase() {
  try {
    if (!fs.existsSync(DATA_FILE)) {
      fs.writeFileSync(
        DATA_FILE,
        JSON.stringify(createEmptyDatabase(), null, 2)
      );
    }

    const raw = fs.readFileSync(DATA_FILE, "utf8");
    const parsed = raw.trim() ? JSON.parse(raw) : {};

    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      transactions: Array.isArray(parsed.transactions)
        ? parsed.transactions
        : []
    };
  } catch (error) {
    console.error("Database loading error:", error);
    return createEmptyDatabase();
  }
}

let db = loadDatabase();

function saveDatabase() {
  const temporaryFile = DATA_FILE + ".tmp";

  fs.writeFileSync(
    temporaryFile,
    JSON.stringify(db, null, 2),
    "utf8"
  );

  fs.renameSync(temporaryFile, DATA_FILE);
}

function normalizeAccountNumber(value) {
  return String(value ?? "").trim();
}

function findUser(accountNumber) {
  const normalized = normalizeAccountNumber(accountNumber);

  return db.users.find(
    user =>
      normalizeAccountNumber(user.accountNumber) === normalized
  );
}

function makeToken() {
  return crypto.randomBytes(32).toString("hex");
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(String(password), salt, 64).toString("hex");
  return { salt, hash };
}

function verifyPassword(password, salt, savedHash) {
  const calculated = crypto.scryptSync(String(password), salt, 64);
  const saved = Buffer.from(savedHash, "hex");

  return saved.length === calculated.length &&
    crypto.timingSafeEqual(calculated, saved);
}

function publicUser(user) {
  return {
    firstName: user.firstName,
    surname: user.surname,
    middleName: user.middleName,
    fullName: user.fullName,
    email: user.email,
    accountNumber: user.accountNumber,
    balanceKobo: user.balanceKobo
  };
}

function getAuthenticatedUser(req) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  const accountNumber = sessions.get(token);

  if (!accountNumber) return null;

  return findUser(accountNumber) || null;
}

function requireAuth(req, res, next) {
  const user = getAuthenticatedUser(req);

  if (!user) {
    return res.status(401).json({
      error: "Please sign in again."
    });
  }

  req.user = user;
  next();
}

function makeReference() {
  return "XB" + Date.now() + crypto.randomBytes(3).toString("hex").toUpperCase();
}

app.get("/api/status", (req, res) => {
  res.json({ online: true, bank: "X BANK" });
});

// CREATE ACCOUNT
app.post("/api/register", (req, res) => {
  try {
    const firstName = String(req.body.firstName || "").trim();
    const surname = String(req.body.surname || "").trim();
    const middleName = String(req.body.middleName || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const accountNumber = normalizeAccountNumber(req.body.accountNumber);
    const password = String(req.body.password || "");

    if (!firstName || !surname || !email || !accountNumber || !password) {
      return res.status(400).json({
        error: "Please complete all required fields."
      });
    }

    if (!/^\d{10}$/.test(accountNumber)) {
      return res.status(400).json({
        error: "Account number must contain exactly 10 digits."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        error: "Password must be at least 6 characters."
      });
    }

    // Reload saved records before checking for duplicates.
    db = loadDatabase();

    // Only reject a number if a real saved account has that number.
    const existingAccount = db.users.find(user => {
      return normalizeAccountNumber(user.accountNumber) === accountNumber;
    });

    if (existingAccount) {
      return res.status(409).json({
        error: "This account number is taken. Please choose another."
      });
    }

    const existingEmail = db.users.find(
      user => String(user.email || "").trim().toLowerCase() === email
    );

    if (existingEmail) {
      return res.status(409).json({
        error: "An account with this email already exists."
      });
    }

    const passwordData = hashPassword(password);
    const fullName = [firstName, middleName, surname]
      .filter(Boolean)
      .join(" ");

    const newUser = {
      id: crypto.randomUUID(),
      firstName,
      surname,
      middleName,
      fullName,
      email,
      accountNumber,
      passwordSalt: passwordData.salt,
      passwordHash: passwordData.hash,
      balanceKobo: 0,
      createdAt: new Date().toISOString()
    };

    db.users.push(newUser);
    saveDatabase();

    const token = makeToken();
    sessions.set(token, accountNumber);

    return res.status(201).json({
      message: "X BANK account created successfully.",
      token,
      user: publicUser(newUser)
    });
  } catch (error) {
    console.error("Registration error:", error);

    return res.status(500).json({
      error: "Account creation failed. Please try again."
    });
  }
});

// SIGN IN
app.post("/api/login", (req, res) => {
  const accountNumber = normalizeAccountNumber(req.body.accountNumber);
  const password = String(req.body.password || "");

  const user = findUser(accountNumber);

  if (!user || !verifyPassword(
    password,
    user.passwordSalt,
    user.passwordHash
  )) {
    return res.status(401).json({
      error: "Incorrect account number or password."
    });
  }

  const token = makeToken();
  sessions.set(token, user.accountNumber);

  res.json({
    message: "Login successful.",
    token,
    user: publicUser(user)
  });
});

// SIGN OUT
app.post("/api/logout", requireAuth, (req, res) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  sessions.delete(token);

  res.json({ message: "Signed out successfully." });
});

// CURRENT USER
app.get("/api/me", requireAuth, (req, res) => {
  res.json({ user: publicUser(req.user) });
});

// FIND TRANSFER RECIPIENT
app.get("/api/recipient/:number", requireAuth, (req, res) => {
  const recipient = findUser(req.params.number);

  if (!recipient) {
    return res.status(404).json({
      error: "Account not found."
    });
  }

  res.json({
    recipient: {
      fullName: recipient.fullName,
      accountNumber: recipient.accountNumber,
      bank: "X BANK"
    }
  });
});

// ADD SIMULATED MONEY
app.post("/api/add-money", requireAuth, (req, res) => {
  const code = String(req.body.code || "").trim();
  const amount = ACCESS_CODES[code];

  if (!amount) {
    return res.status(400).json({
      error: "Invalid access code."
    });
  }

  // Store whole naira as a string to avoid precision loss
  // with the trillion-naira simulation.
  const currentBalance = BigInt(req.user.balanceNaira || "0");
  const newBalance = currentBalance + BigInt(amount);

  req.user.balanceNaira = newBalance.toString();

  // Compatibility field for the existing frontend.
  req.user.balanceKobo = Number(newBalance) * 100;

  saveDatabase();

  res.json({
    message: "Simulated money added successfully.",
    amount,
    balanceNaira: req.user.balanceNaira,
    user: publicUser(req.user)
  });
});

// TRANSFER BETWEEN X BANK SIMULATED ACCOUNTS
app.post("/api/transfer", requireAuth, (req, res) => {
  try {
    const recipientNumber = normalizeAccountNumber(
      req.body.accountNumber || req.body.recipientAccount
    );

    const amount = Number(req.body.amount);

    if (!/^\d{10}$/.test(recipientNumber)) {
      return res.status(400).json({
        error: "Enter a valid 10-digit recipient account number."
      });
    }

    if (!Number.isSafeInteger(amount) || amount <= 0) {
      return res.status(400).json({
        error: "Enter a valid whole-naira amount."
      });
    }

    const sender = findUser(req.user.accountNumber);
    const recipient = findUser(recipientNumber);

    if (!recipient) {
      return res.status(404).json({
        error: "Recipient account not found."
      });
    }

    if (sender.accountNumber === recipient.accountNumber) {
      return res.status(400).json({
        error: "You cannot transfer to your own account."
      });
    }

    const senderBalance = BigInt(sender.balanceNaira || "0");
    const transferAmount = BigInt(amount);

    if (senderBalance < transferAmount) {
      return res.status(400).json({
        error: "Insufficient balance."
      });
    }

    const recipientBalance = BigInt(recipient.balanceNaira || "0");

    sender.balanceNaira = (senderBalance - transferAmount).toString();
    recipient.balanceNaira = (recipientBalance + transferAmount).toString();

    sender.balanceKobo = Number(sender.balanceNaira) * 100;
    recipient.balanceKobo = Number(recipient.balanceNaira) * 100;

    const reference = makeReference();
    const transactionDate = new Date().toISOString();

    const transaction = {
      reference,
      type: "transfer",
      amount,
      status: "successful",
      senderAccount: sender.accountNumber,
      senderName: sender.fullName,
      recipientAccount: recipient.accountNumber,
      recipientName: recipient.fullName,
      date: transactionDate,
      simulated: true
    };

    db.transactions.push(transaction);
    saveDatabase();

    res.json({
      message: "Simulated transfer successful.",
      transaction,
      user: publicUser(sender)
    });
  } catch (error) {
    console.error("Transfer error:", error);

    res.status(500).json({
      error: "Transfer could not be completed."
    });
  }
});

// TRANSACTION HISTORY
app.get("/api/transactions", requireAuth, (req, res) => {
  const accountNumber = req.user.accountNumber;

  const transactions = db.transactions
    .filter(transaction =>
      transaction.senderAccount === accountNumber ||
      transaction.recipientAccount === accountNumber
    )
    .sort((a, b) => new Date(b.date) - new Date(a.date));

  res.json({ transactions });
});

// RECEIPT
app.get("/api/receipt/:reference", requireAuth, (req, res) => {
  const transaction = db.transactions.find(item =>
    item.reference === req.params.reference &&
    (
      item.senderAccount === req.user.accountNumber ||
      item.recipientAccount === req.user.accountNumber
    )
  );

  if (!transaction) {
    return res.status(404).json({
      error: "Receipt not found."
    });
  }

  res.json({
    transaction,
    notice: "SIMULATED RECEIPT — NOT PROOF OF A REAL BANK PAYMENT."
  });
});

// UNKNOWN API ROUTE
app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API route not found."
  });
});

app.listen(PORT, () => {
  console.log(`X BANK server running on port ${PORT}`);
});
