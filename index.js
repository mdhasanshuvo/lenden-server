require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const { MongoClient, ServerApiVersion } = require('mongodb');

const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10) || 10;

const app = express();
const port = process.env.PORT || 5000;

// Allow credentials (cookies) from your frontend URL
app.use(cors({
  origin: ['http://localhost:5173'],
  credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

function verifyToken(req, res, next) {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).json({ message: 'No token, unauthorized' });
  }

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token, unauthorized' });
    }
    req.user = decoded;
    next();
  });
}

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.0nnvi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
  serverApi: { version: ServerApiVersion.v1, strict: true, deprecationErrors: true },
});

async function run() {
  try {
    await client.connect();
    console.log("Connected to MongoDB!");

    const usersCollection = client.db('lendenDB').collection('users');

    // ========== REGISTER ==========
    app.post('/register', async (req, res) => {
      const { name, pin, email, mobileNumber, accountType, nid } = req.body;
      try {
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ success: false, message: "User already exists." });
        }

        const hashedPin = await bcrypt.hash(pin, SALT_ROUNDS);
        const newUser = {
          name,
          pin: hashedPin,
          email,
          mobileNumber,
          accountType,
          nid,
          createdAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);

        if (result.acknowledged) {
          return res.status(201).json({
            success: true,
            user: { _id: result.insertedId, ...newUser }
          });
        } else {
          return res.status(500).json({ success: false, message: 'Failed to register user.' });
        }
      } catch (error) {
        console.error('Error registering new user:', error);
        res.status(500).json({ success: false, message: 'Failed to register user.' });
      }
    });

    // ========== LOGIN ==========
    app.post('/login', async (req, res) => {
      const { emailOrMobile, pin } = req.body;

      try {
        const user = await usersCollection.findOne({
          $or: [
            { email: emailOrMobile },
            { mobileNumber: emailOrMobile },
          ]
        });

        if (!user) {
          return res.status(401).json({ success: false, message: 'Invalid credentials (user not found)' });
        }

        const isValid = await bcrypt.compare(pin, user.pin);
        if (!isValid) {
          return res.status(401).json({ success: false, message: 'Invalid credentials (wrong PIN)' });
        }

        // Build the JWT payload
        const payload = {
          email: user.email,
          _id: user._id,
          accountType: user.accountType
        };

        // Sign the JWT
        const token = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
          expiresIn: '5h'
        });

        // Send the token as an httpOnly cookie
        res
          .cookie('token', token, {
            httpOnly: true,
            secure: false, // set to true in production if using HTTPS
            sameSite: 'strict',
            maxAge: 5 * 60 * 60 * 1000, // 5 hours
          })
          .status(200)
          .json({
            success: true,
            user: {
              _id: user._id,
              name: user.name,
              email: user.email,
              mobileNumber: user.mobileNumber,
              accountType: user.accountType,
            }
          });
      } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ success: false, message: 'Failed to login.' });
      }
    });

    // ========== LOGOUT ==========
    app.post('/logout', (req, res) => {
      res
        .clearCookie('token')
        .json({ success: true, message: 'Logged out successfully' });
    });

    // ========== PROTECTED ROUTE EXAMPLE ==========
    app.get('/profile', verifyToken, (req, res) => {
      // We have access to req.user here
      return res.json({
        success: true,
        message: 'Protected route accessed successfully.',
        user: req.user,
      });
    });

  } catch (err) {
    console.error('DB connection error:', err);
  }
}

run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('Hello, LenDen JWT Server!');
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
