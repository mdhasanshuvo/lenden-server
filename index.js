require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const { MongoClient, ServerApiVersion } = require('mongodb');

/**
 * Parse SALT_ROUNDS as an integer. If it's not set or invalid,
 * fallback to 10 (or any default you prefer).
 */
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10) || 10;

const app = express();
const port = process.env.PORT || 5000;

/**
 * Configure CORS so that:
 * - the frontend origin is allowed
 * - credentials (cookies) are allowed
 */
app.use(cors({
  origin: [
    'http://localhost:5173', // or wherever your React app runs
  ],
  credentials: true,
}));

app.use(express.json());
app.use(cookieParser());

/**
 *  Middleware to verify the JWT from cookies
 */
const verifyToken = (req, res, next) => {
  // Grab token from cookies
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).json({ message: 'No token, unauthorized' });
  }

  // Verify token
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token, unauthorized' });
    }

    // Attach decoded data to req for further use
    req.user = decoded;
    next();
  });
};

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.0nnvi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    // Connect to MongoDB
    await client.connect();
    console.log("Connected to MongoDB!");

    const usersCollection = client.db('lendenDB').collection('users');

    /**
     * ========== REGISTER ENDPOINT ==========
     */
    app.post('/register', async (req, res) => {
      const { name, pin, email, mobileNumber, accountType, nid } = req.body;

      try {
        // 1) Check if user already exists
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ success: false, message: "User already exists." });
        }

        // 2) Hash the PIN
        const hashedPin = await bcrypt.hash(pin, SALT_ROUNDS);

        // 3) Create the new user object
        const newUser = {
          name,
          pin: hashedPin, // store the hashed pin
          email,
          mobileNumber,
          accountType,
          nid,
          createdAt: new Date(),
        };

        // 4) Insert into the database
        const result = await usersCollection.insertOne(newUser);

        // 5) Respond based on DB result
        if (result.acknowledged) {
          return res.status(201).json({
            success: true,
            user: { _id: result.insertedId, ...newUser }
          });
        } else {
          return res.status(500).json({
            success: false,
            message: 'Failed to register user.'
          });
        }
      } catch (error) {
        console.error('Error registering new user:', error);
        return res.status(500).json({
          success: false,
          message: 'Failed to register user.'
        });
      }
    });

    /**
     * ========== LOGIN ENDPOINT ==========
     */
    app.post('/login', async (req, res) => {
      const { emailOrMobile, pin } = req.body;

      try {
        // 1) Find user by email OR mobileNumber
        const user = await usersCollection.findOne({
          $or: [
            { email: emailOrMobile },
            { mobileNumber: emailOrMobile },
          ]
        });

        if (!user) {
          return res.status(401).json({
            success: false,
            message: 'Invalid credentials (user not found)',
          });
        }

        // 2) Compare hashed PIN
        const isValid = await bcrypt.compare(pin, user.pin);
        if (!isValid) {
          return res.status(401).json({
            success: false,
            message: 'Invalid credentials (wrong PIN)',
          });
        }

        // 3) If valid, create a JWT
        // You can put any fields you need in the payload
        const payload = {
          email: user.email,
          _id: user._id,
          accountType: user.accountType
        };
        const token = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, {
          expiresIn: '5h'
        });

        // 4) Set the token as a cookie (or you can just send it in JSON)
        res
          .cookie('token', token, {
            httpOnly: true,                 // helps prevent XSS
            secure: false,                  // set true in production with HTTPS
            sameSite: 'strict',             // or 'none' if on different domains with HTTPS
            maxAge: 5 * 60 * 60 * 1000,     // 5h in milliseconds
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
        return res.status(500).json({
          success: false,
          message: 'Failed to login.'
        });
      }
    });

    /**
     * ========== LOGOUT ENDPOINT ==========
     * Clear the JWT cookie
     */
    app.post('/logout', (req, res) => {
      res
        .clearCookie('token')
        .json({ success: true, message: 'Logged out successfully' });
    });

    /**
     * ========== PROTECTED ROUTE EXAMPLE ==========
     * This route is protected by `verifyToken` middleware.
     * Access requires a valid JWT in the 'token' cookie.
     */
    app.get('/profile', verifyToken, (req, res) => {
      // The user's decoded info is available in req.user
      // For instance, you can fetch user details from DB if needed:
      return res.json({
        success: true,
        message: 'You have access to your profile!',
        user: req.user  // or fetch fresh from DB
      });
    });

  } catch (err) {
    console.error('DB connection error:', err);
  }
  // finally {
  //   If you want the server to keep running, don't close the connection here.
  //   await client.close();
  // }
}

run().catch(console.dir);

app.get('/', (req, res) => {
  res.send('Hello JWT World!');
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
