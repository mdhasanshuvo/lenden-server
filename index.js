require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { MongoClient, ServerApiVersion } = require('mongodb');

/**
 * Parse SALT_ROUNDS as an integer. If it's not set or invalid,
 * fallback to 10 (or any default you prefer).
 */
const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10) || 10;

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(express.json());

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
    // Connect to MongoDB (comment out if using Serverless approach)
    await client.connect();
    console.log("Connected to MongoDB!");

    const usersCollection = client.db('lendenDB').collection('users');

    /**
     *  Register Endpoint
     */
    app.post('/register', async (req, res) => {
      const { name, pin, email, mobileNumber, accountType, nid } = req.body;

      try {
        // Check for existing user by email
        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res.status(400).json({ success: false, message: "User already exists." });
        }

        // Hash the PIN
        const hashedPin = await bcrypt.hash(pin, SALT_ROUNDS);

        const newUser = {
          name,
          pin: hashedPin, // store the hashed pin
          email,
          mobileNumber,
          accountType,
          nid,
          createdAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);

        // If insertion was successful
        if (result.acknowledged) {
          return res.status(201).json({
            success: true,
            // Return the inserted user (including the Mongo ObjectId)
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
     *  Login Endpoint
     */
    app.post('/login', async (req, res) => {
      const { emailOrMobile, pin } = req.body;

      try {
        // Find user by email OR mobile (NOT by hashed pin)
        const user = await usersCollection.findOne({
          $or: [
            { email: emailOrMobile },
            { mobileNumber: emailOrMobile },
          ]
        });

        // If user not found, return error
        if (!user) {
          return res.status(401).json({ success: false, message: 'Invalid credentials (user not found)' });
        }

        // Compare the provided pin with the hashed pin in DB
        const isValid = await bcrypt.compare(pin, user.pin);

        if (isValid) {
          // PIN matches
          return res.status(200).json({ success: true, user });
        } else {
          // PIN invalid
          return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }
      } catch (error) {
        console.error('Error logging in:', error);
        return res.status(500).json({
          success: false,
          message: 'Failed to login.'
        });
      }
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
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
