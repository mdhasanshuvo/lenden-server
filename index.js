require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const SALT_ROUNDS = parseInt(process.env.SALT_ROUNDS, 10) || 10;

const app = express();
const port = process.env.PORT || 5000;

app.use(cors({
    origin: ['http://localhost:5173'],
    credentials: true,
}));
app.use(express.json());
app.use(cookieParser());

// JWT middleware
function verifyToken(req, res, next) {
    const token = req.cookies?.token;
    if (!token) {
        return res.status(401).json({ message: 'No token, unauthorized' });
    }
    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token, unauthorized' });
        }
        req.user = decoded; // { _id, role: 'User' | 'Agent' | 'Admin', ... }
        next();
    });
}

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.0nnvi.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    },
});

async function run() {
    try {
        await client.connect();
        console.log('Connected to MongoDB!');

        const db = client.db('lendenDB');
        const usersColl = db.collection('users');   // for normal users
        const agentsColl = db.collection('agents'); // for agents
        const adminsColl = db.collection('admins'); // for admin(s)
        const transactionsColl = db.collection('transactions');

        /*
         * ============ USER REGISTRATION ============
         */
        app.post('/register-user', async (req, res) => {
            const { name, pin, email, mobileNumber, nid } = req.body;
            try {
                // Check duplicates
                const emailExists = await usersColl.findOne({ email });
                if (emailExists) {
                    return res.status(400).json({ success: false, message: 'Email already in use.' });
                }
                const phoneExists = await usersColl.findOne({ mobileNumber });
                if (phoneExists) {
                    return res.status(400).json({ success: false, message: 'Mobile number already in use.' });
                }

                // Hash pin
                const hashedPin = await bcrypt.hash(pin, SALT_ROUNDS);
                const newUser = {
                    name,
                    pin: hashedPin,
                    email,
                    mobileNumber,
                    nid,
                    balance: 40,          // user gets 40 Taka bonus
                    isBlocked: false,
                    createdAt: new Date(),
                };

                const result = await usersColl.insertOne(newUser);
                if (!result.acknowledged) {
                    return res.status(500).json({ success: false, message: 'Failed to create user.' });
                }
                // Return user without the pin field
                const { pin: removed, ...rest } = newUser;
                return res.status(201).json({ success: true, user: { ...rest, _id: result.insertedId } });
            } catch (err) {
                console.error('Register user error:', err);
                res.status(500).json({ success: false, message: 'Server error.' });
            }
        });

        /*
         * ============ AGENT REGISTRATION ============
         */
        app.post('/register-agent', async (req, res) => {
            const { name, pin, email, mobileNumber, nid } = req.body;
            try {
                // Check duplicates
                const emailExists = await agentsColl.findOne({ email });
                if (emailExists) {
                    return res.status(400).json({ success: false, message: 'Email already in use.' });
                }
                const phoneExists = await agentsColl.findOne({ mobileNumber });
                if (phoneExists) {
                    return res.status(400).json({ success: false, message: 'Mobile number already in use.' });
                }

                // Hash pin
                const hashedPin = await bcrypt.hash(pin, SALT_ROUNDS);
                const newAgent = {
                    name,
                    pin: hashedPin,
                    email,
                    mobileNumber,
                    nid,
                    balance: 100000,   // agent gets 100k
                    isApproved: false, // needs admin approval
                    isBlocked: false,
                    agentIncome: 0,    // total agent’s earned income
                    createdAt: new Date(),
                };

                const result = await agentsColl.insertOne(newAgent);
                if (!result.acknowledged) {
                    return res.status(500).json({ success: false, message: 'Failed to create agent.' });
                }
                const { pin: removed, ...rest } = newAgent;
                return res.status(201).json({ success: true, agent: { ...rest, _id: result.insertedId } });
            } catch (err) {
                console.error('Register agent error:', err);
                res.status(500).json({ success: false, message: 'Server error.' });
            }
        });

        /*
         * ============ LOGIN (USER / AGENT / ADMIN) ============
         */
        app.post('/login', async (req, res) => {
            const { emailOrMobile, pin } = req.body;
            try {
                // Attempt user collection first
                let foundUser = await usersColl.findOne({
                    $or: [{ email: emailOrMobile }, { mobileNumber: emailOrMobile }],
                });
                let role = 'User';
                let coll = usersColl;

                if (!foundUser) {
                    // If not found in users, check agents
                    foundUser = await agentsColl.findOne({
                        $or: [{ email: emailOrMobile }, { mobileNumber: emailOrMobile }],
                    });
                    if (foundUser) {
                        role = 'Agent';
                        coll = agentsColl;
                    } else {
                        // If not found in agents, check admin
                        foundUser = await adminsColl.findOne({
                            $or: [{ email: emailOrMobile }, { mobileNumber: emailOrMobile }],
                        });
                        if (foundUser) {
                            role = 'Admin';
                            coll = adminsColl;
                        }
                    }
                }

                if (!foundUser) {
                    return res.status(401).json({ success: false, message: 'Invalid credentials (not found)' });
                }

                // Compare pin
                const pinMatch = await bcrypt.compare(pin, foundUser.pin);
                if (!pinMatch) {
                    console.log(foundUser.pin)
                    return res.status(401).json({ success: false, message: 'Invalid credentials (wrong PIN)' });
                }

                // If agent is not approved
                if (role === 'Agent' && foundUser.isApproved === false) {
                    return res.status(403).json({ success: false, message: 'Agent not approved by admin yet.' });
                }
                // If blocked
                if (foundUser.isBlocked) {
                    return res.status(403).json({ success: false, message: 'Account is blocked.' });
                }

                // Build JWT
                const payload = {
                    _id: foundUser._id,
                    role, // "User", "Agent", or "Admin"
                };

                const token = jwt.sign(payload, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '5h' });
                // Send httpOnly cookie
                res
                    .cookie('token', token, {
                        httpOnly: true,
                        secure: false,
                        sameSite: 'strict',
                        maxAge: 5 * 60 * 60 * 1000,
                    })
                    .json({
                        success: true,
                        role,
                        user: {
                            _id: foundUser._id,
                            name: foundUser.name,
                            email: foundUser.email,
                            mobileNumber: foundUser.mobileNumber,
                            balance: foundUser.balance,
                            // Additional fields as needed
                        },
                    });
            } catch (err) {
                console.error('Login error:', err);
                console.log(emailOrMobile);
                res.status(500).json({ success: false, message: 'Server error.' });
            }
        });

        /*
         * ============ LOGOUT ============
         */
        app.post('/logout', (req, res) => {
            res.clearCookie('token').json({ success: true, message: 'Logged out.' });
        });

        /*
         * ============ GET PROFILE (User / Agent / Admin) ============
         */
        app.get('/profile', verifyToken, async (req, res) => {
            try {
                const { _id, role } = req.user;
                let coll;
                if (role === 'User') coll = usersColl;
                else if (role === 'Agent') coll = agentsColl;
                else coll = adminsColl; // 'Admin'

                const userDoc = await coll.findOne({ _id: new ObjectId(_id) });
                if (!userDoc) {
                    return res.status(404).json({ success: false, message: `${role} not found.` });
                }
                const { pin, ...rest } = userDoc;
                res.json({ success: true, user: rest, role });
            } catch (err) {
                console.error('Profile error:', err);
                res.status(500).json({ success: false, message: 'Server error.' });
            }
        });

        // Example: GET /users?accountType=User
        // Protected by verifyToken middleware
        app.get('/users', verifyToken, async (req, res) => {
            try {
                const { accountType } = req.query;

                // If using separate collections:
                // We only query the usersColl for "User" accounts
                if (accountType === 'User') {
                    // Project only name, mobileNumber (or add more fields as needed)
                    const projection = { name: 1, mobileNumber: 1 };
                    const users = await usersColl.find({}).project(projection).toArray();

                    return res.json({ success: true, users });
                }
                else {
                    // If no accountType or something else:
                    return res.json({ success: true, users: [] });
                }
            } catch (error) {
                console.error('Error in GET /users:', error);
                return res.status(500).json({
                    success: false,
                    message: 'Server error while fetching user contacts.'
                });
            }
        });


        /*
         * ============ SEND MONEY: USER => USER ============
         * (Adjust logic for your fee rules, admin earning, etc.)
         */
        app.post('/transactions/send-money', verifyToken, async (req, res) => {
            // Only a "User" can send money to another user?
            const { role, _id: senderId } = req.user;
            if (role !== 'User') {
                return res.status(403).json({ success: false, message: 'Only a user can send money.' });
            }

            const { recipientPhone, amount, pin, reference } = req.body;
            const numericAmount = Number(amount) || 0;
            if (numericAmount < 50) {
                return res.status(400).json({ success: false, message: 'Minimum amount is 50 Taka.' });
            }

            try {
                // 1) Find sender
                const sender = await usersColl.findOne({ _id: new ObjectId(senderId) });
                if (!sender) {
                    return res.status(404).json({ success: false, message: 'Sender not found.' });
                }
                // 2) Verify pin
                const pinMatch = await bcrypt.compare(pin, sender.pin);
                if (!pinMatch) {
                    return res.status(401).json({ success: false, message: 'Wrong PIN.' });
                }
                if (sender.isBlocked) {
                    return res.status(403).json({ success: false, message: 'Your account is blocked.' });
                }

                // 3) Find recipient user by phone
                const recipient = await usersColl.findOne({ mobileNumber: recipientPhone });
                if (!recipient) {
                    return res.status(404).json({ success: false, message: 'Recipient not found.' });
                }
                if (recipient.isBlocked) {
                    return res.status(403).json({ success: false, message: 'Recipient is blocked.' });
                }

                // 4) Compute fee if > 100
                let fee = 0;
                if (numericAmount > 100) fee = 5;

                // check sender has enough
                if (sender.balance < numericAmount + fee) {
                    return res.status(400).json({ success: false, message: 'Insufficient balance.' });
                }

                // 5) Deduct from sender
                const updatedSenderBal = sender.balance - (numericAmount + fee);

                // 6) Add to recipient
                const updatedRecipientBal = (recipient.balance || 0) + numericAmount;

                // 7) Admin takes 5 Taka or something from the fee
                // Suppose we have only 1 admin doc
                const adminDoc = await adminsColl.findOne({});
                if (!adminDoc) {
                    return res.status(500).json({ success: false, message: 'Admin record not found.' });
                }
                const updatedAdminBal = (adminDoc.adminIncome || 0) + fee;
                // Also track totalSystemMoney if needed
                const updatedTotalSystemMoney = (adminDoc.totalSystemMoney || 0) + fee; // or more complex logic

                // 8) Perform DB updates
                await usersColl.updateOne(
                    { _id: sender._id },
                    { $set: { balance: updatedSenderBal } }
                );
                await usersColl.updateOne(
                    { _id: recipient._id },
                    { $set: { balance: updatedRecipientBal } }
                );
                await adminsColl.updateOne(
                    { _id: adminDoc._id },
                    { $set: { adminIncome: updatedAdminBal, totalSystemMoney: updatedTotalSystemMoney } }
                );

                // 9) Insert transaction record
                const transactionId = new ObjectId().toString();
                const txDoc = {
                    transactionId,
                    senderId: sender._id,
                    senderPhone: sender.mobileNumber,
                    recipientId: recipient._id,
                    recipientPhone,
                    amount: numericAmount,
                    fee,
                    totalDeducted: numericAmount + fee,
                    reference: reference || '',
                    createdAt: new Date(),
                };
                await transactionsColl.insertOne(txDoc);

                // 10) Return success
                res.json({
                    success: true,
                    message: 'Send money success',
                    transactionId,
                    senderBalance: updatedSenderBal,
                    receiverBalance: updatedRecipientBal,
                });
            } catch (err) {
                console.error('Send-money error:', err);
                res.status(500).json({ success: false, message: 'Server error.' });
            }
        });

        // app.post('/transactions/cash-out', verifyToken, async (req, res) => {
        app.post('/transactions/cash-out', verifyToken, async (req, res) => {
            try {
                // The user must be 'User' role
                if (req.user.role !== 'User') {
                    return res.status(403).json({ success: false, message: 'Only users can cash out.' });
                }

                const userId = req.user._id; // from JWT
                const { agentPhone, amount, pin, reference } = req.body;
                const numericAmount = Number(amount) || 0;

                // 1) Basic checks
                if (numericAmount <= 0) {
                    return res.status(400).json({ success: false, message: 'Invalid amount.' });
                }

                // Calculate 1.5% fee
                const fee = +(numericAmount * 0.015).toFixed(2);

                // 2) Find user in the 'users' collection
                const userDoc = await usersColl.findOne({ _id: new ObjectId(userId) });
                if (!userDoc) {
                    return res.status(404).json({ success: false, message: 'User not found.' });
                }

                // Verify pin
                const pinMatch = await bcrypt.compare(pin, userDoc.pin);
                if (!pinMatch) {
                    return res.status(401).json({ success: false, message: 'Invalid PIN.' });
                }

                // Check user balance
                if (userDoc.balance < numericAmount + fee) {
                    return res.status(400).json({ success: false, message: 'Insufficient balance.' });
                }

                // 3) Find agent by phone in the 'agents' collection
                const agentDoc = await agentsColl.findOne({ mobileNumber: agentPhone });
                if (!agentDoc) {
                    return res.status(404).json({ success: false, message: 'Agent not found.' });
                }
                if (!agentDoc.isApproved) {
                    return res.status(403).json({ success: false, message: 'Agent is not approved.' });
                }
                if (agentDoc.isBlocked) {
                    return res.status(403).json({ success: false, message: 'Agent is blocked.' });
                }

                // 4) Split the 1.5% fee => 1% to agent, 0.5% to admin
                const agentIncomePart = +(numericAmount * 0.01).toFixed(2); // 1%
                const adminIncomePart = +(numericAmount * 0.005).toFixed(2); // 0.5%

                // (Remainder of fee if rounding error)
                // e.g. fee = 1.85, agentIncomePart=1.00, adminIncomePart=0.5 => total 1.5 => 0.35 difference
                // For simplicity, we can put that difference to admin or just ignore beyond 2 decimals.

                // 5) Deduct from user
                const updatedUserBalance = userDoc.balance - (numericAmount + fee);

                // 6) Agent gets the "amount" from user
                const updatedAgentBalance = agentDoc.balance + numericAmount;

                // Also, agent's "agentIncome" + agentIncomePart
                const updatedAgentIncome = (agentDoc.agentIncome || 0) + agentIncomePart;

                // 7) Admin gets the 0.5% portion
                // Find admin doc in "admins" collection (assuming only 1 admin doc)
                const adminDoc = await adminsColl.findOne({});
                if (!adminDoc) {
                    return res.status(500).json({ success: false, message: 'Admin record not found.' });
                }
                const updatedAdminIncome = (adminDoc.adminIncome || 0) + adminIncomePart;
                // Also, totalSystemMoney if you track that
                const updatedTotalSystemMoney =
                    (adminDoc.totalSystemMoney || 0) + fee; // total fee goes into system?

                // 8) Perform DB updates (preferably in a DB transaction if your environment supports)
                // Example:
                await usersColl.updateOne(
                    { _id: userDoc._id },
                    { $set: { balance: updatedUserBalance } }
                );
                await agentsColl.updateOne(
                    { _id: agentDoc._id },
                    { $set: { balance: updatedAgentBalance, agentIncome: updatedAgentIncome } }
                );
                await adminsColl.updateOne(
                    { _id: adminDoc._id },
                    {
                        $set: {
                            adminIncome: updatedAdminIncome,
                            totalSystemMoney: updatedTotalSystemMoney,
                        },
                    }
                );

                // 9) Insert transaction record in "transactions"
                const transactionId = new ObjectId().toString();
                const txDoc = {
                    transactionId,
                    type: "cash-out",
                    userId: userDoc._id,
                    userPhone: userDoc.mobileNumber,
                    agentId: agentDoc._id,
                    agentPhone,
                    amount: numericAmount,
                    fee,
                    userBalanceAfter: updatedUserBalance,
                    agentBalanceAfter: updatedAgentBalance,
                    reference: reference || "",
                    createdAt: new Date(),
                };
                await transactionsColl.insertOne(txDoc);

                // 10) Return success response
                res.json({
                    success: true,
                    message: "Cash-out successful",
                    transactionId,
                    userBalance: updatedUserBalance,
                    agentBalance: updatedAgentBalance,
                });
            } catch (error) {
                console.error("Cash-out error:", error);
                res.status(500).json({ success: false, message: "Failed to cash out" });
            }
        });

        // Example: GET /agents?approved=true
        app.get('/agents', verifyToken, async (req, res) => {
            try {
                const { approved } = req.query;
                let query = {};
                if (approved === "true") {
                    query.isApproved = true;
                }
                // Also can ensure isBlocked = false
                query.isBlocked = false;

                const projection = { name: 1, mobileNumber: 1, agentIncome: 1 };
                const agents = await agentsColl.find(query).project(projection).toArray();

                return res.json({ success: true, agents });
            } catch (error) {
                console.error('GET /agents error:', error);
                res.status(500).json({ success: false, message: 'Server error' });
            }
        });



        /* Additional endpoints for:
           - agent cash-in
           - user cash-out
           - admin approvals
           etc. 
           following the same pattern, each with its own logic.
        */
    } catch (err) {
        console.error('DB connection error:', err);
    }
}

run().catch(console.dir);

app.get('/', (req, res) => {
    res.send('Hello, LenDen Server with separate collections!');
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
