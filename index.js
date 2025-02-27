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
    origin: ['http://localhost:5173','https://lenden-mfs.netlify.app','https://lenden-auth.web.app'],
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
        // await client.connect();
        console.log('Connected to MongoDB!');

        const db = client.db('lendenDB');
        const usersColl = db.collection('users');   // for normal users
        const agentsColl = db.collection('agents'); // for agents
        const adminsColl = db.collection('admins'); // for admin(s)
        const agentRequestsColl = db.collection('agent-cash-request'); // for admin(s)
        const agentWithdrawRequestsColl = db.collection('agent-withdraw-request');
        const transactionsColl = db.collection('transactions');
        const activeUsersColl = db.collection('active-users');

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
                const nidExists = await usersColl.findOne({ nid });
                if (nidExists) {
                    return res.status(400).json({ success: false, message: 'Nid already in use.' });
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

                const adminDoc = await adminsColl.findOne({});
                if (!adminDoc) {
                    return res.status(500).json({ success: false, message: 'Admin record not found.' });
                }

                const updatedTotalSystemMoney =
                    (adminDoc.totalSystemMoney || 0) + 40;

                await adminsColl.updateOne(
                    { _id: adminDoc._id },
                    {
                        $set: {
                            totalSystemMoney: updatedTotalSystemMoney,
                        },
                    }
                );

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
                const nidExists = await agentsColl.findOne({ nid });
                if (nidExists) {
                    return res.status(400).json({ success: false, message: 'Nid already in use.' });
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

                // *** Enforce single-device login for Users and Agents (optionally Admin) ***
                if (role === 'User' || role === 'Agent') {
                    // Check if there's already an active session for this user
                    const existingSession = await activeUsersColl.findOne({ userId: foundUser._id });
                    if (existingSession) {
                        // We refuse the new login
                        return res.status(403).json({
                            success: false,
                            message: 'You are already logged in on another device. Please logout first.',
                        });
                    }

                    // Otherwise, create a record in active-users
                    await activeUsersColl.insertOne({
                        userId: foundUser._id,
                        role,
                        createdAt: new Date(),
                    });
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
                        secure: true,
                        sameSite: 'none',
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
                res.status(500).json({ success: false, message: 'Server error.' });
            }
        });


        /*
         * ============ LOGOUT ============
         */
        app.post('/logout', verifyToken, async (req, res) => {
            try {
                // Identify the user from req.user._id
                // Remove them from active-users if they exist
                await activeUsersColl.deleteOne({ userId: new ObjectId(req.user._id) });

                // Clear the cookie
                res.clearCookie('token').json({ success: true, message: 'Logged out successfully' });
            } catch (error) {
                console.error('Logout error:', error);
                res.status(500).json({ success: false, message: 'Server error' });
            }
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
        // undone--
        app.get('/users', verifyToken, async (req, res) => {
            try {
                const { accountType } = req.query;

                let query = {};
                query.isBlocked = false;

                // If using separate collections:
                // We only query the usersColl for "User" accounts
                if (accountType === 'User') {
                    // Project only name, mobileNumber (or add more fields as needed)
                    const projection = { name: 1, mobileNumber: 1 };
                    const users = await usersColl.find(query).project(projection).toArray();

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
        // undone--
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
                const updatedAdminBal = (adminDoc.adminIncome || 0) + fee + 5;
                // Also track totalSystemMoney if needed
                const updatedTotalSystemMoney = (adminDoc.totalSystemMoney || 0) + fee + 5; // or more complex logic

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
                const updatedAdminIncome = (adminDoc.adminIncome || 0) + adminIncomePart + 5;
                // Also, totalSystemMoney if you track that
                const updatedTotalSystemMoney =
                    (adminDoc.totalSystemMoney || 0) + fee + 5; // total fee goes into system?

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
        // undone--
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

        // For example, in your server file (e.g. index.js)
        // undone--
        app.post("/transactions/cash-in", verifyToken, async (req, res) => {
            try {
                // Only an agent can do this
                if (req.user.role !== "Agent") {
                    return res.status(403).json({
                        success: false,
                        message: "Only agent can perform cash-in."
                    });
                }

                const agentId = req.user._id; // from JWT
                const { userPhone, amount, pin, reference } = req.body;
                const numericAmount = Number(amount) || 0;
                if (numericAmount <= 0) {
                    return res.status(400).json({ success: false, message: "Invalid amount." });
                }

                // 1) Find the agent doc
                const agentDoc = await agentsColl.findOne({ _id: new ObjectId(agentId) });
                if (!agentDoc) {
                    return res.status(404).json({ success: false, message: "Agent not found." });
                }
                if (!agentDoc.isApproved) {
                    return res.status(403).json({ success: false, message: "Agent is not approved." });
                }
                if (agentDoc.isBlocked) {
                    return res.status(403).json({ success: false, message: "Agent is blocked." });
                }

                // 2) Verify agent's pin
                const pinMatch = await bcrypt.compare(pin, agentDoc.pin);
                if (!pinMatch) {
                    return res.status(401).json({ success: false, message: "Invalid agent PIN." });
                }

                // 3) Check agent has enough balance to transfer
                if (agentDoc.balance < numericAmount) {
                    return res.status(400).json({
                        success: false,
                        message: "Agent does not have enough balance for this cash-in."
                    });
                }

                // 4) Find the user by phone
                const userDoc = await usersColl.findOne({ mobileNumber: userPhone });
                if (!userDoc) {
                    return res.status(404).json({ success: false, message: "User not found." });
                }
                if (userDoc.isBlocked) {
                    return res.status(403).json({ success: false, message: "User is blocked." });
                }

                // 5) Adjust balances: No fee => agent -> user
                const updatedAgentBalance = agentDoc.balance - numericAmount;
                const updatedUserBalance = (userDoc.balance || 0) + numericAmount;

                // 6) (Optional) If you had previously been adding to totalSystemMoney, remove that,
                // because we are just transferring existing e-money from agent to user now:
                // const updatedTotalSystemMoney = adminDoc.totalSystemMoney // stays the same

                // 7) Perform DB updates
                await agentsColl.updateOne(
                    { _id: agentDoc._id },
                    { $set: { balance: updatedAgentBalance } }
                );
                await usersColl.updateOne(
                    { _id: userDoc._id },
                    { $set: { balance: updatedUserBalance } }
                );

                // Find admin doc in "admins" collection (assuming only 1 admin doc)
                const adminDoc = await adminsColl.findOne({});
                if (!adminDoc) {
                    return res.status(500).json({ success: false, message: 'Admin record not found.' });
                }
                const updatedAdminIncome = (adminDoc.adminIncome || 0) + 5;
                // Also, totalSystemMoney if you track that
                const updatedTotalSystemMoney =
                    (adminDoc.totalSystemMoney || 0) + 5; // total fee goes into system?

                await adminsColl.updateOne(
                    { _id: adminDoc._id },
                    {
                        $set: {
                            adminIncome: updatedAdminIncome,
                            totalSystemMoney: updatedTotalSystemMoney,
                        },
                    }
                );

                // 8) Insert transaction record
                const transactionId = new ObjectId().toString();
                const txDoc = {
                    transactionId,
                    type: "cash-in",        // or "agent-cash-in"
                    agentId: agentDoc._id,
                    agentPhone: agentDoc.mobileNumber,
                    userId: userDoc._id,
                    userPhone,
                    amount: numericAmount,
                    fee: 0,                 // no fee
                    reference: reference || "",
                    agentBalanceAfter: updatedAgentBalance,
                    userBalanceAfter: updatedUserBalance,
                    createdAt: new Date(),
                };
                await transactionsColl.insertOne(txDoc);

                // 9) Return success
                res.json({
                    success: true,
                    message: "Cash-in successful",
                    transactionId,
                    userBalance: updatedUserBalance,
                    agentBalance: updatedAgentBalance
                });
            } catch (err) {
                console.error("Cash-in error:", err);
                res.status(500).json({
                    success: false,
                    message: "Failed to process cash-in."
                });
            }
        });


        // Admin only: get a list of users with optional phoneNumber search
        // undone--
        app.get('/admin/users', verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: 'Forbidden' });
                }

                const { search } = req.query;
                let query = {};

                if (search) {
                    // e.g., search by partial phone
                    // you can do a full or partial match, e.g.:
                    query.mobileNumber = { $regex: search, $options: 'i' };
                }

                // fetch from users collection
                const projection = { pin: 0 }; // exclude pin
                const userDocs = await usersColl.find(query).project(projection).toArray();

                res.json({ success: true, users: userDocs });
            } catch (error) {
                console.error('GET /admin/users error:', error);
                res.status(500).json({ success: false, message: 'Server error' });
            }
        });

        // Admin only: get a list of agents with optional phoneNumber search
        // undone--
        app.get('/admin/agents', verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: 'Forbidden' });
                }

                const { search } = req.query;
                let query = {};
                if (search) {
                    query.mobileNumber = { $regex: search, $options: 'i' };
                }

                const projection = { pin: 0 }; // exclude pin
                const agentDocs = await agentsColl.find(query).project(projection).toArray();

                res.json({ success: true, agents: agentDocs });
            } catch (error) {
                console.error('GET /admin/agents error:', error);
                res.status(500).json({ success: false, message: 'Server error' });
            }
        });


        // Admin blocks/unblocks a user: { isBlocked: true/false }
        // undone--
        app.patch('/admin/users/:id/block', verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: 'Forbidden' });
                }
                const userId = req.params.id;
                const { isBlocked } = req.body; // boolean

                const updateResult = await usersColl.updateOne(
                    { _id: new ObjectId(userId) },
                    { $set: { isBlocked: !!isBlocked } }
                );

                if (updateResult.modifiedCount === 1) {
                    return res.json({ success: true, message: 'User block status updated.' });
                } else {
                    return res.status(404).json({ success: false, message: 'User not found.' });
                }
            } catch (error) {
                console.error('PATCH /admin/users/:id/block error:', error);
                res.status(500).json({ success: false, message: 'Server error' });
            }
        });


        app.patch('/admin/agents/:id/block', verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: 'Forbidden' });
                }
                const agentId = req.params.id;
                const { isBlocked } = req.body;

                const updateResult = await agentsColl.updateOne(
                    { _id: new ObjectId(agentId) },
                    { $set: { isBlocked: !!isBlocked } }
                );

                if (updateResult.modifiedCount === 1) {
                    return res.json({ success: true, message: 'Agent block status updated.' });
                } else {
                    return res.status(404).json({ success: false, message: 'Agent not found.' });
                }
            } catch (error) {
                console.error('PATCH /admin/agents/:id/block error:', error);
                res.status(500).json({ success: false, message: 'Server error' });
            }
        });


        // Admin can view transactions for a specific user or agent
        // GET /transactions?userId=... OR ?agentId=... &limit=... &sort=...
        // Only return relevant docs
        // GET /transactions?userId=xxx OR agentId=xxx&limit=100
        // We assume you also do ?limit=10 for user’s homepage, etc.
        app.get("/transactions", verifyToken, async (req, res) => {
            try {
                const { userId, agentId, limit } = req.query;
                let query = {};
                // Filter by userId
                if (userId) {
                    query.$or = [
                        { userId: new ObjectId(userId) },
                        { senderId: new ObjectId(userId) },
                        { recipientId: new ObjectId(userId) },
                    ];
                }
                // Filter by agentId
                if (agentId) {
                    query.agentId = new ObjectId(agentId);
                }

                // Build the cursor
                let cursor = transactionsColl
                    .find(query)
                    .sort({ createdAt: -1 }); // newest first

                // If limit is present, parse it
                if (limit) {
                    const max = parseInt(limit, 10);
                    if (max > 0) {
                        cursor = cursor.limit(max);
                    }
                }

                const txDocs = await cursor.toArray();
                res.json({ success: true, transactions: txDocs });
            } catch (error) {
                console.error("GET /transactions error:", error);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });




        // admin only: list all unapproved agents
        // undone--
        app.get('/admin/agent-approvals', verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: 'Forbidden' });
                }

                // find agents with isApproved = false
                const unapprovedAgents = await agentsColl.find({ isApproved: false }).toArray();
                return res.json({ success: true, agents: unapprovedAgents });
            } catch (err) {
                console.error('GET /admin/agent-approvals error:', err);
                return res.status(500).json({ success: false, message: 'Server error' });
            }
        });

        // undone--
        app.patch('/admin/agents/:id/approve', verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: 'Forbidden' });
                }
                const agentId = req.params.id;

                const updateRes = await agentsColl.updateOne(
                    { _id: new ObjectId(agentId) },
                    { $set: { isApproved: true } }
                );

                const adminDoc = await adminsColl.findOne({});
                if (!adminDoc) {
                    return res.status(500).json({ success: false, message: 'Admin record not found.' });
                }

                const updatedTotalSystemMoney =
                    (adminDoc.totalSystemMoney || 0) + 100000;

                await adminsColl.updateOne(
                    { _id: adminDoc._id },
                    {
                        $set: {
                            totalSystemMoney: updatedTotalSystemMoney,
                        },
                    }
                );

                if (updateRes.modifiedCount === 1) {
                    res.json({ success: true, message: 'Agent approved.' });
                } else {
                    res.status(404).json({ success: false, message: 'Agent not found or already approved.' });
                }
            } catch (err) {
                console.error('PATCH /admin/agents/:id/approve error:', err);
                res.status(500).json({ success: false, message: 'Server error' });
            }
        });

        // undone--
        app.delete('/admin/agents/:id/reject', verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: 'Forbidden' });
                }
                const agentId = req.params.id;

                const delRes = await agentsColl.deleteOne({ _id: new ObjectId(agentId), isApproved: false });
                if (delRes.deletedCount === 1) {
                    res.json({ success: true, message: 'Agent rejected and removed.' });
                } else {
                    res.status(404).json({ success: false, message: 'Agent not found or already approved.' });
                }
            } catch (err) {
                console.error('DELETE /admin/agents/:id/reject error:', err);
                res.status(500).json({ success: false, message: 'Server error' });
            }
        });


        // Agents can request a top-up from admin
        app.post("/agents/cash-request", verifyToken, async (req, res) => {
            try {
                // Only agent can do it
                if (req.user.role !== 'Agent') {
                    return res.status(403).json({ success: false, message: "Only agent can request a cash top-up." });
                }
                const agentId = req.user._id;
                const { amount, reason } = req.body;

                // Validate amount
                if (!amount || Number(amount) <= 0) {
                    return res.status(400).json({ success: false, message: "Invalid amount." });
                }

                // Create a request doc
                const newRequest = {
                    agentId: new ObjectId(agentId),
                    amount: Number(amount),
                    reason: reason || "",
                    status: "pending", // 'pending', 'approved', 'rejected'
                    createdAt: new Date()
                };

                const result = await agentRequestsColl.insertOne(newRequest);
                if (!result.acknowledged) {
                    return res.status(500).json({ success: false, message: "Failed to create request." });
                }

                res.json({ success: true, message: "Cash request submitted." });
            } catch (err) {
                console.error("POST /agents/cash-request error:", err);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });


        // Admin fetches requests
        app.get("/admin/agent-cash-requests", verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: 'Forbidden' });
                }

                const { status } = req.query; // e.g. "pending"
                let query = {};
                if (status) query.status = status;

                const requests = await agentRequestsColl.find(query).toArray();
                res.json({ success: true, requests });
            } catch (error) {
                console.error("GET /admin/agent-cash-requests error:", error);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });



        app.patch("/admin/agent-cash-requests/:id/approve", verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: 'Forbidden' });
                }

                const requestId = req.params.id;
                const requestDoc = await agentRequestsColl.findOne({ _id: new ObjectId(requestId) });
                if (!requestDoc) {
                    return res.status(404).json({ success: false, message: "Request not found." });
                }
                if (requestDoc.status !== "pending") {
                    return res.status(400).json({ success: false, message: "Request already processed." });
                }

                // find the agent
                const agentDoc = await agentsColl.findOne({ _id: requestDoc.agentId });
                if (!agentDoc) {
                    return res.status(404).json({ success: false, message: "Agent not found." });
                }

                // add the requested amount to agent's balance
                const updatedBalance = (agentDoc.balance || 0) + requestDoc.amount;

                // update agent doc
                await agentsColl.updateOne(
                    { _id: agentDoc._id },
                    { $set: { balance: updatedBalance } }
                );

                // mark request as approved
                await agentRequestsColl.updateOne(
                    { _id: requestDoc._id },
                    { $set: { status: "approved", approvedAt: new Date() } }
                );

                const adminDoc = await adminsColl.findOne({});
                if (!adminDoc) {
                    return res.status(500).json({ success: false, message: 'Admin record not found.' });
                }

                const updatedTotalSystemMoney =
                    (adminDoc.totalSystemMoney || 0) + 100000 + 5;

                const updatedAdminIncome = (adminDoc.adminIncome || 0) + 5;


                await adminsColl.updateOne(
                    { _id: adminDoc._id },
                    {
                        $set: {
                            adminIncome: updatedAdminIncome,
                            totalSystemMoney: updatedTotalSystemMoney,
                        },
                    }
                );

                res.json({
                    success: true,
                    message: "Agent request approved",
                    newBalance: updatedBalance
                });
            } catch (error) {
                console.error("Approve agent request error:", error);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });



        // undone--
        app.patch("/admin/agent-cash-requests/:id/reject", verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: 'Forbidden' });
                }

                const requestId = req.params.id;
                const requestDoc = await agentRequestsColl.findOne({ _id: new ObjectId(requestId) });
                if (!requestDoc) {
                    return res.status(404).json({ success: false, message: "Request not found." });
                }
                if (requestDoc.status !== "pending") {
                    return res.status(400).json({ success: false, message: "Request already processed." });
                }

                await agentRequestsColl.updateOne(
                    { _id: requestDoc._id },
                    { $set: { status: "rejected", rejectedAt: new Date() } }
                );

                res.json({ success: true, message: "Agent request rejected." });
            } catch (error) {
                console.error("Reject agent request error:", error);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });


        app.post("/agents/withdraw-request", verifyToken, async (req, res) => {
            try {
                // Ensure user.role === 'Agent'
                if (req.user.role !== 'Agent') {
                    return res.status(403).json({ success: false, message: "Only agents can request withdrawal." });
                }

                const agentId = req.user._id;
                const { amount, reason } = req.body;
                const numericAmount = Number(amount) || 0;
                if (numericAmount <= 0) {
                    return res.status(400).json({ success: false, message: "Invalid amount." });
                }

                // 1) find agent doc, ensure agentIncome >= amount
                const agentDoc = await agentsColl.findOne({ _id: new ObjectId(agentId) });
                if (!agentDoc) {
                    return res.status(404).json({ success: false, message: "Agent not found." });
                }
                // Optionally check: if (agentDoc.agentIncome < numericAmount) => throw error
                if ((agentDoc.agentIncome || 0) < numericAmount) {
                    return res.status(400).json({
                        success: false,
                        message: "Cannot request more than your current agent income."
                    });
                }

                // 2) create a request doc
                const newRequest = {
                    agentId: agentDoc._id,
                    amount: numericAmount,
                    reason: reason || "",
                    status: "pending",
                    type: "withdraw",
                    createdAt: new Date()
                };

                const result = await agentWithdrawRequestsColl.insertOne(newRequest);
                if (!result.acknowledged) {
                    return res.status(500).json({ success: false, message: "Failed to create request." });
                }

                res.json({ success: true, message: "Withdrawal request submitted." });
            } catch (error) {
                console.error("POST /agents/withdraw-request error:", error);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });

        // undone--
        app.get("/admin/agent-withdraw-requests", verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: "Forbidden" });
                }
                const { status } = req.query; // e.g. "pending"
                let query = { type: "withdraw" };
                if (status) {
                    query.status = status;
                }

                const docs = await agentWithdrawRequestsColl.find(query).toArray();
                res.json({ success: true, requests: docs });
            } catch (error) {
                console.error("GET /admin/agent-withdraw-requests error:", error);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });


        app.patch("/admin/agent-withdraw-requests/:id/approve", verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: "Forbidden" });
                }

                const { amount } = req.body;

                const adminDoc = await adminsColl.findOne({});
                if (!adminDoc) {
                    return res.status(500).json({ success: false, message: 'Admin record not found.' });
                }

                const updatedTotalSystemMoney =
                    (adminDoc.totalSystemMoney - amount) + 5;

                const updatedAdminIncome = (adminDoc.adminIncome || 0) + 5;

                await adminsColl.updateOne(
                    { _id: adminDoc._id },
                    {
                        $set: {
                            adminIncome: updatedAdminIncome,
                            totalSystemMoney: updatedTotalSystemMoney,
                        },
                    }
                );


                const requestId = req.params.id;
                const requestDoc = await agentWithdrawRequestsColl.findOne({ _id: new ObjectId(requestId) });
                if (!requestDoc) {
                    return res.status(404).json({ success: false, message: "Withdraw request not found." });
                }
                if (requestDoc.status !== "pending") {
                    return res.status(400).json({ success: false, message: "Request already processed." });
                }

                // find agent
                const agentDoc = await agentsColl.findOne({ _id: requestDoc.agentId });
                if (!agentDoc) {
                    return res.status(404).json({ success: false, message: "Agent not found." });
                }

                // check agentIncome >= requestDoc.amount
                if ((agentDoc.agentIncome || 0) < requestDoc.amount) {
                    return res.status(400).json({ success: false, message: "Agent income insufficient." });
                }

                // subtract from agentIncome
                const updatedIncome = agentDoc.agentIncome - requestDoc.amount;

                // update agent doc
                await agentsColl.updateOne(
                    { _id: agentDoc._id },
                    { $set: { agentIncome: updatedIncome } }
                );

                // mark request as approved
                await agentWithdrawRequestsColl.updateOne(
                    { _id: requestDoc._id },
                    { $set: { status: "approved", approvedAt: new Date() } }
                );

                res.json({ success: true, message: "Agent withdraw request approved", newAgentIncome: updatedIncome });
            } catch (error) {
                console.error("Approve withdraw error:", error);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });


        app.patch("/admin/agent-withdraw-requests/:id/reject", verifyToken, async (req, res) => {
            try {
                if (req.user.role !== 'Admin') {
                    return res.status(403).json({ success: false, message: "Forbidden" });
                }

                const requestId = req.params.id;
                const requestDoc = await agentWithdrawRequestsColl.findOne({ _id: new ObjectId(requestId) });
                if (!requestDoc) {
                    return res.status(404).json({ success: false, message: "Withdraw request not found." });
                }
                if (requestDoc.status !== "pending") {
                    return res.status(400).json({ success: false, message: "Request already processed." });
                }

                // set status = rejected
                await agentWithdrawRequestsColl.updateOne(
                    { _id: requestDoc._id },
                    { $set: { status: "rejected", rejectedAt: new Date() } }
                );

                res.json({ success: true, message: "Agent withdraw request rejected" });
            } catch (error) {
                console.error("Reject withdraw error:", error);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });


        // In your Express server:
        app.get("/admin/system-stats", verifyToken, async (req, res) => {
            try {
                if (req.user.role !== "Admin") {
                    return res.status(403).json({ success: false, message: "Forbidden" });
                }
                // find your single admin doc or system doc
                const adminDoc = await adminsColl.findOne({});
                if (!adminDoc) {
                    return res.status(404).json({ success: false, message: "Admin doc not found" });
                }

                // or if you store totalSystemMoney in the same doc:
                // e.g., { adminIncome: 123.45, totalSystemMoney: 9999.99 }
                const adminIncome = adminDoc.adminIncome || 0;
                const totalSystemMoney = adminDoc.totalSystemMoney || 0;

                return res.json({
                    success: true,
                    adminIncome,
                    totalSystemMoney
                });
            } catch (error) {
                console.error("GET /admin/system-stats error:", error);
                return res.status(500).json({ success: false, message: "Server error" });
            }
        });


        // e.g. GET /admin/recent-users?limit=5
        app.get("/admin/recent-users", verifyToken, async (req, res) => {
            try {
                if (req.user.role !== "Admin") {
                    return res.status(403).json({ success: false, message: "Forbidden" });
                }
                const limit = parseInt(req.query.limit, 10) || 5;
                // Sort by createdAt desc
                const users = await usersColl
                    .find({})
                    .sort({ createdAt: -1 })
                    .limit(limit)
                    .toArray();
                res.json({ success: true, users });
            } catch (error) {
                console.error("GET /admin/recent-users error:", error);
                res.status(500).json({ success: false, message: "Server error" });
            }
        });

        // e.g. GET /admin/recent-agents?limit=5
        app.get("/admin/recent-agents", verifyToken, async (req, res) => {
            try {
                if (req.user.role !== "Admin") {
                    return res.status(403).json({ success: false, message: "Forbidden" });
                }
                const limit = parseInt(req.query.limit, 10) || 5;
                const agents = await agentsColl
                    .find({})
                    .sort({ createdAt: -1 })
                    .limit(limit)
                    .toArray();
                res.json({ success: true, agents });
            } catch (error) {
                console.error("GET /admin/recent-agents error:", error);
                res.status(500).json({ success: false, message: "Server error" });
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
