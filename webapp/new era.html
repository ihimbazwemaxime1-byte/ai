const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { PrismaClient } = require('@prisma/client');

const app = express();
const prisma = new PrismaClient();

// Middleware to parse incoming JSON requests
app.use(express.json());

// Secret key for signing tokens (In production, this comes from an .env file)
const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

/**
 * ROUTE 1: REGISTER A NEW PATIENT
 * Securely hashes the password before saving to PostgreSQL.
 */
app.post('/register', async (req, res) => {
    try {
        const { email, password, fullName } = req.body;

        // 1. Check if the user already exists
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already in use.' });
        }

        // 2. Hash the password (Salt rounds = 10)
        const hashedPassword = await bcrypt.hash(password, 10);

        // 3. Save the new user to the database
        const newUser = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
                fullName,
                role: 'PATIENT'
            }
        });

        res.status(201).json({ message: 'Patient registered successfully.', userId: newUser.id });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

/**
 * ROUTE 2: SECURE LOGIN
 * Verifies credentials and issues a JSON Web Token (JWT).
 */
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Find the user in the database
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // 2. Compare the provided password against the stored hash
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid email or password.' });
        }

        // 3. Generate the JWT (The digital ID card)
        const token = jwt.sign(
            { userId: user.id, role: user.role }, 
            JWT_SECRET, 
            { expiresIn: '8h' } // Token expires in 8 hours to prevent session hijacking
        );

        res.status(200).json({
            message: 'Login successful.',
            token,
            user: {
                id: user.id,
                fullName: user.fullName,
                role: user.role
            }
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error.' });
    }
});

// Start the microservice
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
    console.log(`Auth Service is securely running on port ${PORT}`);
});