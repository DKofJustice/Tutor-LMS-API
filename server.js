const express = require('express')
const mysql = require('mysql2')
const cors = require('cors')
const bodyParser = require('body-parser')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const cookieParser = require('cookie-parser');

require('dotenv').config()

const app = express()

app.use(cors())
app.use(express.json());
app.use(bodyParser.json());
app.use(cookieParser());

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '2003nuva',
    database: 'tutorlms'
})

// Register user in the Database
app.post('/register', (req, res) => {
    const { email, password } = req.body;
    const saltRounds = 10;

    const sqlEmail = "SELECT * from users WHERE username = ?"

    db.query(sqlEmail, [email], (err, results) => {
        if (err) {
            console.error('Could not validate email, please try again' + err);
            return res.status(500).send('Could not validate email, please try again');
        } else if(results.length > 0) {
            return res.status(400).send("Email already exists");
        }
        
    })

    bcrypt.hash(password, saltRounds, (err, hash) => {
        if (err) {
            console.error("Error hashing password: " + err);
            res.status(500).send("Registration failed");
        } else {
            const sql = "INSERT INTO users (username, password) VALUES (?, ?)";
            const values = [email, hash];

            db.query(sql, values, (err) => {
                if (err) {
                    console.error('Error registering user: ' + err);
                    res.status(500).send("Registration failed");
                } else {
                    res.status(200).send("Registration successful");
                }
            })
        }
    })
})

// Authenticate, log the user in and generate JWT token
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const sql = 'SELECT * FROM users WHERE username = ?';

    db.query(sql, [email], (err, results) => {
        if (err) {
          console.error('Could not validate email: ' + err);
          return res.status(500).send('Could not validate email, please try again');
        }

        if (results.length === 0) {
            return res.status(401).send('Email not found');
        }

        const hashedPassword = results[0].password;
        bcrypt.compare(password, hashedPassword, (compareErr, isPasswordMatch) => {
        if (compareErr) {
            console.error('Error comparing passwords: ' + compareErr);
            return res.status(500).send('Authentication failed');
        }

        if (!isPasswordMatch) {
            return res.status(401).send('Invalid password'); // Incorrect password
        }

        // Password is correct, create and send a JWT token
        const accessToken = jwt.sign({ email: email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '3h' });

        res.status(200).json({accessToken, email})
        });
    })
})

app.listen(8081, () => {
    console.log("server started...")
})