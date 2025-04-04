const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cryptoModule = require('crypto');
const nodemailer = require('nodemailer');
const process = require('process');


const app = express();
const db = new sqlite3.Database(':memory:');

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

const SECRET_KEY = cryptoModule.randomBytes(32); 
const IV_LENGTH = 16;
const gmail = process.env.EMAIL
const email_password = process.env.PASSWORD

function encrypt(text) {
    const iv = cryptoModule.randomBytes(IV_LENGTH);
    const cipher = cryptoModule.createCipheriv('aes-256-cbc', SECRET_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted; 
}

function decrypt(text) {
    try {
        const parts = text.split(':');
        const iv = Buffer.from(parts.shift(), 'hex');
        const encryptedText = Buffer.from(parts.join(':'), 'hex');
        const decipher = cryptoModule.createDecipheriv('aes-256-cbc', SECRET_KEY, iv);
        let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (error) {
        return 'Decryption failed';
    }
}


const { generateKeyPairSync, sign, verify } = cryptoModule;
const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});


function generateSignature(message) {
    const signature = sign('sha256', Buffer.from(message), privateKey);
    return signature.toString('hex');
}


function verifySignature(message, signature) {
    return verify('sha256', Buffer.from(message), publicKey, Buffer.from(signature, 'hex'));
}

db.serialize(() => {
    db.run('CREATE TABLE users (name TEXT, password TEXT)');
});

app.get('/', (req, res) => {
    db.all('SELECT * FROM users', [], (err, rows) => {
        if (err) {
            return res.status(500).send('Database error');
        }
        res.render('index', { users: rows });
    });
});

app.post('/add-user', async (req, res) => {
    const { name, password } = req.body;
    if (!name || !password) {
        return res.redirect('/');
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const encryptedName = encrypt(name);
        db.run('INSERT INTO users (name, password) VALUES (?, ?)', [encryptedName, hashedPassword], (err) => {
            if (err) {
                return res.status(500).send('Database error');
            }
            res.redirect('/');
        });
    } catch (err) {
        res.status(500).send('Error encrypting name');
    }
});

app.post('/decrypt', async (req, res) => {
    const globalPassword = req.body.globalPassword;
    if (!globalPassword) {
        return res.status(400).send('Global password is required');
    }
    db.all('SELECT * FROM users', [], async (err, rows) => {
        if (err) {
            return res.status(500).send('Database error');
        }
        const decryptedUsers = await Promise.all(
            rows.map(async (user) => {
                const isMatch = await bcrypt.compare(globalPassword, user.password);
                return {
                    name: isMatch ? decrypt(user.name) : 'not your content', // Decrypt only if password matches
                    password: isMatch ? globalPassword : 'not your content',
                };
            })
        );
        res.render('index', { users: decryptedUsers });
    });
});

const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com', 
    port: 587, 
    secure: false,
    auth: {
        user: gmail,
        pass: email_password
    }
});


app.post('/send-email', (req, res) => {
    const { email, message } = req.body;
    if (!email || !message) {
        return res.status(400).send('Email and message are required');
    }

    const signature = generateSignature(message); 
    const emailDetails = {
        recipient: email,
        time: new Date().toLocaleString(),
        signed: true
    };

    const mailOptions = {
        from: gmail,
        to: email,
        subject: 'Message with Digital Signature',
        text: `Message: ${message}\n\nDigital Signature: ${signature}`
    };

    transporter.sendMail(mailOptions, (err, info) => {
        if (err) {
            console.error('Error sending email:', err);
            return res.status(500).send('Failed to send email');
        }
        console.log('Email sent:', info.response);
        res.render('index', { users: [], emailDetails }); // Pass email details to the view
    });
});

// to display signature on screen
app.post('/generate-signature', (req, res) => {
    const { message } = req.body;
    if (!message) {
        return res.status(400).send('Message is required');
    }

    const signature = generateSignature(message);
    res.render('index', { users: [], signature }); 
});

app.post('/verify-signature', (req, res) => {
    const { message, signature } = req.body;
    if (!message || !signature) {
        return res.status(400).send('Message and signature are required');
    }

    const isValid = verifySignature(message, signature); 
    res.render('index', { users: [], signature, message, isValid }); 
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
