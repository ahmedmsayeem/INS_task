const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const cryptoModule = require('crypto');

const app = express();
const db = new sqlite3.Database(':memory:');

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));

const SECRET_KEY = cryptoModule.randomBytes(32); 
const IV_LENGTH = 16; // AES IV length


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
        const hashedPassword = await bcrypt.hash(password, 10); // Hash the password
        const encryptedName = encrypt(name); // Encrypt the name
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
                    name: isMatch ? decrypt(user.name) : 'password wrong', // Decrypt only if password matches
                    password: isMatch ? globalPassword : 'password wrong',
                };
            })
        );
        res.render('index', { users: decryptedUsers });
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
