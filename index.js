import express from 'express';
import jwt from 'jsonwebtoken';
import { uuid } from 'uuidv4'

const SECRET_KEY = '!]%(zA%cI{gcCY4';
let users = {}; // In-memory storage for users, assume that this is a database
let noncekeys = {}; // storing nonce values for each user when signing and verifying tokens

const app = express();

app.get('/register', (req, res) => {
    const { username, password } = req.query;

    if(users[username]) return res.status(400).send('User already exists');

    users[username] = { username, password };
    noncekeys[username] = uuid();

    return res.status(200).send('User created');
});

app.get('/login', async (req, res) => {
    const { username, password } = req.query;

    if(!users[username]) return res.status(400).send('User does not exist');
    if(users[username].password !== password) return res.status(400).send('Invalid password');
    
    const signed_token = jwt.sign({ username }, `${SECRET_KEY}${noncekeys[username]}`);
    return res.status(200).send(signed_token);
});

app.get('/logout', async (req, res) => {
    const { token } = req.query;

    let result;

    try{
        let payload = jwt.decode(token);
        result = jwt.verify(token, `${SECRET_KEY}${noncekeys[payload.username]}`);
        noncekeys[result.username] = uuid();
        return res.status(200).send('All the tokens are invalidated for ' + result.username);
    }catch(err){
        return res.status(400).send('Invalid token');
    }
});

app.get('/', (req, res) => {
    const { token } = req.query;

    try{
        let payload = jwt.decode(token);
        const result = jwt.verify(token, `${SECRET_KEY}${noncekeys[payload.username]}`);
        return res.status(200).send('Hello ' + result.username);
    }catch(err){
        return res.status(400).send('Invalid token');
    }
});

app.listen(5055, () => {
    console.log('Server is running on port :5055');
})