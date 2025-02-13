const mongoose = require('mongoose');
require('dotenv').config();

const dbURI = process.env.MONGODB_URI;

async function testConnection() {
    try {
        console.log('Attempting to connect...');
        await mongoose.connect(dbURI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });
        console.log('Connected successfully!');
        await mongoose.connection.close();
        console.log('Connection closed.');
    } catch (err) {
        console.error('Connection error:', err);
    }
}

testConnection(); 