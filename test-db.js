const mongoose = require('mongoose');
require('dotenv').config();

// Construct MongoDB URI
const username = encodeURIComponent(process.env.MONGODB_USERNAME);
const password = encodeURIComponent(process.env.MONGODB_PASSWORD);
const database = process.env.MONGODB_DATABASE;

const mongoURI = `mongodb+srv://${username}:${password}@cluster0.y7axs.mongodb.net/${database}?retryWrites=true&w=majority`;

async function testConnection() {
    try {
        console.log('Attempting to connect to MongoDB...');
        await mongoose.connect(mongoURI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 5000,
        });
        console.log('Successfully connected to MongoDB!');
        
        // Test the connection by performing a simple operation
        const collections = await mongoose.connection.db.collections();
        console.log('Available collections:', collections.map(c => c.collectionName));
        
        await mongoose.connection.close();
        console.log('Connection closed successfully.');
    } catch (err) {
        console.error('Connection error:', err);
    } finally {
        process.exit();
    }
}

testConnection(); 