// Imports

import express from 'express';
import {engine} from 'express-handlebars';
import {join} from 'path';
import {router as viewsRouter} from './routes/routes.views.js';
import {router as productRouter} from './routes/routes.products.js';
import {router as cartRouter} from './routes/routes.carts.js';
import {router as sessionsRouter} from './routes/routes.sessions.js'
import {Server} from 'socket.io';
import { messagesModel } from './dao/models/messages.model.js';
import sessions from 'express-session';
import MongoStore from 'connect-mongo';
import __dirname from './utils.js'; 
import mongoose from 'mongoose';
import { initializePassport } from './config/config.passport.js';
import passport from 'passport';

// Definitions

const PORT = 3000; 
const viewFolder = join(__dirname, '/views');
const publicFolder = join(__dirname, '/public');
const app = express();
const server = app.listen(PORT, ()=> console.log('Server online on Port: ', PORT));
export const io = new Server (server);

// Methods

app.use(sessions({
  store: MongoStore.create({
    mongoUrl: 'mongodb+srv://codiox:CoderCoder@ecommerce.76nmmgq.mongodb.net/?retryWrites=true&w=majority',
    mongoOptions: {dbName:'ecommerce'},
    ttl: 180,
  }),

  secret: 'codercoder',
  resave: true,
  saveUninitialized: false
}))

app.use(express.json());
app.use(express.urlencoded({extended:true}));
initializePassport();
app.use(passport.initialize());
app.use(passport.session())
app.engine('handlebars', engine({
  runtimeOptions: {
    allowProtoPropertiesByDefault: true,
    allowProtoMethodsByDefault: true,
  }
}));
app.set('view engine', 'handlebars');
app.set('views', viewFolder);
app.use(express.static(publicFolder));
app.use('/', viewsRouter);
app.use('/api/products', productRouter);
app.use('/api/carts', cartRouter)
app.use('/api/sessions', sessionsRouter)

async function connectDB() { // Connects to MongoDB
  try {
    await mongoose.connect('mongodb+srv://codiox:CoderCoder@ecommerce.76nmmgq.mongodb.net/?retryWrites=true&w=majority', {dbName:'ecommerce'})
    console.log('DB Online');
  } catch (error) {
    console.log(error)
  }
}

async function getChats() { // Load the chats form DB
  try {
    let result = await messagesModel.find();
    return result
  } catch (error) {
    console.log('Error loading the chats: ', error);
  }
}

async function saveChats({sender, message}) { // Save chats to DB
  try {
    let result = await messagesModel.create({email:sender, message: message});
    return result
  } catch (error) {
    console.log('Error saving the chats: ', error);
  }

}

// Init

connectDB();

let users = []; // Stores the users that are currently logged in to broadcast them

io.on('connection', (socket) => {
  console.log(`New socket connected with ID: ${socket.id}`)
  socket.on('login', async (name) => {
    console.log('The user with the following ID has logged in: ', name);
    socket.broadcast.emit('newUser', name); // We broadcast to everyone (except the sender), that a user has logged in
    users.push({ name, id: socket.id });
    let messagesDB = await getChats(); // Get the messages from MongoDB
    console.log('Messages in the DB: ', messagesDB)
    socket.emit('getMessages', messagesDB); // Loads all the messages stored in memory to the new user
  });

  socket.on('message', async (messageObj) => {
    console.log(
      `The user ${messageObj.sender} sent the following message: ${messageObj.message}`
    );
    io.emit('newMessage', messageObj); // We send the message to everyone connected to the server
    await saveChats(messageObj); // Saves the message to the DB
  });

  socket.on('disconnect', () => {
    // If a user disconnects, we let everyone know
    let disconnectedUser = users.find((user) => user.id === socket.id);
    if (disconnectedUser) {
      io.emit('userDisconnect', disconnectedUser.name);
    }
  });
});
