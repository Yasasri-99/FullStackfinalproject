const express = require('express');
const bcrypt = require('bcrypt');
const admin = require('firebase-admin');
const serviceAccount = require('./jyothiservicekey.json');

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: 'https://ecommerce-f85b8.firebaseio.com' 
});

const db = admin.firestore();
const bodyParser = require('body-parser');
const app = express();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(__dirname + '/public'));

app.get('/signup.html', (req, res) => {
  res.sendFile(__dirname + '/public/signup.html');
});

app.post('/signupSubmit', async (req, res) => {
  // Your signup form processing code here
  try {
    const { Firstname, Email, Password } = req.body;

    // Check if the email is already registered
    const usersRef = db.collection('details');
    const snapshot = await usersRef.where('Email', '==', Email).get();

    if (snapshot.empty) {
      // Email is not registered, so create a new user record with a hashed password
      const saltRounds = 10;

      // Hash the password
      const hashedPassword = await bcrypt.hash(Password, saltRounds);

      // Store the hashed password in the database
      await usersRef.add({
        Firstname,
        Email,
        Password: hashedPassword, // Store the hashed password
      });

      // Redirect to the index page with a success flag
      res.redirect('/login.html?signupSuccess=true');
    } else {
      // Email is already registered
      res.redirect('/signup.html?signupSuccess=false');
    }
  } catch (error) {
    console.error('Error processing signup: ', error);
    res.redirect('/signup.html?signupSuccess=false');
  }
});

app.get('/login.html', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
});

app.post('/loginSubmit', async (req, res) => {
  // Your login form processing code here
  try {
    const { Email, Password } = req.body;

    const usersRef = db.collection('details');
    const snapshot = await usersRef.where('Email', '==', Email).get();

    if (!snapshot.empty) {
      const user = snapshot.docs[0].data();
      const hashedPassword = user.Password;

      const passwordMatch = await bcrypt.compare(Password, hashedPassword);

      if (passwordMatch) {
        // Passwords match, login successful
        res.cookie('userEmail', Email, { path: '/' });
        res.redirect('/index.html?loginSuccess=true');
      } else {
        // Passwords do not match, login failed
        res.redirect('/login.html?loginSuccess=false');
      }
    } else {
      // Email not found, login failed
      res.redirect('/login.html?loginSuccess=false');
    }
  } catch (error) {
    console.error('Error processing login: ', error);
    res.redirect('/login.html?loginSuccess=false');
  }
});

app.get('/index.html', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
