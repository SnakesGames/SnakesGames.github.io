// Import Firebase SDK
import { db } from './firebaseConfig';

// Login/Register function
async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  if (username && password) {
    const userRef = db.collection("users").doc(username);
    const userSnap = await userRef.get();

    if (!userSnap.exists) {
      // User doesn't exist, create an account
      await userRef.set({
        username,
        password,
        role: 'Member',  // Default role
        canMakeAnnouncements: false  // Default permission
      });
      alert('Account created successfully!');
    } else {
      const userData = userSnap.data();
      if (userData.password === password) {
        alert(`Welcome back, ${username}!`);
      } else {
        alert('Incorrect password!');
      }
    }
  } else {
    alert('Please enter both username and password.');
  }
}
