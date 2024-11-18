import { auth, db } from './firebaseConfig';

async function login() {
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  try {
    // Check if user exists
    const userRef = db.collection("users").doc(username);
    const userSnap = await userRef.get();

    if (userSnap.exists) {
      const userData = userSnap.data();

      // Validate password (simple check for demo)
      if (password === userData.password) {
        // Store user data in sessionStorage for the session
        sessionStorage.setItem('username', username);
        
        // Check user's role
        if (userData.role === 'Admin' || userData.role === 'Moderator') {
          // Allow mod posting if the user has the correct role
          document.getElementById('modPostForm').style.display = 'block'; // Show mod post form
        } else {
          // Hide mod post form if the user does not have permission
          document.getElementById('modPostForm').style.display = 'none';
          alert('You do not have permission to post mods.');
        }
      } else {
        alert('Incorrect password.');
      }
    } else {
      alert('User does not exist.');
    }
  } catch (error) {
    console.error("Error logging in: ", error);
    alert("Login failed. Please try again.");
  }
}

