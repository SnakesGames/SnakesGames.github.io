import { db } from './firebaseConfig';

async function postMod() {
  const username = document.getElementById('username').value;
  const modName = document.getElementById('modName').value;
  const modDescription = document.getElementById('modDescription').value;
  const modFileURL = document.getElementById('modFileURL').value;

  // Check if the user exists
  const userRef = db.collection("users").doc(username);
  const userSnap = await userRef.get();

  if (userSnap.exists) {
    const userData = userSnap.data();

    // Check if the user has permission to post mods (e.g., role is "Admin" or "Moderator")
    if (userData.role === 'Admin' || userData.role === 'Moderator') {
      // Create a new mod document in the 'mods' sub-collection
      await userRef.collection('mods').add({
        modName,
        modDescription,
        modFileURL,
        modAuthor: username,
        datePosted: firebase.firestore.FieldValue.serverTimestamp()
      });

      alert('Mod posted successfully!');
    } else {
      alert('You do not have permission to post mods.');
    }
  } else {
    alert('User does not exist.');
  }
}
