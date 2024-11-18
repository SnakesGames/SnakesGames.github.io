// Firebase configuration
const firebaseConfig = {
  apiKey: "AIzaSyAVuOFprs63HWGiiaPYJg8tO_Exd4xLPkY",
  authDomain: "snakes-mods-website.firebaseapp.com",
  projectId: "snakes-mods-website",
  storageBucket: "snakes-mods-website.firebasestorage.app",
  messagingSenderId: "625901442559",
  appId: "1:625901442559:web:80fab007932b5bd63903ca",
  measurementId: "G-4H680E8EM0"
};

// Initialize Firebase
const app = firebase.initializeApp(firebaseConfig);
const db = firebase.firestore();
