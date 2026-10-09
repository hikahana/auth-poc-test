// Copy to firebase-config.js and fill in (Firebase console > Project settings > Your apps > SDK setup).
export const firebaseConfig = {
  apiKey: "YOUR_API_KEY",
  authDomain: "YOUR_PROJECT.firebaseapp.com",
  projectId: "YOUR_PROJECT",
  appId: "YOUR_APP_ID",
};

// OAuth client ID for the "Sign in with Google" button. Must be the same value as
// GOOGLE_OAUTH_CLIENT_ID in .env (Google Cloud console > APIs & Services > Credentials,
// "Web client (auto created by Google Service)").
export const googleClientId = "YOUR_CLIENT_ID.apps.googleusercontent.com";
