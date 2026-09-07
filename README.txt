JNCC La Gonave Stripe Backend - Vercel Ready

Files:
- server.js
- package.json

Vercel environment variables required:
STRIPE_SECRET_KEY=sk_live_...
STRIPE_PUBLISHABLE_KEY=pk_live_...
ALLOWED_ORIGINS=https://www.jnccfaith.org,https://jnccfaith.org
DONATION_RETURN_URL=https://www.jnccfaith.org/parroise-st.-marie-madleine(-lagonave)

Never put STRIPE_SECRET_KEY in website HTML or public code.
After saving environment variables in Vercel, redeploy the project.
Test the deployed backend by opening:
https://YOUR-PROJECT.vercel.app/health
Expected response: {"ok":true}

Then update the website HTML variable:
var STRIPE_API_BASE = "https://YOUR-PROJECT.vercel.app";
