# Cyber Forge QR Checker

## Run locally

1. Install Node.js 18 or newer.
2. From this folder, run `npm install`.
3. Run `npm start`.
4. Open <http://localhost:3000/app>.

The Express server and frontend pages are kept together in this folder. QR
image decoding and QR generation run in the browser. Local account data is
stored in `data/db.json`; keep `.env` private and configure it from
`.env.example` when needed.
