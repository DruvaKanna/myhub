# Chat Chat

A code-based private messaging app. People exchange temporary five-character codes in person, each person confirms the other person's current code, and then they can message each other from anywhere.

## Included features

- Responsive browser interface for desktop and mobile.
- Account registration and sign-in with bcrypt password hashing.
- HttpOnly signed session cookies.
- A permanent random five-character connection code that stays the same across sign-ins and does not expire. It changes only from Settings.
- Two-way code confirmation before a connection is created; the person approving the request enters a contact name for the requester.
- Private one-to-one text conversations.
- Clickable website links in messages.
- Private file sharing for images, PDFs, text/CSV files, and common Office documents.
- Up to five files per message, default limit 15 MB per file.
- Live message and connection notifications with Socket.IO.
- Blocking and reporting controls.
- Settings with saved screen-color choices: blue, green, red, black, white, purple, and orange.
- Changing a connection code shows a warning, then removes all contacts, pending requests, and the user's conversations and shared files.
- No voice calls or video calls.

## Run locally

1. Install Node.js 20 or newer.
2. Copy the example environment file to a file named .env.
3. Set SESSION_SECRET to a long random string. One option is to generate it with the OpenSSL random command.
4. Install packages with npm install.
5. Start the app with npm start.
6. Open localhost on port 3000 in your browser.

The SQLite database and uploaded files are stored under DATA_DIR. The default local folder is ./data. Messages and attachments are stored on the server; this version does not use end-to-end encryption, so the service operator may be able to access stored content.

## How connections work

1. Sign in. Chat Chat shows your permanent five-character connection code. It does not expire.
2. Meet someone you already know and exchange the codes you currently see.
3. Enter their code to send a connection request.
4. The other person opens Requests, asks you for your current code, and enters it to confirm.
5. Both accounts are connected and can start a private chat.

Codes are for finding and confirming a connection. They are not account passwords, passkeys, or proof of someone's identity. Your code stays the same when you sign out or sign back in. To replace it, open Settings and choose Change my code; after the warning, confirming this action removes all contacts, pending requests, conversations, and shared files associated with your account. Never share your account password or a code with someone you do not know and trust.

## File-sharing safety

The server accepts a limited set of common image, PDF, text/CSV, and Office document types. Executables, scripts, and archive files are not accepted. Downloads are served as attachments and are only available to participants in that connected conversation.

This first version does not include a malware-scanning service or an administrator report-review dashboard. Reports are saved in the database but are not automatically reviewed. Do not open unexpected files, even if they came from someone you know. Before opening the service to the public, add malware scanning, email verification, a moderation process, backups, and monitoring.

## Deploy

The repository includes a Render Blueprint. It configures a Node web service, a generated session secret, and a persistent disk mounted at /var/data so the SQLite database and uploaded files survive restarts.

Connect this repository to Render and create a Blueprint instance from render.yaml. The service must use HTTPS in production. Keep SESSION_SECRET private and never commit .env or database files.

## Production checklist

- This is a working first version, not a security-reviewed production messaging service.
- Use HTTPS, keep dependencies updated, and configure backups for the persistent data disk.
- Add email verification and account recovery before inviting a large group of users.
- Add automated malware scanning and a moderation process before enabling broad file sharing.
- The five-character codes are temporary connection codes; account access is protected separately by password-based sign-in.
- There is no phone or video calling feature.

## Main files

- server.js — Express API, authentication, SQLite database, uploads, and Socket.IO.
- public/index.html — front-end structure.
- public/styles.css — responsive midnight-blue interface.
- public/app.js — front-end behavior and API integration.
- render.yaml — deployment blueprint.